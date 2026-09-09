//! GitHub webhook parsing and signature verification.

use axum::body::Bytes;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Verify the `X-Hub-Signature-256` header against the webhook secret.
///
/// GitHub sends: `sha256=<hex digest>`.
///
/// # Errors
///
/// Returns an error if the signature is missing, malformed, or doesn't match.
pub fn verify_signature(body: &Bytes, secret: &str, signature_header: &str) -> anyhow::Result<()> {
    let hex_sig = signature_header
        .strip_prefix("sha256=")
        .ok_or_else(|| anyhow::anyhow!("invalid signature format"))?;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);

    let expected = hex::decode(hex_sig)?;
    mac.verify_slice(&expected)
        .map_err(|_| anyhow::anyhow!("webhook signature mismatch"))
}

/// The subset of a GitHub `pull_request` webhook event we care about.
#[derive(Debug, Deserialize)]
pub struct PullRequestEvent {
    pub action: String,
    pub number: u64,
    pub pull_request: PullRequest,
    pub repository: Repository,
    pub installation: Option<Installation>,
}

#[derive(Debug, Deserialize)]
pub struct PullRequest {
    pub head: PullRequestHead,
    // Parsed from the webhook payload for completeness; not read yet.
    #[allow(dead_code)]
    pub base: PullRequestBase,
    #[allow(dead_code)]
    pub merged: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PullRequestHead {
    /// Branch name (e.g., `feature/new-header`).
    #[serde(rename = "ref")]
    pub ref_name: String,
    /// SHA of the head commit.
    pub sha: String,
    /// The head repository (absent for a deleted fork). See
    /// [`PullRequestRepo::clone_url`] for why it is not a fetch source.
    pub repo: Option<PullRequestRepo>,
}

#[derive(Debug, Deserialize)]
pub struct PullRequestBase {
    #[serde(rename = "ref")]
    #[allow(dead_code)]
    pub ref_name: String,
}

#[derive(Debug, Deserialize)]
pub struct PullRequestRepo {
    /// The head repo's clone URL. Parsed for completeness but deliberately not
    /// used as a fetch source: `refs/pull/<n>/head` on the base repo resolves
    /// the same commit without trusting a fork.
    #[allow(dead_code)]
    pub clone_url: String,
    /// `owner/name` of the head repo — compared against the base repo to
    /// detect a fork.
    pub full_name: String,
}

#[derive(Debug, Deserialize)]
pub struct Repository {
    pub full_name: String,
    pub clone_url: String,
    pub name: String,
    pub owner: RepoOwner,
    /// Whether the base repository is private. GitHub always sends this on a
    /// `pull_request` webhook; defaulted to `true` (fail closed) for the same
    /// reason as the job path — an absent value must not publish a private
    /// preview open.
    #[serde(default = "private_when_absent")]
    pub private: bool,
}

/// Serde default for [`Repository::private`]: absent ⇒ private (fail closed).
fn private_when_absent() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct RepoOwner {
    pub login: String,
}

#[derive(Debug, Deserialize)]
pub struct Installation {
    pub id: u64,
}

impl PullRequestEvent {
    /// Build the provisioning request for this event.
    ///
    /// The label is computed here only because this legacy path has no job
    /// file to read it from; the rules are the same ones switchboard-api ports
    /// (see [`preview_label`]), so both producers agree.
    #[must_use]
    pub fn to_preview_request(&self) -> crate::deployer::PreviewRequest {
        crate::deployer::PreviewRequest {
            label: preview_label(
                &self.repository.owner.login,
                &self.repository.name,
                self.number,
            ),
            repo_full_name: self.repository.full_name.clone(),
            owner: self.repository.owner.login.clone(),
            repo_name: self.repository.name.clone(),
            pr_number: self.number,
            // Base repo + refs/pull/<n>/head: one fetch strategy for both the
            // queue path and this one.
            fetch_url: self.repository.clone_url.clone(),
            fetch_ref: Some(format!("refs/pull/{}/head", self.number)),
            branch: Some(self.pull_request.head.ref_name.clone()),
            sha: self.pull_request.head.sha.clone(),
            installation_id: self.installation.as_ref().map(|i| i.id),
            fork: self.is_fork(),
            private: self.repository.private,
        }
    }

    /// Whether the PR head is a fork — the same rule switchboard-api applies:
    /// the head repo's `full_name` differs from the base repo's
    /// (case-insensitively, GitHub full names are case-preserving but
    /// case-insensitive), **or the head repo is absent** (deleted fork).
    #[must_use]
    pub fn is_fork(&self) -> bool {
        match &self.pull_request.head.repo {
            None => true,
            Some(repo) => !repo
                .full_name
                .eq_ignore_ascii_case(&self.repository.full_name),
        }
    }

    /// Whether this is an event we should deploy on.
    #[must_use]
    pub fn should_deploy(&self) -> bool {
        matches!(self.action.as_str(), "opened" | "synchronize" | "reopened")
    }

    /// Whether this is an event we should tear down on.
    #[must_use]
    pub fn should_teardown(&self) -> bool {
        self.action == "closed"
    }
}

/// Maximum length of a single DNS label (RFC 1035).
const MAX_LABEL: usize = 63;
/// Number of hex characters of the identity hash appended on collision/overflow.
const HASH_LEN: usize = 6;

/// Normalize an arbitrary string into a DNS-label-safe form: lowercase, only
/// `[a-z0-9-]`, with repeated `-` collapsed and leading/trailing `-` trimmed.
fn sanitize_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let c = ch.to_ascii_lowercase();
        let mapped = if c.is_ascii_alphanumeric() { c } else { '-' };
        if mapped == '-' {
            if !prev_dash {
                out.push('-');
            }
            prev_dash = true;
        } else {
            out.push(mapped);
            prev_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

/// First [`HASH_LEN`] hex chars of `sha256("owner/repo#N")` — a stable,
/// collision-resistant disambiguator tied to the exact (pre-sanitization)
/// identity, so two identities that sanitize alike still get distinct hosts.
fn identity_hash(owner: &str, repo: &str, number: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{owner}/{repo}#{number}").as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    hex[..HASH_LEN].to_string()
}

/// Build the single DNS label for a PR preview host: `<owner>-<repo>-pr-<N>`,
/// sanitized. If sanitization changed the raw identity (uppercase/invalid
/// chars) or the label exceeds [`MAX_LABEL`], append `-<hash>` (truncating the
/// base so the whole label fits and never ends in `-`). Otherwise the
/// human-readable label is used verbatim.
#[must_use]
pub fn preview_label(owner: &str, repo: &str, number: u64) -> String {
    let raw = format!("{owner}-{repo}-pr-{number}");
    let sanitized = sanitize_label(&raw);

    // Verbatim only when nothing was lost to sanitization and it fits.
    if sanitized == raw && sanitized.len() <= MAX_LABEL {
        return sanitized;
    }

    let hash = identity_hash(owner, repo, number);
    let max_base = MAX_LABEL - HASH_LEN - 1; // room for '-' + hash
    let mut base = sanitized;
    if base.len() > max_base {
        base.truncate(max_base);
    }
    let base = base.trim_end_matches('-');
    format!("{base}-{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_valid_signature() {
        let secret = "test-secret";
        let body = Bytes::from_static(b"hello world");

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(&body);
        let sig = hex::encode(mac.finalize().into_bytes());
        let header = format!("sha256={sig}");

        assert!(verify_signature(&body, secret, &header).is_ok());
    }

    #[test]
    fn reject_invalid_signature() {
        let body = Bytes::from_static(b"hello world");
        let header = "sha256=0000000000000000000000000000000000000000000000000000000000000000";

        assert!(verify_signature(&body, "secret", header).is_err());
    }

    #[test]
    fn reject_missing_prefix() {
        let body = Bytes::from_static(b"hello world");
        assert!(verify_signature(&body, "secret", "bad-header").is_err());
    }

    /// An event whose head repo is `head_repo` (None = deleted fork).
    fn event_with_head_repo(head_repo: Option<&str>) -> PullRequestEvent {
        PullRequestEvent {
            action: "opened".into(),
            number: 42,
            pull_request: PullRequest {
                head: PullRequestHead {
                    ref_name: "feature/xyz".into(),
                    sha: "abc123".into(),
                    repo: head_repo.map(|full_name| PullRequestRepo {
                        clone_url: format!("https://github.com/{full_name}.git"),
                        full_name: full_name.into(),
                    }),
                },
                base: PullRequestBase {
                    ref_name: "main".into(),
                },
                merged: None,
            },
            repository: Repository {
                full_name: "ephpm/my-blog".into(),
                clone_url: "https://github.com/ephpm/my-blog.git".into(),
                name: "my-blog".into(),
                owner: RepoOwner {
                    login: "ephpm".into(),
                },
                private: false,
            },
            installation: None,
        }
    }

    #[test]
    fn event_converts_to_a_preview_request() {
        let event = event_with_head_repo(Some("ephpm/my-blog"));

        let req = event.to_preview_request();
        assert!(!req.fork, "same-repo head must not be flagged as a fork");
        assert_eq!(req.label, "ephpm-my-blog-pr-42");
        assert_eq!(
            req.preview_host("preview.ephpm.dev"),
            "ephpm-my-blog-pr-42.preview.ephpm.dev"
        );
        // Fetch is always base repo + refs/pull/<n>/head, never the head repo.
        assert_eq!(req.fetch_url, "https://github.com/ephpm/my-blog.git");
        assert_eq!(req.fetch_ref.as_deref(), Some("refs/pull/42/head"));
        assert_eq!(req.sha, "abc123");
        assert_eq!(req.pr_number, 42);
    }

    #[test]
    fn private_repo_flows_to_the_request() {
        let mut event = event_with_head_repo(Some("ephpm/my-blog"));
        assert!(
            !event.to_preview_request().private,
            "the sample repo is public"
        );
        event.repository.private = true;
        assert!(
            event.to_preview_request().private,
            "a private base repo must reach the deployer so its preview is gated"
        );
    }

    #[test]
    fn fork_detected_by_differing_head_repo() {
        // Same rules switchboard-api applies to compute `pull_request.fork`.
        let event = event_with_head_repo(Some("attacker/my-blog"));
        assert!(event.is_fork());
        assert!(event.to_preview_request().fork);
    }

    #[test]
    fn fork_comparison_is_case_insensitive() {
        // GitHub full names are case-preserving but case-insensitive; a
        // capitalization difference is the same repo, not a fork.
        let event = event_with_head_repo(Some("EPHPM/My-Blog"));
        assert!(!event.is_fork());
    }

    #[test]
    fn deleted_fork_head_repo_counts_as_a_fork() {
        // A missing head repo means the fork was deleted — same-repo PRs
        // always carry their repo, so absent ⇒ fork (matches the API).
        let event = event_with_head_repo(None);
        assert!(event.is_fork());
        assert!(event.to_preview_request().fork);
    }

    #[test]
    fn preview_label_verbatim_when_clean() {
        // Normal case: human-readable, used verbatim (no hash).
        assert_eq!(
            preview_label("ephpm", "wordpress-sample", 1),
            "ephpm-wordpress-sample-pr-1"
        );
    }

    #[test]
    fn preview_label_sanitized_and_hashed() {
        // Uppercase + underscore force sanitization, so a hash is appended.
        let label = preview_label("ephpm", "My_Repo", 1);
        let hash = identity_hash("ephpm", "My_Repo", 1);
        assert_eq!(label, format!("ephpm-my-repo-pr-1-{hash}"));
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );
    }

    #[test]
    fn preview_label_long_repo_truncated_and_hashed() {
        let long_repo = "a".repeat(100);
        let label = preview_label("ephpm", &long_repo, 7);
        assert!(label.len() <= MAX_LABEL, "label too long: {}", label.len());
        // Ends in the identity hash, not a dash.
        let hash = identity_hash("ephpm", &long_repo, 7);
        assert!(label.ends_with(&format!("-{hash}")));
        assert!(!label.trim_end_matches(&format!("-{hash}")).ends_with('-'));
    }

    #[test]
    fn preview_label_collision_safe() {
        // Two distinct identities that sanitize to the same base must not
        // collide onto the same host — the hash disambiguates them.
        let a = preview_label("ephpm", "My-Repo", 1);
        let b = preview_label("ephpm", "my_repo", 1);
        assert!(a.starts_with("ephpm-my-repo-pr-1-"));
        assert!(b.starts_with("ephpm-my-repo-pr-1-"));
        assert_ne!(a, b, "distinct identities collided: {a}");
    }

    #[test]
    fn should_deploy_on_opened() {
        let make = |action: &str| PullRequestEvent {
            action: action.into(),
            number: 1,
            pull_request: PullRequest {
                head: PullRequestHead {
                    ref_name: "x".into(),
                    sha: "x".into(),
                    repo: None,
                },
                base: PullRequestBase {
                    ref_name: "main".into(),
                },
                merged: None,
            },
            repository: Repository {
                full_name: "a/b".into(),
                clone_url: "x".into(),
                name: "b".into(),
                owner: RepoOwner { login: "a".into() },
                private: false,
            },
            installation: None,
        };

        assert!(make("opened").should_deploy());
        assert!(make("synchronize").should_deploy());
        assert!(make("reopened").should_deploy());
        assert!(!make("closed").should_deploy());
        assert!(!make("edited").should_deploy());
    }

    #[test]
    fn should_teardown_on_closed() {
        let make = |action: &str| PullRequestEvent {
            action: action.into(),
            number: 1,
            pull_request: PullRequest {
                head: PullRequestHead {
                    ref_name: "x".into(),
                    sha: "x".into(),
                    repo: None,
                },
                base: PullRequestBase {
                    ref_name: "main".into(),
                },
                merged: None,
            },
            repository: Repository {
                full_name: "a/b".into(),
                clone_url: "x".into(),
                name: "b".into(),
                owner: RepoOwner { login: "a".into() },
                private: false,
            },
            installation: None,
        };

        assert!(make("closed").should_teardown());
        assert!(!make("opened").should_teardown());
    }
}
