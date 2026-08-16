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
    pub clone_url: String,
    #[allow(dead_code)]
    pub full_name: String,
}

#[derive(Debug, Deserialize)]
pub struct Repository {
    pub full_name: String,
    pub clone_url: String,
    pub name: String,
    pub owner: RepoOwner,
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
    /// The clone URL for the PR's head (handles forks).
    #[must_use]
    pub fn clone_url(&self) -> &str {
        self.pull_request
            .head
            .repo
            .as_ref()
            .map_or(&self.repository.clone_url, |r| &r.clone_url)
    }

    /// Generate the preview hostname for this PR.
    ///
    /// The host is a **single DNS label** of the form `<owner>-<repo>-pr-<N>`
    /// followed by `.{domain}`. Keeping the identity in one label means a
    /// wildcard certificate for `*.{domain}` covers every preview host, so no
    /// per-host certificate issuance is required at the edge.
    ///
    /// The label is normalized to be DNS-safe (see [`preview_label`]). When
    /// normalization alters the raw identity, or the label would exceed the
    /// 63-character DNS label limit, a short hash of the exact `owner/repo#N`
    /// identity is appended so distinct PRs can never collide onto one host.
    #[must_use]
    pub fn preview_host(&self, domain: &str) -> String {
        let label = preview_label(
            &self.repository.owner.login,
            &self.repository.name,
            self.number,
        );
        format!("{label}.{domain}")
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

    #[test]
    fn preview_host_format() {
        let event = PullRequestEvent {
            action: "opened".into(),
            number: 42,
            pull_request: PullRequest {
                head: PullRequestHead {
                    ref_name: "feature/xyz".into(),
                    sha: "abc123".into(),
                    repo: None,
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
            },
            installation: None,
        };

        assert_eq!(
            event.preview_host("preview.ephpm.dev"),
            "ephpm-my-blog-pr-42.preview.ephpm.dev"
        );
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
            },
            installation: None,
        };

        assert!(make("closed").should_teardown());
        assert!(!make("opened").should_teardown());
    }
}
