//! GitHub webhook parsing and signature verification.

use axum::body::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::Deserialize;

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
    pub base: PullRequestBase,
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
    pub ref_name: String,
}

#[derive(Debug, Deserialize)]
pub struct PullRequestRepo {
    pub clone_url: String,
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
    #[must_use]
    pub fn preview_host(&self, domain: &str) -> String {
        let repo = &self.repository.name;
        format!("pr-{}.{repo}.{domain}", self.number)
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
            "pr-42.my-blog.preview.ephpm.dev"
        );
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
                head: PullRequestHead { ref_name: "x".into(), sha: "x".into(), repo: None },
                base: PullRequestBase { ref_name: "main".into() },
                merged: None,
            },
            repository: Repository {
                full_name: "a/b".into(), clone_url: "x".into(), name: "b".into(),
                owner: RepoOwner { login: "a".into() },
            },
            installation: None,
        };

        assert!(make("closed").should_teardown());
        assert!(!make("opened").should_teardown());
    }
}
