//! The job document — the interface the daemon implements against.
//!
//! switchboard-api verifies a GitHub webhook delivery and writes one of these
//! (schema version 1) into `queue/`; the daemon reads it and acts. The full
//! contract, field by field, is switchboard-api's `README.md` ("The job file
//! contract") and its `src/Queue/Job.php`; this module mirrors it.
//!
//! # Trust
//!
//! The job originates from an internet-facing process. The API already
//! validates every value against the same patterns replicated here — a signed
//! payload is authentic, not harmless, and a `head.ref` of
//! `--upload-pack=/bin/sh` is rejected there before it is ever written. The
//! queue is nonetheless the daemon's trust boundary (signature verification now
//! lives only in the API), so the daemon re-validates: defense in depth is
//! cheap, and "the API validated it" is a claim about another codebase. Every
//! field that becomes a `git` argument or a path component is checked in
//! [`Job::validate`] before use.

use anyhow::{Context, ensure};
use serde::Deserialize;

use crate::site::is_valid_site_key;

/// The only job schema version this daemon understands.
pub const SUPPORTED_SCHEMA: u32 = 1;

/// What the API decided a delivery means. Act on this, never re-derive it from
/// `action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Provision or refresh a preview.
    Deploy,
    /// Remove a preview.
    Teardown,
}

/// A parsed, validated job.
///
/// The DTO structs here mirror the schema-1 wire contract in full; not every
/// field is read by the daemon today (`job_id`, `action`, `sender`, `title`,
/// `draft`, `merged`, `private`, `head.repo_full_name` are carried for
/// completeness, tracing, and forward-compat). `allow(dead_code)` documents
/// that intent rather than dropping fields the contract defines.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    /// Schema version — validated to equal [`SUPPORTED_SCHEMA`].
    pub schema: u32,
    /// `<millis>-<16 hex>`; unique, sortable, safe as a filename.
    pub job_id: String,
    /// The `X-GitHub-Delivery` GUID, for tracing back to GitHub's UI.
    pub delivery_id: String,
    /// Always `"pull_request"` in schema 1.
    pub event: String,
    /// The raw GitHub action (`opened`/`synchronize`/`reopened`/`closed`).
    pub action: String,
    /// `"deploy"` or `"teardown"`. Parsed via [`Job::intent`].
    pub intent: String,
    /// Preview identity.
    pub preview: Preview,
    /// The repository the PR targets (the base repo).
    pub repository: Repository,
    /// The pull request.
    pub pull_request: PullRequest,
    /// The GitHub login that triggered the event.
    #[serde(default)]
    pub sender: Option<String>,
    /// The GitHub App installation — needed to mint a token. `None` means the
    /// daemon cannot report to GitHub for this job.
    #[serde(default)]
    pub installation_id: Option<u64>,
}

/// Preview identity — the authoritative label.
#[derive(Debug, Clone, Deserialize)]
pub struct Preview {
    /// The DNS label naming this preview. **Authoritative** — used verbatim,
    /// never recomputed. See [`crate::preview`].
    pub label: String,
}

/// The base repository of the PR.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Repository {
    /// `owner/name`.
    pub full_name: String,
    /// Owner login.
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// `https://` clone URL on the configured GitHub host.
    pub clone_url: String,
    /// Default branch, when the payload carried one.
    #[serde(default)]
    pub default_branch: Option<String>,
    /// Whether the base repo is private.
    #[serde(default)]
    pub private: bool,
}

/// The pull request.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct PullRequest {
    /// PR number.
    pub number: u64,
    /// PR title (truncated by the API), for logging.
    #[serde(default)]
    pub title: Option<String>,
    /// Draft flag.
    #[serde(default)]
    pub draft: bool,
    /// Merged flag (meaningful on `closed`).
    #[serde(default)]
    pub merged: bool,
    /// True when the head repo differs from the base repo, or the head repo is
    /// absent (deleted fork). Drives the secret policy — see the deployer.
    pub fork: bool,
    /// The head commit.
    pub head: Head,
    /// The base ref.
    pub base: Base,
}

/// The PR head.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Head {
    /// Branch name. Validated: no leading `-`, no `..`, conservative charset.
    #[serde(rename = "ref")]
    pub ref_name: String,
    /// Head commit SHA. Validated: 40 or 64 lowercase hex.
    pub sha: String,
    /// The head repo's clone URL, falling back to the base repo's when the head
    /// repo is absent. `None` only if the payload carried neither (should not
    /// happen after API validation).
    #[serde(default)]
    pub clone_url: Option<String>,
    /// `owner/name` of the head repo; `null` when the fork was deleted.
    #[serde(default)]
    pub repo_full_name: Option<String>,
    /// `refs/pull/<n>/head` — resolves the head from the *base* repository. The
    /// recommended fetch path: works for forks and deleted forks without
    /// trusting a third-party clone URL.
    pub pull_ref: String,
}

/// The PR base.
#[derive(Debug, Clone, Deserialize)]
pub struct Base {
    /// Base branch name.
    #[serde(rename = "ref")]
    pub ref_name: String,
}

impl Job {
    /// Parse and validate a job from its raw bytes.
    ///
    /// The `schema` is checked **first**, against the parsed JSON, so an
    /// unrecognized version fails with a clear message rather than as a
    /// confusing field-shape error from optimistic deserialization.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not JSON, declare an unsupported
    /// `schema`, or fail any field validation in [`Job::validate`].
    pub fn parse(bytes: &[u8], github_host: &str) -> anyhow::Result<Self> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).context("job is not valid JSON")?;

        let schema = value
            .get("schema")
            .and_then(serde_json::Value::as_u64)
            .context("job has no numeric `schema` field")?;
        ensure!(
            schema == u64::from(SUPPORTED_SCHEMA),
            "unsupported job schema {schema} (this daemon understands schema {SUPPORTED_SCHEMA})"
        );

        let job: Self = serde_json::from_value(value).context("job does not match schema 1")?;
        job.validate(github_host)?;
        Ok(job)
    }

    /// `deploy` or `teardown`; `None` for any other string (rejected in
    /// [`Job::validate`]).
    #[must_use]
    pub fn intent(&self) -> Option<Intent> {
        match self.intent.as_str() {
            "deploy" => Some(Intent::Deploy),
            "teardown" => Some(Intent::Teardown),
            _ => None,
        }
    }

    /// The clone URL for the PR's head, with the same fork fallback the API
    /// applied: the head repo's URL when present, else the base repo's.
    #[must_use]
    pub fn effective_clone_url(&self) -> &str {
        self.pull_request
            .head
            .clone_url
            .as_deref()
            .unwrap_or(&self.repository.clone_url)
    }

    /// Validate every field that reaches `git` or the filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first field that fails.
    pub fn validate(&self, github_host: &str) -> anyhow::Result<()> {
        ensure!(self.schema == SUPPORTED_SCHEMA, "unsupported schema");
        ensure!(
            self.event == "pull_request",
            "unexpected event {:?}",
            self.event
        );
        ensure!(
            self.intent().is_some(),
            "unknown intent {:?} (expected \"deploy\" or \"teardown\")",
            self.intent
        );

        // The label is the primary key: a single valid DNS label. It also has
        // to be a valid ePHPm site key, since it (or the host built from it)
        // names the vhost directory.
        ensure!(
            is_dns_label(&self.preview.label),
            "invalid preview.label {:?}",
            self.preview.label
        );

        validate_name(&self.repository.owner, "repository.owner")?;
        validate_name(&self.repository.name, "repository.name")?;
        ensure!(
            self.repository.full_name.eq_ignore_ascii_case(&format!(
                "{}/{}",
                self.repository.owner, self.repository.name
            )),
            "repository.full_name disagrees with owner/name"
        );
        validate_clone_url(
            &self.repository.clone_url,
            github_host,
            "repository.clone_url",
        )?;
        if let Some(branch) = &self.repository.default_branch {
            validate_git_ref(branch, "repository.default_branch")?;
        }

        ensure!(
            self.pull_request.number >= 1 && self.pull_request.number <= 1_000_000_000,
            "pull_request.number out of range"
        );
        validate_git_ref(&self.pull_request.head.ref_name, "pull_request.head.ref")?;
        validate_sha(&self.pull_request.head.sha, "pull_request.head.sha")?;
        validate_pull_ref(
            &self.pull_request.head.pull_ref,
            self.pull_request.number,
            "pull_request.head.pull_ref",
        )?;
        if let Some(url) = &self.pull_request.head.clone_url {
            validate_clone_url(url, github_host, "pull_request.head.clone_url")?;
        }
        validate_git_ref(&self.pull_request.base.ref_name, "pull_request.base.ref")?;

        Ok(())
    }
}

/// A single DNS label (RFC 1035 shape): `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, ≤63.
/// Mirrors switchboard-api's `PreviewLabel::isValid`. Also guarantees the label
/// is a valid ePHPm site key.
fn is_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 || !is_valid_site_key(label) {
        return false;
    }
    let bytes = label.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    label.bytes().all(|b| alnum(b) || b == b'-')
}

/// A GitHub login or repository name: `[A-Za-z0-9._-]{1,100}`, not `.`/`..`.
fn validate_name(value: &str, field: &str) -> anyhow::Result<()> {
    let ok = (1..=100).contains(&value.len())
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ensure!(ok, "invalid {field}: {value:?}");
    Ok(())
}

/// A branch name safe to hand to `git`: no leading `-` (read as an option), no
/// `..` (revision syntax), conservative charset, ≤255. Argument-vector
/// execution prevents *shell* injection; this prevents *argument* injection.
fn validate_git_ref(value: &str, field: &str) -> anyhow::Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'+' | b'-'));
    ensure!(ok, "invalid {field}: {value:?}");
    Ok(())
}

/// A commit id: 40 hex (SHA-1) or 64 hex (SHA-256 repos), lowercase.
fn validate_sha(value: &str, field: &str) -> anyhow::Result<()> {
    let ok = (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    ensure!(ok, "invalid {field}: {value:?}");
    Ok(())
}

/// `refs/pull/<number>/head`, with `<number>` matching the PR number.
fn validate_pull_ref(value: &str, number: u64, field: &str) -> anyhow::Result<()> {
    let expected = format!("refs/pull/{number}/head");
    ensure!(
        value == expected,
        "invalid {field}: {value:?} (expected {expected:?})"
    );
    Ok(())
}

/// An `https://` clone URL on the configured GitHub host, with no embedded
/// credentials.
fn validate_clone_url(value: &str, github_host: &str, field: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value).with_context(|| format!("invalid {field}: not a URL"))?;
    ensure!(
        url.scheme() == "https",
        "invalid {field}: scheme is not https"
    );
    ensure!(
        url.host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(github_host)),
        "invalid {field}: host is not {github_host}"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "invalid {field}: embedded credentials"
    );
    Ok(())
}

impl std::fmt::Display for Intent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Deploy => "deploy",
            Self::Teardown => "teardown",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete, valid schema-1 job — the README's own example.
    const VALID: &str = r#"{
      "schema": 1,
      "job_id": "1787456737243-b81167e5b47a38b9",
      "delivery_id": "aaaaaaaa-1111-2222-3333-000000000001",
      "event": "pull_request",
      "action": "opened",
      "intent": "deploy",
      "received_at": "2026-08-23T03:45:37.243Z",
      "received_at_ms": 1787456737243,
      "preview": { "label": "ephpm-wordpress-sample-pr-7" },
      "repository": {
        "full_name": "ephpm/wordpress-sample",
        "owner": "ephpm",
        "name": "wordpress-sample",
        "clone_url": "https://github.com/ephpm/wordpress-sample.git",
        "default_branch": "main",
        "private": false
      },
      "pull_request": {
        "number": 7,
        "title": "Live test",
        "draft": false,
        "merged": false,
        "fork": false,
        "head": {
          "ref": "feature/live",
          "sha": "0123456789abcdef0123456789abcdef01234567",
          "clone_url": "https://github.com/ephpm/wordpress-sample.git",
          "repo_full_name": "ephpm/wordpress-sample",
          "pull_ref": "refs/pull/7/head"
        },
        "base": { "ref": "main" }
      },
      "sender": "octocat",
      "installation_id": 999
    }"#;

    fn parse(json: &str) -> anyhow::Result<Job> {
        Job::parse(json.as_bytes(), "github.com")
    }

    #[test]
    fn parses_valid_job() {
        let job = parse(VALID).unwrap();
        assert_eq!(job.schema, 1);
        assert_eq!(job.intent(), Some(Intent::Deploy));
        assert_eq!(job.preview.label, "ephpm-wordpress-sample-pr-7");
        assert_eq!(job.pull_request.number, 7);
        assert_eq!(job.pull_request.head.pull_ref, "refs/pull/7/head");
        assert!(!job.pull_request.fork);
        assert_eq!(job.installation_id, Some(999));
        assert_eq!(
            job.effective_clone_url(),
            "https://github.com/ephpm/wordpress-sample.git"
        );
    }

    #[test]
    fn rejects_unsupported_schema() {
        let json = VALID.replace("\"schema\": 1", "\"schema\": 2");
        let err = parse(&json).unwrap_err().to_string();
        assert!(err.contains("unsupported job schema 2"), "{err}");
    }

    #[test]
    fn rejects_missing_schema() {
        let err = parse(r#"{"intent":"deploy"}"#).unwrap_err().to_string();
        assert!(err.contains("schema"), "{err}");
    }

    #[test]
    fn rejects_unknown_intent() {
        let json = VALID.replace("\"intent\": \"deploy\"", "\"intent\": \"detonate\"");
        let err = parse(&json).unwrap_err().to_string();
        assert!(err.contains("unknown intent"), "{err}");
    }

    #[test]
    fn rejects_argument_injection_ref() {
        // A branch that git would read as an option must be rejected.
        let json = VALID.replace("feature/live", "--upload-pack=/bin/sh");
        assert!(parse(&json).is_err());
    }

    #[test]
    fn rejects_dotdot_ref() {
        let json = VALID.replace("feature/live", "feature/../etc");
        assert!(parse(&json).is_err());
    }

    #[test]
    fn rejects_bad_sha() {
        let json = VALID.replace("0123456789abcdef0123456789abcdef01234567", "nothex");
        assert!(parse(&json).is_err());
    }

    #[test]
    fn accepts_64_hex_sha() {
        let sha64 = "a".repeat(64);
        let json = VALID.replace("0123456789abcdef0123456789abcdef01234567", &sha64);
        assert!(parse(&json).is_ok());
    }

    #[test]
    fn rejects_clone_url_off_host() {
        let json = VALID.replace(
            "github.com/ephpm/wordpress-sample.git",
            "evil.example/x.git",
        );
        let err = parse(&json).unwrap_err().to_string();
        assert!(err.contains("clone_url") || err.contains("host"), "{err}");
    }

    #[test]
    fn rejects_non_https_clone_url() {
        let json = VALID.replace(
            "https://github.com/ephpm/wordpress-sample.git",
            "http://github.com/ephpm/wordpress-sample.git",
        );
        assert!(parse(&json).is_err());
    }

    #[test]
    fn rejects_pull_ref_number_mismatch() {
        let json = VALID.replace("refs/pull/7/head", "refs/pull/9/head");
        assert!(parse(&json).is_err());
    }

    #[test]
    fn rejects_full_name_disagreement() {
        let json = VALID.replace(
            "\"full_name\": \"ephpm/wordpress-sample\"",
            "\"full_name\": \"ephpm/other\"",
        );
        assert!(parse(&json).is_err());
    }

    #[test]
    fn rejects_bad_label() {
        let json = VALID.replace("ephpm-wordpress-sample-pr-7", "Bad_Label");
        assert!(parse(&json).is_err());
    }

    #[test]
    fn teardown_intent_parses() {
        let json = VALID
            .replace("\"intent\": \"deploy\"", "\"intent\": \"teardown\"")
            .replace("\"action\": \"opened\"", "\"action\": \"closed\"");
        assert_eq!(parse(&json).unwrap().intent(), Some(Intent::Teardown));
    }

    #[test]
    fn fork_flag_is_read() {
        let json = VALID.replace("\"fork\": false", "\"fork\": true");
        assert!(parse(&json).unwrap().pull_request.fork);
    }

    #[test]
    fn deleted_fork_head_clone_url_falls_back_to_base() {
        // repo_full_name null + head clone_url absent → effective URL is the base.
        let json = VALID
            .replace(
                "\"clone_url\": \"https://github.com/ephpm/wordpress-sample.git\",\n          \"repo_full_name\": \"ephpm/wordpress-sample\",",
                "\"repo_full_name\": null,",
            )
            .replace("\"fork\": false", "\"fork\": true");
        let job = parse(&json).unwrap();
        assert_eq!(
            job.effective_clone_url(),
            "https://github.com/ephpm/wordpress-sample.git"
        );
    }
}
