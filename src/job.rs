//! The job file contract — schema 1.
//!
//! A job file is the *only* input the daemon takes for provisioning work. It is
//! produced by `ephpm/switchboard-api` (a PHP vhost inside ePHPm that receives
//! GitHub webhooks) and dropped into `<state_dir>/queue/`. See that repo's
//! README, section "The job file contract", for the authoritative description.
//!
//! Two rules from that contract are enforced here rather than left to the
//! caller:
//!
//! * **`schema` must be exactly 1.** An unrecognised schema is rejected, never
//!   guessed at — a future producer may change field meanings, and a daemon
//!   that "mostly parsed" a schema-2 document could deploy the wrong thing.
//! * **Act on `intent`, not `action`.** `intent` is the API's interpretation of
//!   the raw GitHub action; an unknown intent is rejected for the same reason.
//!
//! `preview.label` is authoritative and is never recomputed here. It names the
//! directory under `sites_dir` and, with the configured preview domain
//! appended, the vhost ePHPm resolves.

use serde::Deserialize;

use crate::deployer::PreviewRequest;

/// The schema version this daemon understands.
pub const SCHEMA: u32 = 1;

/// What the API decided the event means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Create or refresh the preview.
    Deploy,
    /// Remove the preview.
    Teardown,
}

/// A parsed, validated schema-1 job document.
#[derive(Debug, Deserialize)]
pub struct Job {
    /// Schema version. Validated to equal [`SCHEMA`] by [`Job::parse`].
    pub schema: u32,
    /// `<millis>-<16 hex>` — unique, sortable, filename-safe.
    pub job_id: String,
    /// The `X-GitHub-Delivery` GUID, for tracing back to GitHub's UI.
    #[serde(default)]
    pub delivery_id: Option<String>,
    /// The raw GitHub action. Recorded for logs only — dispatch on `intent`.
    #[serde(default)]
    pub action: String,
    /// `"deploy"` or `"teardown"`. Validated by [`Job::parse`].
    pub intent: String,
    /// Preview identity.
    pub preview: Preview,
    /// The base repository the PR targets.
    pub repository: JobRepository,
    /// The pull request itself.
    pub pull_request: JobPullRequest,
    /// The GitHub App installation, when the API saw one. The daemon needs it
    /// to mint a token; `None` means no reporting is possible for this job.
    #[serde(default)]
    pub installation_id: Option<u64>,
}

/// Preview identity. One field today, deliberately a nested object so the
/// contract can grow without a schema bump.
#[derive(Debug, Deserialize)]
pub struct Preview {
    /// **Authoritative.** The directory name under `sites_dir` and the leading
    /// DNS label of the preview host. Never recomputed by the daemon.
    pub label: String,
}

/// The base repository.
#[derive(Debug, Deserialize)]
pub struct JobRepository {
    /// `owner/name`.
    pub full_name: String,
    /// Owner login.
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// `https://` clone URL of the **base** repo — the fetch source, because
    /// `refs/pull/<n>/head` resolves there even for forks.
    pub clone_url: String,
    /// Whether the base repository is **private** (`repository.private` in the
    /// GitHub payload; switchboard-api copies it into the job file).
    ///
    /// **Absent means private** (fail closed): a private repo's preview must be
    /// access-gated, and a job document lacking the field has unproven visibility.
    /// switchboard-api has emitted `private` since it began writing schema-1 jobs
    /// (it is in the README's own example), so a document without it was either
    /// not written by the API or predates it — either way, defaulting to private
    /// gates a preview that might otherwise leak, and the worst case for a genuinely
    /// public repo is a login prompt.
    #[serde(default = "private_when_absent")]
    pub private: bool,
}

/// Serde default for [`JobRepository::private`]: absent ⇒ private (fail closed).
fn private_when_absent() -> bool {
    true
}

/// The pull request.
#[derive(Debug, Deserialize)]
pub struct JobPullRequest {
    /// PR number.
    pub number: u64,
    /// True when the PR head comes from a fork — or when the head repository is
    /// gone (deleted fork), which the API also reports as `true`.
    ///
    /// **Absent means fork.** switchboard-api has emitted this field in every
    /// schema-1 job file since its initial commit, and it is the only producer
    /// of job files, so a document without the field was not written by the
    /// API. Trust is the thing being decided here; a document that cannot
    /// prove same-repo provenance is treated as a fork (fail closed). The
    /// worst case for a legitimate job is a refused deploy with a clear
    /// message — teardowns are unaffected either way.
    #[serde(default = "fork_when_absent")]
    pub fork: bool,
    /// Head of the PR.
    pub head: JobHead,
}

/// Serde default for [`JobPullRequest::fork`]: absent ⇒ fork (fail closed).
fn fork_when_absent() -> bool {
    true
}

/// The PR head.
#[derive(Debug, Deserialize)]
pub struct JobHead {
    /// Branch name (validated by the API; no leading `-`, no `..`).
    #[serde(rename = "ref")]
    pub ref_name: String,
    /// 40- or 64-char lowercase hex commit SHA.
    pub sha: String,
    /// `refs/pull/<n>/head`.
    #[serde(default)]
    pub pull_ref: Option<String>,
}

impl Job {
    /// Parse and validate a job document.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed, if `schema` is not
    /// [`SCHEMA`], or if `intent` is neither `deploy` nor `teardown`.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let job: Self = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            job.schema == SCHEMA,
            "unsupported job schema {} (this daemon understands {SCHEMA})",
            job.schema
        );
        // Validate the intent at the parse boundary so no caller can act on a
        // job whose meaning it does not understand.
        job.intent()?;
        anyhow::ensure!(
            !job.preview.label.is_empty(),
            "job has an empty preview label"
        );
        Ok(job)
    }

    /// The validated intent.
    ///
    /// # Errors
    ///
    /// Returns an error for any value other than `deploy` or `teardown`.
    pub fn intent(&self) -> anyhow::Result<Intent> {
        match self.intent.as_str() {
            "deploy" => Ok(Intent::Deploy),
            "teardown" => Ok(Intent::Teardown),
            other => anyhow::bail!("unknown job intent {other:?}"),
        }
    }

    /// The preview label — the `sites_dir` directory name for this preview.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.preview.label
    }

    /// Convert to the provisioning request the deployer consumes.
    #[must_use]
    pub fn to_preview_request(&self) -> PreviewRequest {
        PreviewRequest {
            label: self.preview.label.clone(),
            repo_full_name: self.repository.full_name.clone(),
            owner: self.repository.owner.clone(),
            repo_name: self.repository.name.clone(),
            pr_number: self.pull_request.number,
            // Always the BASE repo: `refs/pull/<n>/head` resolves there, which
            // works for forks and for deleted forks without trusting a
            // third-party clone URL.
            fetch_url: self.repository.clone_url.clone(),
            fetch_ref: self.pull_request.head.pull_ref.clone(),
            branch: Some(self.pull_request.head.ref_name.clone()),
            sha: self.pull_request.head.sha.clone(),
            installation_id: self.installation_id,
            fork: self.pull_request.fork,
            private: self.repository.private,
        }
    }
}

/// A minimal but realistic schema-1 document, matching the example in the
/// switchboard-api README. Shared with the queue tests, which need real job
/// files on disk.
#[cfg(test)]
pub fn sample_json(label: &str, intent: &str) -> String {
    format!(
        r#"{{
              "schema": 1,
              "job_id": "1787456737243-b81167e5b47a38b9",
              "delivery_id": "aaaaaaaa-1111-2222-3333-000000000001",
              "event": "pull_request",
              "action": "opened",
              "intent": "{intent}",
              "received_at": "2026-08-23T03:45:37.243Z",
              "received_at_ms": 1787456737243,
              "preview": {{ "label": "{label}" }},
              "repository": {{
                "full_name": "ephpm/wordpress-sample",
                "owner": "ephpm",
                "name": "wordpress-sample",
                "clone_url": "https://github.com/ephpm/wordpress-sample.git",
                "default_branch": "main",
                "private": false
              }},
              "pull_request": {{
                "number": 7,
                "title": "Live test",
                "draft": false,
                "merged": false,
                "fork": false,
                "head": {{
                  "ref": "feature/live",
                  "sha": "0123456789abcdef0123456789abcdef01234567",
                  "clone_url": "https://github.com/ephpm/wordpress-sample.git",
                  "repo_full_name": "ephpm/wordpress-sample",
                  "pull_ref": "refs/pull/7/head"
                }},
                "base": {{ "ref": "main" }}
              }},
              "sender": "octocat",
              "installation_id": 999
            }}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_schema_1_document() {
        let job = Job::parse(sample_json("ephpm-wordpress-sample-pr-7", "deploy").as_bytes())
            .expect("the README's own example must parse");
        assert_eq!(job.schema, 1);
        assert_eq!(job.label(), "ephpm-wordpress-sample-pr-7");
        assert_eq!(job.intent().unwrap(), Intent::Deploy);
        assert_eq!(job.pull_request.number, 7);
        assert_eq!(
            job.pull_request.head.pull_ref.as_deref(),
            Some("refs/pull/7/head")
        );
        assert_eq!(job.installation_id, Some(999));
    }

    #[test]
    fn fork_false_parses_as_not_a_fork() {
        let job = Job::parse(sample_json("l", "deploy").as_bytes()).unwrap();
        assert!(
            !job.pull_request.fork,
            "the sample document says fork:false"
        );
        assert!(!job.to_preview_request().fork);
    }

    #[test]
    fn fork_true_reaches_the_preview_request() {
        let doc = sample_json("l", "deploy").replace("\"fork\": false", "\"fork\": true");
        let job = Job::parse(doc.as_bytes()).unwrap();
        assert!(job.pull_request.fork);
        assert!(job.to_preview_request().fork);
    }

    #[test]
    fn absent_fork_field_is_treated_as_fork() {
        // switchboard-api has emitted `pull_request.fork` since its first
        // commit and is the only job-file producer, so a schema-1 document
        // without the field has unproven provenance — fail closed.
        let doc = sample_json("l", "deploy").replace("\"fork\": false,", "");
        assert!(
            !doc.contains("\"fork\""),
            "test setup must actually drop the field"
        );
        let job = Job::parse(doc.as_bytes()).expect("the field is optional, not required");
        assert!(
            job.pull_request.fork,
            "absent fork must deserialize as true"
        );
        assert!(job.to_preview_request().fork);
    }

    #[test]
    fn public_repo_reaches_the_request_as_not_private() {
        // The sample says "private": false.
        let job = Job::parse(sample_json("l", "deploy").as_bytes()).unwrap();
        assert!(!job.repository.private);
        assert!(
            !job.to_preview_request().private,
            "a public repo is not gated"
        );
    }

    #[test]
    fn private_repo_reaches_the_request() {
        let doc = sample_json("l", "deploy").replace("\"private\": false", "\"private\": true");
        let job = Job::parse(doc.as_bytes()).unwrap();
        assert!(job.repository.private);
        assert!(
            job.to_preview_request().private,
            "a private repo must reach the deployer so its preview is gated"
        );
    }

    /// **Absent visibility fails closed.** A schema-1 job with no `private` field
    /// is treated as private — its preview is gated rather than published open.
    #[test]
    fn absent_private_field_is_treated_as_private() {
        // Drop the whole `, "private": false` tail (comma included) so the JSON
        // stays valid without the field.
        let doc = sample_json("l", "deploy").replace(",\n                \"private\": false", "");
        assert!(
            !doc.contains("\"private\""),
            "test setup must drop the field"
        );
        let job = Job::parse(doc.as_bytes()).expect("private is optional, not required");
        assert!(
            job.repository.private,
            "absent visibility must default to private (fail closed)"
        );
        assert!(job.to_preview_request().private);
    }

    #[test]
    fn rejects_unknown_schema() {
        // A schema bump may redefine field meanings. Guessing is worse than
        // refusing: the daemon must not deploy from a document it cannot
        // claim to understand.
        let doc = sample_json("l", "deploy").replace("\"schema\": 1", "\"schema\": 2");
        let err = Job::parse(doc.as_bytes()).expect_err("schema 2 must be rejected");
        assert!(
            err.to_string().contains("unsupported job schema 2"),
            "{err}"
        );
    }

    #[test]
    fn rejects_missing_schema() {
        let doc = sample_json("l", "deploy").replace("\"schema\": 1,", "");
        assert!(Job::parse(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_unknown_intent() {
        let doc = sample_json("l", "rollback");
        let err = Job::parse(doc.as_bytes()).expect_err("unknown intent must be rejected");
        assert!(err.to_string().contains("unknown job intent"), "{err}");
    }

    #[test]
    fn teardown_intent_parses() {
        let job = Job::parse(sample_json("l", "teardown").as_bytes()).unwrap();
        assert_eq!(job.intent().unwrap(), Intent::Teardown);
    }

    #[test]
    fn rejects_empty_label() {
        // The label is a path component under sites_dir; an empty one would
        // resolve to sites_dir itself.
        let doc = sample_json("", "deploy");
        assert!(Job::parse(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(Job::parse(b"{not json").is_err());
    }

    #[test]
    fn preview_request_fetches_from_the_base_repo() {
        // Fork PRs must be fetched via refs/pull/<n>/head on the BASE repo,
        // not from the head repo's clone URL.
        let doc = sample_json("ephpm-wordpress-sample-pr-7", "deploy").replace(
            "\"clone_url\": \"https://github.com/ephpm/wordpress-sample.git\",\n                  \"repo_full_name\"",
            "\"clone_url\": \"https://github.com/attacker/fork.git\",\n                  \"repo_full_name\"",
        );
        let job = Job::parse(doc.as_bytes()).unwrap();
        let req = job.to_preview_request();
        assert_eq!(
            req.fetch_url,
            "https://github.com/ephpm/wordpress-sample.git"
        );
        assert_eq!(req.fetch_ref.as_deref(), Some("refs/pull/7/head"));
        assert_eq!(req.sha, "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(req.label, "ephpm-wordpress-sample-pr-7");
        assert_eq!(req.owner, "ephpm");
        assert_eq!(req.repo_name, "wordpress-sample");
        assert_eq!(req.pr_number, 7);
    }
}
