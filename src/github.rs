//! GitHub API interactions — PR comments and deployment statuses.

use anyhow::Context;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde_json::json;

use crate::deployer::{DeployResult, PreviewRequest};
use crate::validate::{PullRequestState, classify_pull_request};

/// Hidden HTML marker carried by every switchboard comment. It renders as
/// nothing on GitHub but is what [`GitHubClient::find_existing_comment`] matches
/// on to decide update-vs-create — so the sticky comment is found by an
/// invisible, stable token rather than by user-visible prose that could be
/// reworded. The visible `**ePHPm Preview**` header is matched too, as a
/// fallback for comments posted before this marker existed.
const COMMENT_MARKER: &str = "<!-- switchboard-preview -->";

/// GitHub API client for posting comments and deployment statuses.
pub struct GitHubClient {
    client: reqwest::Client,
    /// Installation access token (short-lived, scoped to repo).
    token: String,
}

impl GitHubClient {
    /// Create a new client with the given installation access token.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
        }
    }

    /// Post a preview deployment comment on the PR.
    ///
    /// If a switchboard comment already exists, updates it instead of creating a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the GitHub API calls fail.
    pub async fn post_preview_comment(
        &self,
        req: &PreviewRequest,
        result: &DeployResult,
    ) -> anyhow::Result<()> {
        let owner = &req.owner;
        let repo = &req.repo_name;
        let pr_number = req.pr_number;

        let body = format_deploy_comment(result);

        // Check if we already have a comment on this PR.
        if let Some(comment_id) = self.find_existing_comment(owner, repo, pr_number).await? {
            self.update_comment(owner, repo, comment_id, &body).await?;
        } else {
            self.create_comment(owner, repo, pr_number, &body).await?;
        }

        Ok(())
    }

    /// Update the PR comment to show the preview was removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the GitHub API calls fail.
    pub async fn post_teardown_comment(&self, req: &PreviewRequest) -> anyhow::Result<()> {
        let owner = &req.owner;
        let repo = &req.repo_name;
        let pr_number = req.pr_number;

        if let Some(comment_id) = self.find_existing_comment(owner, repo, pr_number).await? {
            self.update_comment(owner, repo, comment_id, &teardown_comment_body())
                .await?;
        }

        Ok(())
    }

    /// Set the commit deployment status (creates the "Environments" UI in GitHub).
    ///
    /// # Errors
    ///
    /// Returns an error if the GitHub API calls fail.
    pub async fn create_deployment_status(
        &self,
        req: &PreviewRequest,
        result: &DeployResult,
    ) -> anyhow::Result<()> {
        let owner = &req.owner;
        let repo = &req.repo_name;
        let sha = &req.sha;

        // Same URL the PR comment shows, port map included — the two must not
        // disagree about where the preview lives.
        let url = crate::deployer::preview_url(&result.hostname, result.php_version.as_deref());

        // Create deployment.
        let deploy_url = format!("https://api.github.com/repos/{owner}/{repo}/deployments");
        let resp = self
            .client
            .post(&deploy_url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
            .json(&json!({
                "ref": sha,
                "environment": format!("preview-pr-{}", req.pr_number),
                "auto_merge": false,
                "required_contexts": [],
                "description": format!("ePHPm preview for PR #{}", req.pr_number),
            }))
            .send()
            .await
            .context("failed to create deployment")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(%status, %body, "failed to create deployment");
            return Ok(()); // Non-fatal — the comment is more important.
        }

        let deployment: serde_json::Value = resp.json().await?;
        let deployment_id = deployment["id"]
            .as_u64()
            .context("deployment response missing id")?;

        // A preview the analyze gate blocked was never published, so its
        // deployment status is a failure, not a success — otherwise the PR's
        // Environments UI would claim a live preview that does not exist.
        let (state, description) = match &result.analyze_block {
            Some(block) => (
                "failure",
                format!("preview blocked by the analyze gate ({})", block.verdict),
            ),
            None => (
                "success",
                format!("{} preview deployed", result.framework.as_str()),
            ),
        };

        let status_url = format!(
            "https://api.github.com/repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
        );
        self.client
            .post(&status_url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
            .json(&json!({
                "state": state,
                "environment_url": url,
                "description": description,
            }))
            .send()
            .await
            .context("failed to set deployment status")?;

        Ok(())
    }

    /// Ask GitHub what a pull request's state is **right now**.
    ///
    /// The authoritative half of the claim-time re-validation (issue #18): a
    /// job file records what was true when the API wrote it, and a queue can
    /// hold that statement for days. Uses the `pulls` endpoint rather than
    /// `issues` because only the former carries `merged`, and "merged" is the
    /// case worth naming in the log.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or GitHub answers with a non-2xx
    /// status. Callers treat that as "unknown" and apply the job — see
    /// [`crate::validate`] on failing open.
    pub async fn pull_request_state(
        &self,
        owner: &str,
        repo: &str,
        pr_number: u64,
    ) -> anyhow::Result<PullRequestState> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}");
        let resp = self
            .client
            .get(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .with_context(|| format!("failed to read {owner}/{repo}#{pr_number}"))?;

        anyhow::ensure!(
            resp.status().is_success(),
            "GitHub returned {} for {owner}/{repo}#{pr_number}",
            resp.status()
        );

        let body: serde_json::Value = resp.json().await?;
        let state = body["state"]
            .as_str()
            .context("pull request response missing 'state'")?;
        // Absent `merged` is not "merged" — the field is always present on this
        // endpoint, and guessing true would discard a live preview's deploy.
        let merged = body["merged"].as_bool().unwrap_or(false);
        Ok(classify_pull_request(state, merged))
    }

    /// Find an existing switchboard comment on a PR.
    async fn find_existing_comment(
        &self,
        owner: &str,
        repo: &str,
        pr_number: u64,
    ) -> anyhow::Result<Option<u64>> {
        let url =
            format!("https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments");
        let resp = self
            .client
            .get(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(None);
        }

        let comments: Vec<serde_json::Value> = resp.json().await?;
        for comment in comments {
            let body = comment["body"].as_str().unwrap_or("");
            if is_switchboard_comment(body) {
                if let Some(id) = comment["id"].as_u64() {
                    return Ok(Some(id));
                }
            }
        }

        Ok(None)
    }

    async fn create_comment(
        &self,
        owner: &str,
        repo: &str,
        pr_number: u64,
        body: &str,
    ) -> anyhow::Result<()> {
        let url =
            format!("https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments");
        self.client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
            .json(&json!({ "body": body }))
            .send()
            .await
            .context("failed to create PR comment")?;
        Ok(())
    }

    async fn update_comment(
        &self,
        owner: &str,
        repo: &str,
        comment_id: u64,
        body: &str,
    ) -> anyhow::Result<()> {
        let url =
            format!("https://api.github.com/repos/{owner}/{repo}/issues/comments/{comment_id}");
        self.client
            .patch(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
            .json(&json!({ "body": body }))
            .send()
            .await
            .context("failed to update PR comment")?;
        Ok(())
    }
}

/// Whether a comment body is one of ours: the hidden marker (current) or the
/// visible header (comments posted before the marker was introduced).
fn is_switchboard_comment(body: &str) -> bool {
    body.contains(COMMENT_MARKER) || body.contains("**ePHPm Preview**")
}

/// The PR comment body posted when a preview is torn down. Kept as its own
/// pure function (rather than inlined in the async network path) so the exact
/// rendered markdown is unit-testable and still carries the hidden
/// [`COMMENT_MARKER`] that [`GitHubClient::find_existing_comment`] matches on.
fn teardown_comment_body() -> String {
    format!(
        "{COMMENT_MARKER}\n\
         **ePHPm Preview** — removed\n\n\
         Preview deployment has been torn down."
    )
}

/// How many findings the blocked-preview comment lists before it truncates.
const MAX_COMMENT_FINDINGS: usize = 10;

/// Format the sticky PR comment body for a deploy.
///
/// A **blocked** deploy (the analyze gate refused it) renders a distinct body —
/// no "ready" URL, the verdict, and the top findings — so the reviewer sees why
/// the preview is not up. A published deploy renders the usual table. Both carry
/// the hidden [`COMMENT_MARKER`] so the one sticky comment is updated in place.
fn format_deploy_comment(result: &DeployResult) -> String {
    if let Some(block) = &result.analyze_block {
        return format_block_comment(result, block);
    }
    let url = crate::deployer::preview_url(&result.hostname, result.php_version.as_deref());
    let php_display = result.php_version.as_deref().unwrap_or("latest");
    let status = if result.healthy {
        "ready"
    } else {
        "deployed (health check pending)"
    };

    let mut body = format!(
        "{COMMENT_MARKER}\n\
         **ePHPm Preview** — {status}\n\n\
         | | |\n\
         |---|---|\n\
         | URL | {url} |\n\
         | Framework | {} |\n\
         | PHP | {php_display} |\n\
         | Deployed in | {:.1}s |\n\n\
         Preview updates automatically on each push to this PR.",
        result.framework.as_str(),
        result.duration.as_secs_f64(),
    );
    body.push_str(&access_section(result));
    body
}

/// Format the sticky comment body for a preview the analyze gate **blocked**.
///
/// It states plainly that the preview was not published, names the verdict and
/// finding count, and lists the top [`MAX_COMMENT_FINDINGS`] findings (rule, file,
/// line, message) so the author can act without opening the daemon logs. The
/// list is capped and says "showing N of M" when it truncates. Kept a pure
/// function of [`DeployResult`] + [`crate::analyze::AnalyzeBlock`] so the exact
/// markdown is unit-testable, and it carries the hidden [`COMMENT_MARKER`] so it
/// updates the same sticky comment a later (passing) push will overwrite.
fn format_block_comment(result: &DeployResult, block: &crate::analyze::AnalyzeBlock) -> String {
    let mut body = format!(
        "{COMMENT_MARKER}\n\
         **ePHPm Preview** — blocked by the analyze gate 🚫\n\n\
         This {} preview was **not published**. `ephpm analyze` returned **{}** \
         ({} finding(s)) on the pull request's code before it could be served.\n\n\
         > {}\n",
        result.framework.as_str(),
        block.verdict,
        block.total_findings,
        block.reason,
    );

    if block.findings.is_empty() {
        body.push_str(
            "\nNo per-finding detail was captured (the analyzer produced no parseable \
             report — e.g. a timeout or an internal error). See the switchboard logs on \
             the node for the full output.\n",
        );
    } else {
        let shown = block.findings.len().min(MAX_COMMENT_FINDINGS);
        body.push_str("\n| Rule | Location | Message |\n|---|---|---|\n");
        for f in block.findings.iter().take(MAX_COMMENT_FINDINGS) {
            // Every field here is attacker-controlled: `f.file` is a filename
            // *inside the PR* (ePHPm's SARIF emits the artifact URI without
            // percent-encoding, so newlines, pipes and backticks — all legal in a
            // Linux/git filename — flow through verbatim), and `f.rule_id` /
            // `f.message` originate from the same untrusted report. Rendered raw
            // they could break the table row or close their code span and inject
            // markdown (a heading/link spoof) into switchboard's trusted-identity
            // sticky comment. `file` and `rule_id` sit inside code spans, so they
            // go through `sanitize_code` (also neutralizes backticks); `message`
            // is a plain cell.
            let rule = sanitize_code(&f.rule_id);
            let location = match f.line {
                // The line is our own `u64`, never attacker text.
                Some(line) => format!("`{}:{line}`", sanitize_code(&f.file)),
                None => format!("`{}`", sanitize_code(&f.file)),
            };
            body.push_str(&format!(
                "| `{rule}` | {location} | {} |\n",
                sanitize_cell(&f.message),
            ));
        }
        if block.total_findings > shown {
            body.push_str(&format!(
                "\n_Showing {shown} of {} findings._\n",
                block.total_findings
            ));
        }
    }

    body.push_str(
        "\nFix the findings and push again — the preview redeploys and this comment \
         refreshes automatically.",
    );
    body
}

/// Make an untrusted string safe for a single Markdown **table cell**: collapse
/// the newlines and carriage returns that would break the row, escape the pipe
/// that would open a new column, and neutralize the backtick so an odd number of
/// them cannot toggle a code span open across the rest of the comment.
fn sanitize_cell(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
        .replace('|', "\\|")
        .replace('`', "'")
}

/// Make an untrusted string safe to interpolate **inside a backtick code span**
/// in a table cell (`` `<here>` ``). On top of [`sanitize_cell`]'s row/column
/// protection it must ensure the value carries no backtick of its own — a single
/// one would close the span early and let everything after it render as active
/// markdown (heading/link spoofing under switchboard's trusted identity). The
/// backtick is replaced with an apostrophe so the rendered span stays visually
/// faithful.
fn sanitize_code(s: &str) -> String {
    // Reuse the cell rules — they already replace the backtick, plus handle the
    // newline/pipe that would break the row a code span sits in.
    sanitize_cell(s)
}

/// The access-guidance block appended to a **gated** preview's comment.
///
/// A gated preview is not world-readable, so a reviewer needs to be told how to
/// get in: log in with GitHub (they are authorised automatically if they have
/// read access to the repo the preview is for). When switchboard also minted a
/// share link, it is included with the bearer-capability warning stated plainly —
/// anyone with the link is in until it expires — because that is a weaker property
/// than the OAuth gate and the person pasting it must know so. The signing secret
/// never appears here; only the token, inside the URL, does.
///
/// An ungated (public) preview gets no block — its content is already public.
fn access_section(result: &DeployResult) -> String {
    if !result.gated {
        return String::new();
    }
    let mut section = String::from(
        "\n\n**Access:** this preview is private. Sign in with GitHub at the URL above — \
         you'll be authorised automatically if your GitHub account has read access to this \
         repository.",
    );
    if let Some(share) = &result.share_url {
        section.push_str(&format!(
            "\n\n**Shareable link (no login required):** {share}\n\n\
             > ⚠️ This link is a bearer capability: **anyone who has it can view the preview** \
             > until it expires or is revoked, without signing in. Share it only with people \
             > who should see this preview, and don't post it anywhere public. It is revoked \
             > automatically when the PR is closed."
        ));
    }
    section
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployer::Framework;
    use std::time::Duration;

    #[test]
    fn comment_format_default_php() {
        let result = DeployResult {
            hostname: "pr-42.my-blog.preview.ephpm.dev".into(),
            framework: Framework::WordPress,
            duration: Duration::from_millis(14_320),
            php_version: None,
            healthy: true,
            gated: false,
            share_url: None,
            analyze_block: None,
        };
        let comment = format_deploy_comment(&result);
        assert!(comment.contains("https://pr-42.my-blog.preview.ephpm.dev"));
        assert!(
            !comment.contains(":80"),
            "default PHP should not have a port"
        );
        assert!(comment.contains("WordPress"));
        assert!(comment.contains("latest"));
        assert!(comment.contains("14.3s"));
        assert!(comment.contains("ready"));
    }

    #[test]
    fn comment_format_php84() {
        let result = DeployResult {
            hostname: "pr-42.my-blog.preview.ephpm.dev".into(),
            framework: Framework::Laravel,
            duration: Duration::from_millis(9_500),
            php_version: Some("8.4".into()),
            healthy: false,
            gated: false,
            share_url: None,
            analyze_block: None,
        };
        let comment = format_deploy_comment(&result);
        assert!(comment.contains(":8084"), "PHP 8.4 should use port 8084");
        assert!(comment.contains("health check pending"));
        assert!(comment.contains("Laravel"));
        assert!(comment.contains("8.4"));
    }

    #[test]
    fn comment_carries_marker_and_table() {
        // The marker is load-bearing: find_existing_comment matches on it to
        // decide update-vs-create, so it must always be present.
        let result = DeployResult {
            hostname: "pr-1.app.preview.ephpm.dev".into(),
            framework: Framework::Symfony,
            duration: Duration::from_millis(3_000),
            php_version: Some("8.3".into()),
            healthy: true,
            gated: false,
            share_url: None,
            analyze_block: None,
        };
        let comment = format_deploy_comment(&result);
        assert!(
            comment.contains(COMMENT_MARKER),
            "hidden marker must be present"
        );
        assert!(is_switchboard_comment(&comment));
        assert!(comment.contains("**ePHPm Preview**"));
        assert!(comment.contains("| URL |"));
        assert!(comment.contains("| Framework |"));
        assert!(comment.contains("| PHP |"));
        assert!(comment.contains("Symfony"));
        assert!(comment.contains(":8083"), "PHP 8.3 should use port 8083");
        // Auto-update footer is present so reviewers know pushes refresh it.
        assert!(comment.contains("updates automatically"));
    }

    #[test]
    fn comment_duration_rounds_to_one_decimal() {
        // 2_449ms rounds to 2.4s (one decimal), not 2s or 2.449s.
        let result = DeployResult {
            hostname: "h".into(),
            framework: Framework::Drupal,
            duration: Duration::from_millis(2_449),
            php_version: Some("8.5".into()),
            healthy: true,
            gated: false,
            share_url: None,
            analyze_block: None,
        };
        let comment = format_deploy_comment(&result);
        assert!(comment.contains("2.4s"), "got: {comment}");
        assert!(comment.contains("Drupal"));
        // 8.5 is the default port-less URL — no explicit port in the link.
        assert!(!comment.contains(":8085"));
    }

    // ── access-gate guidance (ephpm#487/#491) ──────────────────────────

    fn gated_result(share_url: Option<String>) -> DeployResult {
        DeployResult {
            hostname: "pr-1.app.preview.ephpm.dev".into(),
            framework: Framework::Laravel,
            duration: Duration::from_millis(3_000),
            php_version: Some("8.4".into()),
            healthy: true,
            gated: true,
            share_url,
            analyze_block: None,
        }
    }

    #[test]
    fn ungated_comment_has_no_access_section() {
        let result = DeployResult {
            hostname: "pr-1.app.preview.ephpm.dev".into(),
            framework: Framework::Laravel,
            duration: Duration::from_millis(1),
            php_version: None,
            healthy: true,
            gated: false,
            share_url: None,
            analyze_block: None,
        };
        let comment = format_deploy_comment(&result);
        assert!(
            !comment.contains("Access:"),
            "a public preview needs no access block: {comment}"
        );
        assert!(!comment.contains("Shareable link"));
    }

    #[test]
    fn gated_comment_tells_the_reviewer_to_log_in() {
        let comment = format_deploy_comment(&gated_result(None));
        assert!(comment.contains("Access:"), "{comment}");
        assert!(comment.contains("Sign in with GitHub"), "{comment}");
        assert!(comment.contains("read access"), "{comment}");
        // No share link was minted, so none is advertised.
        assert!(!comment.contains("Shareable link"), "{comment}");
    }

    /// A minted share link is shown with the bearer-capability warning, and only
    /// the token (inside the URL) appears — never the signing secret.
    #[test]
    fn gated_comment_with_a_share_link_warns_it_is_a_bearer_capability() {
        let token = "eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let url = format!("https://pr-1.app.preview.ephpm.dev:8084/?ephpm_share={token}");
        let comment = format_deploy_comment(&gated_result(Some(url.clone())));
        assert!(
            comment.contains(&url),
            "the full share URL must be present: {comment}"
        );
        assert!(comment.contains("bearer capability"), "{comment}");
        assert!(comment.contains("anyone who has it"), "{comment}");
        assert!(
            comment.contains("revoked"),
            "must say teardown revokes it: {comment}"
        );
        // The comment carries the token (in the URL) but nothing that looks like
        // the raw HS256 secret — there is no separate secret field to leak.
        assert!(comment.contains(token), "the token travels in the URL");
    }

    // ── analyze gate: blocked-preview comment ──────────────────────────

    fn blocked_result(block: crate::analyze::AnalyzeBlock) -> DeployResult {
        DeployResult {
            hostname: "pr-9.app.preview.ephpm.dev".into(),
            framework: Framework::WordPress,
            duration: Duration::from_millis(1_200),
            php_version: Some("8.4".into()),
            healthy: false,
            gated: false,
            share_url: None,
            analyze_block: Some(block),
        }
    }

    #[test]
    fn blocked_comment_names_the_verdict_and_lists_findings() {
        use crate::analyze::{AnalyzeBlock, Finding};
        let block = AnalyzeBlock {
            verdict: "deny".into(),
            reason: "ephpm analyze reached the deny threshold (exit 3)".into(),
            findings: vec![
                Finding {
                    rule_id: "dangerous-sinks/eval".into(),
                    file: "wp-content/themes/x/functions.php".into(),
                    line: Some(42),
                    message: "eval() on request data".into(),
                },
                Finding {
                    rule_id: "secrets-scan/aws-access-key-id".into(),
                    file: ".env.example".into(),
                    line: None,
                    message: "AWS access key committed".into(),
                },
            ],
            total_findings: 2,
        };
        let comment = format_deploy_comment(&blocked_result(block));
        // Still a sticky switchboard comment.
        assert!(comment.contains(COMMENT_MARKER));
        assert!(is_switchboard_comment(&comment));
        // Makes the block unmistakable and never advertises a live URL.
        assert!(comment.contains("blocked by the analyze gate"), "{comment}");
        assert!(
            comment.contains("**deny**"),
            "the verdict is named: {comment}"
        );
        assert!(
            !comment.contains("ready"),
            "a blocked preview must not read as ready: {comment}"
        );
        // The findings are listed with rule, location and message.
        assert!(comment.contains("dangerous-sinks/eval"), "{comment}");
        assert!(
            comment.contains("wp-content/themes/x/functions.php:42"),
            "{comment}"
        );
        assert!(comment.contains("eval() on request data"), "{comment}");
        // A finding with no line renders just the file.
        assert!(
            comment.contains("secrets-scan/aws-access-key-id"),
            "{comment}"
        );
    }

    #[test]
    fn blocked_comment_caps_the_findings_list_and_says_how_many() {
        use crate::analyze::{AnalyzeBlock, Finding};
        let findings: Vec<Finding> = (0..25)
            .map(|i| Finding {
                rule_id: format!("rule-{i}"),
                file: format!("f{i}.php"),
                line: Some(i + 1),
                message: "m".into(),
            })
            .collect();
        let block = AnalyzeBlock {
            verdict: "quarantine".into(),
            reason: "over threshold".into(),
            findings,
            total_findings: 137,
        };
        let comment = format_deploy_comment(&blocked_result(block));
        // Only the first MAX_COMMENT_FINDINGS rows are rendered.
        assert!(comment.contains("rule-0"), "{comment}");
        assert!(comment.contains("rule-9"), "{comment}");
        assert!(
            !comment.contains("rule-10"),
            "the list must cap at {MAX_COMMENT_FINDINGS}: {comment}"
        );
        assert!(comment.contains("Showing 10 of 137"), "{comment}");
    }

    /// A block with no parseable findings (timeout / analyzer error) still posts
    /// a clear comment — the verdict and a pointer to the node logs.
    #[test]
    fn blocked_comment_without_findings_still_explains() {
        use crate::analyze::AnalyzeBlock;
        let block = AnalyzeBlock {
            verdict: "timeout".into(),
            reason: "ephpm analyze exceeded its wall-clock timeout".into(),
            findings: Vec::new(),
            total_findings: 0,
        };
        let comment = format_deploy_comment(&blocked_result(block));
        assert!(comment.contains("blocked by the analyze gate"), "{comment}");
        assert!(comment.contains("**timeout**"), "{comment}");
        assert!(comment.contains("No per-finding detail"), "{comment}");
    }

    /// A message with pipes/newlines/backticks must not break the row or toggle
    /// a code span.
    #[test]
    fn finding_message_is_sanitized_for_a_table_cell() {
        assert_eq!(sanitize_cell("a | b\nc"), "a \\| b c");
        // A backtick would otherwise open a code span spanning the rest of the
        // comment; it is neutralized to an apostrophe.
        assert_eq!(sanitize_cell("`code`"), "'code'");
        assert!(!sanitize_cell("a`b").contains('`'));
        assert!(!sanitize_code("a`b").contains('`'));
    }

    /// **Regression: comment rendering is injection-safe.** A pull request can
    /// name a file with newlines, pipes, backticks and markdown (all legal in a
    /// git/Linux filename, and ePHPm's SARIF passes the URI through unencoded).
    /// The `file` and `rule_id` fields are rendered inside backtick code spans, so
    /// a raw backtick would close the span and turn the attacker's markdown into
    /// active markup inside switchboard's trusted-identity sticky comment. Assert
    /// the rendered block: one table row per finding (no stray newline), no
    /// unescaped backtick that could close a span, and no active injected markup.
    #[test]
    fn blocked_comment_neutralizes_a_malicious_filename() {
        use crate::analyze::{AnalyzeBlock, Finding};
        // Assemble the hostile filename at runtime so no literal sequence trips
        // tooling: a real newline, a pipe, a backtick, a spoof heading and link.
        let evil_file = format!(
            "x{nl}## Approved {link}{nl}.php",
            nl = '\n',
            link = "[merge](http://evil.example)"
        );
        let evil_rule = format!("rule{bt}## pwned", bt = '`');
        let block = AnalyzeBlock {
            verdict: "deny".into(),
            reason: "reached the deny threshold".into(),
            findings: vec![Finding {
                rule_id: evil_rule,
                file: evil_file,
                line: Some(3),
                message: "eval on request data".into(),
            }],
            total_findings: 1,
        };
        let comment = format_deploy_comment(&blocked_result(block));

        // (a) The findings table is exactly one data row: the header row, its
        // `|---|` separator, and one finding row — the injected newline must not
        // have split the finding across lines.
        let finding_rows = comment
            .lines()
            .filter(|l| l.starts_with("| ") && !l.contains("---") && !l.contains("| Rule |"))
            .count();
        assert_eq!(
            finding_rows, 1,
            "the malicious filename must not break the single finding row:\n{comment}"
        );

        // (b) Every backtick in the output is balanced into complete code spans —
        // an attacker backtick can never leave a span hanging open. Since our
        // template only ever emits backticks in matched pairs, an even count
        // proves no injected one survived.
        assert_eq!(
            comment.matches('`').count() % 2,
            0,
            "unbalanced backticks would leave a code span open:\n{comment}"
        );

        // (c) The injected markdown does not appear as active markup: the spoof
        // link/heading text may appear as inert characters, but not on its own
        // line as a real heading, and the code-span content is escaped.
        assert!(
            !comment.contains("\n## Approved"),
            "a spoofed heading must not start its own line:\n{comment}"
        );
        // The rule_id's backtick was neutralized, so `## pwned` cannot escape its
        // code span.
        assert!(
            !comment.contains("`rule`## pwned"),
            "the rule_id backtick must not close its span:\n{comment}"
        );
    }

    #[test]
    fn teardown_body_is_marked_and_removed() {
        let body = teardown_comment_body();
        // Must keep the marker so the existing comment is found and updated in
        // place rather than a fresh "removed" comment being appended.
        assert!(
            body.contains(COMMENT_MARKER),
            "hidden marker must be present"
        );
        assert!(is_switchboard_comment(&body));
        assert!(body.contains("**ePHPm Preview**"));
        assert!(body.contains("removed"));
        assert!(body.contains("torn down"));
    }

    #[test]
    fn find_matches_hidden_marker_and_legacy_header() {
        // Current comments carry the hidden marker.
        assert!(is_switchboard_comment(
            "<!-- switchboard-preview -->\nanything at all"
        ));
        // A pre-marker comment is still recognised by its visible header so the
        // first post-upgrade deploy updates it in place instead of duplicating.
        assert!(is_switchboard_comment("**ePHPm Preview** — ready"));
        // An unrelated comment is not ours.
        assert!(!is_switchboard_comment("LGTM, merging"));
    }
}
