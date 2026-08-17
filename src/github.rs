//! GitHub API interactions — PR comments and deployment statuses.

use anyhow::Context;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde_json::json;

use crate::deployer::DeployResult;
use crate::webhook::PullRequestEvent;

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
    pub async fn post_preview_comment(
        &self,
        event: &PullRequestEvent,
        result: &DeployResult,
    ) -> anyhow::Result<()> {
        let owner = &event.repository.owner.login;
        let repo = &event.repository.name;
        let pr_number = event.number;

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
    pub async fn post_teardown_comment(&self, event: &PullRequestEvent) -> anyhow::Result<()> {
        let owner = &event.repository.owner.login;
        let repo = &event.repository.name;
        let pr_number = event.number;

        if let Some(comment_id) = self.find_existing_comment(owner, repo, pr_number).await? {
            self.update_comment(owner, repo, comment_id, teardown_comment_body())
                .await?;
        }

        Ok(())
    }

    /// Set the commit deployment status (creates the "Environments" UI in GitHub).
    pub async fn create_deployment_status(
        &self,
        event: &PullRequestEvent,
        result: &DeployResult,
    ) -> anyhow::Result<()> {
        let owner = &event.repository.owner.login;
        let repo = &event.repository.name;
        let sha = &event.pull_request.head.sha;

        let url = format!("https://{}", result.hostname);

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
                "environment": format!("preview-pr-{}", event.number),
                "auto_merge": false,
                "required_contexts": [],
                "description": format!("ePHPm preview for PR #{}", event.number),
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

        // Set deployment status to success.
        let status_url = format!(
            "https://api.github.com/repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
        );
        self.client
            .post(&status_url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
            .json(&json!({
                "state": "success",
                "environment_url": url,
                "description": format!("{} preview deployed", result.framework.as_str()),
            }))
            .send()
            .await
            .context("failed to set deployment status")?;

        Ok(())
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
            if body.contains("**ePHPm Preview**") {
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

/// The PR comment body posted when a preview is torn down. Kept as its own
/// pure function (rather than inlined in the async network path) so the exact
/// rendered markdown is unit-testable and still carries the `**ePHPm Preview**`
/// marker that [`GitHubClient::find_existing_comment`] matches on.
fn teardown_comment_body() -> &'static str {
    "**ePHPm Preview** — removed\n\n\
     Preview deployment has been torn down."
}

/// Format the PR comment body for a successful deploy.
fn format_deploy_comment(result: &DeployResult) -> String {
    let url = crate::deployer::preview_url(&result.hostname, result.php_version.as_deref());
    let php_display = result.php_version.as_deref().unwrap_or("latest");
    let status = if result.healthy {
        "ready"
    } else {
        "deployed (health check pending)"
    };

    format!(
        "**ePHPm Preview** — {status}\n\n\
         | | |\n\
         |---|---|\n\
         | URL | {url} |\n\
         | Framework | {} |\n\
         | PHP | {php_display} |\n\
         | Deployed in | {:.1}s |\n\n\
         Preview updates automatically on each push to this PR.",
        result.framework.as_str(),
        result.duration.as_secs_f64(),
    )
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
        };
        let comment = format_deploy_comment(&result);
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
        };
        let comment = format_deploy_comment(&result);
        assert!(comment.contains("2.4s"), "got: {comment}");
        assert!(comment.contains("Drupal"));
        // 8.5 is the default port-less URL — no explicit port in the link.
        assert!(!comment.contains(":8085"));
    }

    #[test]
    fn teardown_body_is_marked_and_removed() {
        let body = teardown_comment_body();
        // Must keep the marker so the existing comment is found and updated in
        // place rather than a fresh "removed" comment being appended.
        assert!(body.contains("**ePHPm Preview**"));
        assert!(body.contains("removed"));
        assert!(body.contains("torn down"));
    }
}
