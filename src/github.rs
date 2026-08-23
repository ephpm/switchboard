//! GitHub interaction — the Deployments API lifecycle plus a failure-only PR
//! comment.
//!
//! GitHub is the interface: the daemon creates a Deployment as its first action
//! on claiming a deploy job (so even a failed build shows on the PR), then posts
//! `in_progress` → `success`/`failure` with the preview URL as
//! `environment_url`, which renders the native "View deployment" box. Teardown
//! posts `inactive`.
//!
//! A `failure` deployment state carries no log, so a build failure additionally
//! posts a PR comment carrying the `**ePHPm Preview**` marker — the same marker
//! used to find-and-update in place rather than appending a new comment each
//! push. The success-path comment is redundant once the deployment box renders,
//! so it is gone.

use anyhow::{Context, ensure};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde_json::json;

use crate::app_auth::InstallationToken;

/// A deployment status state, per the GitHub Deployments API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentState {
    /// Created, not yet started.
    Queued,
    /// Clone/build underway.
    InProgress,
    /// Preview healthy.
    Success,
    /// A step failed.
    Failure,
    /// Torn down.
    Inactive,
}

impl DeploymentState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::InProgress => "in_progress",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Inactive => "inactive",
        }
    }
}

/// GitHub API client bound to one installation token.
pub struct GitHubClient {
    client: reqwest::Client,
    token: InstallationToken,
    api_base: String,
}

impl GitHubClient {
    /// Create a client. `github_host` selects the API base (`github.com` →
    /// `api.github.com`, else GHES `/api/v3`).
    #[must_use]
    pub fn new(token: InstallationToken, github_host: &str) -> Self {
        let api_base = if github_host.eq_ignore_ascii_case("github.com") {
            "https://api.github.com".to_string()
        } else {
            format!("https://{github_host}/api/v3")
        };
        Self {
            client: reqwest::Client::new(),
            token,
            api_base,
        }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header(AUTHORIZATION, format!("Bearer {}", self.token.expose()))
            .header(USER_AGENT, "switchboard")
            .header(ACCEPT, "application/vnd.github+json")
    }

    /// Create a Deployment and return its id. Uses a transient ref (the head
    /// SHA), disables auto-merge, and requires no status contexts so GitHub does
    /// not refuse to create it.
    ///
    /// # Errors
    ///
    /// Returns an error if GitHub does not return a numeric deployment id.
    pub async fn create_deployment(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        number: u64,
    ) -> anyhow::Result<u64> {
        let url = format!("{}/repos/{owner}/{repo}/deployments", self.api_base);
        let resp = self
            .auth(self.client.post(&url))
            .json(&json!({
                "ref": sha,
                "environment": deployment_environment(number),
                "auto_merge": false,
                "required_contexts": [],
                "transient_environment": true,
                "description": format!("ePHPm preview for PR #{number}"),
            }))
            .send()
            .await
            .context("failed to create deployment")?;

        ensure!(
            resp.status().is_success(),
            "create deployment failed: HTTP {}",
            resp.status()
        );
        let deployment: serde_json::Value = resp.json().await.context("deployment response")?;
        deployment["id"]
            .as_u64()
            .context("deployment response missing id")
    }

    /// Post a status on an existing Deployment.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or GitHub rejects it.
    pub async fn set_deployment_status(
        &self,
        owner: &str,
        repo: &str,
        deployment_id: u64,
        state: DeploymentState,
        environment_url: Option<&str>,
        description: &str,
    ) -> anyhow::Result<()> {
        let url = format!(
            "{}/repos/{owner}/{repo}/deployments/{deployment_id}/statuses",
            self.api_base
        );
        let mut body = json!({
            "state": state.as_str(),
            "description": truncate(description, 140),
        });
        if let Some(env_url) = environment_url {
            body["environment_url"] = json!(env_url);
        }
        let resp = self
            .auth(self.client.post(&url))
            .json(&body)
            .send()
            .await
            .context("failed to set deployment status")?;
        ensure!(
            resp.status().is_success(),
            "set deployment status failed: HTTP {}",
            resp.status()
        );
        Ok(())
    }

    /// Mark the most recent Deployment for a PR's environment `inactive` (the
    /// teardown signal). Best-effort: absence of a prior deployment is not an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns an error only on a transport failure; a missing deployment is a
    /// successful no-op.
    pub async fn deactivate_environment(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> anyhow::Result<()> {
        let list_url = format!(
            "{}/repos/{owner}/{repo}/deployments?environment={}&per_page=1",
            self.api_base,
            deployment_environment(number)
        );
        let resp = self
            .auth(self.client.get(&list_url))
            .send()
            .await
            .context("list deployments")?;
        if !resp.status().is_success() {
            return Ok(());
        }
        let deployments: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();
        let Some(id) = deployments.first().and_then(|d| d["id"].as_u64()) else {
            return Ok(());
        };
        self.set_deployment_status(
            owner,
            repo,
            id,
            DeploymentState::Inactive,
            None,
            "preview removed",
        )
        .await
    }

    /// Post (or update in place) the failure comment on a PR. Failure-only —
    /// success is carried by the deployment box.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn post_failure_comment(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        log_excerpt: &str,
    ) -> anyhow::Result<()> {
        let body = failure_comment_body(log_excerpt);
        if let Some(id) = self.find_marked_comment(owner, repo, number).await? {
            let url = format!(
                "{}/repos/{owner}/{repo}/issues/comments/{id}",
                self.api_base
            );
            self.auth(self.client.patch(&url))
                .json(&json!({ "body": body }))
                .send()
                .await
                .context("failed to update failure comment")?;
        } else {
            let url = format!(
                "{}/repos/{owner}/{repo}/issues/{number}/comments",
                self.api_base
            );
            self.auth(self.client.post(&url))
                .json(&json!({ "body": body }))
                .send()
                .await
                .context("failed to create failure comment")?;
        }
        Ok(())
    }

    /// Find a prior switchboard comment on a PR by its marker.
    async fn find_marked_comment(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> anyhow::Result<Option<u64>> {
        let url = format!(
            "{}/repos/{owner}/{repo}/issues/{number}/comments",
            self.api_base
        );
        let resp = self.auth(self.client.get(&url)).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let comments: Vec<serde_json::Value> = resp.json().await?;
        for comment in comments {
            if comment["body"]
                .as_str()
                .unwrap_or("")
                .contains(COMMENT_MARKER)
                && let Some(id) = comment["id"].as_u64()
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }
}

/// The marker every switchboard-authored comment carries, so it is found and
/// updated in place rather than duplicated on each push.
const COMMENT_MARKER: &str = "**ePHPm Preview**";

/// The GitHub Deployment environment name for a PR.
#[must_use]
pub fn deployment_environment(number: u64) -> String {
    format!("preview-pr-{number}")
}

/// The failure comment markdown. Carries the marker and a fenced log excerpt.
fn failure_comment_body(log_excerpt: &str) -> String {
    let excerpt = truncate(log_excerpt.trim(), 3000);
    format!(
        "{COMMENT_MARKER} — build failed\n\n\
         The preview could not be deployed. Latest output:\n\n\
         ```\n{excerpt}\n```\n\n\
         Push a fix to retry."
    )
}

/// Truncate `s` to at most `max` bytes on a char boundary, appending `…` when cut.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_name() {
        assert_eq!(deployment_environment(42), "preview-pr-42");
    }

    #[test]
    fn deployment_state_strings() {
        assert_eq!(DeploymentState::Queued.as_str(), "queued");
        assert_eq!(DeploymentState::InProgress.as_str(), "in_progress");
        assert_eq!(DeploymentState::Success.as_str(), "success");
        assert_eq!(DeploymentState::Failure.as_str(), "failure");
        assert_eq!(DeploymentState::Inactive.as_str(), "inactive");
    }

    #[test]
    fn failure_comment_has_marker_and_log() {
        let body = failure_comment_body("composer: command not found\nexit 127");
        assert!(body.contains(COMMENT_MARKER));
        assert!(body.contains("build failed"));
        assert!(body.contains("composer: command not found"));
        assert!(body.contains("```"));
    }

    #[test]
    fn truncate_respects_char_boundary_and_marks_cut() {
        let s = "a".repeat(10);
        assert_eq!(truncate(&s, 100), s);
        let cut = truncate(&s, 4);
        assert_eq!(cut, "aaaa…");
    }

    #[test]
    fn truncate_does_not_split_multibyte() {
        // '€' is 3 bytes; cutting at 2 must not panic and must not split it.
        let s = "a€b";
        let cut = truncate(s, 2);
        assert!(cut.ends_with('…'));
        assert!(cut.starts_with('a'));
    }
}
