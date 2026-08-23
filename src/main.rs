//! switchboard — the preview-deployment daemon for ePHPm.
//!
//! It is a queue worker, not an HTTP server. switchboard-api
//! (`ephpm/switchboard-api`) receives GitHub webhooks, verifies them, and writes
//! job files into a directory; this daemon watches that directory, provisions
//! (or tears down) previews, and reports status to GitHub via the Deployments
//! API. The webhook receiver and this daemon are the two halves of a deliberate
//! split — see `README.md` and switchboard-api's `MIGRATION.md`.

mod app_auth;
mod config;
mod deployer;
mod git_askpass;
mod github;
mod job;
mod manifest;
mod preview;
mod queue;
mod secrets;
mod site;

use std::time::Duration;

use app_auth::{AppAuth, InstallationToken};
use config::Config;
use deployer::DeployContext;
use git_askpass::Askpass;
use github::{DeploymentState, GitHubClient};
use job::{Intent, Job};
use queue::{HandleOutcome, JobSink, QueueWatcher};
use secrets::Secrets;

use clap::Parser;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,switchboard=debug".parse().unwrap()),
        )
        .init();

    let config = Config::parse();
    info!(queue = %config.queue_dir.display(), "starting switchboard daemon");
    info!(sites_dir = %config.sites_dir.display(), preview_domain = %config.preview_domain, "preview target");

    // App auth: load + permission-check the key, resolve the API base.
    let app_auth = AppAuth::load(config.app_id, config.app_key.clone(), &config.github_host)?;

    // Secret store for `${secret.NAME}` resolution (never from the app repo).
    let secrets = Secrets::load(config.secrets_file.as_deref())?;

    // GIT_ASKPASS helper — carries the token to git via env, never argv/disk.
    let askpass = Askpass::create()?;

    let orchestrator = Orchestrator {
        config: config.clone(),
        secrets,
        app_auth,
        askpass,
    };

    let watcher = QueueWatcher::new(
        &config.queue_dir,
        config.github_host.clone(),
        Duration::from_secs(config.poll_interval_secs),
    );

    watcher
        .run(&orchestrator, Box::pin(shutdown_signal()))
        .await;
    info!("switchboard daemon stopped");
    Ok(())
}

/// Resolves when the process receives a shutdown signal (Ctrl-C, or SIGTERM on
/// Unix) so the watcher can finish its current pass and exit cleanly.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// The daemon's [`JobSink`]: mints tokens, reports to GitHub, and drives the
/// deploy/teardown pipeline.
struct Orchestrator {
    config: Config,
    secrets: Secrets,
    app_auth: AppAuth,
    askpass: Askpass,
}

impl JobSink for Orchestrator {
    async fn handle(&self, job: Job) -> HandleOutcome {
        match job.intent() {
            Some(Intent::Deploy) => self.deploy(&job).await,
            Some(Intent::Teardown) => self.teardown(&job).await,
            // Validation guarantees this is unreachable; drop it rather than spin.
            None => {
                warn!(delivery = %job.delivery_id, "job with no actionable intent — dropping");
                HandleOutcome::Done
            }
        }
    }
}

impl Orchestrator {
    fn deploy_context(&self) -> DeployContext<'_> {
        DeployContext {
            sites_dir: &self.config.sites_dir,
            preview_domain: &self.config.preview_domain,
            sites_domain_suffix: self.config.sites_domain_suffix.as_deref(),
            site_overrides_dir: self.config.site_overrides_dir.as_deref(),
            sqlite_dir: self.config.sqlite_dir.as_deref(),
            vhost_temp_base: self.config.vhost_temp_base.as_deref(),
            composer: &self.config.composer,
            secrets: &self.secrets,
            fork_secrets: self.config.fork_secrets,
            askpass: &self.askpass,
            health_timeout: Duration::from_secs(self.config.health_timeout_secs),
            health_interval: Duration::from_secs(self.config.health_interval_secs),
        }
    }

    /// Mint an installation token if the job carries an installation id.
    async fn mint_token(&self, job: &Job) -> Option<InstallationToken> {
        let installation_id = job.installation_id?;
        match self.app_auth.installation_token(installation_id).await {
            Ok(token) => Some(token),
            Err(e) => {
                warn!(%e, "failed to mint installation token — proceeding without GitHub reporting");
                None
            }
        }
    }

    async fn deploy(&self, job: &Job) -> HandleOutcome {
        // Fork gate (defense in depth over switchboard-api's own gate).
        if job.pull_request.fork && !self.config.allow_fork_deploy {
            warn!(
                repo = %job.repository.full_name,
                pr = job.pull_request.number,
                "refusing fork PR deploy (allow_fork_deploy is off)"
            );
            return HandleOutcome::Done;
        }

        let owner = &job.repository.owner;
        let repo = &job.repository.name;
        let number = job.pull_request.number;
        let sha = &job.pull_request.head.sha;

        // Token + GitHub client. Create the Deployment as the FIRST action so a
        // failed build still shows on the PR.
        let token = self.mint_token(job).await;
        let client = token
            .clone()
            .map(|t| GitHubClient::new(t, &self.config.github_host));
        let mut deployment_id = None;
        if let Some(client) = &client {
            match client.create_deployment(owner, repo, sha, number).await {
                Ok(id) => {
                    deployment_id = Some(id);
                    let _ = client
                        .set_deployment_status(
                            owner,
                            repo,
                            id,
                            DeploymentState::Queued,
                            None,
                            "queued",
                        )
                        .await;
                    let _ = client
                        .set_deployment_status(
                            owner,
                            repo,
                            id,
                            DeploymentState::InProgress,
                            None,
                            "provisioning preview",
                        )
                        .await;
                }
                Err(e) => warn!(%e, "failed to create GitHub deployment — continuing without it"),
            }
        }

        let ctx = self.deploy_context();
        match deployer::deploy_preview(job, &ctx, token.as_ref()).await {
            Ok(result) => {
                info!(
                    site_key = %result.site_key,
                    hostname = %result.hostname,
                    url = %result.preview_url,
                    framework = result.framework.as_str(),
                    php = result.php_version.as_deref().unwrap_or("default"),
                    healthy = result.healthy,
                    duration_ms = result.duration.as_millis(),
                    "preview deployed"
                );
                if let (Some(client), Some(id)) = (&client, deployment_id) {
                    let desc = format!("{} preview deployed", result.framework.as_str());
                    let _ = client
                        .set_deployment_status(
                            owner,
                            repo,
                            id,
                            DeploymentState::Success,
                            Some(&result.preview_url),
                            &desc,
                        )
                        .await;
                }
                HandleOutcome::Done
            }
            Err(e) => {
                error!(repo = %job.repository.full_name, pr = number, %e, "preview deployment failed");
                if let Some(client) = &client {
                    if let Some(id) = deployment_id {
                        let _ = client
                            .set_deployment_status(
                                owner,
                                repo,
                                id,
                                DeploymentState::Failure,
                                None,
                                "deploy failed",
                            )
                            .await;
                    }
                    // A failure deployment carries no log — post the error too.
                    let _ = client
                        .post_failure_comment(owner, repo, number, &format!("{e:#}"))
                        .await;
                }
                // Leave the claimed file for inspection.
                HandleOutcome::Retain
            }
        }
    }

    async fn teardown(&self, job: &Job) -> HandleOutcome {
        let ctx = self.deploy_context();
        if let Err(e) = deployer::teardown_preview(job, &ctx).await {
            error!(%e, "preview teardown failed");
            return HandleOutcome::Retain;
        }
        // Best-effort: mark the environment inactive.
        if let Some(token) = self.mint_token(job).await {
            let client = GitHubClient::new(token, &self.config.github_host);
            let _ = client
                .deactivate_environment(
                    &job.repository.owner,
                    &job.repository.name,
                    job.pull_request.number,
                )
                .await;
        }
        HandleOutcome::Done
    }
}
