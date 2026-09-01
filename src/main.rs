//! switchboard — the preview-deployment daemon for an ePHPm cluster.
//!
//! It used to be one binary that received GitHub webhooks *and* provisioned
//! previews. Receiving moved to `ephpm/switchboard-api`, a PHP vhost running
//! inside ePHPm itself, which cannot reach `sites_dir` and holds no GitHub
//! credential. What is left here is the half that needs to be unconfined:
//!
//! 1. **Consume the job queue** written by the API at `<state_dir>/queue/` —
//!    claim, coalesce, and provision. See [`job`] and [`queue`].
//! 2. **Kick `/drain`** on the local ePHPm instance on a configurable interval,
//!    because a PHP vhost has no timer of its own. See [`drain`].
//! 3. **Talk to GitHub** — mint an installation token, post the preview comment
//!    and the Deployment status. Optional: with no App credentials configured
//!    the daemon still deploys, it just says nothing on the PR.
//!
//! The legacy webhook receiver is still compiled in but defaults to **off**
//! (`--webhook-server-enabled`).

mod config;
mod deployer;
mod drain;
mod github;
mod job;
mod manifest;
mod queue;
mod secrets;
mod webhook;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use clap::Parser;
use tracing::info;

use config::Config;
use deployer::PreviewRequest;
use drain::DrainKicker;
use job::Intent;
use queue::{ClaimedJob, Queue};
use secrets::Secrets;

/// Shared application state.
struct AppState {
    config: Config,
    secrets: Secrets,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,switchboard=debug".parse().unwrap()),
        )
        .init();

    let config = Config::parse();
    config.validate()?;

    info!(state_dir = %config.state_dir.display(), "starting switchboard daemon");
    info!(sites_dir = %config.sites_dir.display(), "preview deployments target");
    info!(domain = %config.preview_domain, "preview domain");

    if config.github_reporting_enabled() {
        let app_key = config
            .app_key
            .as_deref()
            .expect("github_reporting_enabled() implies an app key");
        anyhow::ensure!(
            app_key.exists(),
            "GitHub App private key not found at {}",
            app_key.display()
        );
        info!(app_key = %app_key.display(), "GitHub reporting enabled");
    } else {
        // The one INFO the operator needs: deploys will work, PRs stay quiet.
        info!(
            "no GitHub App credentials configured — preview deploys will run but \
             will not be reported on the pull request"
        );
    }

    tokio::fs::create_dir_all(&config.sites_dir).await?;

    // The API owns these directories, but the daemon may well start first.
    let queue = Queue::new(&config.state_dir);
    queue.ensure_dirs()?;
    info!(
        queue = %queue.queue_dir().display(),
        claimed = %queue.claimed_dir().display(),
        "consuming job queue"
    );

    // Load switchboard's own secret store (file + SWITCHBOARD_SECRET_* env).
    let secrets = Secrets::load(config.secrets_file.as_deref())?;

    // Build the drain kicker before anything else runs: a missing token file
    // should fail at startup, not silently warn every two seconds forever.
    let kicker = if config.drain_enabled() {
        let host = config
            .drain_host
            .clone()
            .expect("validate() guarantees a drain host when the kick is enabled");
        let token_file = config
            .drain_token_file
            .clone()
            .expect("validate() guarantees a token file when the kick is enabled");
        let kicker = DrainKicker::new(config.drain_addr.clone(), host.clone(), token_file)?;
        info!(
            url = %kicker.url(),
            vhost = %host,
            interval_s = config.drain_interval_secs,
            "drain kick enabled"
        );
        Some(kicker)
    } else {
        info!("drain kick disabled (--drain-interval-secs 0) — single-node mode");
        None
    };

    let drain_interval = Duration::from_secs(config.drain_interval_secs.max(1));
    let queue_interval = Duration::from_secs(config.queue_interval_secs.max(1));
    let webhook_server_enabled = config.webhook_server_enabled;
    let listen = config.listen.clone();

    let state = Arc::new(AppState { config, secrets });

    if let Some(kicker) = kicker {
        tokio::spawn(drain_loop(kicker, drain_interval));
    }

    if webhook_server_enabled {
        tracing::warn!(
            %listen,
            "legacy in-process webhook receiver enabled — webhook handling belongs \
             to switchboard-api; this exists only for un-migrated deployments"
        );
        tokio::spawn(serve_webhooks(Arc::clone(&state), listen));
    }

    queue_loop(state, queue, queue_interval).await
}

// ── the drain kick ─────────────────────────────────────────────────────

/// Kick `/drain` forever. Every failure mode here is transient — ePHPm
/// restarting, the vhost briefly unhappy — so nothing in this loop is fatal.
async fn drain_loop(kicker: DrainKicker, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match kicker.kick().await {
            Ok(()) => tracing::trace!("drain kicked"),
            Err(e) => tracing::warn!(%e, url = %kicker.url(), "drain kick failed — will retry"),
        }
    }
}

// ── the queue consumer ─────────────────────────────────────────────────

/// Scan, claim, coalesce and process, forever.
async fn queue_loop(state: Arc<AppState>, queue: Queue, interval: Duration) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;

        // Directory scanning and claiming is blocking filesystem work; keep it
        // off the async worker threads.
        let scan = queue.clone();
        let claimed = match tokio::task::spawn_blocking(move || scan.claim_pending()).await {
            Ok(Ok(claimed)) => claimed,
            Ok(Err(e)) => {
                tracing::error!(%e, "failed to scan the job queue");
                continue;
            }
            Err(e) => {
                tracing::error!(%e, "queue scan task panicked");
                continue;
            }
        };
        if claimed.is_empty() {
            continue;
        }

        // Coalescing is the daemon's job: rapid pushes to one PR produce
        // several jobs for one label and only the newest is worth running.
        let batch = queue::coalesce(claimed);
        for stale in batch.superseded {
            tracing::info!(
                job = %stale.name,
                label = %stale.job.label(),
                "superseded by a newer job for the same preview — discarding"
            );
            if let Err(e) = queue.complete(&stale.name) {
                tracing::warn!(job = %stale.name, %e, "failed to remove superseded job");
            }
        }

        for claimed in batch.run {
            process_job(&state, &queue, claimed).await;
        }
    }
}

/// Run one claimed job, then either clear it or leave it in `claimed/`.
async fn process_job(state: &AppState, queue: &Queue, claimed: ClaimedJob) {
    let ClaimedJob { name, path, job } = claimed;
    let intent = match job.intent() {
        Ok(intent) => intent,
        // Unreachable in practice: Job::parse validates the intent. Handled
        // rather than unwrapped so a future schema tweak cannot panic a daemon.
        Err(e) => {
            tracing::error!(job = %name, %e, "job has no usable intent — left in claimed/");
            return;
        }
    };
    let req = job.to_preview_request();

    tracing::info!(
        job = %name,
        // The delivery GUID is how an operator traces this back to the
        // delivery in GitHub's webhook UI.
        delivery = job.delivery_id.as_deref().unwrap_or("-"),
        action = %job.action,
        label = %req.label,
        repo = %req.repo_full_name,
        pr = req.pr_number,
        ?intent,
        "processing job"
    );

    let outcome = match intent {
        Intent::Deploy => handle_deploy(state, &req).await,
        Intent::Teardown => handle_teardown(state, &req).await,
    };

    match outcome {
        Ok(()) => {
            if let Err(e) = queue.complete(&name) {
                tracing::warn!(job = %name, %e, "job succeeded but could not be cleared");
            }
        }
        // Left in `claimed/` deliberately: an operator can see what failed, and
        // the job is not retried forever against a repo that will keep failing.
        Err(e) => tracing::error!(
            job = %name,
            label = %req.label,
            path = %path.display(),
            %e,
            "job failed — left in claimed/ for inspection"
        ),
    }
}

/// Deploy a preview and report it on the PR.
async fn handle_deploy(state: &AppState, req: &PreviewRequest) -> anyhow::Result<()> {
    // The daemon-side fork gate. The API refusing to queue fork deploys is a
    // different repo's policy; this process holds the secret store and builds
    // the code, so it decides again. A refused fork deploy is a hard error —
    // the job fails with the gate's message and stays in claimed/.
    let fork_secrets_mode = deployer::fork_deploy_gate(
        req.fork,
        state.config.allow_fork_deploy,
        state.config.fork_secrets,
    )?;
    let withheld = Secrets::default();
    let secrets = match fork_secrets_mode {
        deployer::ForkSecrets::Resolve => &state.secrets,
        deployer::ForkSecrets::Withhold => {
            tracing::warn!(
                label = %req.label,
                repo = %req.repo_full_name,
                "fork deploy allowed but operator secrets are withheld — every \
                 ${{secret.NAME}} expands to empty (set --fork-secrets to resolve them)"
            );
            &withheld
        }
    };

    let ctx = deployer::DeployContext {
        sites_dir: &state.config.sites_dir,
        preview_domain: &state.config.preview_domain,
        composer: &state.config.composer,
        secrets,
        health_timeout: Duration::from_secs(state.config.health_timeout_secs),
        health_interval: Duration::from_secs(state.config.health_interval_secs),
    };
    let result = deployer::deploy_preview(req, &ctx).await?;

    // Reporting is best-effort: the preview is live either way, and a GitHub
    // outage must not mark a good deploy as failed. Every node reconciles the
    // same preview and reports, but the comment is deduplicated by its hidden
    // marker: `post_preview_comment` finds an existing switchboard comment and
    // updates it in place, so N nodes converge on one comment.
    if let Some(client) = github_client(state, req).await {
        if let Err(e) = client.post_preview_comment(req, &result).await {
            tracing::error!(%e, "failed to post PR comment");
        }
        if let Err(e) = client.create_deployment_status(req, &result).await {
            tracing::error!(%e, "failed to set deployment status");
        }
    }
    Ok(())
}

/// Tear down a preview and update the PR comment.
///
/// Deliberately not fork-gated: teardown resolves no secrets and removes
/// data, and refusing fork teardowns would strand fork previews on disk.
async fn handle_teardown(state: &AppState, req: &PreviewRequest) -> anyhow::Result<()> {
    deployer::teardown_preview(&req.label, &state.config.sites_dir).await?;

    if let Some(client) = github_client(state, req).await {
        if let Err(e) = client.post_teardown_comment(req).await {
            tracing::error!(%e, "failed to update PR comment on teardown");
        }
    }
    Ok(())
}

// ── GitHub ─────────────────────────────────────────────────────────────

/// A GitHub client for this job, or `None` when reporting is not possible.
///
/// Two reasons it can be `None`, both non-fatal: no App credentials are
/// configured at all (the e2e cluster has no App installed), or this particular
/// job carries no installation id.
async fn github_client(state: &AppState, req: &PreviewRequest) -> Option<github::GitHubClient> {
    let (Some(app_id), Some(app_key)) = (state.config.app_id, state.config.app_key.as_deref())
    else {
        // The operator was told once at startup; don't repeat it per job.
        tracing::debug!("GitHub reporting disabled — no App credentials configured");
        return None;
    };
    let Some(installation_id) = req.installation_id else {
        tracing::warn!(
            label = %req.label,
            "job carries no installation id — skipping GitHub reporting"
        );
        return None;
    };

    match get_installation_token(app_id, app_key, installation_id).await {
        Ok(token) => Some(github::GitHubClient::new(token)),
        Err(e) => {
            tracing::error!(%e, "failed to get installation token");
            None
        }
    }
}

/// Get a short-lived installation access token from GitHub.
///
/// GitHub Apps authenticate by:
/// 1. Creating a JWT signed with the app's private key
/// 2. Exchanging the JWT for an installation access token
async fn get_installation_token(
    app_id: u64,
    app_key: &Path,
    installation_id: u64,
) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let header = base64_url_encode(&serde_json::to_vec(&serde_json::json!({
        "alg": "RS256",
        "typ": "JWT"
    }))?);

    let payload = base64_url_encode(&serde_json::to_vec(&serde_json::json!({
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id
    }))?);

    let signing_input = format!("{header}.{payload}");

    // Sign with RSA private key (shells out to openssl for MVP).
    let mut child = tokio::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(app_key)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(signing_input.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
    anyhow::ensure!(output.status.success(), "openssl signing failed");

    let signature = base64_url_encode(&output.stdout);
    let jwt = format!("{signing_input}.{signature}");

    // Exchange JWT for installation token.
    let url = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .header("User-Agent", "switchboard")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;

    anyhow::ensure!(
        resp.status().is_success(),
        "failed to get installation token: {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await?;
    body["token"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("installation token response missing 'token' field"))
}

/// Base64url encode (no padding) for JWT.
fn base64_url_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

// ── legacy webhook receiver (off by default) ───────────────────────────

/// Serve the legacy `/webhook` endpoint. Only reached when
/// `--webhook-server-enabled` is set.
async fn serve_webhooks(state: Arc<AppState>, listen: String) {
    let app = axum::Router::new()
        .route("/webhook", post(handle_webhook))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%listen, %e, "failed to bind the legacy webhook listener");
            return;
        }
    };
    match listener.local_addr() {
        Ok(addr) => info!(listen_addr = %addr, "legacy webhook receiver listening"),
        Err(e) => tracing::warn!(%e, "webhook listener has no local address"),
    }
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(%e, "legacy webhook receiver stopped");
    }
}

/// Handle incoming GitHub webhook events.
async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // `validate()` guarantees a secret whenever the server is enabled; refuse
    // rather than authenticate against nothing if that ever stops holding.
    let Some(secret) = state.config.webhook_secret.as_deref() else {
        tracing::error!("webhook received but no secret is configured");
        return StatusCode::UNAUTHORIZED;
    };

    // Verify webhook signature.
    let Some(signature) = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
    else {
        tracing::warn!("webhook missing signature header");
        return StatusCode::UNAUTHORIZED;
    };

    if let Err(e) = webhook::verify_signature(&body, secret, signature) {
        tracing::warn!(%e, "webhook signature verification failed");
        return StatusCode::UNAUTHORIZED;
    }

    // Only handle pull_request events.
    let event_type = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if event_type != "pull_request" {
        tracing::debug!(event = event_type, "ignoring non-PR event");
        return StatusCode::OK;
    }

    // Parse the event.
    let event: webhook::PullRequestEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(%e, "failed to parse pull_request event");
            return StatusCode::BAD_REQUEST;
        }
    };

    tracing::info!(
        repo = %event.repository.full_name,
        pr = event.number,
        action = %event.action,
        "received PR event"
    );

    // Spawn the deploy/teardown work in a background task so we respond 200 quickly.
    tokio::spawn(async move {
        let req = event.to_preview_request();
        let result = if event.should_deploy() {
            handle_deploy(&state, &req).await
        } else if event.should_teardown() {
            handle_teardown(&state, &req).await
        } else {
            Ok(())
        };
        if let Err(e) = result {
            tracing::error!(label = %req.label, %e, "webhook-driven preview work failed");
        }
    });

    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_encodes_without_padding() {
        // "hello" is standard base64 "aGVsbG8=" — the JWT encoding must drop
        // the '=' padding (a padded segment is not a valid JWS part).
        assert_eq!(base64_url_encode(b"hello"), "aGVsbG8");
        assert!(!base64_url_encode(b"hello").contains('='));
        // Empty input is the empty string, not "=".
        assert_eq!(base64_url_encode(b""), "");
    }

    #[test]
    fn base64url_uses_url_safe_alphabet() {
        // These bytes encode to "+/8" in the standard alphabet; the URL-safe
        // JWT encoding must instead emit '-' and '_' and never '+' or '/',
        // otherwise the token breaks when placed in an Authorization header.
        let encoded = base64_url_encode(&[0xfb, 0xff]);
        assert_eq!(encoded, "-_8");
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn base64url_roundtrips_via_decode() {
        use base64::Engine;
        let original = b"the quick brown fox \x00\x01\xff";
        let encoded = base64_url_encode(original);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("url-safe no-pad output must decode");
        assert_eq!(decoded, original);
    }
}
