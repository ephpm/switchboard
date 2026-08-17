//! switchboard — GitHub webhook handler for ePHPm preview deployments.
//!
//! Receives `pull_request` webhook events from GitHub, deploys preview
//! sites to an ePHPm instance's `sites_dir`, and posts PR comments
//! with the preview URL.

mod config;
mod deployer;
mod github;
mod manifest;
mod secrets;
mod webhook;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use clap::Parser;
use tracing::info;

use config::Config;
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
    info!(listen = %config.listen, "starting switchboard");
    info!(sites_dir = %config.sites_dir.display(), "preview deployments target");
    info!(domain = %config.preview_domain, "preview domain");

    // Verify the GitHub App private key exists.
    anyhow::ensure!(
        config.app_key.exists(),
        "GitHub App private key not found at {}",
        config.app_key.display()
    );

    // Ensure sites_dir exists.
    tokio::fs::create_dir_all(&config.sites_dir).await?;

    // Load switchboard's own secret store (file + SWITCHBOARD_SECRET_* env).
    let secrets = Secrets::load(config.secrets_file.as_deref())?;

    let listen = config.listen.clone();
    let state = Arc::new(AppState { config, secrets });

    let app = axum::Router::new()
        .route("/webhook", post(handle_webhook))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let listen_addr = listener.local_addr()?;
    info!(%listen_addr, "switchboard listening");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Handle incoming GitHub webhook events.
async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Verify webhook signature.
    let signature = match headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
    {
        Some(sig) => sig,
        None => {
            tracing::warn!("webhook missing signature header");
            return StatusCode::UNAUTHORIZED;
        }
    };

    if let Err(e) = webhook::verify_signature(&body, &state.config.webhook_secret, signature) {
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
        if event.should_deploy() {
            handle_deploy(&state, &event).await;
        } else if event.should_teardown() {
            handle_teardown(&state, &event).await;
        }
    });

    StatusCode::OK
}

/// Deploy a preview and post a comment.
async fn handle_deploy(state: &AppState, event: &webhook::PullRequestEvent) {
    let ctx = deployer::DeployContext {
        sites_dir: &state.config.sites_dir,
        preview_domain: &state.config.preview_domain,
        composer: &state.config.composer,
        secrets: &state.secrets,
        health_timeout: std::time::Duration::from_secs(state.config.health_timeout_secs),
        health_interval: std::time::Duration::from_secs(state.config.health_interval_secs),
    };
    let result = deployer::deploy_preview(event, &ctx).await;

    match result {
        Ok(deploy_result) => match get_installation_token(state, event).await {
            Ok(token) => {
                let client = github::GitHubClient::new(token);

                if let Err(e) = client.post_preview_comment(event, &deploy_result).await {
                    tracing::error!(%e, "failed to post PR comment");
                }
                if let Err(e) = client.create_deployment_status(event, &deploy_result).await {
                    tracing::error!(%e, "failed to set deployment status");
                }
            }
            Err(e) => {
                tracing::error!(%e, "failed to get installation token");
            }
        },
        Err(e) => {
            tracing::error!(
                repo = %event.repository.full_name,
                pr = event.number,
                %e,
                "preview deployment failed"
            );
        }
    }
}

/// Tear down a preview and update the comment.
async fn handle_teardown(state: &AppState, event: &webhook::PullRequestEvent) {
    if let Err(e) =
        deployer::teardown_preview(event, &state.config.sites_dir, &state.config.preview_domain)
            .await
    {
        tracing::error!(%e, "preview teardown failed");
    }

    match get_installation_token(state, event).await {
        Ok(token) => {
            let client = github::GitHubClient::new(token);
            if let Err(e) = client.post_teardown_comment(event).await {
                tracing::error!(%e, "failed to update PR comment on teardown");
            }
        }
        Err(e) => {
            tracing::error!(%e, "failed to get installation token for teardown");
        }
    }
}

/// Get a short-lived installation access token from GitHub.
///
/// GitHub Apps authenticate by:
/// 1. Creating a JWT signed with the app's private key
/// 2. Exchanging the JWT for an installation access token
async fn get_installation_token(
    state: &AppState,
    event: &webhook::PullRequestEvent,
) -> anyhow::Result<String> {
    let installation_id = event
        .installation
        .as_ref()
        .map(|i| i.id)
        .ok_or_else(|| anyhow::anyhow!("webhook event missing installation id"))?;

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
        "iss": state.config.app_id
    }))?);

    let signing_input = format!("{header}.{payload}");

    // Sign with RSA private key (shells out to openssl for MVP).
    let mut child = tokio::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(&state.config.app_key)
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
