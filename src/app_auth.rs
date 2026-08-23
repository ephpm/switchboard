//! GitHub App authentication — minting short-lived installation tokens entirely
//! in memory.
//!
//! The daemon is the only half of the split that authenticates to GitHub
//! (switchboard-api holds no key and makes no outbound request — that is the
//! confinement the split exists to create). The flow:
//!
//! 1. Load the App private key from a `0600` path (checked below).
//! 2. Build a JWT (`RS256`) asserting the App id, signed by piping the signing
//!    input to `openssl` — the key is read by `openssl` from its path and never
//!    materialized in this process's memory as bytes we manage.
//! 3. Exchange the JWT for a ~60-minute installation token over HTTPS.
//!
//! The token is wrapped in [`InstallationToken`], whose `Debug` and `Display`
//! redact it: it is never logged and never written to disk. It reaches `git`
//! through the environment (see [`crate::git_askpass`]), never argv.

use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use base64::Engine;
use tokio::io::AsyncWriteExt;

/// A minted installation access token. Redacts itself in logs; expose the raw
/// value only at the point of use.
#[derive(Clone)]
pub struct InstallationToken(String);

impl InstallationToken {
    /// The raw token. Call this only where the token is actually used (the
    /// `GIT_ASKPASS` env and the `Authorization` header) — never in a log.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Construct a token from a raw string. Test-only: the real constructor is
    /// [`AppAuth::installation_token`], which mints one from GitHub.
    #[cfg(test)]
    #[must_use]
    pub fn from_raw_for_test(raw: &str) -> Self {
        Self(raw.to_string())
    }
}

impl std::fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstallationToken(<redacted>)")
    }
}

impl std::fmt::Display for InstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// GitHub App credentials and the API base to authenticate against.
#[derive(Debug, Clone)]
pub struct AppAuth {
    app_id: u64,
    key_path: PathBuf,
    api_base: String,
}

impl AppAuth {
    /// Load and check the App key.
    ///
    /// On Unix the key file must not be readable by group or other (`0600`).
    /// This fails closed: a broadly-readable App private key is a credential
    /// any co-tenant uid could exfiltrate, so the daemon refuses to start rather
    /// than run with it.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is missing or (on Unix) has permissions
    /// looser than `0600`.
    pub fn load(app_id: u64, key_path: PathBuf, github_host: &str) -> anyhow::Result<Self> {
        ensure!(
            key_path.exists(),
            "GitHub App private key not found at {}",
            key_path.display()
        );
        check_key_permissions(&key_path)?;
        Ok(Self {
            app_id,
            key_path,
            api_base: api_base_for(github_host),
        })
    }

    /// Mint an installation access token for `installation_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails or GitHub does not return a token.
    pub async fn installation_token(
        &self,
        installation_id: u64,
    ) -> anyhow::Result<InstallationToken> {
        let jwt = self.app_jwt().await?;

        let url = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            self.api_base
        );
        let resp = reqwest::Client::new()
            .post(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("User-Agent", "switchboard")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .context("failed to request installation token")?;

        ensure!(
            resp.status().is_success(),
            "failed to get installation token: HTTP {}",
            resp.status()
        );

        let body: serde_json::Value = resp.json().await.context("installation token response")?;
        let token = body["token"]
            .as_str()
            .context("installation token response missing 'token'")?;
        Ok(InstallationToken(token.to_string()))
    }

    /// Build and sign the App JWT.
    async fn app_jwt(&self) -> anyhow::Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let header = base64_url_encode(&serde_json::to_vec(&serde_json::json!({
            "alg": "RS256",
            "typ": "JWT"
        }))?);
        let payload = base64_url_encode(&serde_json::to_vec(&serde_json::json!({
            "iat": now - 60,
            "exp": now + 10 * 60,
            "iss": self.app_id
        }))?);
        let signing_input = format!("{header}.{payload}");

        let mut child = tokio::process::Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&self.key_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("failed to spawn openssl for JWT signing")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(signing_input.as_bytes()).await?;
        }
        let output = child.wait_with_output().await?;
        ensure!(output.status.success(), "openssl signing failed");

        let signature = base64_url_encode(&output.stdout);
        Ok(format!("{signing_input}.{signature}"))
    }
}

/// On Unix, refuse a key readable by group or other. On other platforms this is
/// a no-op (the daemon is not supported there; the check has no cheap portable
/// equivalent).
#[cfg(unix)]
fn check_key_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("cannot stat App key {}", path.display()))?
        .permissions()
        .mode();
    ensure!(
        mode & 0o077 == 0,
        "GitHub App key {} is group/world-accessible (mode {:o}); tighten it to 0600",
        path.display(),
        mode & 0o777
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// The GitHub API base for a host: `github.com` uses `api.github.com`, a GHES
/// host uses `https://<host>/api/v3`.
fn api_base_for(github_host: &str) -> String {
    if github_host.eq_ignore_ascii_case("github.com") {
        "https://api.github.com".to_string()
    } else {
        format!("https://{github_host}/api/v3")
    }
}

/// Base64url encode (no padding) for JWT.
fn base64_url_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_encodes_without_padding() {
        assert_eq!(base64_url_encode(b"hello"), "aGVsbG8");
        assert!(!base64_url_encode(b"hello").contains('='));
        assert_eq!(base64_url_encode(b""), "");
    }

    #[test]
    fn base64url_uses_url_safe_alphabet() {
        let encoded = base64_url_encode(&[0xfb, 0xff]);
        assert_eq!(encoded, "-_8");
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn token_redacts_in_debug_and_display() {
        let t = InstallationToken("ghs_supersecret".to_string());
        assert_eq!(format!("{t:?}"), "InstallationToken(<redacted>)");
        assert_eq!(format!("{t}"), "<redacted>");
        // The raw value is only reachable through expose().
        assert_eq!(t.expose(), "ghs_supersecret");
    }

    #[test]
    fn api_base_maps_host() {
        assert_eq!(api_base_for("github.com"), "https://api.github.com");
        assert_eq!(api_base_for("GitHub.com"), "https://api.github.com");
        assert_eq!(
            api_base_for("ghe.corp.example"),
            "https://ghe.corp.example/api/v3"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("app.pem");
        std::fs::write(&key, "x").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(AppAuth::load(1, key, "github.com").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn accepts_0600_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("app.pem");
        std::fs::write(&key, "x").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AppAuth::load(1, key, "github.com").is_ok());
    }
}
