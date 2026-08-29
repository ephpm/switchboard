//! The drain kick — the cluster fan-out half of the daemon.
//!
//! `switchboard-api` runs as a vhost inside ePHPm and has no timer of its own:
//! PHP only runs when a request arrives. Work it must do off the webhook path
//! (fanning a job out to the other nodes of the cluster, expiring delivery
//! markers) therefore needs someone to call it. That someone is this daemon,
//! which is already running beside ePHPm on every node.
//!
//! The kick is a plain `GET http://<drain_addr>/drain` with two headers:
//!
//! * `Host: <drain_host>` — ePHPm routes by vhost, and the daemon connects to
//!   `127.0.0.1`, so the Host header is what selects the API's site.
//! * `X-Drain-Token: <drain_token_file contents>` — a shared secret proving the
//!   request came from the local daemon and not from the internet.
//!
//! Nothing about a kick is fatal. A refused connection means ePHPm is
//! restarting; a non-200 means the API is unhappy. Both are logged at WARN and
//! the loop carries on — a missed kick is picked up by the next one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use reqwest::header::HOST;

/// Per-request timeout for a kick. Comfortably above a healthy local response
/// and well below any sane kick interval, so a wedged API cannot stall the
/// loop.
const KICK_TIMEOUT: Duration = Duration::from_secs(5);

/// The header carrying the shared drain secret.
const TOKEN_HEADER: &str = "X-Drain-Token";

/// A configured drain kicker.
pub struct DrainKicker {
    client: reqwest::Client,
    /// `host:port` of the local ePHPm instance.
    addr: String,
    /// The vhost to address, sent as the `Host` header.
    host: String,
    /// File holding the shared secret (the API's `.switchboard/drain_secret`).
    token_file: PathBuf,
}

impl DrainKicker {
    /// Build a kicker. The token file is read once here so a misconfigured
    /// path fails loudly at startup rather than every two seconds forever.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built or the token file
    /// cannot be read.
    pub fn new(addr: String, host: String, token_file: PathBuf) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(KICK_TIMEOUT)
            .build()
            .context("failed to build the drain HTTP client")?;
        // Validate now; the value itself is re-read per kick so the secret can
        // be rotated without restarting the daemon.
        let _ = read_token(&token_file)?;
        Ok(Self {
            client,
            addr,
            host,
            token_file,
        })
    }

    /// The URL a kick targets.
    #[must_use]
    pub fn url(&self) -> String {
        drain_url(&self.addr)
    }

    /// Send one kick.
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be read, the request fails, or the
    /// response is not a 200. Callers log and continue — never abort.
    pub async fn kick(&self) -> anyhow::Result<()> {
        let token = read_token(&self.token_file)?;
        let resp = self
            .client
            .get(self.url())
            .header(HOST, &self.host)
            .header(TOKEN_HEADER, token)
            .send()
            .await
            .context("drain request failed")?;

        let status = resp.status();
        anyhow::ensure!(status.as_u16() == 200, "drain returned HTTP {status}");
        Ok(())
    }
}

/// The drain URL for an `addr`. Always plain HTTP: the daemon and ePHPm are on
/// the same host, and TLS terminates in front of ePHPm, not on the loopback.
#[must_use]
pub fn drain_url(addr: &str) -> String {
    format!("http://{addr}/drain")
}

/// Read the shared drain secret, trimming surrounding whitespace.
///
/// Trimming matters: a secret written with `echo` carries a trailing newline
/// that would otherwise be sent as part of the header value and fail a
/// constant-time comparison on the API side.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is empty after trimming.
pub fn read_token(path: &Path) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read drain token file {}", path.display()))?;
    let token = raw.trim().to_string();
    anyhow::ensure!(
        !token.is_empty(),
        "drain token file {} is empty",
        path.display()
    );
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_is_plain_http_on_the_configured_addr() {
        assert_eq!(drain_url("127.0.0.1:8080"), "http://127.0.0.1:8080/drain");
        assert_eq!(drain_url("10.0.0.4:80"), "http://10.0.0.4:80/drain");
    }

    #[test]
    fn token_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drain_secret");
        // `echo secret > file` leaves a trailing newline; it must not be sent.
        std::fs::write(&path, "  s3cr3t-value\n").unwrap();
        assert_eq!(read_token(&path).unwrap(), "s3cr3t-value");
    }

    #[test]
    fn empty_token_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drain_secret");
        std::fs::write(&path, "\n \n").unwrap();
        assert!(
            read_token(&path).is_err(),
            "an empty secret must fail loudly, not authenticate as \"\""
        );
    }

    #[test]
    fn missing_token_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_token(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn kicker_construction_validates_the_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drain_secret");
        assert!(
            DrainKicker::new("127.0.0.1:8080".into(), "api.example".into(), path.clone()).is_err(),
            "a missing token file must fail at startup"
        );
        std::fs::write(&path, "tok\n").unwrap();
        let kicker = DrainKicker::new("127.0.0.1:8080".into(), "api.example".into(), path).unwrap();
        assert_eq!(kicker.url(), "http://127.0.0.1:8080/drain");
    }

    #[tokio::test]
    async fn a_refused_connection_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drain_secret");
        std::fs::write(&path, "tok").unwrap();
        // Port 1 on loopback: nothing listens, so the kick must return Err for
        // the caller to log — the daemon keeps running either way.
        let kicker = DrainKicker::new("127.0.0.1:1".into(), "api.example".into(), path).unwrap();
        assert!(kicker.kick().await.is_err());
    }
}
