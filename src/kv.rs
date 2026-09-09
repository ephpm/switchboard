//! A tiny RESP2 client for the one thing switchboard needs from ePHPm's KV: to
//! write a preview's **share-link revocation** keys on teardown.
//!
//! # Why a client at all, and why this narrow
//!
//! The preview access gate ([`crate::preview_auth`]) lets a repo member mint a
//! `via:"share"` bearer token that opens one preview without a GitHub login. The
//! gate revokes such tokens two ways, both read from the request's **own
//! per-vhost KV keyspace** (ephpm#487/#491):
//!
//! * a per-`jti` deny-list key `preview:share:revoked:<jti>` (revoke one link);
//! * a per-site epoch `preview:share:epoch` = unix-seconds (revoke *all* links
//!   issued before that instant — a token whose `iat` is below it is refused).
//!
//! On teardown, removing the override file and the checkout already stops the gate
//! on **this** node. But the per-vhost KV is gossip-replicated in a cluster, and a
//! preview can be redeployed, so the contract has switchboard also bump the epoch:
//! `preview:share:epoch = now`. That kills every outstanding share link for the
//! preview at once, cluster-wide, without enumerating `jti`s.
//!
//! # How the write is scoped to the tenant
//!
//! ePHPm's RESP listener scopes a connection to one vhost's KV store by its
//! **AUTH username**: `AUTH <site> <derived>` selects that site's dedicated store,
//! and subsequent commands use **bare** keys (the `\x1f<site>\x1f` gossip envelope
//! is internal to replication, never on the client wire). The password is
//! `HMAC-SHA256(kv_secret, site)` hex — [`crate::preview_auth::derive_site_kv_password`].
//! The `<site>` must be byte-identical to the token's `site` claim (the canonical
//! site key), which is exactly the vhost directory name teardown already has.
//!
//! # Best-effort, never fatal
//!
//! The write is best-effort: teardown's primary revocation is removing the gate
//! and the tree, and a teardown that *fails* because ePHPm's KV port was
//! unreachable would strand the preview's on-disk artifacts (the opposite of what
//! teardown is for). A failed bump is a `warn!`, not a teardown failure. It is
//! also skipped entirely, with a log line, when the operator has not told
//! switchboard the KV secret (`--kv-secret-file`).

use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

use crate::preview_auth::derive_site_kv_password;

/// The per-site epoch key the gate compares a share token's `iat` against.
///
/// (The gate also honours a per-`jti` deny-list key `preview:share:revoked:<jti>`
/// for revoking one link, but switchboard's daemon has no trigger for that today —
/// teardown revokes *all* links via the epoch — so this client writes only the
/// epoch. A per-link revoke path would add its own writer alongside its trigger.)
const EPOCH_KEY: &str = "preview:share:epoch";

/// Ceiling on the whole connect + AUTH + SET round trip. Teardown must not hang
/// on an unreachable or wedged KV port; a slow bump is dropped, loudly.
const OP_TIMEOUT: Duration = Duration::from_secs(5);

/// Where and how to reach ePHPm's per-site KV RESP listener.
///
/// `addr` is the listener (`[kv.redis_compat] listen`, default `127.0.0.1:6379`);
/// `kv_secret` is ePHPm's `[kv] secret`, which switchboard must be told
/// (`--kv-secret-file`) to derive per-site passwords. When switchboard has no KV
/// secret there is no [`KvRevoker`] and revocation writes are skipped.
#[derive(Debug, Clone)]
pub struct KvRevoker {
    addr: String,
    kv_secret: String,
}

impl KvRevoker {
    /// Build a revoker for a listener address and ePHPm's `[kv] secret`.
    #[must_use]
    pub fn new(addr: impl Into<String>, kv_secret: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            kv_secret: kv_secret.into(),
        }
    }

    /// Revoke **all** outstanding share links for `site` by setting its epoch to
    /// `now_unix` — every share token issued before that instant is refused.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection, AUTH, or SET fails (the caller treats
    /// this as best-effort and only warns).
    pub async fn bump_share_epoch(&self, site: &str, now_unix: u64) -> anyhow::Result<()> {
        self.set_site_key(site, EPOCH_KEY, &now_unix.to_string())
            .await
    }

    /// `AUTH <site> <derived>` then `SET <key> <value>` against the site's own
    /// KV store, under one short-lived connection with an overall timeout.
    async fn set_site_key(&self, site: &str, key: &str, value: &str) -> anyhow::Result<()> {
        let password = derive_site_kv_password(&self.kv_secret, site);
        tokio::time::timeout(
            OP_TIMEOUT,
            self.set_site_key_inner(site, &password, key, value),
        )
        .await
        .with_context(|| format!("KV write to {} timed out after {OP_TIMEOUT:?}", self.addr))?
    }

    async fn set_site_key_inner(
        &self,
        site: &str,
        password: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let stream = TcpStream::connect(&self.addr)
            .await
            .with_context(|| format!("cannot connect to ePHPm KV listener at {}", self.addr))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // AUTH scopes the connection to this vhost's KV store. On the client wire
        // the key is bare — the per-site envelope is internal to gossip.
        write_half
            .write_all(&encode_command(&["AUTH", site, password]))
            .await
            .context("failed to send KV AUTH")?;
        read_reply(&mut reader)
            .await
            .context("KV AUTH was rejected")?;

        write_half
            .write_all(&encode_command(&["SET", key, value]))
            .await
            .context("failed to send KV SET")?;
        read_reply(&mut reader).await.context("KV SET failed")?;

        // A courtesy QUIT so the server closes cleanly; ignore its result.
        let _ = write_half.write_all(&encode_command(&["QUIT"])).await;
        Ok(())
    }
}

/// Encode a command as a RESP2 array of bulk strings — the dialect ePHPm's KV
/// server parses (`*<n>\r\n` then `$<len>\r\n<arg>\r\n` per argument).
fn encode_command(args: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Read one RESP reply line and classify it. A `-` prefix is an error reply
/// (returned as `Err`); anything else (`+OK`, `:1`, `$…`) is success. Replies to
/// AUTH and SET are single simple-string/error lines, so one line is enough.
async fn read_reply<R>(reader: &mut R) -> anyhow::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let n = reader
        .read_until(b'\n', &mut line)
        .await
        .context("failed to read KV reply")?;
    anyhow::ensure!(n > 0, "ePHPm KV closed the connection without replying");
    let text = String::from_utf8_lossy(&line);
    let text = text.trim_end_matches(['\r', '\n']);
    if let Some(err) = text.strip_prefix('-') {
        anyhow::bail!("ePHPm KV returned an error: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

    #[test]
    fn resp_command_encoding_is_an_array_of_bulk_strings() {
        let bytes = encode_command(&["SET", "k", "v"]);
        assert_eq!(bytes, b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n");
    }

    #[tokio::test]
    async fn an_error_reply_is_surfaced() {
        let mut reply: &[u8] = b"-ERR bad auth\r\n";
        let mut reader = BufReader::new(&mut reply);
        let err = read_reply(&mut reader).await.unwrap_err();
        assert!(err.to_string().contains("bad auth"), "{err}");
    }

    #[tokio::test]
    async fn a_simple_ok_reply_is_success() {
        let mut reply: &[u8] = b"+OK\r\n";
        let mut reader = BufReader::new(&mut reply);
        read_reply(&mut reader).await.unwrap();
    }

    /// **The end-to-end revocation write.** Stand up a minimal RESP server that
    /// records the frames it receives and replies `+OK`, point a [`KvRevoker`] at
    /// it, and assert the AUTH is scoped to the site with the derived password and
    /// the SET writes `preview:share:epoch = <now>`.
    #[tokio::test]
    async fn bump_share_epoch_auths_for_the_site_and_sets_the_epoch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Reply +OK to AUTH and +OK to SET up front — the client reads them in
            // order. Then read to EOF (the client sends AUTH, SET, QUIT and closes),
            // so we capture every frame, not just whatever arrived first.
            sock.write_all(b"+OK\r\n+OK\r\n").await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });

        let revoker = KvRevoker::new(addr, "master-secret");
        revoker
            .bump_share_epoch("app-pr-1", 1_725_000_000)
            .await
            .unwrap();

        let received = server.await.unwrap();
        let expected_pw = derive_site_kv_password("master-secret", "app-pr-1");
        assert!(received.contains("AUTH"), "must authenticate: {received:?}");
        assert!(
            received.contains("app-pr-1"),
            "AUTH must name the site: {received:?}"
        );
        assert!(
            received.contains(&expected_pw),
            "AUTH must use the derived per-site password"
        );
        assert!(received.contains("SET"), "must issue a SET: {received:?}");
        assert!(
            received.contains("preview:share:epoch"),
            "must set the epoch key: {received:?}"
        );
        assert!(
            received.contains("1725000000"),
            "epoch value must be the unix time: {received:?}"
        );
    }

    #[tokio::test]
    async fn a_rejected_auth_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"-WRONGPASS invalid\r\n").await.unwrap();
        });
        let revoker = KvRevoker::new(addr, "master-secret");
        let err = revoker.bump_share_epoch("app-pr-1", 1).await.unwrap_err();
        assert!(err.to_string().contains("AUTH"), "{err}");
    }
}
