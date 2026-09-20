//! A tiny RESP2 client for the two things switchboard needs from ePHPm's KV:
//! writing a preview's **share-link revocation** keys on teardown
//! ([`KvRevoker`]), and reading/writing the **cluster-shared analyze verdict
//! cache** ([`VerdictCache`]) so the pre-serve analyze gate scans a commit once
//! per cluster instead of once per node.
//!
//! Both rely on the same property: ePHPm's per-site KV is **gossip-replicated**
//! across the cluster (see below), so a value one node writes is readable on its
//! peers. That is exactly what lets the verdict computed by the first node to
//! scan be reused by the others.
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

/// The **switchboard-private** KV namespace the analyze verdict cache lives in.
///
/// This is an AUTH *site* string, deliberately chosen so no preview tenant can
/// ever reach it. Two facts make it disjoint from every preview keyspace:
///
/// * A tenant's `ephpm_kv_*` calls are auto-scoped **server-side** by ePHPm to
///   the request's own resolved site key — a tenant never gets to choose an AUTH
///   site, it can only ever read/write its one keyspace.
/// * A resolvable site key is always a *valid* one: DNS-style labels drawn from
///   `[a-z0-9._-]` (ePHPm's `is_valid_site_key`, mirrored in
///   [`crate::site_key::is_valid_site_key`]). This namespace begins with the
///   gossip unit-separator `\x1f`, which is outside that charset, so it can never
///   equal any preview site key — and therefore no tenant is ever scoped to it.
///
/// switchboard holds `kv_secret`, so it can derive the password for *any* AUTH
/// site and reach this one. That asymmetry — switchboard can address it, no
/// tenant can — is what prevents a malicious preview from poisoning the cache
/// (writing a forged `Passed` for a future SHA it authors). All nodes' daemons
/// AUTH as this same reserved site, so they share one gossip-replicated verdict
/// keyspace; the per-commit key ([`crate::analyze::verdict_key`]) keeps distinct
/// previews from colliding within it.
pub const VERDICT_STORE_SITE: &str = "\x1fswitchboard-verdicts";

/// A client for the cluster-shared **analyze verdict cache** in ePHPm's KV.
///
/// The pre-serve analyze gate's verdict is a pure function of (repo, PR head SHA,
/// gate config) and therefore identical on every node. Since switchboard runs on
/// every node and each materializes the same checkout, this cache lets the first
/// node to scan publish its verdict and the rest reuse it — one scan per commit,
/// cluster-wide, rather than N.
///
/// # Scope and store
///
/// Values live in the switchboard-private [`VERDICT_STORE_SITE`] namespace — NOT
/// a preview's own keyspace — reached with the same AUTH scoping [`KvRevoker`]
/// uses (`AUTH <site> <derived>`, then bare keys) but with the reserved site.
/// The store is gossip-replicated, so a peer reads what the first scanner wrote;
/// and because no tenant can authenticate to this namespace (see
/// [`VERDICT_STORE_SITE`]), the deployed preview code cannot read or forge a
/// verdict. That is what closes the cache-poisoning hole: an earlier design put
/// verdicts in the preview's own keyspace, where the running app could
/// `ephpm_kv_set` a forged `Passed` for a future malicious commit it authors
/// (it knows the repo/PR/SHA, and the config fingerprint is derivable from the
/// public policy) and bypass the gate.
///
/// Best-effort in both directions: a read failure means the caller scans locally
/// (fail-safe), and a write failure means peers scan themselves — neither ever
/// blocks a deploy.
#[derive(Debug, Clone)]
pub struct VerdictCache {
    addr: String,
    kv_secret: String,
    ttl: Duration,
}

impl VerdictCache {
    /// Build a cache client for the switchboard-private verdict namespace.
    ///
    /// `addr` is ePHPm's RESP listener, `kv_secret` its `[kv] secret` (for the
    /// per-site password derivation, here against [`VERDICT_STORE_SITE`]), and
    /// `ttl` the expiry applied to a published verdict (the SHA is the real
    /// invalidator; the TTL just garbage-collects old entries). There is
    /// deliberately no preview-`site` parameter — every verdict for the whole
    /// fleet lives in the one reserved namespace, keyed per commit.
    #[must_use]
    pub fn new(addr: impl Into<String>, kv_secret: impl Into<String>, ttl: Duration) -> Self {
        Self {
            addr: addr.into(),
            kv_secret: kv_secret.into(),
            ttl,
        }
    }

    /// `GET <key>` from the reserved verdict namespace. `Ok(None)` is a genuine
    /// miss (nil reply); an `Err` is a transport/auth problem the caller treats
    /// as "unavailable" and scans locally.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection, AUTH, or GET fails.
    pub async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        let password = derive_site_kv_password(&self.kv_secret, VERDICT_STORE_SITE);
        tokio::time::timeout(OP_TIMEOUT, self.get_inner(&password, key))
            .await
            .with_context(|| format!("KV GET from {} timed out after {OP_TIMEOUT:?}", self.addr))?
    }

    /// `SET <key> <value> EX <ttl>` in the reserved verdict namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection, AUTH, or SET fails.
    pub async fn put(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let password = derive_site_kv_password(&self.kv_secret, VERDICT_STORE_SITE);
        let ttl = self.ttl.as_secs().max(1).to_string();
        tokio::time::timeout(OP_TIMEOUT, self.put_inner(&password, key, value, &ttl))
            .await
            .with_context(|| format!("KV SET to {} timed out after {OP_TIMEOUT:?}", self.addr))?
    }

    async fn get_inner(&self, password: &str, key: &str) -> anyhow::Result<Option<String>> {
        let stream = TcpStream::connect(&self.addr)
            .await
            .with_context(|| format!("cannot connect to ePHPm KV listener at {}", self.addr))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        write_half
            .write_all(&encode_command(&["AUTH", VERDICT_STORE_SITE, password]))
            .await
            .context("failed to send KV AUTH")?;
        read_reply(&mut reader)
            .await
            .context("KV AUTH was rejected")?;

        write_half
            .write_all(&encode_command(&["GET", key]))
            .await
            .context("failed to send KV GET")?;
        let value = read_bulk_reply(&mut reader)
            .await
            .context("KV GET failed")?;

        let _ = write_half.write_all(&encode_command(&["QUIT"])).await;
        Ok(value)
    }

    async fn put_inner(
        &self,
        password: &str,
        key: &str,
        value: &str,
        ttl_secs: &str,
    ) -> anyhow::Result<()> {
        let stream = TcpStream::connect(&self.addr)
            .await
            .with_context(|| format!("cannot connect to ePHPm KV listener at {}", self.addr))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        write_half
            .write_all(&encode_command(&["AUTH", VERDICT_STORE_SITE, password]))
            .await
            .context("failed to send KV AUTH")?;
        read_reply(&mut reader)
            .await
            .context("KV AUTH was rejected")?;

        write_half
            .write_all(&encode_command(&["SET", key, value, "EX", ttl_secs]))
            .await
            .context("failed to send KV SET")?;
        read_reply(&mut reader).await.context("KV SET failed")?;

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

/// Read a RESP bulk-string reply (the shape `GET` returns): `$<len>\r\n<payload>\r\n`,
/// or `$-1\r\n` for a nil (missing key). Returns `Ok(None)` for nil and
/// `Ok(Some(payload))` otherwise. A `-ERR` reply is surfaced as an error.
async fn read_bulk_reply<R>(reader: &mut R) -> anyhow::Result<Option<String>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut header = Vec::new();
    let n = reader
        .read_until(b'\n', &mut header)
        .await
        .context("failed to read KV bulk reply header")?;
    anyhow::ensure!(n > 0, "ePHPm KV closed the connection without replying");
    let header = String::from_utf8_lossy(&header);
    let header = header.trim_end_matches(['\r', '\n']);

    if let Some(err) = header.strip_prefix('-') {
        anyhow::bail!("ePHPm KV returned an error: {err}");
    }
    let Some(len) = header.strip_prefix('$') else {
        anyhow::bail!("expected a RESP bulk string from KV GET, got {header:?}");
    };
    let len: i64 = len
        .parse()
        .with_context(|| format!("KV GET returned a malformed bulk length {len:?}"))?;
    if len < 0 {
        // `$-1` — the key is absent.
        return Ok(None);
    }
    let len = usize::try_from(len).context("KV GET returned an implausible bulk length")?;

    // Read the payload plus its trailing CRLF.
    let mut buf = vec![0u8; len + 2];
    reader
        .read_exact(&mut buf)
        .await
        .context("failed to read KV bulk payload")?;
    buf.truncate(len);
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
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

    // ── the verdict cache (bulk reply, GET/SET-EX) ──────────────────────

    #[tokio::test]
    async fn bulk_reply_parses_a_value() {
        let mut reply: &[u8] = b"$5\r\nhello\r\n";
        let mut reader = BufReader::new(&mut reply);
        assert_eq!(
            read_bulk_reply(&mut reader).await.unwrap(),
            Some("hello".to_string())
        );
    }

    #[tokio::test]
    async fn bulk_reply_nil_is_a_miss() {
        let mut reply: &[u8] = b"$-1\r\n";
        let mut reader = BufReader::new(&mut reply);
        assert_eq!(read_bulk_reply(&mut reader).await.unwrap(), None);
    }

    #[tokio::test]
    async fn bulk_reply_error_is_surfaced() {
        let mut reply: &[u8] = b"-ERR nope\r\n";
        let mut reader = BufReader::new(&mut reply);
        assert!(read_bulk_reply(&mut reader).await.is_err());
    }

    /// A cache **hit**: the fake server replies to AUTH then returns the stored
    /// JSON as a bulk string; `get` returns it, and the AUTH is scoped to the
    /// switchboard-private verdict namespace — never a preview's site key.
    #[tokio::test]
    async fn verdict_cache_get_returns_the_stored_value() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // +OK to AUTH, then a 9-byte bulk string to GET.
            sock.write_all(b"+OK\r\n$9\r\n{\"v\":\"x\"}\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });

        let cache = VerdictCache::new(addr, "master-secret", Duration::from_secs(3600));
        let got = cache
            .get("analyze:verdict:o/r:1:deadbeef:abcd")
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some("{\"v\":\"x\"}"));

        let received = server.await.unwrap();
        assert!(received.contains("AUTH"), "{received:?}");
        assert!(
            received.contains(VERDICT_STORE_SITE),
            "AUTH must name the reserved verdict namespace: {received:?}"
        );
        // The reserved namespace is authenticated with the password derived for
        // *it*, not for any preview.
        let expected_pw = derive_site_kv_password("master-secret", VERDICT_STORE_SITE);
        assert!(
            received.contains(&expected_pw),
            "AUTH must use the reserved-namespace password"
        );
        assert!(received.contains("GET"), "{received:?}");
        assert!(
            received.contains("analyze:verdict:o/r:1:deadbeef:abcd"),
            "{received:?}"
        );
    }

    /// A cache **miss**: nil reply to GET → `Ok(None)`.
    #[tokio::test]
    async fn verdict_cache_get_miss_is_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"+OK\r\n$-1\r\n").await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
        });
        let cache = VerdictCache::new(addr, "master-secret", Duration::from_secs(3600));
        assert_eq!(cache.get("k").await.unwrap(), None);
    }

    /// `put` issues `SET <key> <value> EX <ttl>` after AUTH.
    #[tokio::test]
    async fn verdict_cache_put_sets_with_ttl() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"+OK\r\n+OK\r\n").await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });
        let cache = VerdictCache::new(addr, "master-secret", Duration::from_secs(600));
        cache.put("k", "v").await.unwrap();

        let received = server.await.unwrap();
        assert!(received.contains("SET"), "{received:?}");
        assert!(received.contains("EX"), "must set a TTL: {received:?}");
        assert!(
            received.contains("600"),
            "TTL seconds present: {received:?}"
        );
    }

    /// An unreachable listener is an `Err` (the caller treats it as
    /// "unavailable" and scans locally — fail-safe).
    #[tokio::test]
    async fn verdict_cache_get_on_a_dead_addr_errors() {
        // Port 1 is not connectable; connect fails fast.
        let cache = VerdictCache::new("127.0.0.1:1", "master-secret", Duration::from_secs(60));
        assert!(cache.get("k").await.is_err());
    }

    /// **The cache-poisoning guard.** The verdict namespace must be unreachable
    /// by any preview tenant. A tenant's `ephpm_kv_*` is auto-scoped by ePHPm to
    /// its own resolved site key, which is always a *valid* site key
    /// ([`crate::site_key::is_valid_site_key`]); the reserved namespace is
    /// deliberately not a valid site key (leading `\x1f`), so no tenant can ever
    /// be scoped to it and thus cannot forge a verdict.
    #[test]
    fn verdict_namespace_is_unreachable_by_any_tenant() {
        assert!(
            !crate::site_key::is_valid_site_key(VERDICT_STORE_SITE),
            "the verdict namespace must never equal a resolvable preview site key"
        );
        // Concretely, it carries the gossip unit-separator, outside the
        // [a-z0-9._-] site-key charset.
        assert!(
            VERDICT_STORE_SITE.contains('\u{1f}'),
            "the reserved namespace must use an out-of-charset byte"
        );
        // And it is disjoint from realistic preview site keys.
        for site in [
            "ephpm-wordpress-sample-pr-7",
            "app-pr-1",
            "ephpm-my-blog-pr-42.preview.ephpm.dev",
        ] {
            assert!(crate::site_key::is_valid_site_key(site));
            assert_ne!(
                site, VERDICT_STORE_SITE,
                "no preview site key may equal the verdict namespace"
            );
        }
    }

    /// Every preview's verdict lives in the **one** switchboard-owned namespace,
    /// so the cluster-wide dedup works across the whole fleet — the cache is not
    /// scoped per preview (there is no preview-`site` parameter), only the
    /// per-commit key distinguishes entries.
    #[tokio::test]
    async fn all_previews_share_one_verdict_namespace() {
        // Two caches built independently (as two different previews' deploys
        // would) both AUTH as the same reserved namespace.
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let server = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                sock.write_all(b"+OK\r\n$-1\r\n").await.unwrap();
                let mut buf = Vec::new();
                sock.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).into_owned()
            });
            let cache = VerdictCache::new(addr, "master-secret", Duration::from_secs(60));
            let _ = cache.get("analyze:verdict:o/r:1:sha:cfg").await;
            let received = server.await.unwrap();
            assert!(
                received.contains(VERDICT_STORE_SITE),
                "every cache AUTHs the shared namespace: {received:?}"
            );
        }
    }
}
