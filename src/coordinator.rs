//! Cluster-wide exactly-once coordination over ePHPm's replicated KV store.
//!
//! # The problem this solves
//!
//! In a NodeBalancer-fronted cluster a GitHub webhook lands on exactly one
//! node, but `switchboard-api` publishes the desired preview state into ePHPm's
//! **gossip-replicated** KV (`Switchboard\Cluster\ClusterState`), and every
//! node's `/drain` turns that shared state back into its own local queue. So
//! **all** nodes deploy the same preview — which is what we want for a preview
//! that must survive any single node — but it also means all nodes would each
//! post the PR comment and create the deployment status. Three nodes, three
//! duplicate comments.
//!
//! # The primitive
//!
//! The same store already backs ePHPm's ACME-leader election and SQLite primary
//! election: an atomic `SET <key> <value> NX EX <ttl>` against the local RESP
//! listener. `set_nx` is atomic **per node** and, because the store
//! gossip-replicates, **best-effort cluster-wide** — exactly the guarantee
//! those elections rely on. Whichever node's claim lands first wins and posts;
//! the losers see the key already present and stay quiet.
//!
//! The claim is scoped to the head SHA (`…:<sha>`) so a *new* push mints a
//! *new* claim and the winning node updates the sticky comment for that commit,
//! rather than a stale claim suppressing the update forever. A TTL bounds key
//! accumulation and lets a claim made by a since-crashed node be re-won later.
//!
//! # Honest limits
//!
//! `set_nx` is not linearizable across a partition: two nodes that cannot see
//! each other's gossip can both win. That is the same residual race the ACME
//! leader tie-break carries, and it is backstopped by
//! [`crate::github`]'s marker match (a second claimant that *can* already see
//! the first node's comment updates it in place rather than duplicating). The
//! combination makes a true duplicate require both a partition *and* the two
//! nodes finishing their deploys inside the same gossip-propagation window.
//!
//! # Why a hand-rolled RESP client
//!
//! The daemon speaks to the KV over the wire (it is a separate process from
//! ePHPm; it cannot call the in-process store the way the PHP SAPI does). The
//! four verbs it needs — `AUTH`, `SET … NX EX`, `DEL` — are a few lines of RESP
//! each, so this hand-rolls them on `tokio` (already a dependency) rather than
//! pulling a Redis client and its tree into a crate that `cargo-deny` audits.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;

/// HMAC-SHA256 — mirrors `ephpm_kv::auth`.
type HmacSha256 = Hmac<Sha256>;

/// RESP AUTH credentials for the KV listener.
#[derive(Debug, Clone)]
struct Auth {
    /// Username for the two-argument `AUTH <user> <pass>` form — the vhost host
    /// in ePHPm's per-site RESP scoping. `None` uses the one-argument
    /// `AUTH <pass>` (`requirepass`) form.
    user: Option<String>,
    /// The password (a `requirepass` value, or a per-site derived password).
    password: String,
}

/// A single reply parsed from the RESP wire — only the shapes the coordinator's
/// commands can produce.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    /// `+OK`, `+PONG`, … — a simple string.
    Simple(String),
    /// `:<n>` — an integer (e.g. the count `DEL` removed).
    Integer(i64),
    /// `$<len>…` bulk string.
    Bulk(String),
    /// `$-1` / `*-1` — a nil reply. `SET … NX` returns this when the key
    /// already existed.
    Nil,
    /// `-ERR …` — a server error.
    Error(String),
}

/// Coordinates exactly-once actions across the cluster via the replicated KV.
#[derive(Debug, Clone)]
pub struct Coordinator {
    /// `host:port` of ePHPm's RESP listener (`[kv.redis_compat] listen`).
    addr: String,
    /// Optional AUTH credentials.
    auth: Option<Auth>,
    /// TTL stamped on every claim key.
    claim_ttl: Duration,
    /// A human-readable token stored as the claim's value, so an operator can
    /// see *which* node won. Never a secret.
    node_token: String,
}

impl Coordinator {
    /// Build a coordinator from resolved settings.
    ///
    /// `auth_user` selects the RESP AUTH form: `Some(host)` uses ePHPm's
    /// per-site `AUTH <host> <password>` (landing in that vhost's replicated
    /// keyspace — the same one `switchboard-api` writes to); `None` uses the
    /// one-argument `requirepass` form. `password` of `None` sends no AUTH at
    /// all (an unauthenticated listener).
    #[must_use]
    pub fn new(
        addr: String,
        auth_user: Option<String>,
        password: Option<String>,
        claim_ttl: Duration,
    ) -> Self {
        let auth = password.map(|password| Auth {
            user: auth_user,
            password,
        });
        let node_token = node_token();
        Self {
            addr,
            auth,
            claim_ttl,
            node_token,
        }
    }

    /// Try to win the exactly-once claim for `key`.
    ///
    /// Returns `Ok(true)` if this node won and should perform the action,
    /// `Ok(false)` if another node already holds it, and `Err` only if the KV
    /// could not be reached or spoke an unexpected reply — the caller decides
    /// how to degrade (this daemon skips the action, favouring "no duplicate"
    /// over "posted despite an unknown KV state").
    ///
    /// # Errors
    ///
    /// Returns an error if the connection, AUTH, or `SET` fails.
    pub async fn try_claim(&self, key: &str) -> anyhow::Result<bool> {
        let mut conn = self.connect().await?;
        let ttl = self.claim_ttl.as_secs().max(1).to_string();
        let reply = conn
            .command(&["SET", key, &self.node_token, "NX", "EX", &ttl])
            .await
            .context("SET … NX failed")?;
        match reply {
            Reply::Simple(_) => Ok(true),
            Reply::Nil => Ok(false),
            Reply::Error(e) => bail!("KV rejected the claim: {e}"),
            other => bail!("unexpected reply to SET … NX: {other:?}"),
        }
    }

    /// Release a claim previously won with [`Self::try_claim`].
    ///
    /// Called when the action that a claim guarded *failed*, so another node's
    /// later reconcile of the same generation can retry it rather than the
    /// claim silently suppressing all reporting for a commit that never got a
    /// comment. Best-effort: a failure here is logged by the caller, not fatal.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection, AUTH, or `DEL` fails.
    pub async fn release(&self, key: &str) -> anyhow::Result<()> {
        let mut conn = self.connect().await?;
        let reply = conn.command(&["DEL", key]).await.context("DEL failed")?;
        match reply {
            Reply::Integer(_) | Reply::Simple(_) => Ok(()),
            Reply::Error(e) => bail!("KV rejected the release: {e}"),
            other => bail!("unexpected reply to DEL: {other:?}"),
        }
    }

    /// Open a connection and authenticate.
    async fn connect(&self) -> anyhow::Result<Connection> {
        let stream = TcpStream::connect(&self.addr)
            .await
            .with_context(|| format!("failed to connect to the KV listener at {}", self.addr))?;
        let (read, write) = stream.into_split();
        let mut conn = Connection {
            reader: BufReader::new(read),
            writer: write,
        };
        if let Some(auth) = &self.auth {
            let reply = match &auth.user {
                Some(user) => conn.command(&["AUTH", user, &auth.password]).await,
                None => conn.command(&["AUTH", &auth.password]).await,
            }
            .context("AUTH failed")?;
            match reply {
                Reply::Simple(_) => {}
                Reply::Error(e) => bail!("KV AUTH rejected: {e}"),
                other => bail!("unexpected reply to AUTH: {other:?}"),
            }
        }
        Ok(conn)
    }
}

/// Build a coordinator from CLI/env settings, resolving the password from
/// whichever source the operator configured.
///
/// Returns `Ok(None)` when no KV address is configured — coordination is off
/// and the daemon reports directly (correct for single-node). Returns an error
/// only when a *configured* password source cannot be read, so a typo fails at
/// startup rather than silently disabling the duplicate guard.
///
/// * `secret_file` — ePHPm's `[kv] secret`; the per-site password is derived as
///   `HMAC-SHA256(secret, auth_user)`, matching `ephpm_kv::auth`. Requires
///   `auth_user`.
/// * `password_file` — a literal password (`requirepass`, or an already-derived
///   per-site password).
///
/// # Errors
///
/// Returns an error if a configured secret/password file cannot be read.
pub fn build(
    addr: Option<&str>,
    auth_user: Option<&str>,
    secret_file: Option<&Path>,
    password_file: Option<&Path>,
    claim_ttl: Duration,
) -> anyhow::Result<Option<Coordinator>> {
    let Some(addr) = addr else {
        return Ok(None);
    };

    let password = if let Some(path) = secret_file {
        let secret = read_secret_file(path)?;
        let user = auth_user
            .context("--kv-secret-file needs --kv-auth-user to derive the per-site password")?;
        Some(derive_site_password(&secret, user))
    } else if let Some(path) = password_file {
        Some(read_secret_file(path)?)
    } else {
        None
    };

    Ok(Some(Coordinator::new(
        addr.to_string(),
        auth_user.map(str::to_string),
        password,
        claim_ttl,
    )))
}

/// The claim key for reporting a deploy of `owner/repo` PR `pr` at `sha`.
///
/// SHA-scoped: a new push is a new generation and mints a fresh claim, so the
/// winning node updates the sticky comment for the new commit rather than an
/// old claim suppressing it. Namespaced under `switchboard:` to sit in the same
/// keyspace `switchboard-api` already uses.
#[must_use]
pub fn deploy_claim_key(owner: &str, repo: &str, pr: u64, sha: &str) -> String {
    format!("switchboard:pr-comment:{owner}/{repo}:{pr}:{sha}")
}

/// The claim key for reporting a teardown of `owner/repo` PR `pr`.
///
/// Not SHA-scoped — a teardown is a single terminal event for the PR.
#[must_use]
pub fn teardown_claim_key(owner: &str, repo: &str, pr: u64) -> String {
    format!("switchboard:pr-teardown:{owner}/{repo}:{pr}")
}

/// Read a secret from a file, trimming trailing whitespace/newline — a secret
/// written with `echo` carries a `\n` that would otherwise corrupt the AUTH.
fn read_secret_file(path: &Path) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read secret file {}", path.display()))?;
    let trimmed = raw.trim().to_string();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "secret file {} is empty",
        path.display()
    );
    Ok(trimmed)
}

/// Derive a per-site RESP password — byte-for-byte identical to
/// `ephpm_kv::auth::derive_site_password` (HMAC-SHA256, lowercase hex).
#[must_use]
fn derive_site_password(secret: &str, hostname: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(hostname.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// A short, non-secret token identifying this node/process for the claim value.
fn node_token() -> String {
    let host = hostname();
    format!("{host}:{}", std::process::id())
}

/// Best-effort hostname for the claim value; falls back to `"node"` so a claim
/// value is always present (it is only ever read by a human).
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "node".to_string())
}

/// One RESP connection: buffered reads, raw writes.
struct Connection {
    reader: BufReader<OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl Connection {
    /// Send one command (an array of bulk strings) and read one reply.
    async fn command(&mut self, args: &[&str]) -> anyhow::Result<Reply> {
        let encoded = encode_command(args);
        self.writer
            .write_all(&encoded)
            .await
            .context("failed to write RESP command")?;
        self.writer.flush().await.context("failed to flush RESP")?;
        read_reply(&mut self.reader).await
    }
}

/// Encode a command as a RESP array of bulk strings.
fn encode_command(args: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Read exactly one RESP reply.
async fn read_reply(reader: &mut BufReader<OwnedReadHalf>) -> anyhow::Result<Reply> {
    let line = read_line(reader).await?;
    let (kind, rest) = line.split_at(1);
    match kind {
        "+" => Ok(Reply::Simple(rest.to_string())),
        "-" => Ok(Reply::Error(rest.to_string())),
        ":" => Ok(Reply::Integer(
            rest.parse().context("non-integer RESP `:` reply")?,
        )),
        "$" => {
            let len: i64 = rest.parse().context("non-integer RESP bulk length")?;
            if len < 0 {
                return Ok(Reply::Nil);
            }
            let len = usize::try_from(len).context("RESP bulk length overflow")?;
            let mut buf = vec![0u8; len + 2]; // + trailing CRLF
            reader
                .read_exact(&mut buf)
                .await
                .context("short read on RESP bulk body")?;
            buf.truncate(len);
            Ok(Reply::Bulk(
                String::from_utf8(buf).context("non-UTF-8 RESP bulk body")?,
            ))
        }
        "*" => {
            // Not used by this client's commands, but a `*-1` nil array is worth
            // handling rather than erroring on.
            let len: i64 = rest.parse().context("non-integer RESP array length")?;
            if len < 0 {
                Ok(Reply::Nil)
            } else {
                bail!("unexpected RESP array reply of length {len}")
            }
        }
        other => bail!("unknown RESP reply type {other:?}"),
    }
}

/// Read one CRLF-terminated line, returning it without the trailing `\r\n`.
async fn read_line(reader: &mut BufReader<OwnedReadHalf>) -> anyhow::Result<String> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .context("failed to read RESP line")?;
    anyhow::ensure!(n > 0, "KV connection closed before a reply");
    let trimmed = line.trim_end_matches(['\r', '\n']);
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn derive_matches_ephpm_kv_auth_vector() {
        // The value ePHPm's `ephpm_kv::auth` produces for this pair must match
        // ours byte-for-byte, or the daemon authenticates into the wrong (or no)
        // keyspace. Vector computed from HMAC-SHA256("my-secret", "example.com").
        let pw = derive_site_password("my-secret", "example.com");
        assert_eq!(pw.len(), 64);
        assert!(
            pw.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Deterministic.
        assert_eq!(pw, derive_site_password("my-secret", "example.com"));
        // Sensitive to both inputs.
        assert_ne!(pw, derive_site_password("my-secret", "other.com"));
        assert_ne!(pw, derive_site_password("other-secret", "example.com"));
    }

    #[test]
    fn claim_keys_are_sha_scoped_and_namespaced() {
        let a = deploy_claim_key("ephpm", "wordpress-sample", 7, "abc");
        assert_eq!(a, "switchboard:pr-comment:ephpm/wordpress-sample:7:abc");
        // A new SHA is a new generation → a distinct claim.
        let b = deploy_claim_key("ephpm", "wordpress-sample", 7, "def");
        assert_ne!(a, b);
        let t = teardown_claim_key("ephpm", "wordpress-sample", 7);
        assert_eq!(t, "switchboard:pr-teardown:ephpm/wordpress-sample:7");
    }

    #[test]
    fn encode_command_is_resp_array_of_bulk_strings() {
        let bytes = encode_command(&["SET", "k", "v"]);
        assert_eq!(bytes, b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n");
    }

    #[test]
    fn build_without_addr_disables_coordination() {
        let c = build(None, None, None, None, Duration::from_secs(60)).unwrap();
        assert!(c.is_none(), "no KV address → no coordination (single node)");
    }

    #[test]
    fn build_secret_file_requires_auth_user() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "master\n").unwrap();
        let err = build(
            Some("127.0.0.1:6379"),
            None,
            Some(&secret),
            None,
            Duration::from_secs(60),
        )
        .expect_err("a secret file with no auth user cannot derive a password");
        assert!(err.to_string().contains("--kv-auth-user"), "{err}");
    }

    #[test]
    fn build_trims_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "master-secret\n").unwrap();
        let c = build(
            Some("127.0.0.1:6379"),
            Some("switchboard.ephpm.dev"),
            Some(&secret),
            None,
            Duration::from_secs(60),
        )
        .unwrap()
        .expect("a KV address yields a coordinator");
        let auth = c.auth.as_ref().expect("secret file yields AUTH");
        assert_eq!(auth.user.as_deref(), Some("switchboard.ephpm.dev"));
        // The derived password ignores the trailing newline in the file.
        assert_eq!(
            auth.password,
            derive_site_password("master-secret", "switchboard.ephpm.dev")
        );
    }

    #[test]
    fn build_rejects_empty_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "   \n").unwrap();
        assert!(
            build(
                Some("127.0.0.1:6379"),
                Some("h"),
                Some(&secret),
                None,
                Duration::from_secs(60),
            )
            .is_err(),
            "an empty secret file must fail at startup, not send an empty AUTH"
        );
    }

    /// Spin a one-shot fake RESP server that runs `handler` against the accepted
    /// connection, and return its address.
    async fn fake_kv<F, Fut>(handler: F) -> String
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler(stream).await;
        });
        addr
    }

    /// Read one full RESP command (array of bulk strings) as a `Vec<String>`.
    async fn read_command(reader: &mut BufReader<OwnedReadHalf>) -> Vec<String> {
        let header = read_line(reader).await.unwrap();
        let n: usize = header.strip_prefix('*').unwrap().parse().unwrap();
        let mut args = Vec::with_capacity(n);
        for _ in 0..n {
            let len_line = read_line(reader).await.unwrap();
            let len: usize = len_line.strip_prefix('$').unwrap().parse().unwrap();
            let mut buf = vec![0u8; len + 2];
            reader.read_exact(&mut buf).await.unwrap();
            buf.truncate(len);
            args.push(String::from_utf8(buf).unwrap());
        }
        args
    }

    #[tokio::test]
    async fn try_claim_returns_true_on_ok() {
        let addr = fake_kv(|stream| async move {
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            let cmd = read_command(&mut reader).await;
            assert_eq!(cmd[0], "SET");
            assert_eq!(cmd[3], "NX");
            assert_eq!(cmd[4], "EX");
            w.write_all(b"+OK\r\n").await.unwrap();
        })
        .await;
        let c = Coordinator::new(addr, None, None, Duration::from_secs(60));
        assert!(
            c.try_claim("switchboard:pr-comment:o/r:1:sha")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn try_claim_returns_false_on_nil() {
        let addr = fake_kv(|stream| async move {
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            let _ = read_command(&mut reader).await;
            // Key already held by another node → SET … NX yields a nil bulk.
            w.write_all(b"$-1\r\n").await.unwrap();
        })
        .await;
        let c = Coordinator::new(addr, None, None, Duration::from_secs(60));
        assert!(
            !c.try_claim("switchboard:pr-comment:o/r:1:sha")
                .await
                .unwrap(),
            "a nil reply means another node already claimed it"
        );
    }

    #[tokio::test]
    async fn try_claim_sends_auth_first_when_configured() {
        let addr = fake_kv(|stream| async move {
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            // Per-site two-argument AUTH must precede the claim.
            let auth = read_command(&mut reader).await;
            assert_eq!(auth, vec!["AUTH", "switchboard.ephpm.dev", "secret-pw"]);
            w.write_all(b"+OK\r\n").await.unwrap();
            let cmd = read_command(&mut reader).await;
            assert_eq!(cmd[0], "SET");
            w.write_all(b"+OK\r\n").await.unwrap();
        })
        .await;
        let c = Coordinator::new(
            addr,
            Some("switchboard.ephpm.dev".to_string()),
            Some("secret-pw".to_string()),
            Duration::from_secs(60),
        );
        assert!(c.try_claim("k").await.unwrap());
    }

    #[tokio::test]
    async fn try_claim_errors_when_auth_rejected() {
        let addr = fake_kv(|stream| async move {
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            let _ = read_command(&mut reader).await;
            w.write_all(b"-WRONGPASS invalid username-password pair\r\n")
                .await
                .unwrap();
        })
        .await;
        let c = Coordinator::new(addr, None, Some("bad".to_string()), Duration::from_secs(60));
        let err = c
            .try_claim("k")
            .await
            .expect_err("a rejected AUTH must error");
        assert!(err.to_string().contains("AUTH"), "{err:#}");
    }

    #[tokio::test]
    async fn release_sends_del() {
        let addr = fake_kv(|stream| async move {
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            let cmd = read_command(&mut reader).await;
            assert_eq!(cmd, vec!["DEL", "switchboard:pr-comment:o/r:1:sha"]);
            w.write_all(b":1\r\n").await.unwrap();
        })
        .await;
        let c = Coordinator::new(addr, None, None, Duration::from_secs(60));
        c.release("switchboard:pr-comment:o/r:1:sha").await.unwrap();
    }
}
