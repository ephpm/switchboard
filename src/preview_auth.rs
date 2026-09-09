//! The control-plane half of the preview access gate (ephpm#487/#491).
//!
//! ePHPm ships the *enforcement*: a per-site `preview-gate` middleware that turns
//! on when a resolved vhost's override file carries a `[preview_auth]` section,
//! redirects unauthenticated browsers to a GitHub-OAuth login, and — fail-closed
//! — takes the site out of service (503) rather than serving it ungated when the
//! section is present but unusable. It also *verifies and revokes* time-limited
//! shareable-URL capability tokens. What ePHPm deliberately does **not** do is
//! decide *which* previews to gate, *write* the section, or *mint* share links.
//! That is switchboard's job, and it is this module.
//!
//! The contract this implements is `site/content/roadmap/preview-access-gate.md`
//! in `ephpm/ephpm`. Three pieces live here:
//!
//! 1. **Gating policy** ([`should_gate`]) — a private repo's preview is *always*
//!    gated; a public repo's is gated only when the operator asks
//!    (`--gate-public-previews`). A private preview that comes up ungated is the
//!    exact exposure the feature exists to prevent, so every path that could gate
//!    silently-not-happen is turned into a hard deploy failure by the caller (see
//!    [`crate::deployer`]).
//!
//! 2. **Session-secret resolution** ([`resolve_session_secret`]) — the override
//!    file carries a *reference* (`env:NAME` / `file:/abs` / a literal), never the
//!    key itself, because that file is tenant-adjacent. switchboard resolves the
//!    same reference ePHPm's issuer and gate resolve, both to verify a gated
//!    deploy *can* come up (fail closed if it can't) and to obtain the bytes it
//!    signs share tokens with. The resolution rules and the ≥ 32-byte floor
//!    mirror ePHPm's `site_overrides::resolve_secret` exactly.
//!
//! 3. **Share-token minting** ([`mint_share_token`], [`generate_jti`]) — the
//!    wire-compatible mirror of `ephpm_middleware_builtins::preview_gate::
//!    mint_share_token`. A `via:"share"` HS256 capability, per-preview (`site`
//!    claim), short-lived (`exp`), individually revocable (`jti`) and
//!    epoch-revocable (`iat`). switchboard mints because it already holds the
//!    shared secret; the token is a bearer capability and must be treated as one.
//!
//! Plus [`derive_site_kv_password`], the per-site RESP credential switchboard
//! uses to write the revocation keys on teardown (see [`crate::kv`]).

use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The issuer's default login endpoint, under the router-carved-out
/// `/_ephpm/auth/` namespace. Written verbatim into `[preview_auth] login_url`.
pub const DEFAULT_LOGIN_URL: &str = "/_ephpm/auth/github/login";

/// The default query parameter the gate reads a share token from
/// (`?ephpm_share=<token>`). ePHPm's `preview-gate` `share_param` default; we
/// mirror it so an unconfigured override and switchboard agree on the link shape.
pub const DEFAULT_SHARE_PARAM: &str = "ephpm_share";

/// Minimum resolved session-secret length, in bytes.
///
/// ePHPm's `site_overrides.rs` (`MIN_SESSION_SECRET`) takes a gated preview out
/// of service (503) when the resolved secret is shorter than this. switchboard
/// enforces the same floor *before* writing a gated override, so a too-short key
/// fails the deploy loudly rather than shipping a preview ePHPm will 503.
pub const MIN_SESSION_SECRET_LEN: usize = 32;

/// Whether this preview must be gated.
///
/// The whole policy in one line: a **private** repo's preview is always gated —
/// its code is not world-readable, so its preview must not be either. A
/// **public** repo's preview is ungated by default (the code is already public)
/// but the operator can gate everything with `--gate-public-previews`, e.g. to
/// keep unreleased work-in-progress off the open internet.
#[must_use]
pub fn should_gate(repo_is_private: bool, gate_public_previews: bool) -> bool {
    repo_is_private || gate_public_previews
}

/// Resolve a `session_secret` **reference** to the raw key bytes, applying
/// ePHPm's own rules so the two processes derive byte-identical secrets.
///
/// Accepted forms (mirroring `site_overrides::resolve_secret`):
/// * `env:NAME` — read environment variable `NAME`;
/// * `file:/abs/path` — read the file;
/// * anything else — a literal (discouraged; the reference should point at a
///   secret, not be one, since the same string is written into the tenant-adjacent
///   override file).
///
/// The resolved value is trimmed and must be **non-empty** and at least
/// [`MIN_SESSION_SECRET_LEN`] bytes — the same floor the ePHPm gate enforces. The
/// returned bytes are exactly what ePHPm signs/verifies with, so a share token
/// switchboard mints with them verifies in the gate.
///
/// # Errors
///
/// Returns an error when an `env:`/`file:` reference cannot be resolved, when the
/// resolved value is empty, or when it is shorter than the floor. A gated deploy
/// treats any of these as fatal (fail closed) rather than shipping an open
/// preview.
pub fn resolve_session_secret(reference: &str) -> anyhow::Result<Vec<u8>> {
    let reference = reference.trim();
    anyhow::ensure!(
        !reference.is_empty(),
        "preview-auth session secret reference is empty — set --preview-session-secret-ref \
         (e.g. env:EPHPM_PREVIEW_SESSION_SECRET)"
    );

    let resolved = if let Some(name) = reference.strip_prefix("env:") {
        let name = name.trim();
        anyhow::ensure!(
            !name.is_empty(),
            "session secret reference {reference:?}: env var name is empty"
        );
        std::env::var(name).with_context(|| {
            format!(
                "session secret reference {reference:?}: environment variable {name} is not set"
            )
        })?
    } else if let Some(path) = reference.strip_prefix("file:") {
        let path = path.trim();
        anyhow::ensure!(
            !path.is_empty(),
            "session secret reference {reference:?}: file path is empty"
        );
        std::fs::read_to_string(path).with_context(|| {
            format!("session secret reference {reference:?}: cannot read {path}")
        })?
    } else {
        // A literal secret. ePHPm accepts this (discouraged); we do too, so the
        // resolution rule matches exactly, but the reference SHOULD be an env:/file:.
        reference.to_string()
    };

    let resolved = resolved.trim();
    anyhow::ensure!(
        !resolved.is_empty(),
        "preview-auth session secret resolved from {reference:?} is empty"
    );
    anyhow::ensure!(
        resolved.len() >= MIN_SESSION_SECRET_LEN,
        "preview-auth session secret resolved from {reference:?} is {} bytes; ePHPm requires \
         at least {MIN_SESSION_SECRET_LEN} bytes and would take the preview out of service (503)",
        resolved.len()
    );
    Ok(resolved.as_bytes().to_vec())
}

/// Mint a `via:"share"` capability token — the wire-compatible mirror of
/// `ephpm_middleware_builtins::preview_gate::mint_share_token`.
///
/// The token is a stateless HS256 JWT with exactly five claims, in the shape the
/// ePHPm gate verifies through the *same* `Hs256Policy` an OAuth session uses
/// (there is deliberately no second verifier — issue #396):
///
/// * `site` — the preview's **canonical site key**, so the link opens exactly one
///   preview (the gate checks it as `expected_site`);
/// * `via` — the literal `"share"`, which is what switches on the extra
///   revocation checks (a normal OAuth session pays nothing);
/// * `jti` — a unique id so one link can be revoked (`preview:share:revoked:<jti>`);
/// * `iat` — issue time, which the per-site epoch (`preview:share:epoch`) is
///   compared against for revoke-all;
/// * `exp` — expiry; the gate enforces only that it exists and is in the future,
///   so the minter keeps it short and a leaked link self-heals.
///
/// `secret` must be the bytes [`resolve_session_secret`] returned — the same key
/// the gate resolved — or the token will not verify. The signature is
/// `HMAC-SHA256(secret, base64url(header) + "." + base64url(payload))`, all
/// base64url-**unpadded**, header the fixed bytes `{"alg":"HS256","typ":"JWT"}`.
#[must_use]
pub fn mint_share_token(secret: &[u8], site: &str, jti: &str, iat: u64, exp: u64) -> String {
    let claims = serde_json::json!({
        "site": site,
        "via": "share",
        "jti": jti,
        "iat": iat,
        "exp": exp,
    });
    // The header is a fixed literal on the ePHPm side (not re-serialised from a
    // struct), so reproduce those exact bytes.
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("share claims serialise"));

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(header_b64.as_bytes());
    mac.update(b".");
    mac.update(payload_b64.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{header_b64}.{payload_b64}.{sig}")
}

/// A fresh, unguessable `jti` for a share token: 16 CSPRNG bytes, lowercase hex.
///
/// Uniqueness is what `jti` is for — it lets one link be revoked without touching
/// the others. Unpredictability is a bonus (the HMAC already makes the token
/// unforgeable), but drawing from the OS CSPRNG costs nothing and means a `jti`
/// can never collide or be pre-computed.
#[must_use]
pub fn generate_jti() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG is available");
    hex::encode(bytes)
}

/// The full shareable URL to hand out: `<preview-url>/?<share_param>=<token>`.
///
/// The token travels in the query string exactly as the gate reads it; the
/// signing secret never appears — only the (bearer) token does.
#[must_use]
pub fn share_url(preview_url: &str, share_param: &str, token: &str) -> String {
    format!(
        "{}/?{share_param}={token}",
        preview_url.trim_end_matches('/')
    )
}

/// Derive the per-site KV RESP password for `site`, mirroring
/// `ephpm_kv::auth::derive_site_password`: lowercase-hex
/// `HMAC-SHA256(key = kv_secret, msg = site)`.
///
/// This is the password switchboard authenticates the revocation writes with
/// (`AUTH <site> <derived>`), which scopes the RESP connection to that vhost's
/// own KV keyspace — the same store the gate reads the revocation keys from.
/// `kv_secret` must be ePHPm's `[kv] secret` (the operator-set, deterministic
/// value), or the derived password will not match.
#[must_use]
pub fn derive_site_kv_password(kv_secret: &str, site: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(kv_secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(site.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── gating policy ───────────────────────────────────────────────────

    #[test]
    fn private_repos_are_always_gated() {
        assert!(
            should_gate(true, false),
            "a private repo must be gated by default"
        );
        assert!(
            should_gate(true, true),
            "a private repo is gated regardless of the public knob"
        );
    }

    #[test]
    fn public_repos_are_ungated_unless_the_operator_opts_in() {
        assert!(
            !should_gate(false, false),
            "a public repo is ungated by default"
        );
        assert!(
            should_gate(false, true),
            "--gate-public-previews gates public repos too"
        );
    }

    // ── session-secret resolution ─────────────────────────────────────────

    #[test]
    fn env_reference_resolves_and_enforces_the_floor() {
        // A unique var name so parallel tests don't collide on the environment.
        let name = "EPHPM_TEST_PREVIEW_SECRET_ENV_OK";
        // SAFETY: single-threaded within this test's scope; the name is unique.
        unsafe { std::env::set_var(name, "0123456789abcdef0123456789abcdef") };
        let bytes = resolve_session_secret(&format!("env:{name}")).unwrap();
        assert_eq!(bytes.len(), 32);
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn a_short_secret_is_refused_so_the_deploy_fails_closed() {
        let name = "EPHPM_TEST_PREVIEW_SECRET_ENV_SHORT";
        unsafe { std::env::set_var(name, "too-short") };
        let err = resolve_session_secret(&format!("env:{name}"))
            .expect_err("a secret below the 32-byte floor must be refused");
        assert!(err.to_string().contains("at least"), "{err}");
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn an_unset_env_reference_is_an_error_not_an_empty_secret() {
        let err = resolve_session_secret("env:EPHPM_TEST_DEFINITELY_UNSET_VAR_XYZ")
            .expect_err("an unresolvable reference must fail, never resolve to empty");
        assert!(err.to_string().contains("is not set"), "{err}");
    }

    #[test]
    fn file_reference_is_read_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        // Trailing newline is trimmed, exactly as ePHPm trims it.
        std::fs::write(&path, "0123456789abcdef0123456789abcdef\n").unwrap();
        let bytes = resolve_session_secret(&format!("file:{}", path.display())).unwrap();
        assert_eq!(bytes, b"0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn empty_reference_is_refused() {
        assert!(resolve_session_secret("   ").is_err());
    }

    // ── share-token minting: wire compatibility ───────────────────────────

    /// The token must be a three-segment JWT whose header decodes to the exact
    /// bytes ePHPm's verifier expects (`alg:HS256`) and whose payload carries the
    /// five claims with the right values. This is the shape check the contract's
    /// test asks for.
    #[test]
    fn minted_token_has_the_via_share_shape_for_the_site() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let token = mint_share_token(secret, "app-pr-1", "deadbeef", 1000, 2000);

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWT is header.payload.signature");

        let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        assert_eq!(header, br#"{"alg":"HS256","typ":"JWT"}"#);

        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["site"], "app-pr-1", "per-preview binding");
        assert_eq!(
            claims["via"], "share",
            "distinguishes a share link from an OAuth session"
        );
        assert_eq!(claims["jti"], "deadbeef");
        assert_eq!(claims["iat"], 1000);
        assert_eq!(claims["exp"], 2000);
    }

    /// The signature must be the HMAC the gate recomputes: verify it the way
    /// `Hs256Policy::verify` does — HMAC over `header_b64.payload_b64`.
    #[test]
    fn minted_token_signature_verifies_against_the_secret() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let token = mint_share_token(secret, "site", "jti1", 1, 999_999_999);
        let (signed, sig_b64) = token.rsplit_once('.').unwrap();

        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(signed.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        assert_eq!(
            sig_b64, expected,
            "the signature must be HMAC-SHA256 over header.payload"
        );

        // A different secret must NOT produce the same signature.
        let other = mint_share_token(
            b"ffffffffffffffffffffffffffffffff",
            "site",
            "jti1",
            1,
            999_999_999,
        );
        assert_ne!(other, token, "a different key must yield a different token");
    }

    #[test]
    fn jti_is_unique_and_hex() {
        let a = generate_jti();
        let b = generate_jti();
        assert_eq!(a.len(), 32, "16 bytes hex-encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two draws must differ");
    }

    #[test]
    fn share_url_carries_only_the_token() {
        let url = share_url(
            "https://pr-1.app.preview.ephpm.dev",
            DEFAULT_SHARE_PARAM,
            "tok.en.sig",
        );
        assert_eq!(
            url,
            "https://pr-1.app.preview.ephpm.dev/?ephpm_share=tok.en.sig"
        );
        // A URL with a port and a trailing slash normalises the same way.
        let url = share_url("https://h:8084/", "ephpm_share", "t");
        assert_eq!(url, "https://h:8084/?ephpm_share=t");
    }

    // ── KV password derivation ────────────────────────────────────────────

    /// Must match `ephpm_kv::auth::derive_site_password`: lowercase-hex
    /// HMAC-SHA256(key=secret, msg=site). Pinned against an independently
    /// computed value so a refactor that changes the derivation is caught.
    #[test]
    fn kv_password_is_hmac_sha256_hex_of_the_site() {
        let derived = derive_site_kv_password("master-secret", "app-pr-1");
        // Recompute the reference the same way and compare — 64 lowercase hex chars.
        let mut mac = HmacSha256::new_from_slice(b"master-secret").unwrap();
        mac.update(b"app-pr-1");
        assert_eq!(derived, hex::encode(mac.finalize().into_bytes()));
        assert_eq!(derived.len(), 64);
        assert!(
            derived
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn kv_password_is_site_scoped() {
        assert_ne!(
            derive_site_kv_password("s", "app-pr-1"),
            derive_site_kv_password("s", "app-pr-2"),
            "each site must get a distinct password"
        );
    }
}
