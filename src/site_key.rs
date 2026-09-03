//! The **canonical site key** — switchboard's copy of ePHPm's host→vhost
//! derivation.
//!
//! Every per-site artifact this daemon creates or removes is named by one
//! string, and that string is chosen by ePHPm, not by us:
//!
//! | Artifact | Path |
//! |---|---|
//! | vhost directory | `<sites_dir>/<key>/` |
//! | per-site database | `<db.sqlite.dir>/<key>.db` |
//! | document-root override | `<site_overrides_dir>/<key>.toml` |
//!
//! If our key disagrees with ePHPm's, nothing errors: the preview is
//! provisioned into a directory nobody serves, or the override is filed under a
//! name nobody reads. Both fail *silently*, which is why this derivation is its
//! own module with its own tests rather than an assumption spread across the
//! deploy path.
//!
//! # The rule (ePHPm `Router::resolve_site`, `crates/ephpm-server/src/router.rs`)
//!
//! 1. Normalize the `Host` header: strip the port, strip a trailing dot,
//!    lowercase ([`normalize_host_key`]).
//! 2. If `[server] sites_domain_suffix` is configured and the normalized host
//!    ends with it, strip it. The remainder is a *candidate* key and must pass
//!    [`is_valid_site_key`] in its own right (ePHPm #397 — a dotless suffix
//!    otherwise lets a host strip to the empty string, whose `sites_dir.join("")`
//!    is `sites_dir` itself).
//! 3. ePHPm looks up the stripped candidate **first**, then the literal
//!    normalized host. Whichever names an existing directory under `sites_dir`
//!    wins.
//!
//! Because the daemon creates exactly one of those two directories, step 3
//! collapses to "create the one ePHPm tries first that we can name": the
//! stripped candidate when a suffix is configured, the full host when it is not.
//! That is [`site_key`].
//!
//! # Why this used to be implicit, and why that was a trap
//!
//! Before this module the deploy simply used the preview *label* as the
//! directory name, with a comment noting that ePHPm "strips its
//! `sites_domain_suffix`". That is only true on a node where the suffix is
//! actually configured — which the operator had to know, and which nothing here
//! validated or even recorded (switchboard#13). On a node without it the key is
//! the full FQDN, the label-named directory is never resolved, and per ePHPm's
//! fail-closed rule the request gets no per-site database and no `DB_*`
//! credentials. Making the suffix an explicit, validated input means switchboard
//! is correct under **both** node configurations instead of one.

/// Normalize a `Host` header value the way ePHPm's `normalize_host_key` does:
/// drop the port, drop a trailing dot, lowercase.
///
/// This is only *half* of a tenant's identity — it does not strip the domain
/// suffix, so it is not on its own a site key. See [`site_key`].
#[must_use]
pub fn normalize_host_key(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Whether a **normalized** host key is one ePHPm will join onto `sites_dir`.
///
/// Mirrors ePHPm's `is_valid_site_key` (issue #275): a non-empty sequence of
/// DNS-style labels drawn from `[a-z0-9._-]` with no empty label, at most 255
/// bytes. The "no empty label" test is what rejects `.`, `..`, `a..b` and
/// leading/trailing dots in one go; `/`, `\`, `:` and NUL are outside the
/// charset entirely.
///
/// A key that fails this is one ePHPm will never resolve, so provisioning under
/// it would be writing into a directory nobody serves.
#[must_use]
pub fn is_valid_site_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 255 {
        return false;
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
    {
        return false;
    }
    if key.split('.').any(str::is_empty) {
        return false;
    }
    true
}

/// The canonical site key for a preview host.
///
/// `host` is the full preview hostname (`<label>.<preview-domain>`).
/// `sites_domain_suffix` is ePHPm's `[server] sites_domain_suffix` as
/// configured **on the node this daemon provisions**, or `None` when that node
/// has no suffix configured.
///
/// # Errors
///
/// Returns an error when the host does not normalize to something ePHPm would
/// accept as a vhost directory name. Failing loudly here is deliberate: the
/// alternative is provisioning a preview ePHPm will never resolve.
pub fn site_key(host: &str, sites_domain_suffix: Option<&str>) -> anyhow::Result<String> {
    let clean = normalize_host_key(host);
    anyhow::ensure!(
        is_valid_site_key(&clean),
        "preview host {host:?} does not normalize to a valid ePHPm site key \
         (expected DNS-style labels from [a-z0-9._-])"
    );

    // ePHPm tries the suffix-stripped candidate before the literal host, and
    // discards it unless it is a valid key in its own right (#397).
    // Written as nested `if let`s rather than a let-chain: let-chains need
    // Rust 1.88 and this crate's MSRV is 1.85 (CI pins a 1.85 `cargo check`).
    if let Some(suffix) = sites_domain_suffix {
        if let Some(stripped) = clean.strip_suffix(suffix) {
            if is_valid_site_key(stripped) {
                return Ok(stripped.to_string());
            }
        }
    }

    Ok(clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUFFIX: Option<&str> = Some(".preview.ephpm.dev");

    /// The shape the live preview cluster runs: ePHPm has the suffix
    /// configured, so the key — and therefore the vhost directory — is the
    /// bare label. Verified against the running cluster: `Host:` the full FQDN
    /// and `Host:` the bare label both resolve the same vhost, which is only
    /// possible when the directory is named by the stripped key.
    #[test]
    fn suffix_configured_yields_the_bare_label() {
        assert_eq!(
            site_key("ephpm-wordpress-sample-pr-3.preview.ephpm.dev", SUFFIX).unwrap(),
            "ephpm-wordpress-sample-pr-3"
        );
    }

    /// switchboard#13's shape: a node whose `ephpm.toml` sets no
    /// `sites_domain_suffix`. ePHPm's key is then the full host, so that is
    /// what the vhost directory must be called — naming it by the bare label
    /// (the old behaviour) is exactly the silent miss the issue described.
    #[test]
    fn no_suffix_yields_the_full_host() {
        assert_eq!(
            site_key("ephpm-wordpress-sample-pr-3.preview.ephpm.dev", None).unwrap(),
            "ephpm-wordpress-sample-pr-3.preview.ephpm.dev"
        );
    }

    /// A suffix that does not match the host is not a partial strip — ePHPm
    /// falls back to the literal host and so must we.
    #[test]
    fn non_matching_suffix_falls_back_to_the_full_host() {
        assert_eq!(
            site_key("app.pr.example.com", Some(".preview.ephpm.dev")).unwrap(),
            "app.pr.example.com"
        );
    }

    /// ePHPm #397. A dotless suffix lets a host strip to the empty string, and
    /// `sites_dir.join("")` is `sites_dir` itself — one vhost whose document
    /// root is the entire fleet. ePHPm discards such a candidate; so do we,
    /// falling back to the literal host rather than inventing an empty key.
    #[test]
    fn suffix_stripping_to_empty_is_discarded() {
        assert_eq!(
            site_key("preview.ephpm.dev", Some("preview.ephpm.dev")).unwrap(),
            "preview.ephpm.dev"
        );
    }

    #[test]
    fn host_is_normalized_before_the_key_is_derived() {
        // Port, trailing dot and case all normalize away — the same three
        // transforms ePHPm's `normalize_host_key` applies.
        assert_eq!(
            site_key("EPHPM-My-Blog-PR-42.Preview.EPHPM.dev.:8443", SUFFIX).unwrap(),
            "ephpm-my-blog-pr-42"
        );
    }

    #[test]
    fn traversal_hosts_are_refused_rather_than_joined() {
        for bad in [
            "../../etc",
            "..",
            ".",
            "a//b",
            "a\\b",
            "",
            "a..b",
            ".lead",
            "a b",
            "a%2e",
        ] {
            assert!(
                site_key(bad, SUFFIX).is_err(),
                "{bad:?} must not produce a site key"
            );
        }
    }

    /// A trailing dot is the DNS root label, not a traversal: `blog.` and
    /// `blog` are the same name and ePHPm normalizes them to the same key.
    /// Refusing it here would 404 a request ePHPm serves.
    #[test]
    fn a_trailing_dot_normalizes_away_rather_than_being_refused() {
        assert_eq!(site_key("blog.", None).unwrap(), "blog");
    }

    #[test]
    fn site_key_validity_matches_ephpm_allowlist() {
        for good in ["blog", "a-b_c.d", "ephpm-repo-pr-1.preview.ephpm.dev"] {
            assert!(is_valid_site_key(good), "{good:?} should be valid");
        }
        for bad in [
            "", ".", "..", "a..b", ".a", "a.", "A", "a b", "a/b", "a:b", "a%b",
        ] {
            assert!(!is_valid_site_key(bad), "{bad:?} should be invalid");
        }
        assert!(!is_valid_site_key(&"a".repeat(256)));
    }
}
