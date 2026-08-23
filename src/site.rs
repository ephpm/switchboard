//! The canonical site key — the single identity every per-tenant artifact is
//! derived from, and the one value that MUST agree byte-for-byte with ePHPm's
//! own derivation.
//!
//! ePHPm resolves a request's tenant exactly once, in `Router::resolve_site`
//! (`crates/ephpm-server/src/router.rs`): it normalizes the `Host` header
//! (strip port and trailing dot, lowercase) and removes
//! `[server] sites_domain_suffix`, then validates the result against
//! `is_valid_site_key`. That key names the vhost directory under `sites_dir`,
//! selects the per-site database `<dir>/<key>.db`, keys the per-vhost temp/
//! session root, and names the operator override file `<key>.toml`.
//!
//! The daemon writes those same artifacts, so it must land on the same key.
//! Rather than invent a second derivation (the exact anti-pattern that produced
//! ePHPm issues #290/#291 — one tenant reached by two names splitting into two
//! databases), this module ports ePHPm's derivation. The preview host is always
//! `<label>.<preview_domain>`; the key is what ePHPm strips that host down to.

/// Normalize a `Host` value the way ePHPm's `normalize_host_key` does: take the
/// portion before any `:` (port), trim a trailing `.`, lowercase.
fn normalize_host_key(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Whether `key` is a valid ePHPm site key — a **port of `is_valid_site_key`**
/// from `crates/ephpm-server/src/router.rs`, kept identical so a key this
/// daemon accepts is one ePHPm will also accept (and vice versa).
///
/// A key is valid only if it is a non-empty (≤255-byte) sequence of DNS-style
/// labels drawn from `[a-z0-9._-]` with no empty label. The "no empty label"
/// test rejects a leading/trailing dot and any `..`, so `sites_dir.join(key)`
/// can only ever name a direct child.
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

/// Derive the canonical site key for a preview host, mirroring
/// `Router::resolve_site`.
///
/// `preview_host` is `<label>.<preview_domain>`; `sites_domain_suffix` is the
/// operator's `[server] sites_domain_suffix` (which ePHPm requires to begin
/// with a dot — issue #397). When the suffix is set and strips cleanly to a
/// still-valid key, that shorter key is used (matching a vhost directory named
/// by the bare label); otherwise the full normalized host is the key.
///
/// Returns `None` when the host does not normalize to a valid site key at all —
/// such a request would get no per-site database in ePHPm either, so there is
/// nothing to provision.
#[must_use]
pub fn canonical_site_key(preview_host: &str, sites_domain_suffix: Option<&str>) -> Option<String> {
    let clean = normalize_host_key(preview_host);
    if !is_valid_site_key(&clean) {
        return None;
    }

    if let Some(suffix) = sites_domain_suffix {
        let suffix = suffix.to_ascii_lowercase();
        if let Some(stripped) = clean.strip_suffix(&suffix)
            && is_valid_site_key(stripped)
        {
            return Some(stripped.to_string());
        }
    }

    Some(clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_host_is_the_key_when_no_suffix() {
        // The default deployment: `sites_domain_suffix` unset, so ePHPm names
        // the vhost directory with the full FQDN and the daemon must too.
        assert_eq!(
            canonical_site_key("ephpm-wordpress-sample-pr-7.preview.ephpm.dev", None).as_deref(),
            Some("ephpm-wordpress-sample-pr-7.preview.ephpm.dev")
        );
    }

    #[test]
    fn suffix_strips_to_bare_label() {
        // With the suffix configured (leading dot, as ePHPm requires), the key
        // is the bare label — a vhost directory named `…-pr-7`.
        assert_eq!(
            canonical_site_key(
                "ephpm-wordpress-sample-pr-7.preview.ephpm.dev",
                Some(".preview.ephpm.dev")
            )
            .as_deref(),
            Some("ephpm-wordpress-sample-pr-7")
        );
    }

    #[test]
    fn suffix_case_insensitive_and_normalizes_host() {
        // Host casing and a trailing dot must not change the derived key.
        assert_eq!(
            canonical_site_key(
                "ePHPm-App-pr-1.Preview.ePHPm.Dev.",
                Some(".preview.ephpm.dev")
            )
            .as_deref(),
            Some("ephpm-app-pr-1")
        );
    }

    #[test]
    fn non_matching_suffix_keeps_full_host() {
        // A host that does not end in the suffix falls through to the full key,
        // exactly as ePHPm's `strip_suffix(...).filter(is_valid)` does.
        assert_eq!(
            canonical_site_key("app-pr-1.other.example", Some(".preview.ephpm.dev")).as_deref(),
            Some("app-pr-1.other.example")
        );
    }

    #[test]
    fn suffix_equal_to_host_does_not_yield_empty_key() {
        // Stripping the suffix off the apex host leaves the empty string, which
        // is not a valid key — ePHPm discards it and so must the daemon (issue
        // #397). The full host stands as the key instead.
        let host = "preview.ephpm.dev";
        assert_eq!(
            canonical_site_key(host, Some(".preview.ephpm.dev")).as_deref(),
            Some("preview.ephpm.dev")
        );
    }

    #[test]
    fn invalid_host_is_rejected() {
        assert_eq!(canonical_site_key("", None), None);
        assert_eq!(canonical_site_key("a//b", None), None);
        assert_eq!(
            canonical_site_key("UPPER_is_lowered.only", None).as_deref(),
            Some("upper_is_lowered.only")
        );
    }

    #[test]
    fn is_valid_site_key_matches_ephpm_rules() {
        assert!(is_valid_site_key("app-pr-1"));
        assert!(is_valid_site_key("app-pr-1.preview.ephpm.dev"));
        assert!(!is_valid_site_key(""));
        assert!(!is_valid_site_key(".leading"));
        assert!(!is_valid_site_key("trailing."));
        assert!(!is_valid_site_key("a..b"));
        assert!(!is_valid_site_key("has/slash"));
        assert!(!is_valid_site_key("UPPER"));
    }
}
