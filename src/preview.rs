//! Preview host naming.
//!
//! The **label** is authoritative and comes from switchboard-api in the job
//! file (`preview.label`); the daemon uses it verbatim and only appends the
//! configured preview domain — see [`preview_host`]. One producer of the
//! primary key means the API and the daemon cannot drift into disagreeing about
//! which directory a PR maps to (the reason `preview_label` was ported to PHP
//! and moved out of this crate's request path).
//!
//! [`preview_label`] is retained **only as a cross-implementation guard**: it is
//! not called on the deploy path. switchboard-api's `PreviewLabel` is a port of
//! it, and that suite asserts the same expected values, so if either side ever
//! changes the algorithm one of the two test suites fails. Deleting it here
//! would remove the Rust half of that guard.

/// The preview hostname for a job: the authoritative label joined to the
/// configured preview domain. The daemon supplies only the domain.
#[must_use]
pub fn preview_host(label: &str, preview_domain: &str) -> String {
    format!("{label}.{preview_domain}")
}

/// Maximum length of a single DNS label (RFC 1035).
#[cfg(test)]
const MAX_LABEL: usize = 63;
/// Number of hex characters of the identity hash appended on collision/overflow.
#[cfg(test)]
const HASH_LEN: usize = 6;

/// Normalize an arbitrary string into a DNS-label-safe form: lowercase, only
/// `[a-z0-9-]`, with repeated `-` collapsed and leading/trailing `-` trimmed.
#[cfg(test)]
fn sanitize_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let c = ch.to_ascii_lowercase();
        let mapped = if c.is_ascii_alphanumeric() { c } else { '-' };
        if mapped == '-' {
            if !prev_dash {
                out.push('-');
            }
            prev_dash = true;
        } else {
            out.push(mapped);
            prev_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

/// First [`HASH_LEN`] hex chars of `sha256("owner/repo#N")` — a stable,
/// collision-resistant disambiguator tied to the exact (pre-sanitization)
/// identity, so two identities that sanitize alike still get distinct hosts.
#[cfg(test)]
fn identity_hash(owner: &str, repo: &str, number: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{owner}/{repo}#{number}").as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    hex[..HASH_LEN].to_string()
}

/// Build the single DNS label for a PR preview host: `<owner>-<repo>-pr-<N>`,
/// sanitized. If sanitization changed the raw identity (uppercase/invalid
/// chars) or the label exceeds [`MAX_LABEL`], append `-<hash>` (truncating the
/// base so the whole label fits and never ends in `-`). Otherwise the
/// human-readable label is used verbatim.
///
/// **Not called on the deploy path** — the job file's `preview.label` is
/// authoritative. This exists as the Rust half of the cross-implementation
/// guard against switchboard-api's `PreviewLabel::build`, so it is compiled
/// only under `cfg(test)`; the guard is the test that pins the shared values.
#[cfg(test)]
#[must_use]
fn preview_label(owner: &str, repo: &str, number: u64) -> String {
    let raw = format!("{owner}-{repo}-pr-{number}");
    let sanitized = sanitize_label(&raw);

    // Verbatim only when nothing was lost to sanitization and it fits.
    if sanitized == raw && sanitized.len() <= MAX_LABEL {
        return sanitized;
    }

    let hash = identity_hash(owner, repo, number);
    let max_base = MAX_LABEL - HASH_LEN - 1; // room for '-' + hash
    let mut base = sanitized;
    if base.len() > max_base {
        base.truncate(max_base);
    }
    let base = base.trim_end_matches('-');
    format!("{base}-{hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_host_appends_domain() {
        assert_eq!(
            preview_host("ephpm-my-blog-pr-42", "preview.ephpm.dev"),
            "ephpm-my-blog-pr-42.preview.ephpm.dev"
        );
    }

    #[test]
    fn preview_label_verbatim_when_clean() {
        assert_eq!(
            preview_label("ephpm", "wordpress-sample", 1),
            "ephpm-wordpress-sample-pr-1"
        );
    }

    #[test]
    fn preview_label_sanitized_and_hashed() {
        // Uppercase + underscore force sanitization, so a hash is appended.
        let label = preview_label("ephpm", "My_Repo", 1);
        let hash = identity_hash("ephpm", "My_Repo", 1);
        assert_eq!(label, format!("ephpm-my-repo-pr-1-{hash}"));
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );
    }

    #[test]
    fn preview_label_long_repo_truncated_and_hashed() {
        let long_repo = "a".repeat(100);
        let label = preview_label("ephpm", &long_repo, 7);
        assert!(label.len() <= MAX_LABEL, "label too long: {}", label.len());
        let hash = identity_hash("ephpm", &long_repo, 7);
        assert!(label.ends_with(&format!("-{hash}")));
        assert!(!label.trim_end_matches(&format!("-{hash}")).ends_with('-'));
    }

    #[test]
    fn preview_label_collision_safe() {
        let a = preview_label("ephpm", "My-Repo", 1);
        let b = preview_label("ephpm", "my_repo", 1);
        assert!(a.starts_with("ephpm-my-repo-pr-1-"));
        assert!(b.starts_with("ephpm-my-repo-pr-1-"));
        assert_ne!(a, b, "distinct identities collided: {a}");
    }

    /// Cross-implementation guard: these exact values are asserted by
    /// switchboard-api's `PreviewLabelTest`. If this changes, that suite must
    /// change too (and vice versa) — that is the whole point of keeping both.
    #[test]
    fn preview_label_pins_cross_impl_values() {
        assert_eq!(
            preview_label("ephpm", "wordpress-sample", 7),
            "ephpm-wordpress-sample-pr-7"
        );
    }
}
