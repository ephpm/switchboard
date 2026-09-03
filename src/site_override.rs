//! The per-site document-root override — the operator-owned artifact that makes
//! `docroot:` mean what it reads as.
//!
//! # Why the manifest cannot simply be read by the server
//!
//! ePHPm serves a vhost **container** (`<sites_dir>/<key>/`), which for a PR
//! preview is a whole customer checkout. A front-controller app therefore 404s
//! at `/`, and — the half that actually matters — everything above the web root
//! is published: `composer.json`, `vendor/`, `config/`, and `storage/logs/*.log`,
//! which routinely carries stack traces containing env values and database
//! credentials. Dotfiles are 403 by the hidden-file rule; none of those are
//! dotfiles.
//!
//! ePHPm deliberately will **not** read a tenant's `ephpm.yaml` to decide this
//! (the file lives inside the container, which the tenant's own PHP can rewrite,
//! and YAML has expansion semantics nobody wants on the request path). What it
//! reads instead is a derived, operator-owned TOML file in a directory *outside*
//! `sites_dir` — `[server] site_overrides_dir`, shipped in ephpm#391:
//!
//! ```toml
//! # <site_overrides_dir>/<site-key>.toml
//! document_root = "public"
//! ```
//!
//! Generating that file from the manifest is switchboard's half of the contract,
//! and it is the half that was never written (switchboard#3). This module is it.
//!
//! # Validation is not "the daemon already checked"
//!
//! ePHPm re-validates every declaration it reads and falls back to serving the
//! container when one fails — safely, but *silently*. So we validate with the
//! same rules before writing, and fail the deploy loudly when a manifest
//! declares something that would be rejected. The alternative is a preview that
//! looks deployed and is quietly serving its `vendor/` directory.
//!
//! The checks mirror ePHPm's `validate_declared_root`
//! (`crates/ephpm-server/src/site_overrides.rs`):
//!
//! 1. **Lexical** — plain relative path, `Component::Normal` segments only. That
//!    rejects absolute paths, drive prefixes, root components, `.` and `..`.
//!    Backslashes are rejected outright so an override means the same thing on
//!    every platform.
//! 2. **Charset** — additionally ours, because we *write* the TOML: only
//!    `[A-Za-z0-9._/-]`. A `"` or a newline in a tenant-supplied string is how a
//!    hand-rolled TOML writer turns into a TOML injection, and no real document
//!    root needs anything outside that set.
//! 3. **Canonical containment** — join onto the container, canonicalize both
//!    sides, require the target to be a directory inside the container. This is
//!    what catches a symlink escape, which the lexical check cannot see through.

use std::path::{Component, Path, PathBuf};

use anyhow::Context;

/// The characters a declared document root may contain.
///
/// Deliberately narrower than "any filename": we serialize this value into TOML
/// by hand, and the tenant supplies it. Anything outside this set is rejected
/// rather than escaped, so there is no escaping bug to have.
fn is_allowed_docroot_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')
}

/// A validated document-root declaration, ready to be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentRoot {
    /// The container *is* the web root (`docroot: "."`, or an empty
    /// declaration). ePHPm's behaviour with no override at all, so no file is
    /// needed — and writing one would be indistinguishable anyway.
    Container,
    /// A subdirectory of the container, verified to exist and to be contained.
    Subdirectory {
        /// The declaration exactly as it will appear in the override file —
        /// relative, `/`-separated, no trailing slash.
        declared: String,
        /// The canonicalized absolute path it resolved to. Used by tests and
        /// logging; ePHPm resolves it again itself.
        resolved: PathBuf,
    },
}

impl DocumentRoot {
    /// Whether this declaration needs an override file written for it.
    #[must_use]
    pub fn needs_override_file(&self) -> bool {
        matches!(self, Self::Subdirectory { .. })
    }

    /// The declared value, or `"."` for the container.
    #[must_use]
    pub fn declared(&self) -> &str {
        match self {
            Self::Container => ".",
            Self::Subdirectory { declared, .. } => declared,
        }
    }
}

/// Validate a manifest's `docroot:` against the checkout it describes.
///
/// `container` is the directory that will become the vhost container — during a
/// deploy this is the **staging** directory, because the declaration has to be
/// checked against the tree we are about to swap into place, not against the
/// previous deploy's tree.
///
/// # Errors
///
/// Returns an error for any declaration ePHPm would reject: absolute, traversing,
/// backslash-separated, outside the allowed charset, non-existent, not a
/// directory, or resolving (through a symlink) outside the container.
pub fn validate_docroot(container: &Path, declared: &str) -> anyhow::Result<DocumentRoot> {
    let trimmed = declared.trim();
    // "." / "./" / "" all mean "the container is the web root" — the same three
    // spellings ePHPm treats as "declares nothing".
    if trimmed.is_empty() || trimmed == "." || trimmed == "./" {
        return Ok(DocumentRoot::Container);
    }
    // Only *now* strip a trailing slash, so `"/"` does not collapse into the
    // "declares nothing" case above. ePHPm treats a bare `/` as "declares
    // nothing" and serves the container; we refuse it instead, because in a
    // manifest it is a mistake and the container is precisely what must not be
    // served by accident.
    let trimmed = trimmed.trim_end_matches('/');
    anyhow::ensure!(
        !trimmed.is_empty(),
        "docroot {declared:?}: the repository root is spelled `.`, not `/` — \
         absolute paths are not permitted"
    );

    anyhow::ensure!(
        !trimmed.contains('\\'),
        "docroot {declared:?}: backslashes are not permitted — use `/` as the \
         separator on all platforms"
    );
    anyhow::ensure!(
        trimmed.chars().all(is_allowed_docroot_char),
        "docroot {declared:?}: only [A-Za-z0-9._/-] are permitted in a document root"
    );

    let relative = Path::new(trimmed);
    anyhow::ensure!(
        !relative.is_absolute(),
        "docroot {declared:?}: absolute paths are not permitted — declare a path \
         relative to the repository root"
    );
    anyhow::ensure!(
        relative
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "docroot {declared:?}: must be a plain relative path with no `..`, `.`, \
         drive prefix or root component"
    );

    let candidate = container.join(relative);
    let resolved = candidate.canonicalize().with_context(|| {
        format!(
            "docroot {declared:?}: {} does not exist in the checkout",
            candidate.display()
        )
    })?;
    let canonical_container = container
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", container.display()))?;

    anyhow::ensure!(
        resolved.starts_with(&canonical_container),
        "docroot {declared:?}: resolves outside the repository (symlink escape)"
    );
    anyhow::ensure!(
        resolved.is_dir(),
        "docroot {declared:?}: is not a directory"
    );

    Ok(DocumentRoot::Subdirectory {
        declared: trimmed.to_string(),
        resolved,
    })
}

/// Render the override file's contents for a validated declaration.
///
/// Only `document_root` is emitted. ePHPm ignores keys it does not understand
/// (so an override written by a newer daemon never breaks a site on an older
/// server), which makes it tempting to write forward-looking keys here — don't:
/// a key nothing acts on is a silent no-op dressed as a feature.
#[must_use]
pub fn render_override(document_root: &DocumentRoot) -> String {
    format!(
        "# Generated by switchboard from the preview's ephpm.yaml `docroot:`.\n\
         # Operator-owned: ePHPm reads this, never the tenant's manifest.\n\
         document_root = \"{}\"\n",
        document_root.declared()
    )
}

/// Write `<overrides_dir>/<site_key>.toml` for a validated declaration.
///
/// # Errors
///
/// Returns an error if the overrides directory cannot be created or the file
/// cannot be written.
pub async fn write_override(
    overrides_dir: &Path,
    site_key: &str,
    document_root: &DocumentRoot,
) -> anyhow::Result<PathBuf> {
    let path = override_path(overrides_dir, site_key);
    tokio::fs::create_dir_all(overrides_dir)
        .await
        .with_context(|| format!("failed to create {}", overrides_dir.display()))?;
    tokio::fs::write(&path, render_override(document_root))
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

/// Remove `<overrides_dir>/<site_key>.toml` if it exists.
///
/// A preview whose docroot changed from `public` back to `.` must not keep the
/// stale override — that would serve a subdirectory the new checkout may not
/// even have, and ePHPm's rejection of it is silent.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be removed.
pub async fn remove_override(overrides_dir: &Path, site_key: &str) -> anyhow::Result<()> {
    let path = override_path(overrides_dir, site_key);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// `<overrides_dir>/<site_key>.toml` — the one path ePHPm reads for a site.
#[must_use]
pub fn override_path(overrides_dir: &Path, site_key: &str) -> PathBuf {
    overrides_dir.join(format!("{site_key}.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Laravel-shaped checkout: a `public/` web root, and above it the two
    /// things switchboard#3 measured as publicly readable on a live preview.
    struct Checkout {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    fn laravel_checkout() -> Checkout {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("checkout");
        std::fs::create_dir_all(root.join("public")).unwrap();
        std::fs::create_dir_all(root.join("vendor")).unwrap();
        std::fs::create_dir_all(root.join("storage").join("logs")).unwrap();
        std::fs::write(root.join("public").join("index.php"), b"<?php // front").unwrap();
        std::fs::write(root.join("vendor").join("secret.txt"), b"private").unwrap();
        std::fs::write(
            root.join("storage").join("logs").join("laravel.log"),
            b"stack trace with DB_PASSWORD=abc",
        )
        .unwrap();
        std::fs::write(root.join("composer.json"), br#"{"name":"demo/app"}"#).unwrap();
        Checkout { _dir: dir, root }
    }

    /// Whether an HTTP path would resolve to a readable file under the web root
    /// ePHPm will serve.
    ///
    /// This is the property the exposure is actually about: not "does the front
    /// controller work", but "is there any request path that reaches this file".
    /// A static-file server confined to `document_root` can only serve what
    /// canonicalizes inside it, which is exactly the containment ePHPm enforces
    /// (`serve_file`'s `starts_with(canonical_root)`), so reproducing that rule
    /// here is a faithful test of reachability.
    fn reachable_under(web_root: &Path, request_path: &str) -> bool {
        let mut candidate = web_root.to_path_buf();
        for segment in request_path.trim_start_matches('/').split('/') {
            candidate.push(segment);
        }
        let (Ok(target), Ok(root)) = (candidate.canonicalize(), web_root.canonicalize()) else {
            return false;
        };
        target.starts_with(&root) && target.is_file()
    }

    /// **The regression test for switchboard#3's exposure half.**
    ///
    /// With the override switchboard now writes, the web root is `public/` — so
    /// `vendor/secret.txt` and `storage/logs/laravel.log` have no request path
    /// that reaches them. Proving the front controller *works* is the lesser
    /// half; proving the credentials-bearing log is unreachable is the point.
    #[test]
    fn vendor_and_logs_are_not_reachable_once_the_docroot_is_honoured() {
        let c = laravel_checkout();
        let DocumentRoot::Subdirectory { resolved, .. } = validate_docroot(&c.root, "public")
            .expect("`public` is a valid document root for this checkout")
        else {
            panic!("`public` must resolve to a subdirectory, not the container");
        };

        for exposed in [
            "/vendor/secret.txt",
            "/storage/logs/laravel.log",
            "/composer.json",
            // Traversal back out of the web root must not resolve either — the
            // files are outside `public/`, and containment is by canonical path.
            "/../vendor/secret.txt",
            "/../../checkout/vendor/secret.txt",
        ] {
            assert!(
                !reachable_under(&resolved, exposed),
                "{exposed} must not be reachable once docroot=public is honoured"
            );
        }

        // ...and the app still routes, which is the other half of the issue.
        assert!(reachable_under(&resolved, "/index.php"));
    }

    /// The same checkout **without** the fix: ePHPm serves the container, and
    /// every one of those files is reachable. This is the "before" the test
    /// above is the "after" of — without it, the assertion above could pass for
    /// the wrong reason (e.g. a helper that never finds anything).
    #[test]
    fn container_as_web_root_is_what_exposes_vendor_and_logs() {
        let c = laravel_checkout();
        assert_eq!(
            validate_docroot(&c.root, ".").unwrap(),
            DocumentRoot::Container
        );
        for exposed in [
            "/vendor/secret.txt",
            "/storage/logs/laravel.log",
            "/composer.json",
        ] {
            assert!(
                reachable_under(&c.root, exposed),
                "{exposed} is reachable when the container is the web root — \
                 this is the exposure switchboard#3 reported"
            );
        }
    }

    #[test]
    fn dot_and_empty_declarations_mean_the_container() {
        let c = laravel_checkout();
        for declared in [".", "./", "", "  "] {
            assert_eq!(
                validate_docroot(&c.root, declared).unwrap(),
                DocumentRoot::Container,
                "for {declared:?}"
            );
        }
    }

    #[test]
    fn nested_declarations_are_allowed_while_contained() {
        let c = laravel_checkout();
        std::fs::create_dir_all(c.root.join("app").join("htdocs")).unwrap();
        let root = validate_docroot(&c.root, "app/htdocs").unwrap();
        assert_eq!(root.declared(), "app/htdocs");
        assert!(root.needs_override_file());
    }

    #[test]
    fn trailing_slash_is_normalized_away() {
        let c = laravel_checkout();
        assert_eq!(
            validate_docroot(&c.root, "public/").unwrap().declared(),
            "public"
        );
    }

    // ── declarations refused before anything is written ────────────────

    #[test]
    fn traversal_declarations_are_refused() {
        let c = laravel_checkout();
        for bad in ["..", "../", "../../etc", "public/../..", "a/../../b"] {
            assert!(
                validate_docroot(&c.root, bad).is_err(),
                "traversal {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn absolute_declarations_are_refused() {
        let c = laravel_checkout();
        for bad in ["/", "/etc", "/etc/passwd", r"C:\Windows", r"\\server\share"] {
            assert!(
                validate_docroot(&c.root, bad).is_err(),
                "absolute path {bad:?} must be refused"
            );
        }
    }

    /// We hand-write the TOML, and the value comes from a tenant's YAML. A
    /// quote or a newline would let a declaration append keys of its own — so
    /// the charset gate refuses them outright rather than escaping them.
    #[test]
    fn toml_injection_attempts_are_refused() {
        let c = laravel_checkout();
        for bad in [
            "public\"\ndocument_root = \"..",
            "public\ndocument_root = \"/etc\"",
            "pub\"lic",
            "public\u{0}",
            "public#comment",
            "public public",
        ] {
            assert!(
                validate_docroot(&c.root, bad).is_err(),
                "{bad:?} must be refused by the charset gate"
            );
        }
    }

    #[test]
    fn missing_or_non_directory_declarations_are_refused() {
        let c = laravel_checkout();
        assert!(validate_docroot(&c.root, "nope").is_err());
        assert!(
            validate_docroot(&c.root, "composer.json").is_err(),
            "a file is not a document root"
        );
    }

    /// The lexical check cannot see through a symlink; canonical containment
    /// can. `escape -> <outside>` is a plain relative name with no `..` in it.
    #[test]
    fn symlink_escaping_the_checkout_is_refused() {
        let c = laravel_checkout();
        let outside = c.root.parent().unwrap().join("secrets");
        std::fs::create_dir_all(&outside).unwrap();
        if !try_symlink_dir(&outside, &c.root.join("escape")) {
            return; // platform refuses symlinks (Windows without the privilege)
        }
        assert!(validate_docroot(&c.root, "escape").is_err());
    }

    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link).is_ok()
        }
    }

    // ── the file itself ────────────────────────────────────────────────

    /// The rendered file must be exactly what ePHPm's `site_overrides::load`
    /// parses: a TOML table with a `document_root` string.
    #[test]
    fn rendered_override_is_the_documented_shape() {
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();
        let text = render_override(&root);
        assert!(
            text.contains("document_root = \"public\"\n"),
            "unexpected render: {text}"
        );
        // Exactly one key — no forward-looking no-ops.
        assert_eq!(
            text.lines()
                .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn write_then_remove_round_trips_under_the_site_key() {
        let dir = tempfile::tempdir().unwrap();
        let overrides = dir.path().join("overrides");
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();

        let path = write_override(&overrides, "ephpm-app-pr-1", &root)
            .await
            .unwrap();
        assert_eq!(path, overrides.join("ephpm-app-pr-1.toml"));
        assert!(path.exists());

        remove_override(&overrides, "ephpm-app-pr-1").await.unwrap();
        assert!(!path.exists());
        // Removing a second time is a success, not an error — teardown races.
        remove_override(&overrides, "ephpm-app-pr-1").await.unwrap();
    }

    /// A full-FQDN site key (the shape on a node with no `sites_domain_suffix`)
    /// names the override file just as well — ePHPm reads `<key>.toml` for
    /// whatever key it resolved.
    #[tokio::test]
    async fn override_is_named_by_the_site_key_not_the_label() {
        let dir = tempfile::tempdir().unwrap();
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();
        let path = write_override(dir.path(), "app-pr-1.preview.ephpm.dev", &root)
            .await
            .unwrap();
        assert_eq!(path.file_name().unwrap(), "app-pr-1.preview.ephpm.dev.toml");
    }
}
