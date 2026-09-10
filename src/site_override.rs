//! The per-site override — the operator-owned artifact that makes `docroot:`
//! mean what it reads as, and that wires the generated env prepend into PHP.
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
//! document_root     = "public"
//! auto_prepend_file = ".ephpm-preview-prepend.php"
//! ```
//!
//! Generating that file from the manifest is switchboard's half of the contract,
//! and it is the half that was never written (switchboard#3, then #4). This
//! module is it.
//!
//! # `auto_prepend_file` is the delivery path for `env:` (switchboard#4)
//!
//! `document_root` alone left the manifest's `env:` block with no in-request
//! delivery mechanism for the common shape. switchboard writes a PHP prepend
//! into the checkout that exports the resolved values into `$_SERVER` (and
//! `$_ENV`/`putenv` for older code), but nothing loaded it: the sidecar it was
//! announced in is a file ePHPm never reads, so `ini_get('auto_prepend_file')`
//! on a live preview returned `''`. Apps had to `require_once` it by hand,
//! which the guide documented and `docroot: "."` apps mostly did not do — so
//! `EPHPM_SEED_TOKEN` never reached PHP and `wordpress-sample` came up as stock
//! WordPress.
//!
//! ephpm#463 (PR #472) made `auto_prepend_file` a **typed, enforced** key in
//! this same file. Writing it here is the fix.
//!
//! # Validation is not "the daemon already checked" — and the stakes moved
//!
//! ePHPm re-validates every declaration it reads. It used to fall back to
//! serving the container when one failed — safely, but *silently*. As of #472 a
//! declaration it understands and cannot honour takes **that one site out of
//! service** (503 + `Retry-After`) instead. Both directions argue for the same
//! thing: validate with ePHPm's rules before writing, and fail the deploy loudly
//! when a manifest declares something that would be rejected. What changed is
//! the cost of getting it wrong — a silently-wide web root became a visible
//! outage — and that is why [`write_override`] is **atomic**: a half-written
//! file is no longer a warning, it is a down site.
//!
//! The checks mirror ePHPm's `validate_declared_root` / `validate_declared_prepend`
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
//!    sides, require the target to be inside the container, and to be a
//!    directory (`document_root`) or a regular file (`auto_prepend_file`). This
//!    is what catches a symlink escape, which the lexical check cannot see
//!    through.
//!
//! Both paths resolve against the **container**, not the web root — matching
//! ePHPm — so a prepend may live above the document root where no URL reaches
//! it.

use std::path::{Component, Path, PathBuf};

use anyhow::Context;

/// The characters a declared path (document root or prepend) may contain.
///
/// Deliberately narrower than "any filename": we serialize this value into TOML
/// by hand, and for `docroot:` the tenant supplies it. Anything outside this set
/// is rejected rather than escaped, so there is no escaping bug to have.
fn is_allowed_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')
}

/// What a declared path has to *be* once it resolves — mirrors ePHPm's `Expect`.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// A directory — `document_root`.
    Directory,
    /// A regular file — `auto_prepend_file`.
    File,
}

impl Expect {
    fn describe(self) -> &'static str {
        match self {
            Self::Directory => "is not a directory",
            Self::File => "is not a regular file",
        }
    }
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
    /// Whether this declaration narrows the web root below the container.
    ///
    /// Not "whether a file is written" any more — since switchboard#4 an
    /// override file is written for **every** preview, because it also carries
    /// `auto_prepend_file`, which a `docroot: "."` site needs most.
    #[must_use]
    pub fn narrows_the_web_root(&self) -> bool {
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

/// A validated `auto_prepend_file` declaration, ready to be written.
///
/// Unlike [`DocumentRoot`] this is never tenant-supplied: switchboard picks the
/// filename and writes the file itself. It is validated anyway, with ePHPm's own
/// rules, because ePHPm now takes the site **out of service** for a value it
/// cannot honour — so an unvalidated write turns a repository that happens to
/// ship a symlink or a directory at that name into a 503 discovered by a user
/// rather than an error discovered by the deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrependFile {
    /// The declaration exactly as it will appear in the override file —
    /// relative to the **container**, `/`-separated.
    declared: String,
    /// The canonicalized absolute path it resolved to, for logging and tests.
    /// ePHPm resolves it again itself.
    resolved: PathBuf,
}

impl PrependFile {
    /// The declared value, as it appears in the override file.
    #[must_use]
    pub fn declared(&self) -> &str {
        &self.declared
    }
}

/// Whether `s` can be written between the quotes of a hand-rolled TOML basic
/// string without changing the document's structure.
///
/// The override is written by hand (no `toml` serializer), so a `"` or a newline
/// in a value would close the string and let it inject keys — the same class the
/// `docroot`/`auto_prepend_file` charset gate closes. `preview_auth`'s values are
/// operator-supplied (switchboard's own config), not tenant-supplied, so the risk
/// is lower, but a hand-written writer that trusts its input is exactly how the
/// bug recurs. A backslash is refused too: it is TOML's escape lead-in, and none
/// of these values (an `env:`/`file:` reference, an absolute URL path) needs one.
fn is_toml_string_safe(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c != '"' && c != '\\' && !c.is_control())
}

/// Whether `s` is a GitHub repository full name in the exact `owner/name` shape
/// the preview gate keys on.
///
/// The gate compares this value against the repositories a logged-in GitHub user
/// can read, so the shape has to be precise: **exactly one** `/`, both segments
/// non-empty and neither a bare `.`/`..`, and every character drawn from the same
/// conservative `[A-Za-z0-9._-]` set the path gates use — which also makes the
/// value TOML-safe, since we hand-write it between quotes. Anything else (a space,
/// a second slash, a quote, an empty half) is rejected rather than written, so a
/// malformed base-repo identity fails the deploy here instead of producing a
/// `[preview_auth]` section that gates against a repository name no user has.
fn is_valid_repo_full_name(s: &str) -> bool {
    let mut parts = s.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    // `split('/')` guarantees no segment contains `/`, so the shared
    // `is_allowed_path_char` set (which permits `/`) can never admit one here.
    let segment_ok = |seg: &str| {
        !seg.is_empty() && seg != "." && seg != ".." && seg.chars().all(is_allowed_path_char)
    };
    segment_ok(owner) && segment_ok(name)
}

/// The `[preview_auth]` section that turns the per-site OAuth/​share gate ON for
/// one preview (ephpm#487/#491).
///
/// It carries deliberately little: a **reference** to the shared HS256 session
/// secret (`env:NAME` / `file:/abs` / a literal — never the key itself, since this
/// file is derived from tenant-controlled repository content), the issuer's login
/// entry point, and the preview's **base** repository (`owner/name`) that read
/// access to it gates the preview. Everything else (cookie name,
/// `require_https`/`require_site`, `share_param`, revocation) uses the gate's
/// defaults, which match what the global `github-auth` issuer mount uses. See
/// [`crate::preview_auth`] for the policy that decides *when* to write this and
/// for the secret resolution/​minting that pairs with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewAuthSection {
    /// The `session_secret` reference written verbatim into the file — the SAME
    /// reference the issuer resolves, so the two share one source of truth. Never
    /// the resolved secret.
    session_secret_ref: String,
    /// The issuer's login endpoint (`login_url`), an absolute path under
    /// `/_ephpm/auth/`.
    login_url: String,
    /// The preview's **base** repository full name (`owner/name`). ePHPm gates the
    /// preview to GitHub users with read access to this repository, so it is the
    /// base repo — the one whose access policy the preview should inherit — never
    /// a fork's. Validated to the exact `owner/name` shape (see
    /// [`is_valid_repo_full_name`]).
    repo: String,
}

impl PreviewAuthSection {
    /// Build a validated section from a secret **reference**, a login URL, and
    /// the preview's base repository full name (`owner/name`).
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is empty, the login URL is not an
    /// absolute (`/`-leading) path, the repository is not in the exact
    /// `owner/name` shape, or when any of them would be unsafe to write into the
    /// hand-rolled TOML (a quote, backslash, or control character).
    pub fn new(
        session_secret_ref: impl Into<String>,
        login_url: impl Into<String>,
        repo: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let session_secret_ref = session_secret_ref.into();
        let login_url = login_url.into();
        let repo = repo.into();
        let secret_ref = session_secret_ref.trim();
        anyhow::ensure!(
            !secret_ref.is_empty(),
            "preview_auth session_secret reference is empty"
        );
        anyhow::ensure!(
            is_toml_string_safe(secret_ref),
            "preview_auth session_secret reference {secret_ref:?} contains a quote, backslash \
             or control character and cannot be safely written into the override TOML"
        );
        let login = login_url.trim();
        anyhow::ensure!(
            login.starts_with('/'),
            "preview_auth login_url {login:?} must be an absolute path beginning with `/`"
        );
        anyhow::ensure!(
            is_toml_string_safe(login),
            "preview_auth login_url {login:?} contains a quote, backslash or control character"
        );
        let repo = repo.trim();
        anyhow::ensure!(
            is_valid_repo_full_name(repo),
            "preview_auth repo {repo:?} must be a GitHub repository full name in the exact \
             `owner/name` shape (each segment [A-Za-z0-9._-], no spaces, quotes, backslashes \
             or extra slashes)"
        );
        Ok(Self {
            session_secret_ref: secret_ref.to_string(),
            login_url: login.to_string(),
            repo: repo.to_string(),
        })
    }

    /// The secret reference as it appears in the file (never the resolved key).
    #[must_use]
    pub fn session_secret_ref(&self) -> &str {
        &self.session_secret_ref
    }

    /// The issuer's login endpoint as it appears in the file.
    #[must_use]
    pub fn login_url(&self) -> &str {
        &self.login_url
    }

    /// The base repository (`owner/name`) as it appears in the file.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }
}

/// Everything switchboard declares for one site, in one file.
///
/// One struct rather than two writers because ePHPm reads **one** file per site:
/// writing `document_root` and `auto_prepend_file` separately would mean one of
/// them clobbering the other's file, which is the failure mode that makes a site
/// serve its `vendor/` or lose its env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteOverride {
    /// Where this site's web root is.
    pub document_root: DocumentRoot,
    /// The PHP file ePHPm runs before every request for this site, or `None`
    /// when this deploy has nothing to prepend.
    pub auto_prepend_file: Option<PrependFile>,
    /// The `[preview_auth]` gate section, or `None` for an ungated preview.
    ///
    /// `Some` turns the per-site OAuth/​share gate on. Writing it for a private
    /// preview is the whole point of the access gate; a private preview whose
    /// override lacks this section comes up world-readable, which the deployer
    /// refuses to let happen silently (fail closed).
    pub preview_auth: Option<PreviewAuthSection>,
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

    let resolved = validate_contained(
        container,
        trimmed,
        &format!("docroot {declared:?}"),
        Expect::Directory,
    )?;

    Ok(DocumentRoot::Subdirectory {
        declared: trimmed.to_string(),
        resolved,
    })
}

/// Validate the generated env prepend against the checkout it will ship in.
///
/// `declared` is relative to the **container** (the staging directory during a
/// deploy), matching how ePHPm resolves it — so a prepend may sit above the
/// document root, out of reach of any URL.
///
/// # Errors
///
/// Returns an error for any declaration ePHPm would refuse. Since ephpm#472 a
/// refused `auto_prepend_file` makes the whole override unusable and takes the
/// site to a 503, so this has to fail the deploy, not warn.
pub fn validate_prepend(container: &Path, declared: &str) -> anyhow::Result<PrependFile> {
    let trimmed = declared.trim().trim_end_matches('/');
    anyhow::ensure!(
        !trimmed.is_empty() && trimmed != ".",
        "auto_prepend_file {declared:?}: must name a regular file inside the checkout"
    );
    let resolved = validate_contained(
        container,
        trimmed,
        &format!("auto_prepend_file {declared:?}"),
        Expect::File,
    )?;
    Ok(PrependFile {
        declared: trimmed.to_string(),
        resolved,
    })
}

/// The containment core both declared paths share, mirroring ePHPm's
/// `resolve_contained`.
fn validate_contained(
    container: &Path,
    trimmed: &str,
    key: &str,
    expect: Expect,
) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        !trimmed.contains('\\'),
        "{key}: backslashes are not permitted — use `/` as the separator on all platforms"
    );
    anyhow::ensure!(
        trimmed.chars().all(is_allowed_path_char),
        "{key}: only [A-Za-z0-9._/-] are permitted"
    );

    let relative = Path::new(trimmed);
    anyhow::ensure!(
        !relative.is_absolute(),
        "{key}: absolute paths are not permitted — declare a path relative to the \
         repository root"
    );
    anyhow::ensure!(
        relative
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "{key}: must be a plain relative path with no `..`, `.`, drive prefix or \
         root component"
    );

    let candidate = container.join(relative);
    let resolved = candidate.canonicalize().with_context(|| {
        format!(
            "{key}: {} does not exist in the checkout",
            candidate.display()
        )
    })?;
    // `canonicalize` also resolves `..` — but the lexical check above already
    // refused those, so this only ever resolves symlinks here.
    let canonical_container = container
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", container.display()))?;

    anyhow::ensure!(
        resolved.starts_with(&canonical_container),
        "{key}: resolves outside the repository (symlink escape)"
    );
    let shape_ok = match expect {
        Expect::Directory => resolved.is_dir(),
        Expect::File => resolved.is_file(),
    };
    anyhow::ensure!(shape_ok, "{key}: {}", expect.describe());

    Ok(resolved)
}

/// Render the override file's contents for a validated declaration.
///
/// The two top-level keys (`document_root`, `auto_prepend_file`) are ePHPm typed
/// fields since #472; the optional `[preview_auth]` table is the access-gate
/// activation added in ephpm#487/#491. `document_root` is emitted only when it
/// *narrows* the web root: ePHPm reads an absent key and an explicit `"."`
/// identically, and the absent spelling is the one every ePHPm ever shipped
/// agrees on. The `[preview_auth]` table is emitted **last** — a TOML table must
/// follow all top-level keys, or those keys would parse as belonging to it.
#[must_use]
pub fn render_override(over: &SiteOverride) -> String {
    let mut out = String::from(
        "# Generated by switchboard from the preview's ephpm.yaml.\n\
         # Operator-owned: ePHPm reads this, never the tenant's manifest.\n",
    );
    if over.document_root.narrows_the_web_root() {
        out.push_str(&format!(
            "document_root = \"{}\"\n",
            over.document_root.declared()
        ));
    }
    if let Some(prepend) = &over.auto_prepend_file {
        out.push_str(&format!("auto_prepend_file = \"{}\"\n", prepend.declared()));
    }
    if let Some(auth) = &over.preview_auth {
        // The secret is a REFERENCE (env:/file:), never the key — this file is
        // derived from tenant-controlled repository content, so nothing sensitive
        // is written into it. `repo` is the base repository (`owner/name`) read
        // access to which the gate uses to admit GitHub users. All three strings
        // are validated by `PreviewAuthSection`.
        out.push_str(&format!(
            "\n[preview_auth]\nsession_secret = \"{}\"\nlogin_url = \"{}\"\nrepo = \"{}\"\n",
            auth.session_secret_ref(),
            auth.login_url(),
            auth.repo(),
        ));
    }
    out
}

/// Write `<overrides_dir>/<site_key>.toml` for a validated declaration,
/// **atomically**.
///
/// Write-then-rename rather than `write`, and this is not decoration. Since
/// ephpm#472 an override file that cannot be parsed takes its site out of
/// service with a 503 instead of falling back to serving the container, and
/// ePHPm re-reads the file every couple of seconds — so a plain `write`, which
/// truncates first and can be interrupted by a crash, a full disk or a signal,
/// has a window in which the live file is a truncated TOML fragment and the
/// preview is *down*. `rename(2)` within one directory is atomic: a reader sees
/// either the whole old file or the whole new one.
///
/// The temporary is dot-prefixed and `.tmp`-suffixed so it can never collide
/// with `<some_key>.toml` for any site key, and carries the pid so two writers
/// cannot share one temp file (which would reintroduce exactly the torn read
/// this exists to prevent).
///
/// # Errors
///
/// Returns an error if the overrides directory cannot be created, or the file
/// cannot be written, flushed or renamed into place.
pub async fn write_override(
    overrides_dir: &Path,
    site_key: &str,
    over: &SiteOverride,
) -> anyhow::Result<PathBuf> {
    let path = override_path(overrides_dir, site_key);
    tokio::fs::create_dir_all(overrides_dir)
        .await
        .with_context(|| format!("failed to create {}", overrides_dir.display()))?;

    let tmp = overrides_dir.join(format!(
        ".{site_key}.toml.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    match write_then_rename(&tmp, &path, &render_override(over)).await {
        Ok(()) => Ok(path),
        Err(e) => {
            // Never leave a partial temp behind for the next operator to find.
            tokio::fs::remove_file(&tmp).await.ok();
            Err(e)
        }
    }
}

/// Write `contents` to `tmp`, flush it to disk, then rename it onto `path`.
///
/// The `sync_all` is what makes the rename meaningful across a host crash: the
/// rename can otherwise be durable before the data is, leaving a zero-length
/// override in place — which is *valid* TOML declaring nothing, so the site
/// would come back serving its whole container with no error anywhere.
async fn write_then_rename(tmp: &Path, path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut file = tokio::fs::File::create(tmp)
        .await
        .with_context(|| format!("failed to create {}", tmp.display()))?;
    {
        use tokio::io::AsyncWriteExt as _;
        file.write_all(contents.as_bytes())
            .await
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        file.sync_all()
            .await
            .with_context(|| format!("failed to flush {}", tmp.display()))?;
    }
    drop(file);
    tokio::fs::rename(tmp, path)
        .await
        .with_context(|| format!("failed to move {} into place", path.display()))?;
    Ok(())
}

/// Remove `<overrides_dir>/<site_key>.toml` if it exists.
///
/// Teardown's job now — a *deploy* always writes the file, because it carries
/// the env prepend even when the container is the web root.
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
        assert!(root.narrows_the_web_root());
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

    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
    }

    // ── auto_prepend_file (switchboard#4) ──────────────────────────────

    /// Drop the generated prepend into a checkout, as the deploy does.
    fn write_prepend(root: &Path, relative: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"<?php // generated").unwrap();
        path
    }

    /// **The path-shape test.** ePHPm refuses an `auto_prepend_file` that is
    /// not a plain relative path naming a regular file inside the container —
    /// and since #472 a refusal is a **503 for the site**, not a no-op. So the
    /// exact name switchboard ships must satisfy every rule ePHPm applies.
    #[test]
    fn the_generated_prepend_name_satisfies_ephpms_containment_rules() {
        let c = laravel_checkout();
        let declared = crate::deployer::PREPEND_FILE;
        let script = write_prepend(&c.root, declared);

        // Re-stated here rather than only exercised, because these are ePHPm's
        // rules and this test is what stops the constant drifting off them.
        assert!(
            !Path::new(declared).is_absolute(),
            "absolute prepend paths are refused"
        );
        assert!(
            Path::new(declared)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
            "`..`, `.`, root and drive components are refused"
        );
        assert!(!declared.contains('\\'), "backslashes are refused");
        assert!(
            declared.starts_with('.'),
            "the prepend must be dot-prefixed so ePHPm's `hidden_files` default \
             keeps it off the HTTP surface — it gates serving, never `include`"
        );

        let validated = validate_prepend(&c.root, declared).expect("must be honoured by ePHPm");
        assert_eq!(validated.declared(), declared);
        assert_eq!(validated.resolved, script.canonicalize().unwrap());
    }

    /// The prepend resolves against the **container**, not the web root, so a
    /// Laravel-shaped preview can keep it out of `public/` entirely.
    #[test]
    fn a_prepend_above_the_document_root_is_accepted() {
        let c = laravel_checkout();
        write_prepend(&c.root, ".ephpm-preview-prepend.php");
        assert!(validate_prepend(&c.root, ".ephpm-preview-prepend.php").is_ok());
        // ...and it is genuinely outside the web root ePHPm will serve.
        let DocumentRoot::Subdirectory { resolved, .. } =
            validate_docroot(&c.root, "public").unwrap()
        else {
            panic!("`public` must resolve to a subdirectory");
        };
        assert!(!reachable_under(&resolved, "/.ephpm-preview-prepend.php"));
    }

    #[test]
    fn prepend_escaping_the_container_is_refused() {
        let c = laravel_checkout();
        // Make the traversal targets real, so only containment can refuse them.
        std::fs::write(c.root.parent().unwrap().join("evil.php"), b"<?php").unwrap();
        for bad in [
            "..",
            "../evil.php",
            "../../etc/passwd",
            "public/../../evil.php",
            r"..\..\evil.php",
            "/etc/passwd",
            "/",
            r"C:\Windows\win.ini",
            r"\\server\share\evil.php",
            "",
            ".",
        ] {
            assert!(
                validate_prepend(&c.root, bad).is_err(),
                "prepend {bad:?} escapes the container and must be refused"
            );
        }
    }

    /// A repository that ships a symlink at the generated prepend's name must
    /// not turn into an override ePHPm refuses (503). The deploy unlinks before
    /// writing, so the validated path is always a regular file we created —
    /// this pins that a symlink escape would in fact be caught if it were not.
    #[test]
    fn prepend_symlinked_out_of_the_checkout_is_refused() {
        let c = laravel_checkout();
        let outside = c.root.parent().unwrap().join("credentials.php");
        std::fs::write(&outside, b"<?php const P = 'hunter2';").unwrap();
        if !try_symlink_file(&outside, &c.root.join(".ephpm-preview-prepend.php")) {
            return; // platform refuses symlinks
        }
        assert!(validate_prepend(&c.root, ".ephpm-preview-prepend.php").is_err());
    }

    #[test]
    fn prepend_naming_a_directory_or_a_missing_file_is_refused() {
        let c = laravel_checkout();
        assert!(
            validate_prepend(&c.root, "public").is_err(),
            "a directory is not a script"
        );
        assert!(validate_prepend(&c.root, ".nope.php").is_err());
    }

    /// Same charset gate as `docroot:` — we hand-write the TOML for this key too.
    #[test]
    fn prepend_toml_injection_attempts_are_refused() {
        let c = laravel_checkout();
        for bad in [
            "a.php\"\ndocument_root = \"..",
            "a\"b.php",
            "a.php\u{0}",
            "a.php # comment",
        ] {
            assert!(validate_prepend(&c.root, bad).is_err(), "{bad:?}");
        }
    }

    // ── the file itself ────────────────────────────────────────────────

    fn over(document_root: DocumentRoot, auto_prepend_file: Option<PrependFile>) -> SiteOverride {
        SiteOverride {
            document_root,
            auto_prepend_file,
            preview_auth: None,
        }
    }

    // ── the [preview_auth] gate section (ephpm#487/#491) ────────────────

    #[test]
    fn preview_auth_section_renders_after_the_top_level_keys() {
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();
        write_prepend(&c.root, ".ephpm-preview-prepend.php");
        let prepend = validate_prepend(&c.root, ".ephpm-preview-prepend.php").unwrap();
        let auth = PreviewAuthSection::new(
            "env:EPHPM_PREVIEW_SESSION_SECRET",
            "/_ephpm/auth/github/login",
            "ephpm/wordpress-sample",
        )
        .unwrap();

        let over = SiteOverride {
            document_root: root,
            auto_prepend_file: Some(prepend),
            preview_auth: Some(auth),
        };
        let text = render_override(&over);

        // The reference is written, not a literal secret.
        assert!(
            text.contains("session_secret = \"env:EPHPM_PREVIEW_SESSION_SECRET\""),
            "the file must carry the reference, never the key: {text}"
        );
        assert!(
            text.contains("login_url = \"/_ephpm/auth/github/login\""),
            "{text}"
        );
        // The base repo the gate keys on — the exact `owner/name` contract shared
        // with ePHPm's preview-gate reader.
        assert!(
            text.contains("repo = \"ephpm/wordpress-sample\""),
            "the section must carry the base repo full name: {text}"
        );

        // The table header must come after the two top-level keys, or TOML would
        // read `document_root`/`auto_prepend_file` as members of the table.
        let table_at = text.find("[preview_auth]").expect("the table is present");
        assert!(
            text.find("document_root").unwrap() < table_at
                && text.find("auto_prepend_file").unwrap() < table_at,
            "top-level keys must precede the table: {text}"
        );
    }

    /// A `docroot: "."` private preview writes no `document_root` but still gates:
    /// the section is what makes the preview private, and it must be present.
    #[test]
    fn preview_auth_can_gate_a_container_docroot_preview() {
        let auth = PreviewAuthSection::new(
            "env:EPHPM_PREVIEW_SESSION_SECRET",
            "/_ephpm/auth/github/login",
            "ephpm/wordpress-sample",
        )
        .unwrap();
        let over = SiteOverride {
            document_root: DocumentRoot::Container,
            auto_prepend_file: None,
            preview_auth: Some(auth),
        };
        let text = render_override(&over);
        assert!(!text.contains("document_root"));
        assert!(text.contains("[preview_auth]"), "{text}");
        assert!(text.contains("repo = \"ephpm/wordpress-sample\""), "{text}");
    }

    #[test]
    fn ungated_preview_writes_no_preview_auth_section() {
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();
        let text = render_override(&over(root, None));
        assert!(
            !text.contains("preview_auth"),
            "a public/ungated preview must not carry the section: {text}"
        );
    }

    #[test]
    fn preview_auth_refuses_a_toml_injecting_reference() {
        // A quote or newline in the reference would close the TOML string.
        for bad in [
            "env:X\"\nsomething_evil = \"y",
            "env:X\ndocument_root = \"..",
            "env:X\\bad",
        ] {
            assert!(
                PreviewAuthSection::new(bad, "/_ephpm/auth/github/login", "ephpm/app").is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn preview_auth_login_url_must_be_absolute() {
        assert!(
            PreviewAuthSection::new("env:SECRET", "login", "ephpm/app").is_err(),
            "a relative login_url must be refused"
        );
        assert!(
            PreviewAuthSection::new("env:SECRET", "https://evil/login", "ephpm/app").is_err(),
            "an absolute URL (not a path) is refused — login_url is a path under /_ephpm/auth"
        );
        assert!(
            PreviewAuthSection::new("env:SECRET", "/_ephpm/auth/github/login", "ephpm/app").is_ok()
        );
    }

    #[test]
    fn preview_auth_refuses_an_empty_reference() {
        assert!(PreviewAuthSection::new("   ", "/_ephpm/auth/github/login", "ephpm/app").is_err());
    }

    /// The base repo must be an exact `owner/name`: two non-empty segments and a
    /// single slash. This is the shape ePHPm's gate reads, so a malformed value
    /// (a bare name, an extra path segment, a `.git` suffix's slash, a URL) must
    /// fail the deploy here rather than gate against a repository no user has.
    #[test]
    fn preview_auth_repo_must_be_owner_slash_name() {
        for good in [
            "ephpm/wordpress-sample",
            "ephpm/app",
            "octocat/Hello-World",
            "a/b",
            "owner/repo.name_with-punct",
        ] {
            assert!(
                PreviewAuthSection::new("env:S", "/login", good).is_ok(),
                "{good:?} is a valid owner/name and must be accepted"
            );
            assert_eq!(
                PreviewAuthSection::new("env:S", "/login", good)
                    .unwrap()
                    .repo(),
                good,
                "the value round-trips verbatim"
            );
        }
        for bad in [
            "",
            "   ",
            "noslash",
            "owner/",
            "/name",
            "owner/name/extra",
            "owner//name",
            "own er/name",
            "owner /name",
            "./name",
            "owner/..",
            "https://github.com/owner/name",
        ] {
            assert!(
                PreviewAuthSection::new("env:S", "/login", bad).is_err(),
                "{bad:?} is not an owner/name and must be refused"
            );
        }
    }

    /// A quote, backslash, newline or control character in the repo would close
    /// the hand-rolled TOML string — the same injection class the reference and
    /// login_url gates close. The charset gate refuses them all outright.
    #[test]
    fn preview_auth_repo_toml_injection_attempts_are_refused() {
        for bad in [
            "owner/name\"\nsomething_evil = \"y",
            "owner/name\ndocument_root = \"..",
            "owner\"/name",
            "owner/na\\me",
            "owner/name\u{0}",
            "owner/name # comment",
        ] {
            assert!(
                PreviewAuthSection::new("env:S", "/login", bad).is_err(),
                "{bad:?} must be refused by the repo gate"
            );
        }
    }

    /// The rendered file must be exactly what ePHPm's `site_overrides::load`
    /// parses, and must round-trip through a TOML parser as the two typed keys
    /// #472 declares. Rendering something ePHPm cannot parse is now a 503.
    #[test]
    fn rendered_override_is_the_documented_shape() {
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();
        let script = write_prepend(&c.root, ".ephpm-preview-prepend.php");
        let prepend = validate_prepend(&c.root, ".ephpm-preview-prepend.php").unwrap();
        assert!(script.is_file());

        let text = render_override(&over(root, Some(prepend)));
        assert!(
            text.contains("document_root = \"public\"\n"),
            "unexpected render: {text}"
        );
        assert!(
            text.contains("auto_prepend_file = \".ephpm-preview-prepend.php\"\n"),
            "unexpected render: {text}"
        );
        // Exactly two keys — both typed in ePHPm, no forward-looking no-ops.
        assert_eq!(keys(&text), vec!["auto_prepend_file", "document_root"]);
    }

    /// **The switchboard#4 shape.** `docroot: "."` writes no `document_root`
    /// (absent and `"."` are identical to ePHPm, and absent is the spelling
    /// every ePHPm release agrees on) but must still write the prepend — this
    /// is the shape that had no `env:` delivery path at all.
    #[test]
    fn docroot_dot_still_gets_an_override_carrying_the_prepend() {
        let c = laravel_checkout();
        write_prepend(&c.root, ".ephpm-preview-prepend.php");
        let prepend = validate_prepend(&c.root, ".ephpm-preview-prepend.php").unwrap();

        let text = render_override(&over(DocumentRoot::Container, Some(prepend)));
        assert_eq!(keys(&text), vec!["auto_prepend_file"]);
        assert!(
            !text.contains("document_root"),
            "an absent document_root is how `.` is spelled: {text}"
        );
    }

    /// Nothing to declare renders a comment-only file rather than a stray key.
    #[test]
    fn nothing_declared_renders_no_keys() {
        assert!(keys(&render_override(&over(DocumentRoot::Container, None))).is_empty());
    }

    /// The rendered keys, sorted — a stand-in for "what ePHPm's TOML parser
    /// would see", without taking a `toml` dependency for one assertion.
    fn keys(text: &str) -> Vec<&str> {
        let mut keys: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .map(|l| l.split('=').next().unwrap().trim())
            .collect();
        keys.sort_unstable();
        keys
    }

    #[tokio::test]
    async fn write_then_remove_round_trips_under_the_site_key() {
        let dir = tempfile::tempdir().unwrap();
        let overrides = dir.path().join("overrides");
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();

        let path = write_override(&overrides, "ephpm-app-pr-1", &over(root, None))
            .await
            .unwrap();
        assert_eq!(path, overrides.join("ephpm-app-pr-1.toml"));
        assert!(path.exists());

        remove_override(&overrides, "ephpm-app-pr-1").await.unwrap();
        assert!(!path.exists());
        // Removing a second time is a success, not an error — teardown races.
        remove_override(&overrides, "ephpm-app-pr-1").await.unwrap();
    }

    /// **Atomicity.** ePHPm re-reads this file every couple of seconds and, as
    /// of #472, 503s the site if it cannot parse it — so the write must never
    /// be observable half-done. Two things are checked: the directory is left
    /// with no temporary litter, and a rewrite replaces the file rather than
    /// truncating it in place (a truncate-in-place is precisely the window
    /// where a reader sees a fragment).
    #[tokio::test]
    async fn the_override_is_replaced_atomically_leaving_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let c = laravel_checkout();
        write_prepend(&c.root, ".ephpm-preview-prepend.php");
        let prepend = validate_prepend(&c.root, ".ephpm-preview-prepend.php").unwrap();
        let root = validate_docroot(&c.root, "public").unwrap();

        let first = write_override(dir.path(), "app-pr-1", &over(root, None))
            .await
            .unwrap();
        let second = write_override(
            dir.path(),
            "app-pr-1",
            &over(DocumentRoot::Container, Some(prepend)),
        )
        .await
        .unwrap();
        assert_eq!(first, second, "a rewrite targets the same path");

        let text = tokio::fs::read_to_string(&second).await.unwrap();
        assert_eq!(
            keys(&text),
            vec!["auto_prepend_file"],
            "stale keys survived"
        );

        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        let mut names = Vec::new();
        while let Some(e) = entries.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(
            names,
            vec!["app-pr-1.toml".to_string()],
            "the overrides dir must contain only the override — no .tmp litter"
        );
    }

    /// A full-FQDN site key (the shape on a node with no `sites_domain_suffix`)
    /// names the override file just as well — ePHPm reads `<key>.toml` for
    /// whatever key it resolved.
    #[tokio::test]
    async fn override_is_named_by_the_site_key_not_the_label() {
        let dir = tempfile::tempdir().unwrap();
        let c = laravel_checkout();
        let root = validate_docroot(&c.root, "public").unwrap();
        let path = write_override(dir.path(), "app-pr-1.preview.ephpm.dev", &over(root, None))
            .await
            .unwrap();
        assert_eq!(path.file_name().unwrap(), "app-pr-1.preview.ephpm.dev.toml");
        // The temporary must never have been mistakable for another site's
        // override: dot-prefixed and `.tmp`-suffixed, so `<key>.toml` is the
        // only file ePHPm can read here.
        assert!(path.exists());
    }
}
