//! Preview teardown: remove **everything** a preview left on this node.
//!
//! A deploy creates more than the vhost directory, and every artifact is
//! per-site state that nothing else ever reaps (issue #9). All of them are named
//! by the **canonical site key** (see [`crate::site_key`]) — the same string the
//! deploy used, which on a node with `sites_domain_suffix` configured is the
//! preview label and on one without it is the full preview FQDN:
//!
//! * `<sites_dir>/<key>/` — the vhost directory (and a `<key>.tmp` staging
//!   directory when a deploy died mid-swap);
//! * `<sqlite_dir>/<key>.db` — ePHPm's per-site database, plus its `-wal` /
//!   `-shm` / `-journal` companions. On a WordPress preview this is the
//!   dominant disk consumer;
//! * `<site_overrides_dir>/<key>.toml` — the docroot override the deploy
//!   wrote for ePHPm (ephpm#391);
//! * the per-vhost temp/session state root ePHPm creates under
//!   `<temp>/ephpm-vhosts/` — sessions, uploads, PHP temp files.
//!
//! # Path safety
//!
//! Every removal target is `<configured root>/<derived name>` where the name
//! is derived from the validated site key — never from a glob wider than
//! the one site. [`validate_site_key`] fails closed: a key that is not a single,
//! plain path component (separators, `..`, drive colons, NULs) aborts the
//! teardown before anything is touched.
//!
//! # The state-root name is reproduced, then swept by pattern
//!
//! ePHPm names a vhost's state root `<sanitized-dir-name>-<16 hex>` where the
//! hex is a `DefaultHasher` digest of the resolved site-container path
//! (`vhost_state_root` in ePHPm's router). That digest is stable in practice
//! but is computed by a *different process*: a `TMPDIR` mismatch, a path
//! canonicalization difference, or a std hasher change would make our
//! reproduction miss. So the reproduction is attempted first (both the
//! canonical and the raw container path), and then the base directory is swept
//! for entries matching exactly `<sanitized-key>-<16 lowercase hex>` — the
//! one site's name shape, not a glob over the base.
//!
//! # Cluster story
//!
//! In cluster mode every node's switchboard-api materializes the same teardown
//! job into its local queue (KV desired-state + `/drain`), so every node's
//! daemon runs this teardown against its own disk. Per-node local removal is
//! therefore the complete story: replicated per-site database files and state
//! roots on other nodes are removed by those nodes' own daemons.

use std::path::{Path, PathBuf};

use anyhow::Context;

/// Non-repo inputs to a teardown: where the preview's artifacts live.
///
/// `sqlite_dir` and `site_overrides_dir` mirror ePHPm's `[db.sqlite].dir` and
/// `[server].site_overrides_dir`; when a knob is `None` that artifact class is
/// left in place (stated in the log, not silently skipped).
pub struct TeardownContext<'a> {
    /// ePHPm sites directory — previews live at `<sites_dir>/<site_key>/`.
    pub sites_dir: &'a Path,
    /// ePHPm's `[db.sqlite].dir`, where `<site_key>.db` lives. `None` = leave
    /// database files in place.
    pub sqlite_dir: Option<&'a Path>,
    /// ePHPm's `site_overrides_dir`, where `<site_key>.toml` lives. `None` =
    /// leave override files in place.
    pub site_overrides_dir: Option<&'a Path>,
    /// The directory ePHPm keeps per-vhost state roots in. `None` = use this
    /// process's `std::env::temp_dir()/ephpm-vhosts`, which matches ePHPm's
    /// default when both processes see the same `TMPDIR` (set the flag
    /// explicitly when they don't, e.g. systemd `PrivateTmp`).
    pub vhost_temp_base: Option<&'a Path>,
}

/// Remove a preview deployment and every per-site artifact it left behind.
///
/// Tearing down a preview that was never deployed (or already torn down) is a
/// success, not an error — GitHub sends `closed` for pull requests that never
/// got one, and in cluster mode several nodes race to the same state. Every
/// phase tolerates already-missing files; every phase runs even when an
/// earlier one failed, and the failures are reported together at the end so
/// the job lands in `claimed/` for inspection.
///
/// # Errors
///
/// Returns an error if the site key is not one ePHPm would serve, or if
/// any artifact exists but cannot be removed.
pub async fn teardown_preview(site_key: &str, ctx: &TeardownContext<'_>) -> anyhow::Result<()> {
    validate_site_key(site_key)?;

    let mut failures: Vec<String> = Vec::new();
    let site_dir = ctx.sites_dir.join(site_key);

    // Resolve the container to its canonical form BEFORE removing it — the
    // state-root digest is computed by ePHPm over the resolved path, and a
    // removed directory can no longer be canonicalized.
    let canonical_container = tokio::fs::canonicalize(&site_dir).await.ok();

    // (1) The vhost directory, plus the staging directory a deploy that died
    // between fetch and swap leaves behind (same `with_extension` the deploy
    // uses, so we remove exactly what it creates).
    for dir in [site_dir.clone(), site_dir.with_extension("tmp")] {
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => tracing::info!(%site_key, path = %dir.display(), "removed preview directory"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(format!("failed to remove {}: {e}", dir.display())),
        }
    }

    // (2) The per-site database and its journal companions.
    if let Some(sqlite_dir) = ctx.sqlite_dir {
        for suffix in ["db", "db-wal", "db-shm", "db-journal"] {
            let file = sqlite_dir.join(format!("{site_key}.{suffix}"));
            match tokio::fs::remove_file(&file).await {
                Ok(()) => {
                    tracing::info!(%site_key, path = %file.display(), "removed per-site database file");
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => failures.push(format!("failed to remove {}: {e}", file.display())),
            }
        }
    } else {
        // Stated rather than silently skipped, exactly like the old teardown
        // stated it never tried.
        tracing::debug!(%site_key, "per-site database left in place (--sqlite-dir not configured)");
    }

    // (3) The docroot override file the deploy wrote for ePHPm.
    if let Some(overrides_dir) = ctx.site_overrides_dir {
        let file = overrides_dir.join(format!("{site_key}.toml"));
        match tokio::fs::remove_file(&file).await {
            Ok(()) => {
                tracing::info!(%site_key, path = %file.display(), "removed site override file")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(format!("failed to remove {}: {e}", file.display())),
        }
    } else {
        tracing::debug!(
            %site_key,
            "site override file left in place (--site-overrides-dir not configured)"
        );
    }

    // (4) The per-vhost temp/session state root(s).
    let base = ctx.vhost_temp_base.map_or_else(
        || std::env::temp_dir().join("ephpm-vhosts"),
        Path::to_path_buf,
    );
    if let Err(e) =
        remove_state_roots(&base, site_key, canonical_container.as_deref(), &site_dir).await
    {
        failures.push(format!("{e:#}"));
    }

    anyhow::ensure!(
        failures.is_empty(),
        "teardown of {site_key} left artifacts behind: {}",
        failures.join("; ")
    );
    Ok(())
}

/// Remove the vhost state roots for `site_key` under `base`.
///
/// Tries the reproduced ePHPm names first (canonical and raw container paths),
/// then sweeps `base` for entries matching this site's exact name shape,
/// `<sanitized-key>-<16 lowercase hex>`. Only ever removes direct children
/// of `base` whose names match the one site.
async fn remove_state_roots(
    base: &Path,
    site_key: &str,
    canonical_container: Option<&Path>,
    raw_container: &Path,
) -> anyhow::Result<()> {
    let mut targets: Vec<PathBuf> = Vec::new();

    // Reproduced names. Deduplicated: canonical == raw on most deployments.
    let mut names: Vec<String> = Vec::new();
    if let Some(canonical) = canonical_container {
        names.push(state_root_name(canonical));
    }
    let raw_name = state_root_name(raw_container);
    if !names.contains(&raw_name) {
        names.push(raw_name);
    }
    for name in &names {
        let dir = base.join(name);
        if dir.exists() {
            targets.push(dir);
        }
    }

    // Pattern sweep for the same site under a digest we could not reproduce.
    match tokio::fs::read_dir(base).await {
        Ok(mut entries) => {
            while let Some(entry) = entries
                .next_entry()
                .await
                .context("reading vhost temp base")?
            {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if matches_state_root_name(name, site_key) {
                    let path = entry.path();
                    if !targets.contains(&path) {
                        targets.push(path);
                    }
                }
            }
        }
        // No base directory means no state roots — nothing to clean.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("failed to list {}", base.display()));
        }
    }

    for dir in targets {
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => {
                tracing::info!(%site_key, path = %dir.display(), "removed per-vhost temp/session state root");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("failed to remove {}", dir.display()));
            }
        }
    }
    Ok(())
}

/// Refuse any site key that is not a single, plain path component.
///
/// The key names files under every configured root; this is the check that makes
/// `root.join(key)` incapable of resolving outside the root. It is the same
/// allowlist ePHPm applies before joining a key onto `sites_dir`
/// ([`crate::site_key::is_valid_site_key`]), so a key this refuses is one ePHPm
/// would never have served in the first place.
///
/// # Errors
///
/// Returns an error for any key outside `[a-z0-9._-]`, and for the dot shapes
/// (`.`, `..`, `a..b`, leading/trailing dot) that would traverse when joined.
fn validate_site_key(site_key: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        crate::site_key::is_valid_site_key(site_key),
        "refusing teardown: {site_key:?} is not a valid ePHPm site key — it \
         must be non-empty DNS-style labels from [a-z0-9._-] with no empty label"
    );
    Ok(())
}

/// Reproduce ePHPm's state-root directory name for a site container:
/// `<sanitized-dir-name>-<DefaultHasher(container) as 16 hex>`.
///
/// Mirrors `vhost_state_root` in ePHPm's router. `DefaultHasher` uses fixed
/// keys, so the digest matches across processes on the same platform and std
/// version; the pattern sweep in [`remove_state_roots`] covers the cases
/// where it doesn't.
fn state_root_name(container: &Path) -> String {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    container.hash(&mut hasher);
    let digest = hasher.finish();

    let site_key = container
        .file_name()
        .and_then(|s| s.to_str())
        .map_or_else(|| "site".to_string(), sanitize_path_label);

    format!("{site_key}-{digest:016x}")
}

/// Whether a directory entry under the vhost temp base belongs to `site_key`:
/// exactly `<sanitized-key>-<16 lowercase hex>`, ePHPm's state-root shape.
fn matches_state_root_name(entry: &str, site_key: &str) -> bool {
    let sanitized = sanitize_path_label(site_key);
    let Some(rest) = entry.strip_prefix(&sanitized) else {
        return false;
    };
    let Some(hex) = rest.strip_prefix('-') else {
        return false;
    };
    hex.len() == 16 && hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// ePHPm's site_key sanitization, verbatim (`sanitize_path_label` in its router):
/// keep `[A-Za-z0-9._-]`, map everything else to `_`, cap at 64 chars, and
/// fall back to `"site"` for an empty result.
fn sanitize_path_label(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "site".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context pointing every knob at subdirectories of one tempdir.
    struct Fixture {
        _root: tempfile::TempDir,
        sites: PathBuf,
        sqlite: PathBuf,
        overrides: PathBuf,
        temp_base: PathBuf,
    }

    impl Fixture {
        async fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let sites = root.path().join("sites");
            let sqlite = root.path().join("sqlite");
            let overrides = root.path().join("overrides");
            let temp_base = root.path().join("ephpm-vhosts");
            for dir in [&sites, &sqlite, &overrides, &temp_base] {
                tokio::fs::create_dir_all(dir).await.unwrap();
            }
            Self {
                _root: root,
                sites,
                sqlite,
                overrides,
                temp_base,
            }
        }

        fn ctx(&self) -> TeardownContext<'_> {
            TeardownContext {
                sites_dir: &self.sites,
                sqlite_dir: Some(&self.sqlite),
                site_overrides_dir: Some(&self.overrides),
                vhost_temp_base: Some(&self.temp_base),
            }
        }

        /// Materialize the full artifact set for `site_key`, exactly as a deploy
        /// plus first requests leave them. The state root uses the reproduced
        /// ePHPm digest of the container path.
        async fn deploy_artifacts(&self, site_key: &str) {
            tokio::fs::create_dir_all(self.sites.join(site_key).join("wp-content"))
                .await
                .unwrap();
            for suffix in ["db", "db-wal", "db-shm", "db-journal"] {
                tokio::fs::write(self.sqlite.join(format!("{site_key}.{suffix}")), b"x")
                    .await
                    .unwrap();
            }
            tokio::fs::write(
                self.overrides.join(format!("{site_key}.toml")),
                b"document_root = \"public\"\n",
            )
            .await
            .unwrap();
            let state = self
                .temp_base
                .join(state_root_name(&self.sites.join(site_key)));
            tokio::fs::create_dir_all(state.join("sessions"))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn teardown_removes_every_artifact_class() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(site_key).await;
        // A staging dir from a deploy that died mid-swap.
        tokio::fs::create_dir_all(f.sites.join(format!("{site_key}.tmp")))
            .await
            .unwrap();

        teardown_preview(site_key, &f.ctx()).await.unwrap();

        assert!(
            !f.sites.join(site_key).exists(),
            "vhost dir must be removed"
        );
        assert!(
            !f.sites.join(format!("{site_key}.tmp")).exists(),
            "staging dir must be removed"
        );
        for suffix in ["db", "db-wal", "db-shm", "db-journal"] {
            assert!(
                !f.sqlite.join(format!("{site_key}.{suffix}")).exists(),
                "database artifact .{suffix} must be removed"
            );
        }
        assert!(
            !f.overrides.join(format!("{site_key}.toml")).exists(),
            "override file must be removed"
        );
        let mut entries = tokio::fs::read_dir(&f.temp_base).await.unwrap();
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "state root must be removed"
        );
    }

    #[tokio::test]
    async fn teardown_is_completeness_tested_not_just_the_vhost_dir() {
        // The regression this module exists to prevent: everything OUTSIDE the
        // vhost dir surviving. Deploy two artifacts only (no vhost dir at all)
        // and verify teardown still reaps them.
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-9";
        tokio::fs::write(f.sqlite.join(format!("{site_key}.db")), b"x")
            .await
            .unwrap();
        tokio::fs::write(f.overrides.join(format!("{site_key}.toml")), b"")
            .await
            .unwrap();

        teardown_preview(site_key, &f.ctx()).await.unwrap();
        assert!(!f.sqlite.join(format!("{site_key}.db")).exists());
        assert!(!f.overrides.join(format!("{site_key}.toml")).exists());
    }

    #[tokio::test]
    async fn teardown_never_touches_a_neighbouring_site() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        let neighbour = "ephpm-my-blog-pr-8";
        f.deploy_artifacts(site_key).await;
        f.deploy_artifacts(neighbour).await;
        // A neighbour whose site_key extends ours must also survive the sweep.
        let prefix_neighbour = "ephpm-my-blog-pr-71";
        f.deploy_artifacts(prefix_neighbour).await;

        teardown_preview(site_key, &f.ctx()).await.unwrap();

        for survivor in [neighbour, prefix_neighbour] {
            assert!(f.sites.join(survivor).exists(), "{survivor} vhost dir");
            assert!(
                f.sqlite.join(format!("{survivor}.db")).exists(),
                "{survivor} database"
            );
            assert!(
                f.overrides.join(format!("{survivor}.toml")).exists(),
                "{survivor} override"
            );
            assert!(
                f.temp_base
                    .join(state_root_name(&f.sites.join(survivor)))
                    .exists(),
                "{survivor} state root"
            );
        }
    }

    #[tokio::test]
    async fn state_root_swept_by_pattern_when_the_digest_differs() {
        // A state root created by an ePHPm that hashed a different container
        // path (canonicalization, TMPDIR history) — reproduced digest misses,
        // the exact-shape sweep must still find it.
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        let foreign = f.temp_base.join(format!("{site_key}-00000000deadbeef"));
        tokio::fs::create_dir_all(foreign.join("tmp"))
            .await
            .unwrap();
        // Same prefix but NOT the state-root shape: must survive.
        let short = f.temp_base.join(format!("{site_key}-beef"));
        // A different digest value so it cannot collide with `foreign` on a
        // case-insensitive filesystem (Windows dev machines).
        let upper = f.temp_base.join(format!("{site_key}-11111111DEADBEEF"));
        let longer = f.temp_base.join(format!("{site_key}-x-00000000deadbeef"));
        for dir in [&short, &upper, &longer] {
            tokio::fs::create_dir_all(dir).await.unwrap();
        }

        teardown_preview(site_key, &f.ctx()).await.unwrap();

        assert!(
            !foreign.exists(),
            "pattern-matching state root must be swept"
        );
        assert!(short.exists(), "non-16-hex suffix must survive");
        assert!(upper.exists(), "uppercase hex is not ePHPm's shape");
        assert!(longer.exists(), "extra component must survive");
    }

    #[tokio::test]
    async fn teardown_is_ok_when_everything_is_already_absent() {
        // GitHub sends `closed` for PRs that never deployed, and cluster nodes
        // race teardown of the same preview.
        let f = Fixture::new().await;
        teardown_preview("ephpm-my-blog-pr-7", &f.ctx())
            .await
            .expect("absent preview teardown must succeed");
    }

    #[tokio::test]
    async fn teardown_is_ok_when_the_temp_base_does_not_exist() {
        let f = Fixture::new().await;
        tokio::fs::remove_dir_all(&f.temp_base).await.unwrap();
        teardown_preview("ephpm-my-blog-pr-7", &f.ctx())
            .await
            .expect("missing vhost temp base is not an error");
    }

    #[tokio::test]
    async fn unconfigured_knobs_leave_those_artifacts_in_place() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(site_key).await;

        let ctx = TeardownContext {
            sites_dir: &f.sites,
            sqlite_dir: None,
            site_overrides_dir: None,
            vhost_temp_base: Some(&f.temp_base),
        };
        teardown_preview(site_key, &ctx).await.unwrap();

        assert!(
            !f.sites.join(site_key).exists(),
            "vhost dir is always removed"
        );
        assert!(
            f.sqlite.join(format!("{site_key}.db")).exists(),
            "no --sqlite-dir: database must be left alone"
        );
        assert!(
            f.overrides.join(format!("{site_key}.toml")).exists(),
            "no --site-overrides-dir: override must be left alone"
        );
    }

    #[tokio::test]
    async fn unsafe_labels_are_refused_before_anything_is_touched() {
        let f = Fixture::new().await;
        let canary = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(canary).await;

        for site_key in ["", ".", "..", "a/b", "a\\b", "a:b", "a\0b", "../escape"] {
            let err = teardown_preview(site_key, &f.ctx())
                .await
                .expect_err(&format!("site_key {site_key:?} must be refused"));
            assert!(err.to_string().contains("refusing teardown"), "{err}");
        }
        // Nothing was removed by any refused attempt.
        assert!(f.sites.join(canary).exists());
        assert!(f.sqlite.join(format!("{canary}.db")).exists());
    }

    #[test]
    fn state_root_name_matches_its_own_pattern() {
        // The reproduced name and the sweep pattern must agree, or the sweep
        // could orphan what the reproduction targets (and vice versa).
        let container = Path::new("/var/www/sites/ephpm-my-blog-pr-7");
        let name = state_root_name(container);
        assert!(name.starts_with("ephpm-my-blog-pr-7-"));
        assert!(matches_state_root_name(&name, "ephpm-my-blog-pr-7"));
        assert!(!matches_state_root_name(&name, "ephpm-my-blog-pr-71"));
        assert!(!matches_state_root_name(&name, "ephpm-my-blog-pr-"));
    }

    #[test]
    fn state_root_name_is_stable_across_calls() {
        // ePHPm relies on the digest being deterministic (fixed-key
        // DefaultHasher); so does our reproduction.
        let container = Path::new("/var/www/sites/some-preview");
        assert_eq!(state_root_name(container), state_root_name(container));
    }

    #[test]
    fn sanitize_matches_ephpm_rules() {
        // Verbatim port of ePHPm's sanitize_path_label semantics.
        assert_eq!(
            sanitize_path_label("ephpm-my-blog-pr-7"),
            "ephpm-my-blog-pr-7"
        );
        assert_eq!(sanitize_path_label("weird name!"), "weird_name_");
        assert_eq!(
            sanitize_path_label("dots.and_underscores-ok"),
            "dots.and_underscores-ok"
        );
        assert_eq!(sanitize_path_label(""), "site");
        assert_eq!(sanitize_path_label(&"a".repeat(100)).len(), 64);
    }
}
