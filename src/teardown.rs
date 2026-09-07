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
//!   `<temp>/ephpm-vhosts/` — sessions, uploads, PHP temp files;
//! * `<state_dir>/applied/<label>` — switchboard-api's record of the desired
//!   state **this node** has already materialized (issue #19), but only when it
//!   is unparseable drift. A marker recording this teardown is deliberately
//!   *kept* (switchboard#24) — see [`remove_applied_marker`]. Keyed by the
//!   preview *label*, not the site key; see [`Preview`].
//!
//! # An unconfigured root is not a quiet skip (issue #17)
//!
//! `sqlite_dir` and `site_overrides_dir` are still `Option`, because their
//! locations are ePHPm's configuration and this daemon cannot derive them. What
//! changed is what an unset one *means*: the artifact class is named in the
//! teardown's error and the job fails, so it lands in `queue/claimed/` for an
//! operator instead of reporting success over a tenant database still on disk.
//! An operator who genuinely runs without those roots says so once —
//! `--allow-incomplete-teardown`, surfaced here as [`TeardownContext::allow_incomplete`]
//! — and then gets a `WARN` per teardown naming what was not attempted.
//!
//! The live symptom this closes: the preview cluster's systemd unit passed
//! neither flag, so every webhook-driven teardown removed the vhost directory,
//! left `<key>.db` + `-wal` behind, and reported success.
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
//!
//! That "every node materializes it" is a property of switchboard-api, not a
//! given, and it is what makes the `applied/<label>` receipt load-bearing here.
//! A teardown is published to the cluster KV once; each node must notice it
//! independently, so the published desired state has to outlive the *first*
//! node's drain. It follows that the desired state is still on offer when this
//! teardown finishes, and a node that deletes its own receipt will be handed
//! the same teardown again on its next drain, and the next. Keeping the receipt
//! is the whole brake. See switchboard#24, and switchboard-api's `DrainHandler`
//! for the other half of the contract.

use std::path::{Path, PathBuf};

use anyhow::Context;

/// Directory under `state_dir` holding switchboard-api's per-label record of
/// the desired state this node has already queued (`<intent>@<sha>`).
const APPLIED_DIR: &str = "applied";

/// The two names a preview answers to, and why both are needed.
///
/// They are *usually* the same string and that is exactly the trap: on a node
/// with `sites_domain_suffix` configured (what the preview cluster runs) the
/// site key is the bare label, so a mix-up is invisible. On a node without one
/// the site key is the full preview FQDN while the API's marker is still filed
/// under the short label, and a mix-up silently reaps nothing. Named fields
/// make the two impossible to swap at a call site.
#[derive(Debug, Clone, Copy)]
pub struct Preview<'a> {
    /// ePHPm's **canonical site key** ([`crate::site_key`]) — names every
    /// artifact ePHPm created: the vhost directory, the database, the override.
    pub site_key: &'a str,
    /// switchboard-api's **preview label** (`preview.label` in the job file) —
    /// names the API's `applied/<label>` desired-state marker.
    pub label: &'a str,
}

/// Non-repo inputs to a teardown: where the preview's artifacts live.
///
/// `sqlite_dir` and `site_overrides_dir` mirror ePHPm's `[db.sqlite].dir` and
/// `[server].site_overrides_dir`. When one is `None` the teardown **fails**,
/// naming the artifact it could not remove, unless `allow_incomplete` says the
/// operator has accepted that (see the module docs and issue #17).
pub struct TeardownContext<'a> {
    /// ePHPm sites directory — previews live at `<sites_dir>/<site_key>/`.
    pub sites_dir: &'a Path,
    /// ePHPm's `[db.sqlite].dir`, where `<site_key>.db` lives. `None` = this
    /// node cannot remove per-site databases at all.
    pub sqlite_dir: Option<&'a Path>,
    /// ePHPm's `site_overrides_dir`, where `<site_key>.toml` lives. `None` =
    /// this node cannot remove override files at all.
    pub site_overrides_dir: Option<&'a Path>,
    /// The directory ePHPm keeps per-vhost state roots in. `None` = use this
    /// process's `std::env::temp_dir()/ephpm-vhosts`, which matches ePHPm's
    /// default when both processes see the same `TMPDIR` (set the flag
    /// explicitly when they don't, e.g. systemd `PrivateTmp`). Unlike the two
    /// above this default is a real one, so `None` skips nothing.
    pub vhost_temp_base: Option<&'a Path>,
    /// switchboard-api's state directory (the daemon's `--state-dir`), whose
    /// `applied/<label>` marker records the desired state this node has queued.
    /// Always known — it is the queue's own root.
    pub state_dir: &'a Path,
    /// The operator has acknowledged (`--allow-incomplete-teardown`) that this
    /// node leaves some artifact classes behind. Turns the failure above into a
    /// `WARN` naming the same artifacts.
    pub allow_incomplete: bool,
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
/// An artifact class this node is **not configured** to remove counts as a
/// failure too (issue #17): the phases that can run still run, and the error
/// names exactly what was left on disk. `ctx.allow_incomplete` downgrades that
/// to a `WARN` for an operator who has said the incompleteness is intended.
///
/// # Errors
///
/// Returns an error if the site key is not one ePHPm would serve, if any
/// artifact exists but cannot be removed, or if an artifact class was skipped
/// for want of configuration without `allow_incomplete`.
pub async fn teardown_preview(
    preview: &Preview<'_>,
    ctx: &TeardownContext<'_>,
) -> anyhow::Result<()> {
    let Preview { site_key, label } = *preview;
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
        // The defect this module was rewritten for: an unset root used to be a
        // DEBUG line and a successful teardown, so a tenant database survived a
        // closed PR with every signal green.
        skipped(
            &mut failures,
            ctx.allow_incomplete,
            format!(
                "per-site database {site_key}.db (and its -wal/-shm/-journal companions) \
                 was not removed: --sqlite-dir (SWITCHBOARD_SQLITE_DIR) is not configured, \
                 so this daemon does not know where ePHPm keeps [db.sqlite].dir"
            ),
        );
    }

    // (3) The per-site override file the deploy wrote for ePHPm — the document
    // root and the `auto_prepend_file` naming the generated env prepend. The
    // path is derived by `site_override` rather than re-joined here, so one
    // module owns the one filename ePHPm reads.
    if let Some(overrides_dir) = ctx.site_overrides_dir {
        let file = crate::site_override::override_path(overrides_dir, site_key);
        match crate::site_override::remove_override(overrides_dir, site_key).await {
            Ok(()) => {
                tracing::info!(%site_key, path = %file.display(), "removed site override file")
            }
            Err(e) => failures.push(format!("{e:#}")),
        }
    } else {
        skipped(
            &mut failures,
            ctx.allow_incomplete,
            format!(
                "per-site override {site_key}.toml was not removed: \
                 --site-overrides-dir (SWITCHBOARD_SITE_OVERRIDES_DIR) is not configured"
            ),
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

    // (5) switchboard-api's desired-state marker for this preview. Nothing else
    // reaps it: the daemon owns removing the site, so it owns retiring the
    // record that says the site should exist (issue #19).
    if let Err(e) = remove_applied_marker(ctx.state_dir, label).await {
        failures.push(format!("{e:#}"));
    }

    anyhow::ensure!(
        failures.is_empty(),
        "teardown of {site_key} left artifacts behind: {}",
        failures.join("; ")
    );
    Ok(())
}

/// Record an artifact class this node is not configured to remove.
///
/// Unacknowledged it is a failure, so the teardown cannot report success while
/// a tenant database sits on disk. Acknowledged it is a `WARN` carrying the
/// same sentence — never a silent skip, and never `DEBUG`, because the whole
/// defect was that nobody saw it.
fn skipped(failures: &mut Vec<String>, allow_incomplete: bool, what: String) {
    if allow_incomplete {
        tracing::warn!(
            artifact = %what,
            "incomplete teardown (acknowledged by --allow-incomplete-teardown)"
        );
    } else {
        failures.push(what);
    }
}

/// Retire switchboard-api's `applied/<label>` marker if — and only if — it has
/// become unreadable drift.
///
/// The marker records the last `<intent>@<sha>` **this node** materialized into
/// its queue; `/drain` skips a label whose published desired state still matches
/// it. That makes the marker this node's *receipt*, and a receipt is only useful
/// for as long as the thing it acknowledges is still being offered.
///
/// Three cases, and only the last one is removed:
///
/// * a marker recording a **newer deploy** (`deploy@<sha>`) — the API has
///   already materialized a redeploy for this label since our teardown job was
///   queued (a reopened PR, a push after close); dropping it would make the next
///   `/drain` re-queue that deploy needlessly. Leaving it is the conservative
///   half of "clear what is stale, keep what is current";
/// * a marker recording **this teardown** (`teardown@<sha>`) — kept, which is
///   the opposite of what this function used to do (switchboard#24). A teardown
///   is published to the cluster once and must be materialized independently by
///   *every* node, so `switchboard:preview:<label>` now outlives the first
///   node's drain rather than being deleted by it. With the desired state still
///   published, deleting our receipt makes the very next `/drain` two seconds
///   later see `teardown@<sha>` != *(no marker)*, re-queue the identical
///   teardown, tear down nothing, delete the receipt again — a hot loop for the
///   lifetime of the key. The receipt is the loop's only brake. It costs ~50
///   bytes per label and is superseded in place by the next `deploy@<sha>` if
///   the PR is reopened;
/// * anything this cannot parse as `<intent>@<sha>` — an empty file, a
///   truncated write, a future format. That is genuine drift with no meaning to
///   either side, and the cost of dropping it is one redundant (idempotent)
///   `/drain` materialization.
///
/// A label that is not a plain path component aborts only this phase, not the
/// whole teardown — the label names nothing else we remove.
///
/// # Errors
///
/// Returns an error if the label is unsafe to join, or if the marker exists and
/// cannot be read or removed.
async fn remove_applied_marker(state_dir: &Path, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        crate::site_key::is_valid_site_key(label),
        "refusing to touch the applied/ marker: preview label {label:?} is not a \
         single plain path component"
    );
    let path = state_dir.join(APPLIED_DIR).join(label);

    let recorded = match tokio::fs::read_to_string(&path).await {
        Ok(recorded) => recorded,
        // No marker: single-node mode (the webhook path writes none), or a
        // sibling node already reaped it. Not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| {
                format!("failed to read desired-state marker {}", path.display())
            });
        }
    };

    match marker_intent(&recorded) {
        Some(MarkerIntent::Deploy) => {
            tracing::info!(
                %label,
                marker = %recorded.trim(),
                path = %path.display(),
                "leaving switchboard-api's applied/ marker in place — it records a \
                 deploy newer than this teardown"
            );
            return Ok(());
        }
        Some(MarkerIntent::Teardown) => {
            tracing::debug!(
                %label,
                marker = %recorded.trim(),
                path = %path.display(),
                "leaving switchboard-api's applied/ marker in place — it is this \
                 node's receipt for the teardown just performed, and removing it \
                 would make /drain re-queue the teardown every interval while the \
                 desired state is still published (switchboard#24)"
            );
            return Ok(());
        }
        None => {}
    }

    match tokio::fs::remove_file(&path).await {
        Ok(()) => {
            tracing::info!(
                %label,
                marker = %recorded.trim(),
                path = %path.display(),
                "removed an unparseable switchboard-api desired-state marker"
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e)
            .with_context(|| format!("failed to remove desired-state marker {}", path.display())),
    }
}

/// The intent half of an `applied/<label>` marker body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerIntent {
    Deploy,
    Teardown,
}

/// Parse the intent out of an `applied/<label>` marker body.
///
/// The format is switchboard-api's `<intent>@<sha>`. `None` means the body is
/// neither — an empty file, a partial write, a format this build predates —
/// which [`remove_applied_marker`] treats as drift and reaps.
fn marker_intent(marker: &str) -> Option<MarkerIntent> {
    match marker.trim().split('@').next().map(str::trim) {
        Some("deploy") => Some(MarkerIntent::Deploy),
        Some("teardown") => Some(MarkerIntent::Teardown),
        _ => None,
    }
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

    /// The common shape: on a node with `sites_domain_suffix` configured the
    /// site key *is* the label, which is why a key/label mix-up hides there.
    /// Tests that care about the difference build [`Preview`] by hand.
    fn preview(name: &str) -> Preview<'_> {
        Preview {
            site_key: name,
            label: name,
        }
    }

    /// A context pointing every knob at subdirectories of one tempdir.
    struct Fixture {
        _root: tempfile::TempDir,
        sites: PathBuf,
        sqlite: PathBuf,
        overrides: PathBuf,
        temp_base: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        async fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let sites = root.path().join("sites");
            let sqlite = root.path().join("sqlite");
            let overrides = root.path().join("overrides");
            let temp_base = root.path().join("ephpm-vhosts");
            let state = root.path().join(".switchboard");
            for dir in [&sites, &sqlite, &overrides, &temp_base, &state] {
                tokio::fs::create_dir_all(dir).await.unwrap();
            }
            tokio::fs::create_dir_all(state.join(APPLIED_DIR))
                .await
                .unwrap();
            Self {
                _root: root,
                sites,
                sqlite,
                overrides,
                temp_base,
                state,
            }
        }

        fn ctx(&self) -> TeardownContext<'_> {
            TeardownContext {
                sites_dir: &self.sites,
                sqlite_dir: Some(&self.sqlite),
                site_overrides_dir: Some(&self.overrides),
                vhost_temp_base: Some(&self.temp_base),
                state_dir: &self.state,
                allow_incomplete: false,
            }
        }

        /// switchboard-api's desired-state marker for a label.
        fn marker(&self, label: &str) -> PathBuf {
            self.state.join(APPLIED_DIR).join(label)
        }

        async fn write_marker(&self, label: &str, body: &str) {
            tokio::fs::write(self.marker(label), body).await.unwrap();
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

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();

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

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();
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

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();

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

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();

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
        teardown_preview(&preview("ephpm-my-blog-pr-7"), &f.ctx())
            .await
            .expect("absent preview teardown must succeed");
    }

    #[tokio::test]
    async fn teardown_is_ok_when_the_temp_base_does_not_exist() {
        let f = Fixture::new().await;
        tokio::fs::remove_dir_all(&f.temp_base).await.unwrap();
        teardown_preview(&preview("ephpm-my-blog-pr-7"), &f.ctx())
            .await
            .expect("missing vhost temp base is not an error");
    }

    // ── issue #17: an unconfigured root must not pass as success ────────

    /// The live defect: the preview cluster's unit passed neither `--sqlite-dir`
    /// nor `--site-overrides-dir`, so every webhook teardown removed the vhost
    /// directory, left the tenant database on disk, and reported success. It
    /// must now fail, naming the database it did not remove.
    #[tokio::test]
    async fn unconfigured_roots_fail_the_teardown_and_name_what_was_left() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(site_key).await;

        let ctx = TeardownContext {
            sites_dir: &f.sites,
            sqlite_dir: None,
            site_overrides_dir: None,
            vhost_temp_base: Some(&f.temp_base),
            state_dir: &f.state,
            allow_incomplete: false,
        };
        let err = teardown_preview(&preview(site_key), &ctx)
            .await
            .expect_err("a teardown that abandons a tenant database must not report success");

        let msg = format!("{err:#}");
        assert!(
            msg.contains(site_key),
            "the error must name the site: {msg}"
        );
        assert!(
            msg.contains("--sqlite-dir"),
            "the error must name the missing flag: {msg}"
        );
        assert!(
            msg.contains("--site-overrides-dir"),
            "every skipped class is named, not just the first: {msg}"
        );

        // Everything it *could* do, it still did — a partial teardown beats no
        // teardown, and the failure is what surfaces the rest.
        assert!(
            !f.sites.join(site_key).exists(),
            "the vhost dir is still removed"
        );
        assert!(
            f.sqlite.join(format!("{site_key}.db")).exists(),
            "the database is what the error is about — it is still there"
        );
    }

    /// An operator who genuinely has no per-site databases says so once. Then
    /// the skip is a WARN and the teardown succeeds — the artifacts are still
    /// left, but nobody is being told a lie about it.
    #[tokio::test]
    async fn acknowledged_incompleteness_succeeds_and_leaves_those_artifacts() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(site_key).await;

        let ctx = TeardownContext {
            sites_dir: &f.sites,
            sqlite_dir: None,
            site_overrides_dir: None,
            vhost_temp_base: Some(&f.temp_base),
            state_dir: &f.state,
            allow_incomplete: true,
        };
        teardown_preview(&preview(site_key), &ctx).await.unwrap();

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

    /// One root configured and one not: the error names only the one that was
    /// actually skipped, so it stays actionable.
    #[tokio::test]
    async fn a_single_unconfigured_root_names_only_itself() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(site_key).await;

        let ctx = TeardownContext {
            sites_dir: &f.sites,
            sqlite_dir: Some(&f.sqlite),
            site_overrides_dir: None,
            vhost_temp_base: Some(&f.temp_base),
            state_dir: &f.state,
            allow_incomplete: false,
        };
        let err = teardown_preview(&preview(site_key), &ctx)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--site-overrides-dir"), "{msg}");
        assert!(
            !msg.contains("--sqlite-dir"),
            "a configured root must not be reported as skipped: {msg}"
        );
        assert!(
            !f.sqlite.join(format!("{site_key}.db")).exists(),
            "the configured class is still reaped despite the failure"
        );
    }

    // ── issue #19: switchboard-api's applied/ marker ────────────────────

    /// switchboard#24: the receipt for the teardown we just performed must
    /// survive it. The shared desired state (`switchboard:preview:<label>`)
    /// stays published until every node has had a chance to materialize it, so
    /// a node that deletes its own receipt re-queues the same teardown on its
    /// next `/drain` — every interval, forever.
    #[tokio::test]
    async fn teardown_keeps_its_own_receipt_marker() {
        let f = Fixture::new().await;
        let site_key = "ephpm-wordpress-sample-pr-1";
        let marker = "teardown@0123456789abcdef0123456789abcdef01234567";
        f.deploy_artifacts(site_key).await;
        f.write_marker(site_key, &format!("{marker}\n")).await;

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();

        assert_eq!(
            tokio::fs::read_to_string(f.marker(site_key))
                .await
                .expect("the teardown receipt must survive the teardown")
                .trim(),
            marker,
            "deleting the receipt makes /drain re-queue this teardown every \
             interval while the desired state is still published"
        );
        assert!(
            !f.sites.join(site_key).exists(),
            "the preview itself is still removed"
        );
    }

    /// A marker body neither side can parse is drift, and is still reaped.
    #[tokio::test]
    async fn teardown_clears_an_unparseable_desired_state_marker() {
        let f = Fixture::new().await;
        let site_key = "ephpm-wordpress-sample-pr-1";
        f.deploy_artifacts(site_key).await;
        f.write_marker(site_key, "").await;

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();

        assert!(
            !f.marker(site_key).exists(),
            "a marker with no backing site is a desired-state record that can \
             resurrect the preview — teardown owns retiring it"
        );
    }

    /// The marker is filed under the **label**; every other artifact is filed
    /// under the site key. On a node with no `sites_domain_suffix` those differ,
    /// and a teardown that used the key would silently reap nothing.
    #[tokio::test]
    async fn the_marker_is_keyed_by_label_not_by_site_key() {
        let f = Fixture::new().await;
        let label = "ephpm-wordpress-sample-pr-1";
        let site_key = "ephpm-wordpress-sample-pr-1.preview.ephpm.dev";
        f.deploy_artifacts(site_key).await;
        // Unparseable, so this exercises the branch that *does* touch the file
        // — the keying bug it guards against is invisible on a no-op branch.
        f.write_marker(label, "garbage").await;

        teardown_preview(&Preview { site_key, label }, &f.ctx())
            .await
            .unwrap();

        assert!(
            !f.marker(label).exists(),
            "the label-keyed marker is the one consulted, not a key-named one"
        );
        assert!(
            !f.sites.join(site_key).exists(),
            "the key-named vhost dir is removed"
        );
    }

    /// A marker recording a deploy newer than this teardown is current state,
    /// not drift: dropping it would make the next `/drain` re-queue that deploy.
    #[tokio::test]
    async fn a_marker_recording_a_newer_deploy_is_left_alone() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        f.write_marker(site_key, "deploy@0123456789abcdef").await;

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();

        assert!(
            f.marker(site_key).exists(),
            "a deploy marker is the API's current desired state"
        );
    }

    #[tokio::test]
    async fn an_absent_marker_directory_is_not_a_failure() {
        // Single-node mode writes no markers at all, and a sibling node may
        // have reaped ours already.
        let f = Fixture::new().await;
        tokio::fs::remove_dir_all(f.state.join(APPLIED_DIR))
            .await
            .unwrap();
        teardown_preview(&preview("ephpm-my-blog-pr-7"), &f.ctx())
            .await
            .expect("no marker is the common case, not an error");
    }

    #[tokio::test]
    async fn a_neighbouring_label_keeps_its_marker() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        // Unparseable, so the one branch that removes a file actually runs —
        // a teardown marker is now kept, and a no-op branch cannot show that
        // the removal is scoped to exactly one label.
        f.write_marker(site_key, "garbage").await;
        f.write_marker("ephpm-my-blog-pr-71", "garbage").await;
        f.write_marker("ephpm-my-blog-pr-8", "garbage").await;

        teardown_preview(&preview(site_key), &f.ctx())
            .await
            .unwrap();

        assert!(!f.marker(site_key).exists());
        assert!(
            f.marker("ephpm-my-blog-pr-71").exists(),
            "a label with the target as a prefix is a different label"
        );
        assert!(f.marker("ephpm-my-blog-pr-8").exists());
    }

    /// A label is a path component under the API's state dir. An unsafe one
    /// fails *that phase* — it names nothing else — rather than the removal of
    /// artifacts the (valid) site key does name.
    #[tokio::test]
    async fn an_unsafe_label_fails_only_the_marker_phase() {
        let f = Fixture::new().await;
        let site_key = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(site_key).await;

        let err = teardown_preview(
            &Preview {
                site_key,
                label: "../../escape",
            },
            &f.ctx(),
        )
        .await
        .expect_err("a traversing label must be refused");
        assert!(format!("{err:#}").contains("applied/ marker"), "{err:#}");
        assert!(
            !f.sqlite.join(format!("{site_key}.db")).exists(),
            "the site's own artifacts are still reaped"
        );
    }

    #[test]
    fn marker_bodies_are_classified_by_intent() {
        assert_eq!(
            marker_intent("deploy@0123456789abcdef"),
            Some(MarkerIntent::Deploy)
        );
        assert_eq!(marker_intent(" deploy@abc \n"), Some(MarkerIntent::Deploy));
        assert_eq!(
            marker_intent("teardown@0123456789abcdef0123456789abcdef01234567"),
            Some(MarkerIntent::Teardown)
        );
        assert_eq!(
            marker_intent("\tteardown@abc\n"),
            Some(MarkerIntent::Teardown)
        );
        // Unreadable bodies are drift and get reaped: a redundant (idempotent)
        // re-materialization is cheaper than a marker nobody can interpret.
        assert_eq!(marker_intent(""), None);
        assert_eq!(marker_intent("deployment@abc"), None);
        assert_eq!(marker_intent("whatever the next schema writes"), None);
    }

    #[tokio::test]
    async fn unsafe_labels_are_refused_before_anything_is_touched() {
        let f = Fixture::new().await;
        let canary = "ephpm-my-blog-pr-7";
        f.deploy_artifacts(canary).await;

        for site_key in ["", ".", "..", "a/b", "a\\b", "a:b", "a\0b", "../escape"] {
            let err = teardown_preview(&preview(site_key), &f.ctx())
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
