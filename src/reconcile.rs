//! Level-triggered convergence of this node's on-disk previews to the cluster's
//! desired state.
//!
//! # The bug this closes
//!
//! Preview fan-out is edge-triggered. switchboard-api publishes desired state
//! into gossip-replicated KV and bumps a `switchboard:gen` counter; each node's
//! PHP `DrainHandler` only walks `switchboard:index` when `gen` has advanced
//! past its own `last_gen`, and once it records itself current at a generation
//! it never re-walks. That makes correctness depend on the counter, and the
//! counter is a *separate* gossip key from the content it guards:
//!
//! * a `gen` increment that is lost or not-yet-replicated leaves a node's cursor
//!   "current" at a generation whose teardown it never materialized — so every
//!   later drain short-circuits and the torn-down preview stays served, with its
//!   tenant database and docroot override on disk, every health check green
//!   (switchboard#24, and the gen-vs-key-content propagation race);
//! * the index itself is a read-modify-write with an acknowledged lost-update
//!   window, so a label can transiently vanish from it.
//!
//! Both are the same class of fault: an edge trigger that misses a state it
//! never observed an *event* for. The symptom on the live cluster is override
//! `.toml` counts drifting between nodes and orphaned overrides for torn-down
//! previews lingering as 404s.
//!
//! # The fix: reconcile the level, not the edge
//!
//! This module runs on its own interval, independent of `gen`, and converges the
//! node's actual on-disk state to what the KV *currently says*:
//!
//! * **Prune.** For every preview directory under `sites_dir`, it reads that
//!   site's **own** `switchboard:preview:<label>` key ([`crate::kv::ClusterReader`]).
//!   A key that is present with `intent: deploy` is live and kept; a key that is
//!   a genuine nil (retired — its TTL elapsed) or carries `intent: teardown` is
//!   an orphan and is removed with the same KEEP-guarded, exact-path
//!   [`crate::teardown::teardown_preview`] the webhook teardown path uses. The
//!   per-site key is a plain `set` (only teardown ever gives it a TTL), so it is
//!   immune to *both* the `gen` propagation race and the index lost-update race —
//!   pruning never trusts the index.
//! * **Add.** For every label the index lists whose preview key says `deploy`
//!   but whose directory is absent, it enqueues the exact job document into the
//!   node's queue, so the existing claim → coalesce → validate → deploy path
//!   provisions it. This recovers a deploy a node simply never saw.
//!
//! # Why this is safe under concurrent drains
//!
//! Two nodes reconciling the same desired state converge rather than fight:
//! teardown and enqueue are both idempotent (teardown tolerates already-absent
//! artifacts; a materialized job carries a fresh per-node filename and is
//! coalesced). The gen counter is kept as the PHP fast-path's optimization hint;
//! nothing here depends on it.
//!
//! # Fail-safe posture
//!
//! * A KV read failure aborts the whole cycle — the reconcile does **nothing**
//!   rather than prune against an unreadable authority.
//! * Infra/non-preview vhosts (`switchboard`, `site-a`, …) are protected by an
//!   explicit keep-list plus the API's own site key.
//! * Pruning is opt-in (`--reconcile-prune`); until it is set the reconcile logs
//!   what it *would* remove at WARN, which alone would have surfaced the original
//!   incident that was only found by hand-diffing three nodes.
//! * A per-cycle prune cap bounds the blast radius of a misconfiguration to a few
//!   removals per interval, leaving the loud logs time to be noticed.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::job::{Intent, Job};
use crate::kv::ClusterReader;
use crate::queue::Queue;
use crate::site_key;
use crate::teardown::{self, Preview, TeardownContext};

/// Everything one reconcile pass needs. Mirrors the teardown/deploy context the
/// job path already assembles from [`crate::config::Config`], plus the reconcile
/// policy knobs.
pub struct ReconcileContext<'a> {
    // ── where the artifacts live (same as `TeardownContext`) ────────────
    pub sites_dir: &'a Path,
    pub sqlite_dir: Option<&'a Path>,
    pub site_overrides_dir: Option<&'a Path>,
    pub vhost_temp_base: Option<&'a Path>,
    pub state_dir: &'a Path,
    pub allow_incomplete: bool,

    // ── KV desired-state source ─────────────────────────────────────────
    /// ePHPm's RESP listener (`[kv.redis_compat] listen`).
    pub kv_addr: &'a str,
    /// ePHPm's `[kv] secret`. Required — the reconcile reads desired state over
    /// RESP, so a node without it cannot reconcile and the loop is not started.
    pub kv_secret: &'a str,
    /// The switchboard-api vhost's canonical site key, whose keyspace holds the
    /// `switchboard:*` desired-state keys.
    pub api_site: &'a str,

    // ── host → site-key derivation (same rule as the deploy path) ────────
    pub preview_domain: &'a str,
    pub sites_domain_suffix: Option<&'a str>,

    // ── policy ──────────────────────────────────────────────────────────
    /// Vhost directory names never touched by pruning (infra/test sites). The
    /// API site key is always added to this set by the caller.
    pub keep: &'a HashSet<String>,
    /// Actually remove orphans. When `false` the reconcile is observability-only:
    /// it logs each orphan it *would* prune at WARN and removes nothing.
    pub prune: bool,
    /// Enqueue deploys for desired previews whose directory is absent.
    pub deploy_missing: bool,
    /// Upper bound on prunes performed in a single pass (blast-radius guard).
    pub max_prunes_per_cycle: usize,

    /// The node's job queue (for the add direction).
    pub queue: &'a Queue,
}

/// What one reconcile pass observed and did. Returned for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Preview directories found under `sites_dir` (excluding keep-list and
    /// staging `.tmp` dirs).
    pub on_disk: usize,
    /// Directories whose own preview key says `deploy` — live, kept.
    pub live: usize,
    /// Orphans removed (0 when `--reconcile-prune` is unset).
    pub pruned: usize,
    /// Orphans that would be removed but for `--reconcile-prune` being unset.
    pub would_prune: usize,
    /// Orphans whose removal returned an error.
    pub prune_failed: usize,
    /// Orphans left for a later pass because the per-cycle cap was hit.
    pub prune_deferred: usize,
    /// Deploys enqueued for desired-but-absent previews.
    pub deployed: usize,
    /// Desired-but-absent previews skipped because a job for them is already
    /// queued or in flight.
    pub deploy_skipped: usize,
}

/// A single orphan to remove: its site key (names every ePHPm artifact) and its
/// reconstructed label (names the API's `applied/<label>` marker).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrunePlan {
    site_key: String,
    label: String,
}

/// The decisions a pass reached, separated from executing them so the logic is
/// unit-testable without a filesystem or a KV server.
#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    prune: Vec<PrunePlan>,
    deploy: Vec<String>,
}

/// Run one reconcile pass.
///
/// # Errors
///
/// Returns an error only if the KV desired-state read fails — the caller logs it
/// and waits for the next interval. Individual prune failures are counted in the
/// [`ReconcileReport`], not surfaced as an error, so one wedged site does not
/// stop the rest converging.
pub async fn reconcile_once(ctx: &ReconcileContext<'_>) -> anyhow::Result<ReconcileReport> {
    let suffix = ctx.sites_domain_suffix;
    let domain = ctx.preview_domain;

    // (1) What is actually on disk.
    let on_disk = list_preview_dirs(ctx.sites_dir, ctx.keep)?;

    // (2) The labels those directories reconstruct to, so the snapshot can
    // classify an orphan whose index entry was already pruned from its own key.
    let mut disk_labels: Vec<String> = Vec::with_capacity(on_disk.len());
    for site in &on_disk {
        let label = label_for_site_key(site, suffix, domain);
        if !disk_labels.contains(&label) {
            disk_labels.push(label);
        }
    }

    // (3) One consistent read of desired state. A failure aborts the pass — we
    // never prune against an authority we could not read.
    let reader = ClusterReader::new(ctx.kv_addr, ctx.kv_secret, ctx.api_site);
    let snapshot = reader.snapshot(&disk_labels).await?;

    // (4) Decide.
    let plan = build_plan(
        &on_disk,
        &snapshot.index,
        &snapshot.docs,
        suffix,
        domain,
        ctx.deploy_missing,
    );

    // (5) Execute.
    let mut report = ReconcileReport {
        on_disk: on_disk.len(),
        live: on_disk.len().saturating_sub(plan.prune.len()),
        ..ReconcileReport::default()
    };
    execute_prune(ctx, &plan, &mut report).await;
    execute_deploy(ctx, &plan, &snapshot.docs, &mut report);

    tracing::info!(
        on_disk = report.on_disk,
        live = report.live,
        pruned = report.pruned,
        would_prune = report.would_prune,
        prune_failed = report.prune_failed,
        prune_deferred = report.prune_deferred,
        deployed = report.deployed,
        deploy_skipped = report.deploy_skipped,
        prune_enabled = ctx.prune,
        deploy_missing_enabled = ctx.deploy_missing,
        "reconcile pass complete"
    );
    Ok(report)
}

/// Remove (or, in dry-run, report) each planned orphan.
async fn execute_prune(ctx: &ReconcileContext<'_>, plan: &Plan, report: &mut ReconcileReport) {
    for target in &plan.prune {
        if report.pruned + report.prune_failed >= ctx.max_prunes_per_cycle {
            // Bound the blast radius: the rest wait for the next pass, so a
            // misconfiguration cannot wipe the fleet in one tick and the WARN
            // logs above have time to be noticed.
            report.prune_deferred += 1;
            continue;
        }

        if !ctx.prune {
            report.would_prune += 1;
            tracing::warn!(
                site_key = %target.site_key,
                label = %target.label,
                "reconcile: orphan preview on disk with no live desired state — \
                 WOULD prune (set --reconcile-prune to remove it)"
            );
            continue;
        }

        let tctx = TeardownContext {
            sites_dir: ctx.sites_dir,
            sqlite_dir: ctx.sqlite_dir,
            site_overrides_dir: ctx.site_overrides_dir,
            vhost_temp_base: ctx.vhost_temp_base,
            state_dir: ctx.state_dir,
            allow_incomplete: ctx.allow_incomplete,
            kv_secret: Some(ctx.kv_secret),
            kv_addr: ctx.kv_addr,
        };
        let preview = Preview {
            site_key: &target.site_key,
            label: &target.label,
        };
        match teardown::teardown_preview(&preview, &tctx).await {
            Ok(()) => {
                report.pruned += 1;
                tracing::info!(
                    site_key = %target.site_key,
                    "reconcile: pruned an orphan preview (no live desired state)"
                );
            }
            Err(e) => {
                report.prune_failed += 1;
                tracing::error!(
                    site_key = %target.site_key,
                    error = %format!("{e:#}"),
                    "reconcile: failed to prune an orphan preview"
                );
            }
        }
    }
}

/// Enqueue a deploy for each planned add whose job is not already queued.
fn execute_deploy(
    ctx: &ReconcileContext<'_>,
    plan: &Plan,
    docs: &HashMap<String, Option<String>>,
    report: &mut ReconcileReport,
) {
    for label in &plan.deploy {
        // A job for an absent-but-desired preview is only worth writing if one
        // is not already in flight — the daemon's coalescing would collapse a
        // duplicate anyway, but not writing it keeps a slow deploy from being
        // restarted every interval.
        match ctx.queue.has_job_for_label(label) {
            Ok(true) => {
                report.deploy_skipped += 1;
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    %label,
                    error = %format!("{e:#}"),
                    "reconcile: could not check the queue for an existing job — enqueuing anyway"
                );
            }
        }

        let Some(Some(raw)) = docs.get(label) else {
            // Classified deploy above, so the document was present; this only
            // trips on a race where it vanished between read and here.
            continue;
        };
        match ctx.queue.enqueue(raw.as_bytes()) {
            Ok(name) => {
                report.deployed += 1;
                tracing::info!(
                    %label,
                    job = %name,
                    "reconcile: enqueued a deploy for a desired preview missing from disk"
                );
            }
            Err(e) => tracing::error!(
                %label,
                error = %format!("{e:#}"),
                "reconcile: failed to enqueue a missing deploy"
            ),
        }
    }
}

/// Decide what to prune and what to deploy. Pure — no IO — so it can be tested
/// against hand-built desired-state maps.
fn build_plan(
    on_disk: &[String],
    index: &[String],
    docs: &HashMap<String, Option<String>>,
    suffix: Option<&str>,
    preview_domain: &str,
    deploy_missing: bool,
) -> Plan {
    let mut plan = Plan::default();

    // Prune: classify each on-disk site from its OWN preview key. The index is
    // deliberately not consulted here — a per-site key is immune to the index's
    // lost-update race, so this is the authority that cannot false-positive a
    // live preview into an orphan.
    for site in on_disk {
        let label = label_for_site_key(site, suffix, preview_domain);
        if matches!(classify(docs.get(&label)), Desired::Live) {
            continue;
        }
        plan.prune.push(PrunePlan {
            site_key: site.clone(),
            label,
        });
    }

    if deploy_missing {
        let present: HashSet<&str> = on_disk.iter().map(String::as_str).collect();
        for label in index {
            if !matches!(classify(docs.get(label)), Desired::Live) {
                continue;
            }
            // The directory name a deploy for this label would create.
            let Ok(site) = site_key_for_label(label, suffix, preview_domain) else {
                continue;
            };
            if !present.contains(site.as_str()) && !plan.deploy.contains(label) {
                plan.deploy.push(label.clone());
            }
        }
    }

    plan
}

/// Is a preview's desired state a live deploy, or is it gone?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Desired {
    /// Present with `intent: deploy` — should be on disk.
    Live,
    /// A genuine nil (retired, TTL elapsed), an `intent: teardown`, or an
    /// unparseable document — none of which is a live preview.
    Gone,
}

/// Classify a preview document read from KV.
///
/// `raw` is the map entry: `None` = the label was not in the snapshot (treated
/// as gone), `Some(None)` = a genuine KV nil, `Some(Some(json))` = a document.
/// An unparseable document is `Gone`: desired state the daemon cannot understand
/// is not something it will keep a preview alive for.
fn classify(raw: Option<&Option<String>>) -> Desired {
    let Some(Some(json)) = raw else {
        return Desired::Gone;
    };
    match Job::parse(json.as_bytes()).and_then(|job| job.intent()) {
        Ok(Intent::Deploy) => Desired::Live,
        _ => Desired::Gone,
    }
}

/// The canonical site key (directory name) a deploy for `label` creates —
/// `site_key(<label>.<preview_domain>)`, the exact forward rule the deploy path
/// uses ([`crate::site_key`]).
///
/// # Errors
///
/// Propagates [`crate::site_key::site_key`]'s error when the host does not
/// normalize to a valid key.
fn site_key_for_label(
    label: &str,
    suffix: Option<&str>,
    preview_domain: &str,
) -> anyhow::Result<String> {
    let host = format!("{label}.{}", preview_domain.trim_matches('.'));
    site_key::site_key(&host, suffix)
}

/// Reconstruct the preview *label* from an on-disk site key — the inverse of
/// [`site_key_for_label`].
///
/// With a suffix configured the key *is* the label (the deploy stripped the
/// suffix); without one the key is the full FQDN, so the label is the key with
/// `.<preview_domain>` removed. The label only ever names the API's
/// `applied/<label>` marker and the KV preview key, both of which fail safe if
/// the reconstruction is off (a nil lookup, a no-op marker removal).
fn label_for_site_key(site_key: &str, suffix: Option<&str>, preview_domain: &str) -> String {
    if suffix.is_some() {
        return site_key.to_string();
    }
    let dot_domain = format!(".{}", preview_domain.trim_matches('.'));
    site_key
        .strip_suffix(&dot_domain)
        .unwrap_or(site_key)
        .to_string()
}

/// List preview directories directly under `sites_dir`.
///
/// Keeps only entries that are directories named by a valid site key, excluding
/// the keep-list (infra/test vhosts) and `.tmp` staging directories a deploy in
/// flight owns. A missing `sites_dir` is an empty list, not an error.
///
/// # Errors
///
/// Returns an error if `sites_dir` exists but cannot be listed.
fn list_preview_dirs(sites_dir: &Path, keep: &HashSet<String>) -> anyhow::Result<Vec<String>> {
    use anyhow::Context as _;

    let entries = match std::fs::read_dir(sites_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read {}", sites_dir.display()));
        }
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        // Follow symlinks: `file_type()` on the dirent does not, and a preview
        // dir is a plain directory anyway, but a symlinked docroot must still
        // count as present.
        let is_dir = entry.metadata().map(|m| m.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".tmp") {
            // A staging directory owned by a deploy mid-swap — not a preview.
            continue;
        }
        if !site_key::is_valid_site_key(&name) {
            continue;
        }
        if keep.contains(&name) {
            continue;
        }
        out.push(name);
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::sample_json;

    const DOMAIN: &str = "preview.ephpm.dev";
    const SUFFIX: Option<&str> = Some(".preview.ephpm.dev");

    /// A `Some(Some(deploy job))` document for a label.
    fn deploy_doc(label: &str) -> Option<String> {
        Some(sample_json(label, "deploy"))
    }

    fn docs(pairs: &[(&str, Option<String>)]) -> HashMap<String, Option<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn classify_reads_the_intent() {
        assert_eq!(classify(Some(&deploy_doc("a"))), Desired::Live);
        assert_eq!(
            classify(Some(&Some(sample_json("a", "teardown")))),
            Desired::Gone
        );
        // A genuine nil (retired) and a totally absent label both read as gone.
        assert_eq!(classify(Some(&None)), Desired::Gone);
        assert_eq!(classify(None), Desired::Gone);
        // Unparseable desired state is not something to keep a preview alive for.
        assert_eq!(
            classify(Some(&Some("{not json".to_string()))),
            Desired::Gone
        );
    }

    #[test]
    fn site_key_and_label_are_inverses_with_a_suffix() {
        // On the live cluster (suffix configured) the key is the bare label.
        let key = site_key_for_label("ephpm-wp-pr-8", SUFFIX, DOMAIN).unwrap();
        assert_eq!(key, "ephpm-wp-pr-8");
        assert_eq!(label_for_site_key(&key, SUFFIX, DOMAIN), "ephpm-wp-pr-8");
    }

    #[test]
    fn site_key_and_label_are_inverses_without_a_suffix() {
        // A node with no suffix names the directory by the full FQDN.
        let key = site_key_for_label("ephpm-wp-pr-8", None, DOMAIN).unwrap();
        assert_eq!(key, "ephpm-wp-pr-8.preview.ephpm.dev");
        assert_eq!(label_for_site_key(&key, None, DOMAIN), "ephpm-wp-pr-8");
    }

    #[test]
    fn a_live_deploy_is_kept_and_an_orphan_is_pruned() {
        let on_disk = vec!["live-pr-1".to_string(), "orphan-pr-2".to_string()];
        let docs = docs(&[
            ("live-pr-1", deploy_doc("live-pr-1")),
            // orphan's key is a genuine nil (retired).
            ("orphan-pr-2", None),
        ]);
        let plan = build_plan(&on_disk, &[], &docs, SUFFIX, DOMAIN, false);
        assert_eq!(plan.prune.len(), 1, "only the orphan is pruned");
        assert_eq!(plan.prune[0].site_key, "orphan-pr-2");
        assert_eq!(plan.prune[0].label, "orphan-pr-2");
        assert!(plan.deploy.is_empty());
    }

    #[test]
    fn a_teardown_intent_prunes_even_while_still_in_the_index() {
        // The stranded-teardown case: the preview key still exists but says
        // teardown (retired-with-TTL, not yet expired), and the label is still
        // in the index. The node must prune it, not keep it.
        let on_disk = vec!["torn-pr-3".to_string()];
        let docs = docs(&[("torn-pr-3", Some(sample_json("torn-pr-3", "teardown")))]);
        let index = vec!["torn-pr-3".to_string()];
        let plan = build_plan(&on_disk, &index, &docs, SUFFIX, DOMAIN, true);
        assert_eq!(plan.prune.len(), 1);
        assert_eq!(plan.prune[0].site_key, "torn-pr-3");
        // A teardown-intent label is never re-deployed.
        assert!(plan.deploy.is_empty());
    }

    #[test]
    fn an_orphan_not_in_the_index_is_still_pruned() {
        // The lingering-override symptom: the index entry was already pruned, so
        // the label is absent from the index AND its key is nil. Classified from
        // its own (nil) key, it is still an orphan.
        let on_disk = vec!["ghost-pr-4".to_string()];
        let docs = docs(&[("ghost-pr-4", None)]);
        let plan = build_plan(&on_disk, &[], &docs, SUFFIX, DOMAIN, true);
        assert_eq!(plan.prune.len(), 1);
        assert_eq!(plan.prune[0].site_key, "ghost-pr-4");
    }

    #[test]
    fn a_live_preview_missing_from_the_index_is_not_pruned() {
        // The index lost-update race: a live preview transiently fell out of the
        // index. Because pruning classifies from the per-site key (not the
        // index), it is kept — this is the false-positive the direct-key
        // authority exists to prevent.
        let on_disk = vec!["live-pr-5".to_string()];
        let docs = docs(&[("live-pr-5", deploy_doc("live-pr-5"))]);
        let plan = build_plan(&on_disk, &[], &docs, SUFFIX, DOMAIN, true);
        assert!(
            plan.prune.is_empty(),
            "a live preview absent from the index must not be pruned"
        );
    }

    #[test]
    fn a_desired_preview_missing_from_disk_is_enqueued() {
        let on_disk: Vec<String> = vec![];
        let docs = docs(&[("wanted-pr-6", deploy_doc("wanted-pr-6"))]);
        let index = vec!["wanted-pr-6".to_string()];
        let plan = build_plan(&on_disk, &index, &docs, SUFFIX, DOMAIN, true);
        assert_eq!(plan.deploy, vec!["wanted-pr-6".to_string()]);
        assert!(plan.prune.is_empty());
    }

    #[test]
    fn adds_are_skipped_when_deploy_missing_is_off() {
        let on_disk: Vec<String> = vec![];
        let docs = docs(&[("wanted-pr-6", deploy_doc("wanted-pr-6"))]);
        let index = vec!["wanted-pr-6".to_string()];
        let plan = build_plan(&on_disk, &index, &docs, SUFFIX, DOMAIN, false);
        assert!(plan.deploy.is_empty(), "add direction is opt-in");
    }

    #[test]
    fn a_present_desired_preview_is_not_re_enqueued() {
        let on_disk = vec!["here-pr-7".to_string()];
        let docs = docs(&[("here-pr-7", deploy_doc("here-pr-7"))]);
        let index = vec!["here-pr-7".to_string()];
        let plan = build_plan(&on_disk, &index, &docs, SUFFIX, DOMAIN, true);
        assert!(plan.deploy.is_empty());
        assert!(plan.prune.is_empty());
    }

    #[test]
    fn list_preview_dirs_filters_infra_staging_and_files() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path();
        for dir in ["live-pr-1", "orphan-pr-2", "switchboard", "live-pr-1.tmp"] {
            std::fs::create_dir_all(sites.join(dir)).unwrap();
        }
        // A stray file must never be taken for a preview directory.
        std::fs::write(sites.join("README"), "x").unwrap();

        let mut keep = HashSet::new();
        keep.insert("switchboard".to_string());

        let found = list_preview_dirs(sites, &keep).unwrap();
        assert_eq!(
            found,
            vec!["live-pr-1".to_string(), "orphan-pr-2".to_string()],
            "keep-list, .tmp staging and plain files are all excluded"
        );
    }

    #[test]
    fn a_missing_sites_dir_is_an_empty_list() {
        let root = tempfile::tempdir().unwrap();
        let found = list_preview_dirs(&root.path().join("nope"), &HashSet::new()).unwrap();
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn dry_run_reports_would_prune_and_removes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path().join("sites");
        let state = root.path().join(".switchboard");
        std::fs::create_dir_all(sites.join("orphan-pr-2")).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let queue = Queue::new(&state);
        queue.ensure_dirs().unwrap();
        let keep = HashSet::new();

        let ctx = ReconcileContext {
            sites_dir: &sites,
            sqlite_dir: None,
            site_overrides_dir: None,
            vhost_temp_base: None,
            state_dir: &state,
            allow_incomplete: true,
            kv_addr: "unused",
            kv_secret: "s",
            api_site: "switchboard",
            preview_domain: DOMAIN,
            sites_domain_suffix: SUFFIX,
            keep: &keep,
            prune: false,
            deploy_missing: false,
            max_prunes_per_cycle: 8,
            queue: &queue,
        };
        let plan = Plan {
            prune: vec![PrunePlan {
                site_key: "orphan-pr-2".to_string(),
                label: "orphan-pr-2".to_string(),
            }],
            deploy: vec![],
        };
        let mut report = ReconcileReport::default();
        execute_prune(&ctx, &plan, &mut report).await;

        assert_eq!(report.would_prune, 1);
        assert_eq!(report.pruned, 0);
        assert!(
            sites.join("orphan-pr-2").exists(),
            "dry-run must not remove the directory"
        );
    }

    #[tokio::test]
    async fn prune_removes_the_orphan_directory() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path().join("sites");
        let state = root.path().join(".switchboard");
        std::fs::create_dir_all(sites.join("orphan-pr-2")).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let queue = Queue::new(&state);
        queue.ensure_dirs().unwrap();
        let keep = HashSet::new();

        let ctx = ReconcileContext {
            sites_dir: &sites,
            sqlite_dir: None,
            site_overrides_dir: None,
            vhost_temp_base: None,
            state_dir: &state,
            allow_incomplete: true, // no sqlite/overrides dirs configured in the test
            kv_addr: "127.0.0.1:1", // revocation write fails, best-effort — must not fail teardown
            kv_secret: "s",
            api_site: "switchboard",
            preview_domain: DOMAIN,
            sites_domain_suffix: SUFFIX,
            keep: &keep,
            prune: true,
            deploy_missing: false,
            max_prunes_per_cycle: 8,
            queue: &queue,
        };
        let plan = Plan {
            prune: vec![PrunePlan {
                site_key: "orphan-pr-2".to_string(),
                label: "orphan-pr-2".to_string(),
            }],
            deploy: vec![],
        };
        let mut report = ReconcileReport::default();
        execute_prune(&ctx, &plan, &mut report).await;

        assert_eq!(report.pruned, 1, "the orphan is removed");
        assert!(!sites.join("orphan-pr-2").exists());
    }

    #[tokio::test]
    async fn the_per_cycle_cap_defers_the_rest() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path().join("sites");
        let state = root.path().join(".switchboard");
        for dir in ["a-pr-1", "b-pr-2", "c-pr-3"] {
            std::fs::create_dir_all(sites.join(dir)).unwrap();
        }
        std::fs::create_dir_all(&state).unwrap();
        let queue = Queue::new(&state);
        queue.ensure_dirs().unwrap();
        let keep = HashSet::new();

        let ctx = ReconcileContext {
            sites_dir: &sites,
            sqlite_dir: None,
            site_overrides_dir: None,
            vhost_temp_base: None,
            state_dir: &state,
            allow_incomplete: true,
            kv_addr: "127.0.0.1:1",
            kv_secret: "s",
            api_site: "switchboard",
            preview_domain: DOMAIN,
            sites_domain_suffix: SUFFIX,
            keep: &keep,
            prune: true,
            deploy_missing: false,
            max_prunes_per_cycle: 2,
            queue: &queue,
        };
        let plan = Plan {
            prune: ["a-pr-1", "b-pr-2", "c-pr-3"]
                .iter()
                .map(|s| PrunePlan {
                    site_key: (*s).to_string(),
                    label: (*s).to_string(),
                })
                .collect(),
            deploy: vec![],
        };
        let mut report = ReconcileReport::default();
        execute_prune(&ctx, &plan, &mut report).await;

        assert_eq!(report.pruned, 2, "cap honoured");
        assert_eq!(
            report.prune_deferred, 1,
            "the third waits for the next pass"
        );
    }
}
