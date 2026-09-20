//! Level-triggered convergence of this node's on-disk previews to **GitHub PR
//! state** — the authoritative source of whether a preview is still wanted.
//!
//! # Why not the KV index / the drain cursor
//!
//! Preview fan-out is edge-triggered on the `switchboard:gen` counter: a node
//! only re-walks desired state when the counter advances, so a lost or
//! not-yet-replicated increment strands a teardown (the preview stays served,
//! its database and `<key>.toml` override on disk, every health check green —
//! switchboard#24). The first cut of this reconcile (v0.2.0) read desired state
//! from the KV index over RESP. But the preview nodes keep ePHPm's KV RESP
//! listener **off** (there is no `[kv.redis_compat]` listener and no `[kv]`
//! secret), so that reader was inert there.
//!
//! This version removes the KV dependency entirely and uses the one authority
//! that needs no ePHPm-side change and is *more* authoritative than the KV index
//! (which has an acknowledged lost-update window): **the pull request's state on
//! GitHub**. The daemon already holds the switchboard App credentials it mints
//! installation tokens with for reporting; this reuses that path.
//!
//! # What a pass does (prune-only)
//!
//! For every preview directory under `sites_dir`:
//!
//! * parse its canonical site key `<owner>-<repo>-pr-<N>` back to `(repo, N)`
//!   ([`parse_preview_site_key`]);
//! * ask GitHub what PR `owner/repo#N` is **now**;
//! * **open (or an unrecognised state) ⇒ keep; merged or closed ⇒ prune** with
//!   the same KEEP-guarded, exact-path [`crate::teardown::teardown_preview`] the
//!   webhook teardown uses (site dir, `<key>.db*`, `<key>.toml`,
//!   `/tmp/ephpm-vhosts/<key>-<hash>`, preserving `*.single-db-bak`).
//!
//! Re-*deploying* a missing but still-open preview is deliberately **not** done
//! here — that stays on the existing webhook path. This module only removes what
//! GitHub says is gone.
//!
//! # Fail-safe, in every direction
//!
//! Uncertainty always resolves to **keep**:
//!
//! * a site key that does not parse as `<owner>-<repo>-pr-<N>` (a hashed/overflow
//!   label, or an infra vhost) is skipped — never a prune candidate;
//! * a per-PR GitHub error (rate limit, transient 5xx, a repo/PR that 404s) skips
//!   *that* entry;
//! * a failure to mint the installation token aborts the **whole** pass, so a
//!   total GitHub outage prunes nothing;
//! * an infra/non-preview keep-list still applies on top (the API vhost is added
//!   automatically), though the parse rule already excludes those dirs.
//!
//! Pruning is opt-in (`--reconcile-prune`); until it is set the pass logs each
//! orphan it *would* remove at WARN and removes nothing.

use std::collections::HashMap;
use std::path::Path;

use crate::site_key;
use crate::teardown::{self, Preview, TeardownContext};
use crate::validate::{PullRequestState, pr_state_verdict};

/// Everything one reconcile pass needs.
pub struct ReconcileContext<'a> {
    // ── where the artifacts live (same as `TeardownContext`) ────────────
    pub sites_dir: &'a Path,
    pub sqlite_dir: Option<&'a Path>,
    pub site_overrides_dir: Option<&'a Path>,
    pub vhost_temp_base: Option<&'a Path>,
    pub state_dir: &'a Path,
    pub allow_incomplete: bool,
    /// ePHPm's `[kv] secret`, only for teardown's best-effort share-link
    /// revocation. `None` (the preview cluster's case — no `[kv]` secret) skips
    /// it cleanly; the reconcile itself never reads KV.
    pub kv_secret: Option<&'a str>,
    pub kv_addr: &'a str,

    // ── GitHub PR-state authority ───────────────────────────────────────
    /// switchboard App id (`--app-id`).
    pub app_id: u64,
    /// switchboard App private key (`--app-key`).
    pub app_key: &'a Path,
    /// The GitHub owner/org previews belong to (the leading label segment). All
    /// preview site keys are `<owner>-<repo>-pr-<N>`.
    pub owner: &'a str,

    // ── host → label derivation (same rule as the deploy path) ──────────
    pub preview_domain: &'a str,
    pub sites_domain_suffix: Option<&'a str>,

    // ── policy ──────────────────────────────────────────────────────────
    /// Vhost directory names never pruned (infra/test sites). The parse rule
    /// already excludes non-`<owner>-<repo>-pr-<N>` dirs; this is belt-and-braces.
    pub keep: &'a std::collections::HashSet<String>,
    /// Actually remove orphans. When `false` the pass logs WOULD-prune and
    /// removes nothing.
    pub prune: bool,
}

/// What one reconcile pass observed and did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Preview directories found (excluding keep-list and `.tmp` staging dirs).
    pub on_disk: usize,
    /// Directories whose PR is still open (or an unrecognised state) — kept.
    pub kept_open: usize,
    /// Orphans removed (0 when `--reconcile-prune` is unset).
    pub pruned: usize,
    /// Orphans that would be removed but for `--reconcile-prune` being unset.
    pub would_prune: usize,
    /// Orphans whose removal returned an error.
    pub prune_failed: usize,
    /// Directories whose site key did not parse as `<owner>-<repo>-pr-<N>` — kept.
    pub skipped_unparseable: usize,
    /// Directories whose PR state could not be read from GitHub — kept.
    pub skipped_api_error: usize,
}

/// A single orphan to remove: its site key (names every ePHPm artifact) and its
/// reconstructed label (names the API's `applied/<label>` marker).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrunePlan {
    site_key: String,
    label: String,
}

/// A per-preview GitHub lookup outcome. `Error` is a read that failed (rate
/// limit, transient 5xx, a 404) — treated as "keep", never a prune.
#[derive(Debug, Clone)]
enum PrLookup {
    State(PullRequestState),
    Error,
}

/// The decisions a pass reached, plus the counts for the report — separated from
/// executing them so the logic is unit-testable without a filesystem or GitHub.
#[derive(Debug, Default, PartialEq, Eq)]
struct PlanResult {
    prune: Vec<PrunePlan>,
    kept_open: usize,
    skipped_unparseable: usize,
    skipped_api_error: usize,
}

/// Run one reconcile pass.
///
/// # Errors
///
/// Returns an error only if the installation token could not be minted (a total
/// GitHub-auth failure) — the caller logs it and waits for the next interval, and
/// nothing is pruned. Per-PR read failures and per-site prune failures are
/// counted in the [`ReconcileReport`], not surfaced as an error.
pub async fn reconcile_once(ctx: &ReconcileContext<'_>) -> anyhow::Result<ReconcileReport> {
    let on_disk = list_preview_dirs(ctx.sites_dir, ctx.keep)?;
    if on_disk.is_empty() {
        return Ok(ReconcileReport::default());
    }

    // Ask GitHub about every parseable preview. A token-mint failure aborts here
    // (Err) so a total outage prunes nothing; a per-PR failure becomes `Error`.
    let lookups = fetch_lookups(ctx, &on_disk).await?;

    let plan = build_plan(
        &on_disk,
        ctx.owner,
        ctx.sites_domain_suffix,
        ctx.preview_domain,
        &lookups,
    );

    let mut report = ReconcileReport {
        on_disk: on_disk.len(),
        kept_open: plan.kept_open,
        skipped_unparseable: plan.skipped_unparseable,
        skipped_api_error: plan.skipped_api_error,
        ..ReconcileReport::default()
    };
    execute_prune(ctx, &plan, &mut report).await;

    tracing::info!(
        on_disk = report.on_disk,
        kept_open = report.kept_open,
        pruned = report.pruned,
        would_prune = report.would_prune,
        prune_failed = report.prune_failed,
        skipped_unparseable = report.skipped_unparseable,
        skipped_api_error = report.skipped_api_error,
        prune_enabled = ctx.prune,
        "reconcile pass complete"
    );
    Ok(report)
}

/// Ask GitHub for the PR state of every parseable preview under one installation
/// token.
///
/// Returns a map from site key to its lookup outcome. Only parseable sites are
/// queried; unparseable ones are handled by [`build_plan`]. A failure to mint the
/// token is an error (aborts the pass); a per-PR read failure is recorded as
/// [`PrLookup::Error`] (kept).
async fn fetch_lookups(
    ctx: &ReconcileContext<'_>,
    on_disk: &[String],
) -> anyhow::Result<HashMap<String, PrLookup>> {
    use anyhow::Context as _;

    let parsed: Vec<(String, String, u64)> = on_disk
        .iter()
        .filter_map(|site| {
            parse_preview_site_key(site, ctx.owner).map(|(repo, pr)| (site.clone(), repo, pr))
        })
        .collect();

    if parsed.is_empty() {
        // Nothing to ask GitHub about — don't mint a token for no reason.
        return Ok(HashMap::new());
    }

    // One installation token for the whole pass (rate-limit-friendly: a handful
    // of reads well under any limit).
    let token = crate::installation_token_for_owner(ctx.app_id, ctx.app_key, ctx.owner)
        .await
        .context("reconcile: could not mint a GitHub installation token — pruning nothing")?;
    let client = crate::github::GitHubClient::new(token);

    let mut map = HashMap::with_capacity(parsed.len());
    for (site, repo, pr) in parsed {
        let lookup = match client.pull_request_state(ctx.owner, &repo, pr).await {
            Ok(state) => PrLookup::State(state),
            Err(e) => {
                tracing::warn!(
                    site_key = %site,
                    repo = %format!("{}/{repo}", ctx.owner),
                    pr,
                    error = %format!("{e:#}"),
                    "reconcile: could not read PR state — keeping this preview (fail-safe)"
                );
                PrLookup::Error
            }
        };
        map.insert(site, lookup);
    }
    Ok(map)
}

/// Decide what to prune. Pure — no IO — so it can be tested against hand-built
/// lookup maps.
fn build_plan(
    on_disk: &[String],
    owner: &str,
    suffix: Option<&str>,
    preview_domain: &str,
    lookups: &HashMap<String, PrLookup>,
) -> PlanResult {
    let mut plan = PlanResult::default();

    for site in on_disk {
        let Some((_repo, _pr)) = parse_preview_site_key(site, owner) else {
            // A hashed/overflow label or an infra vhost — never a prune candidate.
            plan.skipped_unparseable += 1;
            continue;
        };
        match lookups.get(site) {
            Some(PrLookup::State(state)) if pr_state_verdict(state).is_discard() => {
                // Merged or closed ⇒ the preview is gone.
                plan.prune.push(PrunePlan {
                    site_key: site.clone(),
                    label: label_for_site_key(site, suffix, preview_domain),
                });
            }
            Some(PrLookup::State(_)) => plan.kept_open += 1, // open / unrecognised ⇒ keep
            Some(PrLookup::Error) | None => plan.skipped_api_error += 1, // unreadable ⇒ keep
        }
    }

    plan
}

/// Remove (or, in dry-run, report) each planned orphan.
async fn execute_prune(
    ctx: &ReconcileContext<'_>,
    plan: &PlanResult,
    report: &mut ReconcileReport,
) {
    for target in &plan.prune {
        if !ctx.prune {
            report.would_prune += 1;
            tracing::warn!(
                site_key = %target.site_key,
                "reconcile: orphan preview on disk whose PR is merged/closed — \
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
            kv_secret: ctx.kv_secret,
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
                    "reconcile: pruned an orphan preview (PR merged/closed)"
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

/// Parse a canonical preview site key `<owner>-<repo>-pr-<N>` into `(repo, N)`.
///
/// Returns `None` for anything that is not a clean preview label for `owner`: an
/// infra vhost (no `<owner>-` prefix), or a hashed/overflow label
/// (`<base>-<6hex>`, whose tail after the last `-pr-` is not all digits). Both
/// are fail-safe — the caller keeps them.
///
/// `<repo>` may itself contain hyphens (`php-sdk`, `switchboard-api`), so the
/// split is on the **last** `-pr-<digits>`, matching how the label is built
/// (`<owner>-<repo>-pr-<N>`); a repo that itself contains `-pr-` still resolves
/// because the trailing number anchors the last one.
fn parse_preview_site_key(key: &str, owner: &str) -> Option<(String, u64)> {
    const SEP: &str = "-pr-";
    let prefix = format!("{owner}-");
    let rest = key.strip_prefix(&prefix)?;
    let idx = rest.rfind(SEP)?;
    let repo = &rest[..idx];
    if repo.is_empty() {
        return None;
    }
    let num = &rest[idx + SEP.len()..];
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pr: u64 = num.parse().ok()?;
    Some((repo.to_string(), pr))
}

/// Reconstruct the preview *label* from an on-disk site key — the inverse of the
/// deploy's `site_key(<label>.<preview_domain>)`.
///
/// With a suffix configured the key *is* the label; without one the key is the
/// full FQDN, so the label is the key with `.<preview_domain>` removed. The label
/// only ever names the API's `applied/<label>` marker, which fails safe if the
/// reconstruction is off (a no-op marker removal).
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
fn list_preview_dirs(
    sites_dir: &Path,
    keep: &std::collections::HashSet<String>,
) -> anyhow::Result<Vec<String>> {
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
        // Follow symlinks: a symlinked docroot must still count as present.
        let is_dir = entry.metadata().map(|m| m.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".tmp") {
            continue; // a deploy-in-flight staging dir, not a preview
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
    use crate::queue::Queue;
    use std::collections::HashSet;

    const DOMAIN: &str = "preview.ephpm.dev";
    const SUFFIX: Option<&str> = Some(".preview.ephpm.dev");
    const OWNER: &str = "ephpm";

    fn lookups(pairs: &[(&str, PrLookup)]) -> HashMap<String, PrLookup> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    // ── the site-key parser ─────────────────────────────────────────────

    #[test]
    fn parses_clean_preview_keys_including_hyphenated_repos() {
        assert_eq!(
            parse_preview_site_key("ephpm-lab-pr-8", OWNER),
            Some(("lab".to_string(), 8))
        );
        // Repos with hyphens: the split is the LAST `-pr-<digits>`.
        assert_eq!(
            parse_preview_site_key("ephpm-php-sdk-pr-67", OWNER),
            Some(("php-sdk".to_string(), 67))
        );
        assert_eq!(
            parse_preview_site_key("ephpm-switchboard-api-pr-5", OWNER),
            Some(("switchboard-api".to_string(), 5))
        );
        // The org repo doubles the owner segment.
        assert_eq!(
            parse_preview_site_key("ephpm-ephpm-pr-488", OWNER),
            Some(("ephpm".to_string(), 488))
        );
        // A repo that itself contains `-pr-` still resolves on the trailing number.
        assert_eq!(
            parse_preview_site_key("ephpm-my-pr-tool-pr-5", OWNER),
            Some(("my-pr-tool".to_string(), 5))
        );
    }

    #[test]
    fn refuses_non_preview_and_hashed_keys() {
        // Infra vhosts have no `<owner>-` prefix.
        assert_eq!(parse_preview_site_key("switchboard", OWNER), None);
        assert_eq!(parse_preview_site_key("site-a", OWNER), None);
        assert_eq!(parse_preview_site_key("preview.ephpm.dev", OWNER), None);
        // A hashed/overflow label ends in `-<6hex>`, not `-pr-<digits>`.
        assert_eq!(
            parse_preview_site_key("ephpm-somelongrepo-pr-12-a1b2c3", OWNER),
            None
        );
        // No number, empty repo, or non-digit tail.
        assert_eq!(parse_preview_site_key("ephpm-lab-pr-", OWNER), None);
        assert_eq!(parse_preview_site_key("ephpm--pr-5", OWNER), None);
        assert_eq!(parse_preview_site_key("ephpm-lab-pr-x", OWNER), None);
        // A different owner is not ours.
        assert_eq!(parse_preview_site_key("other-lab-pr-8", OWNER), None);
    }

    // ── the prune decision ──────────────────────────────────────────────

    #[test]
    fn merged_and_closed_prune_open_and_unknown_keep() {
        let on_disk = vec![
            "ephpm-lab-pr-1".to_string(), // open  -> keep
            "ephpm-lab-pr-2".to_string(), // merged -> prune
            "ephpm-lab-pr-3".to_string(), // closed -> prune
            "ephpm-lab-pr-4".to_string(), // unknown -> keep
        ];
        let l = lookups(&[
            ("ephpm-lab-pr-1", PrLookup::State(PullRequestState::Open)),
            ("ephpm-lab-pr-2", PrLookup::State(PullRequestState::Merged)),
            ("ephpm-lab-pr-3", PrLookup::State(PullRequestState::Closed)),
            (
                "ephpm-lab-pr-4",
                PrLookup::State(PullRequestState::Unknown("locked".into())),
            ),
        ]);
        let plan = build_plan(&on_disk, OWNER, SUFFIX, DOMAIN, &l);
        let pruned: Vec<&str> = plan.prune.iter().map(|p| p.site_key.as_str()).collect();
        assert_eq!(pruned, vec!["ephpm-lab-pr-2", "ephpm-lab-pr-3"]);
        assert_eq!(plan.kept_open, 2, "open + unknown are kept");
        assert_eq!(plan.skipped_api_error, 0);
        assert_eq!(plan.skipped_unparseable, 0);
        // The label is reconstructed for the marker (suffix configured => == key).
        assert_eq!(plan.prune[0].label, "ephpm-lab-pr-2");
    }

    #[test]
    fn an_api_error_keeps_the_preview() {
        let on_disk = vec!["ephpm-lab-pr-9".to_string()];
        let l = lookups(&[("ephpm-lab-pr-9", PrLookup::Error)]);
        let plan = build_plan(&on_disk, OWNER, SUFFIX, DOMAIN, &l);
        assert!(plan.prune.is_empty(), "a read failure must never prune");
        assert_eq!(plan.skipped_api_error, 1);
    }

    #[test]
    fn a_missing_lookup_keeps_the_preview() {
        // Parseable but no lookup entry (e.g. it was added between listing and
        // fetching): fail-safe to keep.
        let on_disk = vec!["ephpm-lab-pr-9".to_string()];
        let plan = build_plan(&on_disk, OWNER, SUFFIX, DOMAIN, &HashMap::new());
        assert!(plan.prune.is_empty());
        assert_eq!(plan.skipped_api_error, 1);
    }

    #[test]
    fn an_unparseable_key_is_never_a_candidate_even_if_a_lookup_exists() {
        // A hashed label is kept regardless of any (spurious) lookup.
        let on_disk = vec!["ephpm-x-pr-1-a1b2c3".to_string()];
        let l = lookups(&[(
            "ephpm-x-pr-1-a1b2c3",
            PrLookup::State(PullRequestState::Merged),
        )]);
        let plan = build_plan(&on_disk, OWNER, SUFFIX, DOMAIN, &l);
        assert!(plan.prune.is_empty(), "a hashed label is never pruned");
        assert_eq!(plan.skipped_unparseable, 1);
    }

    #[test]
    fn label_reconstruction_without_a_suffix_strips_the_domain() {
        assert_eq!(
            label_for_site_key("ephpm-lab-pr-8.preview.ephpm.dev", None, DOMAIN),
            "ephpm-lab-pr-8"
        );
        assert_eq!(
            label_for_site_key("ephpm-lab-pr-8", SUFFIX, DOMAIN),
            "ephpm-lab-pr-8"
        );
    }

    // ── directory listing ───────────────────────────────────────────────

    #[test]
    fn list_preview_dirs_filters_infra_staging_and_files() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path();
        for dir in [
            "ephpm-lab-pr-8",
            "ephpm-switchboard-pr-36",
            "switchboard",
            "ephpm-lab-pr-8.tmp",
        ] {
            std::fs::create_dir_all(sites.join(dir)).unwrap();
        }
        std::fs::write(sites.join("README"), "x").unwrap();

        let mut keep = HashSet::new();
        keep.insert("switchboard".to_string());

        let found = list_preview_dirs(sites, &keep).unwrap();
        assert_eq!(
            found,
            vec![
                "ephpm-lab-pr-8".to_string(),
                "ephpm-switchboard-pr-36".to_string()
            ],
            "keep-list, .tmp staging and plain files are all excluded"
        );
    }

    #[test]
    fn a_missing_sites_dir_is_an_empty_list() {
        let root = tempfile::tempdir().unwrap();
        let found = list_preview_dirs(&root.path().join("nope"), &HashSet::new()).unwrap();
        assert!(found.is_empty());
    }

    // ── execute_prune (dry-run vs real, keep-guarded) ───────────────────

    /// A context whose teardown roots point at one tempdir; GitHub/KV fields are
    /// unused by `execute_prune` (it only runs the plan).
    fn exec_ctx<'a>(
        sites: &'a Path,
        state: &'a Path,
        keep: &'a HashSet<String>,
        prune: bool,
    ) -> ReconcileContext<'a> {
        ReconcileContext {
            sites_dir: sites,
            sqlite_dir: None,
            site_overrides_dir: None,
            vhost_temp_base: None,
            state_dir: state,
            allow_incomplete: true, // no sqlite/overrides dirs in the test
            kv_secret: None,
            kv_addr: "127.0.0.1:6379",
            app_id: 1,
            app_key: Path::new("/dev/null"),
            owner: OWNER,
            preview_domain: DOMAIN,
            sites_domain_suffix: SUFFIX,
            keep,
            prune,
        }
    }

    #[tokio::test]
    async fn dry_run_reports_would_prune_and_removes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path().join("sites");
        let state = root.path().join(".switchboard");
        std::fs::create_dir_all(sites.join("ephpm-lab-pr-2")).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        Queue::new(&state).ensure_dirs().unwrap();
        let keep = HashSet::new();
        let ctx = exec_ctx(&sites, &state, &keep, false);

        let plan = PlanResult {
            prune: vec![PrunePlan {
                site_key: "ephpm-lab-pr-2".to_string(),
                label: "ephpm-lab-pr-2".to_string(),
            }],
            ..PlanResult::default()
        };
        let mut report = ReconcileReport::default();
        execute_prune(&ctx, &plan, &mut report).await;

        assert_eq!(report.would_prune, 1);
        assert_eq!(report.pruned, 0);
        assert!(
            sites.join("ephpm-lab-pr-2").exists(),
            "dry-run must not remove the directory"
        );
    }

    #[tokio::test]
    async fn prune_removes_the_orphan_directory() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path().join("sites");
        let state = root.path().join(".switchboard");
        std::fs::create_dir_all(sites.join("ephpm-lab-pr-2")).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        Queue::new(&state).ensure_dirs().unwrap();
        let keep = HashSet::new();
        let ctx = exec_ctx(&sites, &state, &keep, true);

        let plan = PlanResult {
            prune: vec![PrunePlan {
                site_key: "ephpm-lab-pr-2".to_string(),
                label: "ephpm-lab-pr-2".to_string(),
            }],
            ..PlanResult::default()
        };
        let mut report = ReconcileReport::default();
        execute_prune(&ctx, &plan, &mut report).await;

        assert_eq!(report.pruned, 1);
        assert!(!sites.join("ephpm-lab-pr-2").exists());
    }

    /// The keep-list is honoured end-to-end: a keep-listed dir never reaches the
    /// plan because `list_preview_dirs` excludes it.
    #[test]
    fn keep_list_excludes_a_dir_from_candidacy() {
        let root = tempfile::tempdir().unwrap();
        let sites = root.path();
        std::fs::create_dir_all(sites.join("site-a")).unwrap();
        std::fs::create_dir_all(sites.join("ephpm-lab-pr-2")).unwrap();
        let mut keep = HashSet::new();
        keep.insert("site-a".to_string());

        let found = list_preview_dirs(sites, &keep).unwrap();
        assert!(!found.contains(&"site-a".to_string()));
        assert!(found.contains(&"ephpm-lab-pr-2".to_string()));
    }
}
