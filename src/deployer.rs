//! Preview deployment pipeline: clone, load manifest, materialize env, atomic
//! swap, build, seed, and health-gate.
//!
//! The order is a contract (see [`deploy_preview`]): env materialization, the
//! per-site override and the manifest quarantine all happen BEFORE the atomic
//! swap into `sites_dir`, so the vhost is never briefly served with a container
//! web root or without its `env:`. `build:` and `seed:` — the two steps that run
//! **untrusted tenant commands** — happen AFTER the swap, because both go
//! through `ephpm exec --site <key>` and that primitive sandboxes a command in
//! an *existing* vhost (`sites_dir/<key>`, not the pre-swap `.tmp` staging dir).
//!
//! # Untrusted steps run sandboxed, or not at all
//!
//! `build:` and `seed:` used to run as **root** via `sh -c` — a confirmed
//! root-RCE, since a preview builds arbitrary code from a pull request. Every
//! such step now runs as:
//!
//! ```text
//! ephpm exec --config <ephpm.toml> --site <key> -- sh -c "cd <workdir> && <step>"
//! ```
//!
//! which drops to the tenant uid, applies a Landlock filesystem scope, and arms
//! the host's uid-keyed egress firewall (ephpm#484). Env (`PREVIEW_URL`,
//! `COMPOSER_NO_INTERACTION`, …) reaches the step by *inheritance*: `ephpm exec`
//! `execvp`s the command, so anything set on the `ephpm exec` child's
//! environment is inherited by the step. The working directory is set explicitly
//! with a `cd` prefix (the container root for `build:`, the document root for
//! `seed:`) rather than relying on `ephpm exec`'s own chdir.
//!
//! **Fail closed:** if the configured `ephpm` binary does not support `exec`
//! (an ePHPm predating #484), a deploy **refuses** rather than falling back to
//! running the step as root — see [`ensure_sandboxed_exec`]. That makes the
//! deploy-ordering constraint explicit: the ePHPm carrying #484 must be rolled
//! out to a node before this switchboard is.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::process::Command;

use crate::manifest::AppManifest;
use crate::secrets::Secrets;
use crate::site_override;

/// Generated file (at the checkout/site root) that exports the resolved preview
/// env into PHP via `$_SERVER` — plus `$_ENV`/`putenv` for older code.
///
/// **Auto-loaded** since switchboard#4: the per-site override this deploy writes
/// names it in ePHPm's `auto_prepend_file` key (ephpm#463 / PR #472), so ePHPm
/// runs it before the site's own script on every request. It is written into the
/// checkout, so it is inside the vhost's `open_basedir` and runs with exactly
/// the reach the tenant's own `index.php` already has.
///
/// Three properties of this constant are load-bearing, and all three are pinned
/// by tests in [`crate::site_override`]:
///
/// * **Dot-prefixed** — ePHPm's `hidden_files` default is `deny`, so it is a 403
///   over HTTP even when the repository root *is* the web root. `hidden_files`
///   gates *serving*; it never gates PHP's own `include`, so the file still runs.
/// * **A plain relative name at the container root** — no `..`, no backslash, no
///   drive prefix. ePHPm resolves the declaration against the container and
///   refuses anything else, and since #472 a refusal is a **503 for that site**
///   rather than a silent no-op.
/// * **Stable across deploys and switchboard versions.** Apps that adopted the
///   documented `require_once` workaround name this exact path, so renaming it
///   would break them for no gain. Keeping both mechanisms is safe because the
///   prepend only assigns values: running it twice is the same outcome as
///   running it once. It is also why a *redeploy* stays consistent — the
///   previous container carries the same filename while the new override is
///   written, so the declaration never names a file that is not there.
pub(crate) const PREPEND_FILE: &str = ".ephpm-preview-prepend.php";
/// Generated dotenv file (checkout/site root) for framework-native `.env`
/// loaders, and for the `build:` / `seed:` shell steps.
///
/// **Kept, deliberately, now that the prepend is auto-loaded** — the two do not
/// overlap. `auto_prepend_file` only exists inside an ePHPm *request*, and
/// `build:` and `seed:` run as shell commands outside the server (guide §8:
/// they get no `$_SERVER['DB_*']` and no prepend). A `wp-cli` or `artisan` step
/// that needs the preview's `env:` can only read it from a file, and this is
/// that file. It is also what carries `env:` on a node whose ePHPm predates
/// #472, where `auto_prepend_file` is ignored with a warning.
///
/// The prepend wins where both apply: it runs before the front controller, and
/// phpdotenv/symfony-dotenv are immutable by default (`$_SERVER` set first is
/// not overwritten), so there is no ordering to reason about.
///
/// Written for **every** docroot shape. It used to be skipped for
/// `docroot: "."` on the grounds that the project root is web-served — but the
/// file is dot-prefixed, and ePHPm's `hidden_files` default is `deny`, so it is
/// a 403 either way (verified against the live preview cluster).
const DOTENV_FILE: &str = ".env";
/// Generated sidecar capturing the effective, non-secret manifest for ePHPm /
/// debugging. Contains env KEYS only — never secret values.
const SIDECAR_FILE: &str = ".switchboard-preview.json";

/// Detected PHP framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    WordPress,
    Laravel,
    Symfony,
    Drupal,
    Generic,
}

impl Framework {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WordPress => "WordPress",
            Self::Laravel => "Laravel",
            Self::Symfony => "Symfony",
            Self::Drupal => "Drupal",
            Self::Generic => "PHP",
        }
    }
}

/// Everything about *what* to provision, independent of where it came from.
///
/// A queue job ([`crate::job::Job::to_preview_request`]) and — while the
/// legacy receiver is still compiled in — a webhook event both produce one of
/// these, so the provisioning pipeline below has exactly one entry point.
#[derive(Debug, Clone)]
pub struct PreviewRequest {
    /// **Authoritative preview identity.** Names the directory under
    /// `sites_dir` and the leading DNS label of the preview host. Produced by
    /// switchboard-api and never recomputed here.
    pub label: String,
    /// `owner/repo` of the base repository — the per-repo secret scope.
    pub repo_full_name: String,
    /// Base repository owner login.
    pub owner: String,
    /// Base repository name.
    pub repo_name: String,
    /// Pull request number.
    pub pr_number: u64,
    /// Where to fetch from. Always the **base** repo when `fetch_ref` is set.
    pub fetch_url: String,
    /// `refs/pull/<n>/head` when known — the fetch path that works for forks
    /// and for deleted forks without trusting a third-party clone URL.
    pub fetch_ref: Option<String>,
    /// Head branch name, used only as a fallback when `fetch_ref` is absent.
    pub branch: Option<String>,
    /// Head commit SHA to check out.
    pub sha: String,
    /// GitHub App installation, when one is known. `None` disables reporting
    /// for this preview.
    pub installation_id: Option<u64>,
    /// True when the PR head comes from a fork (or the head repo is gone).
    /// Gates deploys and secret resolution — see [`fork_deploy_gate`].
    pub fork: bool,
}

impl PreviewRequest {
    /// The preview hostname: the authoritative label plus the configured
    /// preview domain.
    #[must_use]
    pub fn preview_host(&self, domain: &str) -> String {
        preview_host(&self.label, domain)
    }
}

/// `<label>.<domain>` — the single place the preview host is assembled.
#[must_use]
pub fn preview_host(label: &str, domain: &str) -> String {
    format!("{label}.{domain}")
}

/// What the fork gate decided about operator secrets for an allowed deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkSecrets {
    /// Resolve `${secret.NAME}` from the operator's secret store as usual.
    Resolve,
    /// Deploy, but resolve against an **empty** store: every `${secret.NAME}`
    /// expands to the empty string (with the usual name-only warning), so no
    /// operator secret reaches the fork's environment.
    Withhold,
}

/// The daemon-side fork gate: may this deploy run, and does it get secrets?
///
/// switchboard-api already refuses to *queue* fork deploys unless
/// `SWITCHBOARD_ALLOW_FORKS=true`, but that is a single gate in a different
/// repo — and the daemon is the process that actually holds the secret store,
/// so it enforces its own policy regardless of what the API decided:
///
/// * fork + no `--allow-fork-deploy` → **hard error**, the job fails loudly;
/// * fork + `--allow-fork-deploy` only → deploy, secrets withheld;
/// * fork + both flags → deploy with secrets (the operator said so twice);
/// * not a fork → deploy with secrets, no flags consulted.
///
/// This gate applies to **deploys only**. Teardowns never resolve secrets and
/// are always processed — refusing them would strand fork previews on disk.
///
/// # Errors
///
/// Returns an error when the job is a fork deploy and `--allow-fork-deploy`
/// is not set.
pub fn fork_deploy_gate(
    fork: bool,
    allow_fork_deploy: bool,
    fork_secrets: bool,
) -> anyhow::Result<ForkSecrets> {
    if !fork {
        return Ok(ForkSecrets::Resolve);
    }
    anyhow::ensure!(
        allow_fork_deploy,
        "refusing to deploy a pull request from a fork: this daemon builds fork \
         PRs only with --allow-fork-deploy (SWITCHBOARD_ALLOW_FORK_DEPLOY=true); \
         note the API's SWITCHBOARD_ALLOW_FORKS gate is separate and does not \
         imply this one"
    );
    if fork_secrets {
        Ok(ForkSecrets::Resolve)
    } else {
        Ok(ForkSecrets::Withhold)
    }
}

/// Non-repo inputs to a deploy: switchboard config plus the secret store.
pub struct DeployContext<'a> {
    /// ePHPm sites directory where previews are swapped into place.
    pub sites_dir: &'a Path,
    /// Preview domain suffix.
    pub preview_domain: &'a str,
    /// ePHPm's `[server] sites_domain_suffix` on this node, or `None` when the
    /// node has none. Decides the canonical site key — see [`crate::site_key`].
    pub sites_domain_suffix: Option<&'a str>,
    /// ePHPm's `[server] site_overrides_dir`. `None` disables the per-site
    /// document-root override entirely, which means a `docroot:` other than
    /// `"."` cannot be honoured — the deploy says so loudly rather than
    /// pretending (switchboard#3).
    pub site_overrides_dir: Option<&'a Path>,
    /// Composer command (or path).
    pub composer: &'a str,
    /// The `ephpm` binary that runs `build:` / `seed:` steps inside the tenant
    /// sandbox (`ephpm exec --site`). A build/seed refuses to run if this binary
    /// does not support `exec` — it is never bypassed to run steps as root.
    pub ephpm_bin: &'a Path,
    /// The node's `ephpm.toml`, passed to `ephpm exec --config` so the sandbox
    /// resolves the same per-site boundary the running server does.
    pub ephpm_config: &'a Path,
    /// Switchboard's own secret store for `${secret.NAME}` resolution.
    pub secrets: &'a Secrets,
    /// Short-lived GitHub App **installation access token** used to authenticate
    /// the checkout fetch, so a **private** repository can be previewed.
    ///
    /// `None` disables fetch authentication: a public repository still fetches
    /// (it needs no credential), and a private one fails with a clear message
    /// rather than a confusing git error. The token is installation-scoped and
    /// short-lived; the App installation must carry `contents: read` for the
    /// fetch to succeed against a private repository.
    ///
    /// It is applied to **that one fetch** as a transient `http.extraheader`
    /// (`-c` on the git invocation), never written into the repository's
    /// persisted git config, and never logged — see [`fetch_auth_config`] and
    /// [`run_git_fetch`].
    pub fetch_token: Option<&'a str>,
    /// How long to poll `health:` for a 200 before giving up. Zero disables the
    /// health gate entirely.
    pub health_timeout: Duration,
    /// Interval between health poll attempts.
    pub health_interval: Duration,
}

/// Result of a successful deployment.
pub struct DeployResult {
    /// The preview hostname.
    pub hostname: String,
    /// Detected framework.
    pub framework: Framework,
    /// Time taken to deploy.
    pub duration: Duration,
    /// PHP version from the manifest (drives the preview URL port map).
    pub php_version: Option<String>,
    /// Whether the health check passed within the timeout (false = timed out or
    /// health gating disabled).
    pub healthy: bool,
}

/// Deploy a preview.
///
/// Pipeline order:
/// 1. Fetch the PR head (`refs/pull/<n>/head` from the base repo) at its SHA.
/// 2. Detect the framework and load the `ephpm.yaml` manifest (or synthesize).
/// 3. Materialize `env:` — resolve `${secret.NAME}` from switchboard's own
///    secret store and write it where the app can read it (`.env` for
///    build/seed shell steps, the PHP prepend for the app).
/// 4. Move the deploy manifest out of the served root (switchboard#16) and
///    strip `.git`, before it could ever be requested.
/// 5. Write the per-site override — document root AND the `auto_prepend_file`
///    that delivers `env:` (switchboard#4) — **before** the swap so the vhost is
///    never briefly served with its container as the web root or without its
///    `env:`.
/// 6. Atomic swap the checkout into `sites_dir`, then `chown -R` the swapped
///    tree to the tenant owner (derived from `sites_dir`'s own ownership) so the
///    sandboxed build — which runs as that uid — can write its own container.
/// 7. Run `build:` commands — now that the code lives at `sites_dir/<key>`,
///    each runs sandboxed via `ephpm exec --site` (failures logged, deploy
///    continues, matching the POC's composer behavior).
/// 8. Run `seed:` commands with `$PREVIEW_URL`/`$PREVIEW_HOST`/`$PR` set, also
///    sandboxed via `ephpm exec --site`.
/// 9. Poll `health:` until it returns 200 or the timeout elapses, so the PR
///    comment is only posted once the site is ready.
///
/// **`build:` moved after the swap** (it used to run pre-swap on the `.tmp`
/// staging tree) because `ephpm exec --site <key>` sandboxes a command in the
/// *existing* vhost directory `sites_dir/<key>`, which does not exist until the
/// swap. The site is therefore routable while `build:` runs; the health gate
/// (step 9) still withholds the PR comment until the site serves a 200, so the
/// URL is not advertised before it is ready. See the module docs.
///
/// # Errors
///
/// Returns an error if the configured `ephpm` cannot run sandboxed steps
/// (fail-closed — see [`ensure_sandboxed_exec`]), or if cloning, manifest
/// loading (present-but-invalid), document-root validation, or the atomic swap
/// fails.
pub async fn deploy_preview(
    req: &PreviewRequest,
    ctx: &DeployContext<'_>,
) -> anyhow::Result<DeployResult> {
    let start = Instant::now();
    let hostname = req.preview_host(ctx.preview_domain);

    // Fail CLOSED before touching disk: `build:`/`seed:` must run through
    // `ephpm exec --site` (uid drop + Landlock + egress). An `ephpm` predating
    // #484 has no `exec`, and the only safe answer is to refuse the deploy —
    // never to fall back to running untrusted tenant commands as root. This is
    // also what enforces the rollout order: ship the ePHPm with `exec` first.
    ensure_sandboxed_exec(ctx.ephpm_bin).await?;
    // The **site key** names every per-site artifact, and it is ePHPm's
    // derivation, not ours: the preview host with the node's
    // `sites_domain_suffix` stripped, or the full host when the node has none.
    // This used to be assumed to equal the label, which is true only on a node
    // that actually configures the suffix (switchboard#13).
    let site_key = crate::site_key::site_key(&hostname, ctx.sites_domain_suffix)?;
    let site_dir = ctx.sites_dir.join(&site_key);

    tracing::info!(
        repo = %req.repo_full_name,
        pr = req.pr_number,
        label = %req.label,
        hostname = %hostname,
        site_key = %site_key,
        site_dir = %site_dir.display(),
        "deploying preview"
    );

    // (1) Fetch into a staging directory first, then move into place.
    let tmp_dir = site_dir.with_extension("tmp");
    if tmp_dir.exists() {
        tokio::fs::remove_dir_all(&tmp_dir).await.ok();
    }
    fetch_checkout(req, &tmp_dir, ctx.fetch_token).await?;

    // (2) Detect framework + load manifest.
    let framework = detect_framework(&tmp_dir).await;
    let manifest = AppManifest::load(&tmp_dir, framework).await?;
    let websocket = manifest.websocket_enabled(&tmp_dir);
    // Validate `docroot:` against the tree we are about to publish, not the
    // previous deploy's. A declaration ePHPm would reject fails the deploy here
    // rather than silently degrading to "serve the whole checkout".
    let document_root = site_override::validate_docroot(&tmp_dir, &manifest.docroot)?;
    tracing::info!(
        %hostname,
        framework = framework.as_str(),
        php = %manifest.php,
        docroot = %manifest.docroot,
        database = manifest.services.database.as_str(),
        kv = manifest.services.kv,
        websocket,
        build_steps = manifest.build.len(),
        seed_steps = manifest.seed.len(),
        "loaded app manifest"
    );

    // (3) Materialize env: resolve secrets and write env for the app to read.
    // Reference the FINAL (post-swap) prepend path in the sidecar. This runs
    // BEFORE the swap (so `.env`/prepend travel with the tree into `site_dir`,
    // where #29's post-swap chown then hands them to the tenant) and now also
    // before `build:`, which moved after the swap (#28) — so a build step reads
    // the preview's resolved `.env` where it used to run before it existed.
    let final_prepend = site_dir.join(PREPEND_FILE);
    materialize_env(
        &req.repo_full_name,
        &manifest,
        ctx.secrets,
        &tmp_dir,
        &final_prepend,
        websocket,
    )
    .await?;

    // (4a) Validate the prepend we just wrote with ePHPm's own rules, against
    // the staged tree — the same tree the declaration will be resolved against
    // once it is swapped into place. A value ePHPm refuses now takes the site
    // to a 503 (ephpm#472), so this fails the deploy rather than shipping an
    // override that puts the preview out of service.
    let prepend = site_override::validate_prepend(&tmp_dir, PREPEND_FILE)?;

    // Remove .git to save disk before the swap.
    let git_dir = tmp_dir.join(".git");
    if git_dir.exists() {
        tokio::fs::remove_dir_all(&git_dir).await.ok();
    }

    // (4) Take the deploy manifest out of the served root, now that it has been
    // read. (`build:` runs after the swap now, sandboxed, and reads the manifest
    // from switchboard's parsed copy — not from the served tree — so quarantine
    // no longer has to wait for it.)
    //
    // `ephpm.yaml` is not dot-prefixed, and for `docroot: "."` the checkout
    // root IS the web root — so it was served: `GET /ephpm.yaml` → 200 with the
    // build commands, the enabled services and the whole seed sequence
    // (switchboard#16). Before the swap, so it is never in a live web root even
    // briefly. See `manifest::quarantine_manifests` for why the per-site
    // override cannot cover this.
    let quarantined = crate::manifest::quarantine_manifests(&tmp_dir).await?;
    if !quarantined.is_empty() {
        tracing::info!(
            %hostname,
            manifests = %quarantined.join(", "),
            archive = crate::manifest::MANIFEST_ARCHIVE_DIR,
            "deploy manifest(s) removed from the served root"
        );
    }

    // (5) The per-site override — document root AND env prepend — written
    // BEFORE the swap.
    //
    // Order matters: ePHPm resolves a vhost's roots on first request and caches
    // them briefly, so writing the override after the swap leaves a window in
    // which a fresh preview serves its container — `vendor/`, `config/`,
    // `storage/logs/*.log` and all — and boots without its `env:`. Writing it
    // first means the directory appears already carrying both. ePHPm validates
    // the declarations against the container, and until the swap the container
    // does not exist, so there is no vhost for that host to resolve in the
    // meantime.
    //
    // On a **redeploy** the previous container is still live while this is
    // written, and it also carries `PREPEND_FILE` (every deploy writes it under
    // that same constant name), so the declaration stays resolvable throughout.
    // That is the second reason the filename must not become deploy-specific.
    let over = site_override::SiteOverride {
        document_root,
        auto_prepend_file: Some(prepend),
    };
    apply_site_override(ctx, &site_key, &over, &hostname).await?;

    // (6) Atomic swap: remove old site dir (if any), rename tmp into place.
    if site_dir.exists() {
        tokio::fs::remove_dir_all(&site_dir)
            .await
            .context("failed to remove old preview")?;
    }
    tokio::fs::rename(&tmp_dir, &site_dir)
        .await
        .context("failed to move preview into place")?;

    // (6b) Hand the swapped tree to the tenant uid, BEFORE the sandboxed build.
    //
    // switchboard runs as root and lays the site directory down root-owned, but
    // since #28 `build:`/`seed:` run through `ephpm exec --site`, which drops to
    // the tenant uid. A root-owned tree the tenant cannot write means
    // `assemble.sh` can't populate the docroot and the seed can't write its log:
    // every step fails "Permission denied" in milliseconds and the preview
    // serves 404. The build must own the container it writes, so the tree is
    // chowned to the tenant here — after the swap (the tree is now at its final
    // path) and before `run_build`.
    //
    // The tenant owner is DERIVED, not configured: it is whoever owns
    // `sites_dir` itself (`ephpm-web:ephpm-web` on the nodes — the uid
    // `ephpm exec` drops to and the per-vhost state root is already chowned to).
    // A freshly-created site directory should match its parent's ownership, so
    // there is no second source of truth for the tenant uid and nothing is
    // hardcoded. The recursion never follows a symlink (`lchown`, and it
    // descends only into real directories) — the fetched checkout is
    // attacker-influenced, and a `chown -R` that followed a planted symlink is
    // the same privesc class fixed in `ephpm exec` (#484).
    //
    // Fail-closed: if the chown cannot be applied the deploy fails loudly rather
    // than proceeding to a build that would 404 anyway.
    chown_site_tree_to_tenant(ctx.sites_dir, &site_dir)
        .await
        .with_context(|| {
            format!(
                "failed to hand the swapped site tree {} to the tenant owner; \
                 refusing to run the sandboxed build as a uid that cannot write it",
                site_dir.display()
            )
        })?;

    // The sandbox handle for every untrusted step: `ephpm exec --config … --site
    // <key> -- …`. Both `build:` and `seed:` run through it, so both inherit the
    // uid drop, Landlock scope, and egress lock. The site key is ePHPm's own
    // canonical derivation (computed above), and `ephpm exec` re-normalizes and
    // allowlist-checks it, so it is a bare vhost name here.
    let sandbox = SandboxExec {
        ephpm_bin: ctx.ephpm_bin,
        ephpm_config: ctx.ephpm_config,
        site_key: &site_key,
    };

    // (7) Run build: commands now that the code lives at `sites_dir/<key>` — the
    // vhost `ephpm exec --site` sandboxes. Runs at the container root (where
    // `composer.json` lives), not the document root.
    run_build(&manifest, &site_dir, ctx.composer, sandbox, &hostname).await;

    // (8) Run seed: commands now that the site is live and its per-site DB can
    // be created on first access.
    let preview_url = preview_url(&hostname, Some(manifest.php.as_str()));
    run_seed(
        &manifest,
        &site_dir,
        sandbox,
        &preview_url,
        &hostname,
        req.pr_number,
    )
    .await;

    // (9) Health-gate: only report ready once the site serves a 200.
    let healthy = wait_healthy(&preview_url, &manifest.health, ctx).await;

    let duration = start.elapsed();
    tracing::info!(
        %hostname,
        framework = framework.as_str(),
        healthy,
        duration_ms = duration.as_millis(),
        "preview deployed"
    );

    Ok(DeployResult {
        hostname,
        framework,
        duration,
        php_version: Some(manifest.php),
        healthy,
    })
}

/// Materialize the PR head at `req.sha` into `dest`.
///
/// The preferred path is a shallow fetch of `refs/pull/<n>/head` from the
/// **base** repository: it resolves the head commit of a fork PR without
/// cloning the fork, and it still resolves after the fork is deleted. The exact
/// SHA is requested first (GitHub serves reachable SHAs), so a force-push
/// between the webhook and the deploy cannot silently swap the code out from
/// under the recorded commit; only if that is refused do we fall back to the
/// ref tip, and then loudly.
///
/// When no `fetch_ref` is known (the legacy webhook path) this degrades to a
/// shallow branch clone.
///
/// `token` is the installation access token that authenticates the fetch against
/// a **private** repository. `None` fetches unauthenticated (public repos only);
/// a private repo then fails with the [`private_repo_hint`] message rather than
/// a bare git error. The token is applied as a transient, per-process
/// `http.extraheader` credential ([`fetch_auth_config`]) and never persisted or
/// logged.
async fn fetch_checkout(
    req: &PreviewRequest,
    dest: &Path,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let auth = fetch_auth_config(token);

    let Some(pull_ref) = req.fetch_ref.as_deref() else {
        return clone_branch(
            &req.fetch_url,
            req.branch.as_deref(),
            &req.sha,
            dest,
            &auth,
            token.is_some(),
        )
        .await;
    };

    tokio::fs::create_dir_all(dest)
        .await
        .with_context(|| format!("failed to create {}", dest.display()))?;
    run_git(dest, &["init", "--quiet"]).await?;
    run_git(dest, &["remote", "add", "origin", &req.fetch_url]).await?;

    // Exact SHA first. The credential rides only on the fetch (it is what talks
    // to GitHub); init/remote-add/checkout are local and take none.
    if run_git_fetch(dest, &auth, &["fetch", "--depth", "1", "origin", &req.sha])
        .await
        .is_ok()
        && run_git(dest, &["checkout", "--quiet", "--detach", &req.sha])
            .await
            .is_ok()
    {
        return Ok(());
    }

    // Fall back to the ref tip. This is the head of the PR *now*, which may be
    // a newer commit than the job recorded — say so rather than pretend.
    run_git_fetch(dest, &auth, &["fetch", "--depth", "1", "origin", pull_ref])
        .await
        .with_context(|| {
            format!(
                "failed to fetch {pull_ref} from {}{}",
                req.fetch_url,
                private_repo_hint(token.is_some())
            )
        })?;
    run_git(dest, &["checkout", "--quiet", "--detach", "FETCH_HEAD"])
        .await
        .context("failed to check out FETCH_HEAD")?;
    tracing::warn!(
        label = %req.label,
        sha = %req.sha,
        %pull_ref,
        "exact SHA unavailable — deployed the current tip of the pull ref instead"
    );
    Ok(())
}

/// Legacy path: shallow clone a branch, falling back to a full clone plus an
/// explicit checkout when the branch has been force-pushed or renamed.
///
/// `auth` is the transient credential prefix from [`fetch_auth_config`] (empty
/// for a public repo); `token_present` only drives the [`private_repo_hint`] on
/// failure. The `auth` args go **before** the `clone` subcommand so `-c` applies,
/// and are kept out of the error context.
async fn clone_branch(
    clone_url: &str,
    branch: Option<&str>,
    sha: &str,
    dest: &Path,
    auth: &[String],
    token_present: bool,
) -> anyhow::Result<()> {
    if let Some(branch) = branch {
        let status = Command::new("git")
            .args(auth)
            .args(["clone", "--depth", "1", "--branch", branch, clone_url])
            .arg(dest)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("failed to run git clone")?;
        if status.success() {
            return Ok(());
        }
        let _ = tokio::fs::remove_dir_all(dest).await;
    }

    let status = Command::new("git")
        .args(auth)
        .args(["clone", "--depth", "1", clone_url])
        .arg(dest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("git clone fallback failed")?;
    anyhow::ensure!(
        status.success(),
        "git clone failed{}",
        private_repo_hint(token_present)
    );

    run_git(dest, &["checkout", "--quiet", "--detach", sha]).await
}

/// Run `git` in `dir`, erroring on a non-zero exit.
///
/// For **unauthenticated** git operations only (init, remote-add, checkout).
/// The authenticated fetch goes through [`run_git_fetch`], which keeps the
/// credential out of the strings this function joins into its error context.
async fn run_git(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    anyhow::ensure!(status.success(), "git {} failed", args.join(" "));
    Ok(())
}

/// The transient `-c http.extraheader=...` arguments that authenticate a fetch
/// with a GitHub App installation token — or an **empty** vec for an
/// unauthenticated (public-repo) fetch.
///
/// The credential is `Authorization: Basic base64("x-access-token:<token>")`,
/// the scheme GitHub documents for App installation tokens over HTTPS. It is
/// passed with `-c` so it applies to the **single** git process it prefixes and
/// is *never* written into the repository's persisted `.git/config`. The
/// returned strings contain the token verbatim, so they must never be logged —
/// [`run_git_fetch`] is the only consumer and it keeps them out of every error
/// string and log line.
fn fetch_auth_config(token: Option<&str>) -> Vec<String> {
    let Some(token) = token else {
        return Vec::new();
    };
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    // NB: `http.extraheader` (not `http.<url>.extraheader`) — scoped to this
    // process by `-c`, so a broad key is fine and matches GitHub Actions'
    // own checkout credential.
    vec![
        "-c".to_owned(),
        format!("http.extraheader=Authorization: Basic {basic}"),
    ]
}

/// Run an authenticated `git fetch` in `dir`.
///
/// `auth` is the token-bearing `-c` prefix from [`fetch_auth_config`] (empty for
/// a public repo). It is placed **before** `fetch_args` so the `-c` config
/// applies, and — critically — it is *not* part of `fetch_args`, which is the
/// only slice joined into any error message. A failing fetch therefore reports
/// `git fetch --depth 1 origin <sha>` and never the credential. stderr is
/// discarded (as elsewhere in this module), so the token cannot leak through a
/// captured git error either.
async fn run_git_fetch(dir: &Path, auth: &[String], fetch_args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(auth)
        .args(fetch_args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .with_context(|| format!("failed to run git {}", fetch_args.join(" ")))?;
    anyhow::ensure!(status.success(), "git {} failed", fetch_args.join(" "));
    Ok(())
}

/// The clause appended to a fetch/clone failure when it might be an
/// unauthenticated attempt at a **private** repository.
///
/// Empty when a token *was* supplied (the failure is something else); otherwise
/// it names the missing credential and the `contents: read` permission the App
/// installation needs, so a private-repo failure reads as a configuration gap
/// rather than a mysterious git error.
fn private_repo_hint(token_present: bool) -> &'static str {
    if token_present {
        ""
    } else {
        " — no GitHub App installation token was available, so a PRIVATE \
         repository cannot be fetched. Configure --app-id/--app-key \
         (SWITCHBOARD_APP_ID/SWITCHBOARD_APP_KEY) and ensure the App \
         installation has `contents: read`"
    }
}

/// Recursively hand the swapped site tree at `site_dir` to the tenant owner so
/// the sandboxed `build:`/`seed:` steps — which `ephpm exec` runs as the tenant
/// uid — can write into their own container.
///
/// The tenant `(uid, gid)` is **derived** from `sites_dir` itself, not
/// configured: previews live directly under `sites_dir`, which ePHPm owns as the
/// tenant user (`ephpm-web:ephpm-web` on the nodes), and a fresh site directory
/// should carry that same ownership. Deriving it here avoids a second source of
/// truth for the tenant uid and avoids hardcoding `ephpm-web`/997.
///
/// The per-vhost state root (`$TMPDIR/ephpm-vhosts/<key>`) is **not** touched
/// here: `ephpm exec` creates and chowns it to the tenant itself (ephpm#484), so
/// doing it again would be redundant (and racy — that path is outside the site
/// tree). Only the deploy tree is switchboard's to hand over.
///
/// The walk is symlink-safe (see [`chown_tree_no_follow`]).
///
/// # Errors
///
/// Returns an error if `sites_dir` cannot be stat'd for its owner, or if any
/// `lchown` in the tree fails — the caller turns that into a failed deploy
/// rather than building as a uid that cannot write the tree.
#[cfg(unix)]
async fn chown_site_tree_to_tenant(sites_dir: &Path, site_dir: &Path) -> anyhow::Result<()> {
    let (uid, gid) = tenant_owner(sites_dir)?;
    let root = site_dir.to_path_buf();
    // The recursive walk is blocking filesystem work; keep it off the async
    // reactor. The tree is a checkout, so bounded but not tiny.
    tokio::task::spawn_blocking(move || chown_tree_no_follow(&root, uid, gid))
        .await
        .context("chown task panicked")?
        .with_context(|| format!("failed to chown the site tree to tenant {uid}:{gid}"))?;
    tracing::info!(
        site_dir = %site_dir.display(),
        uid,
        gid,
        "handed the swapped site tree to the tenant owner (derived from sites_dir)"
    );
    Ok(())
}

/// Non-unix stub: there is no ownership model to hand over, and the tenant
/// sandbox is Unix-only, so this is a no-op that keeps the pipeline portable for
/// `cargo check`/tests on a developer's Windows machine.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn chown_site_tree_to_tenant(_sites_dir: &Path, _site_dir: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// The `(uid, gid)` owning `sites_dir` — the tenant identity every preview under
/// it should carry. Stat (not `lstat`): `sites_dir` is operator-configured
/// infrastructure, not attacker content, and following it to its target is the
/// intended read.
#[cfg(unix)]
fn tenant_owner(sites_dir: &Path) -> anyhow::Result<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(sites_dir).with_context(|| {
        format!(
            "failed to stat sites_dir {} to derive the tenant owner",
            sites_dir.display()
        )
    })?;
    Ok((md.uid(), md.gid()))
}

/// Recursively `lchown` `root` and every descendant to `(uid, gid)` **without
/// ever following a symlink**.
///
/// `lchown` changes the symlink itself, never its target; the set of paths comes
/// from [`walk_no_follow`], which descends only into *real* directories. A
/// `chown -R` that followed a symlink planted in the fetched
/// (attacker-influenced) checkout could redirect ownership onto a file outside
/// the deploy tree — the same privesc class fixed in `ephpm exec` (#484) — which
/// this avoids. Mirrors `ephpm-server`'s `privdrop::chown_tree`.
#[cfg(unix)]
fn chown_tree_no_follow(root: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::lchown;
    for path in walk_no_follow(root)? {
        lchown(&path, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Every path a symlink-safe recursive chown of `root` touches: `root` itself
/// plus each descendant, **never following a symlink**. A symlink is included
/// (so it is `lchown`ed as a link) but its target is not visited, and a
/// symlinked directory is not descended into — `DirEntry::file_type` reports the
/// entry's own type without following, and only real directories are recursed.
///
/// Split out from [`chown_tree_no_follow`] so the traversal — the symlink-safety
/// property — is assertable without needing root to observe an actual `lchown`.
#[cfg(unix)]
fn walk_no_follow(root: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = vec![root.to_path_buf()];
    // Only push a path onto the descend stack if it is a REAL directory.
    let mut stack = if std::fs::symlink_metadata(root)?.is_dir() {
        vec![root.to_path_buf()]
    } else {
        Vec::new()
    };
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let is_real_dir = entry.file_type()?.is_dir();
            out.push(path.clone());
            if is_real_dir {
                stack.push(path);
            }
        }
    }
    Ok(out)
}

/// The `ephpm exec --site` sandbox handle for one preview.
///
/// Turns a tenant shell command into an `ephpm exec` invocation that runs it as
/// the tenant uid, under Landlock, behind the egress firewall. Env for the step
/// is set on the returned [`Command`] and reaches the step by inheritance
/// (`ephpm exec` `execvp`s it); the working directory is fixed with an explicit
/// `cd` prefix rather than relying on `ephpm exec`'s own chdir.
#[derive(Clone, Copy)]
struct SandboxExec<'a> {
    ephpm_bin: &'a Path,
    ephpm_config: &'a Path,
    site_key: &'a str,
}

impl SandboxExec<'_> {
    /// The `ephpm` argv that runs `shell_cmd` with `cwd = workdir` inside the
    /// tenant sandbox. Pure (spawns nothing) so the exact invocation is
    /// assertable in tests.
    ///
    /// `workdir` is an absolute path *inside the site container* (the container
    /// root for `build:`, the document root for `seed:`) — both are within the
    /// Landlock read/write grant, so the `cd` succeeds after the uid drop.
    fn argv(self, workdir: &Path, shell_cmd: &str) -> Vec<String> {
        let inner = format!(
            "cd {} && {shell_cmd}",
            posix_single_quote(&workdir.to_string_lossy())
        );
        vec![
            "exec".to_owned(),
            "--config".to_owned(),
            self.ephpm_config.to_string_lossy().into_owned(),
            "--site".to_owned(),
            self.site_key.to_owned(),
            "--".to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            inner,
        ]
    }

    /// A [`Command`] for [`Self::argv`], ready for the caller to attach env and
    /// stdio before spawning.
    fn command(self, workdir: &Path, shell_cmd: &str) -> Command {
        let mut c = Command::new(self.ephpm_bin);
        c.args(self.argv(workdir, shell_cmd));
        c
    }
}

/// POSIX single-quote a string so it survives one round of `sh -c` word
/// splitting. `'` is closed, escaped, and reopened (`'\''`).
fn posix_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Whether `ephpm --help` output advertises the `exec` subcommand.
///
/// clap lists subcommands one per line, name first, under `Commands:`. An
/// `ephpm` predating #484 has no such line. This is the version probe that keeps
/// the deploy fail-closed.
fn help_advertises_exec(help: &str) -> bool {
    help.lines().any(|line| {
        let t = line.trim_start();
        t == "exec" || t.starts_with("exec ") || t.starts_with("exec\t")
    })
}

/// Probe whether `ephpm_bin` supports `ephpm exec` (ephpm#484).
///
/// Runs `ephpm_bin --help` and inspects the subcommand list. A binary that
/// cannot even be spawned is a hard error (propagated), so a missing or
/// mis-pathed `ephpm` fails the deploy rather than silently degrading.
///
/// # Errors
///
/// Returns an error if the binary cannot be executed.
async fn ephpm_exec_supported(ephpm_bin: &Path) -> anyhow::Result<bool> {
    let output = Command::new(ephpm_bin)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("failed to run {} --help", ephpm_bin.display()))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(help_advertises_exec(&text))
}

/// Refuse the deploy unless `ephpm_bin` can run steps sandboxed (has `exec`).
///
/// This is the fail-closed gate: `build:`/`seed:` run untrusted PR code, and the
/// only two options are "sandboxed via `ephpm exec`" or "not at all". Falling
/// back to the old root `sh -c` path would re-open the exact root-RCE this
/// change closes, so there is deliberately no such fallback.
///
/// # Errors
///
/// Returns an error if `ephpm_bin` cannot be spawned, or runs but does not
/// advertise the `exec` subcommand (an ePHPm predating #484).
async fn ensure_sandboxed_exec(ephpm_bin: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        ephpm_exec_supported(ephpm_bin).await?,
        "the configured ephpm binary ({}) does not support `ephpm exec` — \
         refusing to deploy. build:/seed: steps run untrusted pull-request code \
         and must run sandboxed (uid drop + Landlock + egress, ephpm#484); \
         switchboard will NOT fall back to running them as root. Deploy an ePHPm \
         that carries #484 to this node first, then this switchboard. Set \
         --ephpm-bin (SWITCHBOARD_EPHPM_BIN) if the binary is elsewhere.",
        ephpm_bin.display()
    );
    Ok(())
}

/// Run the manifest's `build:` commands in order, each sandboxed via
/// `ephpm exec --site`. If the manifest declares no build steps, fall back to an
/// implicit `composer install` when a `composer.json` exists (POC
/// compatibility). Failures are logged and the deploy continues.
///
/// Every step runs at the **container root** (`site_dir`) — where
/// `composer.json` and the project files live — not the document root, as the
/// pre-sandbox path did (it ran `sh -c` with `current_dir(checkout)`).
async fn run_build(
    manifest: &AppManifest,
    site_dir: &Path,
    composer: &str,
    sandbox: SandboxExec<'_>,
    hostname: &str,
) {
    if manifest.build.is_empty() {
        if site_dir.join("composer.json").exists() {
            tracing::info!(%hostname, "no build steps declared — running implicit composer install (sandboxed)");
            let cmd = format!(
                "{} install --no-dev --no-interaction --optimize-autoloader --quiet",
                posix_single_quote(composer)
            );
            let status = sandbox
                .command(site_dir, &cmd)
                .env("COMPOSER_NO_INTERACTION", "1")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .status()
                .await;
            match status {
                Ok(s) if s.success() => {}
                _ => {
                    tracing::warn!(%hostname, "composer install failed — deploying without dependencies")
                }
            }
        }
        return;
    }

    for (i, cmd) in manifest.build.iter().enumerate() {
        tracing::info!(%hostname, step = i + 1, command = %cmd, "running build step (sandboxed)");
        let status = sandbox
            .command(site_dir, cmd)
            .env("COMPOSER_NO_INTERACTION", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await;
        match status {
            Ok(s) if s.success() => {}
            Ok(_) => {
                tracing::warn!(%hostname, step = i + 1, command = %cmd, "build step failed — continuing")
            }
            Err(e) => {
                tracing::warn!(%hostname, step = i + 1, command = %cmd, %e, "build step could not run — continuing")
            }
        }
    }
}

/// Publish the preview's per-site override — its document root and the env
/// prepend ePHPm auto-loads.
///
/// # One file, always written
///
/// This used to *remove* the override for `docroot: "."`, on the reasoning that
/// an absent file and "the container is the web root" are the same thing to
/// ePHPm. They are — for routing. They stopped being the same thing when the
/// file gained `auto_prepend_file`: `docroot: "."` is precisely the shape with
/// nowhere else to put a bootstrap hook, and removing its override is what left
/// `env:` with no delivery path at all (switchboard#4). So the file is written
/// for every preview, and `docroot: "."` is expressed by *not emitting*
/// `document_root` rather than by not writing the file.
///
/// Two outcomes, both stated in the log rather than inferred:
///
/// * `--site-overrides-dir` is set → the override is written atomically;
/// * `--site-overrides-dir` is **not** set → a `warn!` naming both consequences:
///   ePHPm serves the whole checkout (the exposure switchboard#3 is about) and
///   the manifest's `env:` reaches PHP only through the generated `.env`. Not an
///   error: a preview without either is still a working preview, and failing
///   every deploy on a node the operator has not finished configuring is worse
///   than saying so loudly.
///
/// `docroot: "."` also gets a `warn!` of its own, in every configuration. It
/// stays **supported** — WordPress genuinely serves from its repository root,
/// and refusing it would refuse the only app this cluster deploys — but it
/// means every non-dot-prefixed file in the checkout is public, which is how
/// switchboard#16 happened. That is a property worth one line per deploy rather
/// than a footnote in a guide.
///
/// # Errors
///
/// Returns an error if the override file cannot be written or removed.
async fn apply_site_override(
    ctx: &DeployContext<'_>,
    site_key: &str,
    over: &site_override::SiteOverride,
    hostname: &str,
) -> anyhow::Result<()> {
    if !over.document_root.narrows_the_web_root() {
        tracing::warn!(
            %hostname,
            site_key,
            "docroot is the repository root (`.`) — every non-dot-prefixed file \
             in this checkout is publicly served, including anything a build \
             step wrote. switchboard removes its own artifacts and the deploy \
             manifest, but it cannot vet the repository's contents \
             (switchboard#16). Declare a `docroot:` subdirectory to narrow it"
        );
    }

    let Some(overrides_dir) = ctx.site_overrides_dir else {
        tracing::warn!(
            %hostname,
            docroot = over.document_root.declared(),
            "no per-site override can be written: --site-overrides-dir is not \
             configured. ePHPm will serve the whole checkout — including \
             vendor/, config/ and storage/logs/ — and the manifest's `env:` will \
             reach PHP only through the generated .env, not through an \
             auto-loaded prepend. Set it to ePHPm's [server] site_overrides_dir \
             (a directory OUTSIDE sites_dir)"
        );
        return Ok(());
    };

    let path = site_override::write_override(overrides_dir, site_key, over).await?;
    tracing::info!(
        %hostname,
        site_key,
        docroot = over.document_root.declared(),
        auto_prepend_file = over.auto_prepend_file.as_ref().map(site_override::PrependFile::declared),
        path = %path.display(),
        "wrote per-site override (document root + env prepend). An ePHPm older \
         than the auto_prepend_file key (ephpm#463) ignores that key with a \
         warning and still honours the document root"
    );
    Ok(())
}

/// Resolve `env:` (including `${secret.NAME}` references) and write it where the
/// app can read it: the PHP prepend ePHPm auto-loads on every request, plus a
/// `.env` for framework-native dotenv loaders and for the out-of-server
/// `build:`/`seed:` steps. Also writes a non-secret sidecar exposing the
/// effective manifest.
///
/// See [`PREPEND_FILE`] and [`DOTENV_FILE`] for why both exist and which wins.
async fn materialize_env(
    repo: &str,
    manifest: &AppManifest,
    secrets: &Secrets,
    checkout: &Path,
    prepend_hint: &Path,
    websocket: bool,
) -> anyhow::Result<()> {
    let mut resolved: BTreeMap<String, String> = BTreeMap::new();
    for (key, raw) in &manifest.env {
        let mut missing = Vec::new();
        let value = secrets.substitute(repo, raw, &mut missing);
        for name in missing {
            // Name-only warning — never the value.
            tracing::warn!(env_key = %key, secret = %name, "referenced secret not found — substituting empty");
        }
        resolved.insert(key.clone(), value);
    }

    // A manifest key the host owns is not an error — the prepend refuses to let
    // it win in `$_SERVER` — but the author should hear that it will not take
    // effect there, because it reads like it would.
    let shadowed: Vec<&str> = resolved
        .keys()
        .filter(|k| HOST_OWNED_SERVER_PREFIXES.iter().any(|p| k.starts_with(p)))
        .map(String::as_str)
        .collect();
    if !shadowed.is_empty() {
        tracing::warn!(
            keys = %shadowed.join(", "),
            "`env:` declares keys ePHPm injects itself (the live per-site \
             database/KV credentials, which rotate). They will NOT replace \
             $_SERVER — the host's values win. They are still set in $_ENV and \
             putenv() for code that reads those"
        );
    }

    // The PHP prepend: ePHPm executes this before every request for the site
    // (see PREPEND_FILE and `apply_site_override`).
    //
    // Unlink first. `write` follows a symlink, so a repository shipping a
    // symlink at this name would have the preview's resolved secrets — every
    // `${secret.NAME}` in the manifest — written through it to wherever it
    // points. Removing the entry replaces the *link*, not its target, and
    // leaves us writing a regular file we own. (ePHPm would refuse to prepend a
    // symlink escaping the container, so this is about the write, not the
    // include.)
    let prepend_path = checkout.join(PREPEND_FILE);
    match tokio::fs::symlink_metadata(&prepend_path).await {
        Ok(meta) => {
            tracing::warn!(
                path = %prepend_path.display(),
                symlink = meta.is_symlink(),
                "repository ships a file at switchboard's generated prepend path — replacing it"
            );
            tokio::fs::remove_file(&prepend_path)
                .await
                .context("failed to replace the repository's file at the preview prepend path")?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).context("failed to inspect the preview prepend path");
        }
    }
    tokio::fs::write(&prepend_path, render_php_prepend(&resolved))
        .await
        .context("failed to write preview env prepend")?;

    // Dotenv: written for every docroot shape. A committed `.env` is replaced,
    // which is intended (the preview's values are the ones that describe *this*
    // deployment) but was never stated anywhere an app author would look — so
    // say it out loud when it happens.
    let dotenv_path = checkout.join(DOTENV_FILE);
    if tokio::fs::try_exists(&dotenv_path).await.unwrap_or(false) {
        tracing::warn!(
            path = %dotenv_path.display(),
            "repository ships a committed .env — replacing it with the preview's \
             resolved env: values"
        );
    }
    tokio::fs::write(&dotenv_path, render_dotenv(&resolved))
        .await
        .context("failed to write preview .env")?;

    // Non-secret sidecar for debugging: env KEYS only, never values.
    //
    // `ini` is recorded exactly as the manifest declared it. It once gained a
    // synthesized `auto_prepend_file` entry pointing at the prepend, which read
    // like a wiring step and was none — ePHPm does not read this file. The real
    // wiring lives in `<site_overrides_dir>/<site_key>.toml`, so what is
    // recorded here is that the declaration was *made*, and where. Whether the
    // server honours it depends on its version (ephpm#463), which this daemon
    // has no channel to ask about — so it is not claimed.
    let sidecar = serde_json::json!({
        "generated_by": "switchboard",
        "php": manifest.php,
        "docroot": manifest.docroot,
        "health": manifest.health,
        "services": {
            "database": manifest.services.database.as_str(),
            "kv": manifest.services.kv,
            "websocket": websocket,
        },
        "ini": manifest.ini,
        "env_keys": resolved.keys().collect::<Vec<_>>(),
        // Where the prepend will live once the checkout is swapped into place,
        // for an app that wants to require it by absolute path.
        "prepend_file": prepend_hint.to_string_lossy(),
        // The relative value written into the site override's
        // `auto_prepend_file`. Present means "declared", not "honoured".
        "prepend_declared_as": PREPEND_FILE,
    });
    tokio::fs::write(
        checkout.join(SIDECAR_FILE),
        serde_json::to_vec_pretty(&sidecar).context("failed to serialize preview sidecar")?,
    )
    .await
    .context("failed to write preview sidecar")?;

    if !manifest.ini.is_empty() {
        tracing::warn!(
            keys = %manifest.ini.keys().cloned().collect::<Vec<_>>().join(", "),
            "ephpm.yaml `ini:` is advisory — switchboard records it but nothing \
             applies it to the running server"
        );
    }
    tracing::info!(
        env_count = resolved.len(),
        prepend = PREPEND_FILE,
        dotenv = DOTENV_FILE,
        "materialized preview environment (auto-loaded prepend + .env for \
         build:/seed: and dotenv-reading frameworks)"
    );
    Ok(())
}

/// `$_SERVER` name prefixes ePHPm itself owns.
///
/// The server injects this vhost's live database and KV credentials into
/// `$_SERVER` through `register_server_variables`, and they **rotate** — the
/// per-site password is `HMAC-SHA256(master_secret, site_key)` over a secret
/// regenerated at every host restart. The prepend must not overwrite them.
///
/// This mattered less when the prepend only ran if the app chose to
/// `require_once` it. Now that ePHPm auto-loads it *after*
/// `register_server_variables` and *before* the app, a manifest declaring
/// `env: { DB_HOST: ... }` would silently replace a working credential with a
/// stale literal on every request. See guide §2.
const HOST_OWNED_SERVER_PREFIXES: [&str; 2] = ["DB_", "EPHPM_"];

/// Render the PHP prepend that exports env via `$_SERVER` (and `$_ENV`/`putenv`
/// for older code).
///
/// `$_SERVER` is the one that matters: ePHPm has no `sapi_module.getenv` handler
/// and injects everything through `register_server_variables`, so the guide
/// tells app authors to read `$_SERVER`, and phpdotenv consults it first. The
/// other two are written for code that predates that advice.
///
/// Keys under [`HOST_OWNED_SERVER_PREFIXES`] are written to `$_ENV`/`putenv` but
/// **not** allowed to overwrite an existing `$_SERVER` entry, so a manifest can
/// never clobber the live per-site credential with a stale literal.
fn render_php_prepend(env: &BTreeMap<String, String>) -> String {
    let mut php = String::from(
        "<?php\n// Generated by switchboard for the ePHPm preview. Do not commit.\n\
         // Loaded by ePHPm as this site's auto_prepend_file (switchboard#4).\n\
         $__ephpm_preview_env = [\n",
    );
    for (key, value) in env {
        php.push_str(&format!(
            "    '{}' => '{}',\n",
            php_single_quote_escape(key),
            php_single_quote_escape(value)
        ));
    }
    let guarded = HOST_OWNED_SERVER_PREFIXES
        .iter()
        .map(|p| format!("'{p}'"))
        .collect::<Vec<_>>()
        .join(", ");
    php.push_str(&format!(
        "];\n$__ephpm_host_owned = [{guarded}];\n\
         foreach ($__ephpm_preview_env as $__k => $__v) {{\n\
         \x20   putenv(\"$__k=$__v\");\n\
         \x20   $_ENV[$__k] = $__v;\n\
         \x20   // Never replace a credential the host injected for this vhost:\n\
         \x20   // it is live, per-site, and rotates on every host restart.\n\
         \x20   $__owned = false;\n\
         \x20   foreach ($__ephpm_host_owned as $__p) {{\n\
         \x20       if (str_starts_with($__k, $__p)) {{ $__owned = true; break; }}\n\
         \x20   }}\n\
         \x20   if ($__owned && isset($_SERVER[$__k])) {{ continue; }}\n\
         \x20   $_SERVER[$__k] = $__v;\n\
         }}\nunset($__k, $__v, $__p, $__owned, $__ephpm_host_owned);\n"
    ));
    php
}

/// Escape a string for a PHP single-quoted literal ('...').
fn php_single_quote_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Render a dotenv file (`KEY="value"` with escaping).
fn render_dotenv(env: &BTreeMap<String, String>) -> String {
    let mut out =
        String::from("# Generated by switchboard for the ePHPm preview. Do not commit.\n");
    for (key, value) in env {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        out.push_str(&format!("{key}=\"{escaped}\"\n"));
    }
    out
}

/// Run the manifest's `seed:` commands in order, each sandboxed via
/// `ephpm exec --site`, at the live site's **document root**, with
/// `$PREVIEW_URL`/`$PREVIEW_HOST`/`$PR` set (these reach the step by inheritance
/// through `ephpm exec`). Failures are logged and the deploy continues.
async fn run_seed(
    manifest: &AppManifest,
    site_dir: &Path,
    sandbox: SandboxExec<'_>,
    preview_url: &str,
    hostname: &str,
    pr_number: u64,
) {
    let workdir = site_dir.join(&manifest.docroot);
    for (i, cmd) in manifest.seed.iter().enumerate() {
        tracing::info!(%hostname, step = i + 1, command = %cmd, "running seed step (sandboxed)");
        let status = sandbox
            .command(&workdir, cmd)
            .env("PREVIEW_URL", preview_url)
            .env("PREVIEW_HOST", hostname)
            .env("PR", pr_number.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .await;
        match status {
            Ok(s) if s.success() => {}
            Ok(_) => {
                tracing::warn!(%hostname, step = i + 1, command = %cmd, "seed step failed — continuing")
            }
            Err(e) => {
                tracing::warn!(%hostname, step = i + 1, command = %cmd, %e, "seed step could not run — continuing")
            }
        }
    }
}

/// Poll `<preview_url><health_path>` until it returns 200 or the timeout
/// elapses. A zero timeout disables the gate (returns `false` without polling).
async fn wait_healthy(preview_url: &str, health_path: &str, ctx: &DeployContext<'_>) -> bool {
    if ctx.health_timeout.is_zero() {
        tracing::debug!("health gating disabled (timeout = 0)");
        return false;
    }
    let url = format!("{}{}", preview_url.trim_end_matches('/'), health_path);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "failed to build health-check client");
            return false;
        }
    };

    let deadline = Instant::now() + ctx.health_timeout;
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().as_u16() == 200 => {
                tracing::info!(%url, "health check passed");
                return true;
            }
            Ok(resp) => tracing::debug!(%url, status = %resp.status(), "health check not ready"),
            Err(e) => tracing::debug!(%url, %e, "health check request failed"),
        }
        if Instant::now() >= deadline {
            tracing::warn!(%url, timeout_s = ctx.health_timeout.as_secs(), "health check did not pass before timeout");
            return false;
        }
        tokio::time::sleep(ctx.health_interval).await;
    }
}

/// Build the full preview URL, accounting for PHP version port mapping.
///
/// Default/latest PHP (8.5) uses port 443 (no port in URL). Older versions get
/// their own port: 8.4 → :8084, 8.3 → :8083.
#[must_use]
pub fn preview_url(hostname: &str, php_version: Option<&str>) -> String {
    match php_version {
        None | Some("8.5") => format!("https://{hostname}"),
        Some(v) => {
            let port = v
                .strip_prefix("8.")
                .and_then(|minor| minor.parse::<u16>().ok())
                .map_or(443, |minor| 8080 + minor);
            if port == 443 {
                format!("https://{hostname}")
            } else {
                format!("https://{hostname}:{port}")
            }
        }
    }
}

/// Detect the PHP framework from the project files.
async fn detect_framework(dir: &Path) -> Framework {
    if dir.join("wp-config.php").exists() || dir.join("wp-config-sample.php").exists() {
        return Framework::WordPress;
    }

    if let Ok(contents) = tokio::fs::read_to_string(dir.join("composer.json")).await {
        let lower = contents.to_ascii_lowercase();
        if lower.contains("laravel/framework") {
            return Framework::Laravel;
        }
        if lower.contains("drupal/core") {
            return Framework::Drupal;
        }
        if lower.contains("symfony/framework-bundle") {
            return Framework::Symfony;
        }
    }

    if dir.join("artisan").exists() {
        return Framework::Laravel;
    }

    Framework::Generic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detect_wordpress() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("wp-config-sample.php"), "<?php")
            .await
            .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::WordPress);
    }

    #[tokio::test]
    async fn detect_laravel_from_composer() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("composer.json"),
            r#"{"require": {"laravel/framework": "^11.0"}}"#,
        )
        .await
        .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Laravel);
    }

    #[tokio::test]
    async fn detect_laravel_from_artisan() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("artisan"), "#!/usr/bin/env php")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Laravel);
    }

    #[tokio::test]
    async fn detect_generic() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.php"), "<?php echo 'hi';")
            .await
            .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Generic);
    }

    #[tokio::test]
    async fn detect_symfony_from_composer() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("composer.json"),
            r#"{"require": {"symfony/framework-bundle": "^7.0"}}"#,
        )
        .await
        .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Symfony);
    }

    #[tokio::test]
    async fn detect_drupal_from_composer() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("composer.json"),
            r#"{"require": {"drupal/core": "^10.0"}}"#,
        )
        .await
        .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Drupal);
    }

    #[tokio::test]
    async fn detect_wordpress_takes_precedence_over_composer() {
        // A repo can carry both wp-config and a composer.json naming another
        // framework; the wp-config check runs first and must win.
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("wp-config.php"), "<?php")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("composer.json"),
            r#"{"require": {"laravel/framework": "^11.0"}}"#,
        )
        .await
        .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::WordPress);
    }

    #[test]
    fn framework_labels() {
        assert_eq!(Framework::WordPress.as_str(), "WordPress");
        assert_eq!(Framework::Laravel.as_str(), "Laravel");
        assert_eq!(Framework::Symfony.as_str(), "Symfony");
        assert_eq!(Framework::Drupal.as_str(), "Drupal");
        // Generic renders as the neutral "PHP" label, not "Generic".
        assert_eq!(Framework::Generic.as_str(), "PHP");
    }

    // ── env materialization ─────────────────────────────────────────

    fn wp_sample_manifest_with_env() -> AppManifest {
        AppManifest::from_yaml_str(
            "version: 1\ndocroot: \"public\"\nenv:\n  \
             WP_ENVIRONMENT_TYPE: \"staging\"\n  SOME_KEY: \"${secret.some_key}\"\n  \
             MISSING: \"${secret.absent}\"\n",
        )
        .unwrap()
    }

    fn make_request() -> PreviewRequest {
        PreviewRequest {
            label: "ephpm-wordpress-sample-pr-7".into(),
            repo_full_name: "ephpm/wordpress-sample".into(),
            owner: "ephpm".into(),
            repo_name: "wordpress-sample".into(),
            pr_number: 7,
            fetch_url: "https://github.com/ephpm/wordpress-sample.git".into(),
            fetch_ref: Some("refs/pull/7/head".into()),
            branch: Some("feature".into()),
            sha: "0123456789abcdef0123456789abcdef01234567".into(),
            installation_id: None,
            fork: false,
        }
    }

    // ── the fork gate ───────────────────────────────────────────────

    #[test]
    fn non_fork_deploys_resolve_secrets_regardless_of_flags() {
        for allow in [false, true] {
            for secrets in [false, true] {
                assert_eq!(
                    fork_deploy_gate(false, allow, secrets).unwrap(),
                    ForkSecrets::Resolve,
                    "a same-repo PR must be unaffected by the fork flags"
                );
            }
        }
    }

    #[test]
    fn fork_deploy_refused_without_the_flag() {
        for secrets in [false, true] {
            let err = fork_deploy_gate(true, false, secrets)
                .expect_err("a fork deploy without --allow-fork-deploy must fail");
            assert!(err.to_string().contains("--allow-fork-deploy"), "{err}");
        }
    }

    #[test]
    fn allowed_fork_deploy_withholds_secrets_by_default() {
        assert_eq!(
            fork_deploy_gate(true, true, false).unwrap(),
            ForkSecrets::Withhold,
            "allowing the build must not imply handing over the secret store"
        );
    }

    #[test]
    fn fork_secrets_flag_releases_the_store() {
        assert_eq!(
            fork_deploy_gate(true, true, true).unwrap(),
            ForkSecrets::Resolve
        );
    }

    #[test]
    fn preview_host_is_label_plus_domain() {
        // The label is authoritative and used verbatim — the daemon appends
        // its configured domain and nothing else.
        let req = make_request();
        assert_eq!(
            req.preview_host("preview.ephpm.dev"),
            "ephpm-wordpress-sample-pr-7.preview.ephpm.dev"
        );
        assert_eq!(preview_host("some-label", "x.dev"), "some-label.x.dev");
    }

    #[tokio::test]
    async fn materialize_writes_prepend_dotenv_and_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = wp_sample_manifest_with_env();
        let mut default = BTreeMap::new();
        default.insert("some_key".to_string(), "resolved-secret".to_string());
        let secrets = Secrets::from_maps(default, BTreeMap::new());
        let req = make_request();
        let final_prepend = dir.path().join("site").join(PREPEND_FILE);

        materialize_env(
            &req.repo_full_name,
            &manifest,
            &secrets,
            dir.path(),
            &final_prepend,
            false,
        )
        .await
        .unwrap();

        // Prepend contains resolved literal + secret, and empty for missing.
        let prepend = tokio::fs::read_to_string(dir.path().join(PREPEND_FILE))
            .await
            .unwrap();
        assert!(prepend.contains("'WP_ENVIRONMENT_TYPE' => 'staging'"));
        assert!(prepend.contains("'SOME_KEY' => 'resolved-secret'"));
        assert!(prepend.contains("'MISSING' => ''"));

        // docroot != "." so a .env is written too.
        let dotenv = tokio::fs::read_to_string(dir.path().join(DOTENV_FILE))
            .await
            .unwrap();
        assert!(dotenv.contains("SOME_KEY=\"resolved-secret\""));

        // Sidecar carries env KEYS but NOT secret values.
        let sidecar = tokio::fs::read_to_string(dir.path().join(SIDECAR_FILE))
            .await
            .unwrap();
        assert!(sidecar.contains("SOME_KEY"));
        assert!(
            !sidecar.contains("resolved-secret"),
            "sidecar must not leak secret values"
        );
        // The sidecar records that the declaration was *made* and where, not
        // that the server honoured it — this daemon has no channel to ask an
        // ePHPm its version, and the old `"prepend_auto_loaded": false` is no
        // longer true on a server carrying ephpm#463.
        assert!(
            sidecar.contains("\"prepend_declared_as\""),
            "the sidecar must name the value written into the site override"
        );
        assert!(
            !sidecar.contains("prepend_auto_loaded"),
            "the sidecar must not claim a server-side outcome it cannot observe"
        );
    }

    /// **switchboard#4, the whole shape.** `docroot: "."` (WordPress, most
    /// bespoke apps) is the case that had no `env:` delivery at all. It must now
    /// produce: the prepend, a `.env`, *and* an override file naming the prepend
    /// in `auto_prepend_file` — with no `document_root`, because absent is how
    /// "the container is the web root" is spelled.
    #[tokio::test]
    async fn a_root_docroot_preview_gets_an_auto_loaded_prepend() {
        let dir = tempfile::tempdir().unwrap();
        let checkout = dir.path().join("checkout");
        let overrides = dir.path().join("overrides");
        tokio::fs::create_dir_all(&checkout).await.unwrap();

        let manifest = AppManifest::from_yaml_str("version: 1\nenv:\n  K: \"v\"\n").unwrap();
        assert_eq!(manifest.docroot, ".", "this test is about the `.` shape");
        let secrets = Secrets::default();
        let req = make_request();

        materialize_env(
            &req.repo_full_name,
            &manifest,
            &secrets,
            &checkout,
            &checkout.join(PREPEND_FILE),
            false,
        )
        .await
        .unwrap();
        assert!(checkout.join(PREPEND_FILE).exists());
        let dotenv = tokio::fs::read_to_string(checkout.join(DOTENV_FILE))
            .await
            .expect("a `docroot: \".\"` preview must still get its env: values");
        assert!(dotenv.contains("K=\"v\""), "{dotenv}");

        // The half that was missing: the override that wires it up.
        let document_root = site_override::validate_docroot(&checkout, &manifest.docroot).unwrap();
        assert_eq!(document_root, site_override::DocumentRoot::Container);
        let prepend = site_override::validate_prepend(&checkout, PREPEND_FILE)
            .expect("the generated prepend must satisfy ePHPm's containment rules");
        let over = site_override::SiteOverride {
            document_root,
            auto_prepend_file: Some(prepend),
        };
        let path = site_override::write_override(&overrides, "app-pr-7", &over)
            .await
            .unwrap();

        let toml = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(
            toml.contains(&format!("auto_prepend_file = \"{PREPEND_FILE}\"\n")),
            "the override must name the prepend ePHPm will load: {toml}"
        );
        assert!(
            !toml.contains("document_root"),
            "`docroot: \".\"` is spelled by omitting the key: {toml}"
        );
    }

    /// Every generated file is dot-prefixed, which is what makes writing them
    /// into a web-served repository root defensible: ePHPm's `hidden_files`
    /// default is `deny` (403). If one ever stops being a dotfile, this fails.
    #[test]
    fn generated_files_are_all_hidden_from_http() {
        for name in [
            PREPEND_FILE,
            DOTENV_FILE,
            SIDECAR_FILE,
            // Where the deploy parks the app's own manifest (switchboard#16).
            crate::manifest::MANIFEST_ARCHIVE_DIR,
        ] {
            assert!(
                name.starts_with('.'),
                "{name} must be dot-prefixed — it can sit in a web-served root"
            );
        }
    }

    #[test]
    fn php_escaping_is_safe() {
        let mut env = BTreeMap::new();
        env.insert("K".to_string(), "it's a \\ backslash".to_string());
        let php = render_php_prepend(&env);
        assert!(php.contains("'K' => 'it\\'s a \\\\ backslash'"));
    }

    #[test]
    fn php_prepend_exports_all_three_superglobals() {
        // The prepend must populate putenv + $_ENV + $_SERVER so both
        // WordPress getenv() and Laravel env() see the values. `$_SERVER` is
        // the one the guide tells authors to read (§2) — ePHPm has no
        // `sapi_module.getenv`, and phpdotenv consults `$_SERVER` first.
        let mut env = BTreeMap::new();
        env.insert("APP_ENV".to_string(), "preview".to_string());
        let php = render_php_prepend(&env);
        assert!(php.starts_with("<?php"));
        assert!(php.contains("'APP_ENV' => 'preview'"));
        assert!(php.contains("putenv("));
        assert!(php.contains("$_ENV["));
        assert!(php.contains("$_SERVER["));
    }

    /// **The auto-load hazard.** The prepend now runs on every request, after
    /// ePHPm's `register_server_variables` and before the app. A manifest
    /// declaring `DB_HOST` must not replace the live, rotating per-site
    /// credential with a stale literal — so `$_SERVER` writes for host-owned
    /// prefixes are guarded by an `isset` check, while `$_ENV`/`putenv` still
    /// carry the declared value for code that reads those.
    #[test]
    fn the_prepend_never_clobbers_a_host_injected_credential() {
        let mut env = BTreeMap::new();
        env.insert("DB_HOST".to_string(), "elsewhere.example".to_string());
        env.insert("EPHPM_REDIS_PORT".to_string(), "1".to_string());
        env.insert("APP_ENV".to_string(), "preview".to_string());
        let php = render_php_prepend(&env);

        for prefix in HOST_OWNED_SERVER_PREFIXES {
            assert!(
                php.contains(&format!("'{prefix}'")),
                "{prefix} must be in the guard list: {php}"
            );
        }
        assert!(
            php.contains("if ($__owned && isset($_SERVER[$__k])) { continue; }"),
            "the guard must skip only the $_SERVER write: {php}"
        );
        // The values are still delivered everywhere else.
        assert!(php.contains("'DB_HOST' => 'elsewhere.example'"));
        // Temporaries are cleaned up — the prepend runs in the same scope as
        // the app's front controller.
        assert!(php.contains("unset($__k, $__v, $__p, $__owned, $__ephpm_host_owned);"));
    }

    // ── dotenv rendering ────────────────────────────────────────────

    #[test]
    fn dotenv_quotes_and_escapes_values() {
        let mut env = BTreeMap::new();
        env.insert("PLAIN".to_string(), "value".to_string());
        env.insert(
            "TRICKY".to_string(),
            "a \"quote\" and a \\ and\nnewline".to_string(),
        );
        let out = render_dotenv(&env);
        assert!(out.starts_with("# Generated by switchboard"));
        // BTreeMap orders keys, so PLAIN precedes TRICKY deterministically.
        assert!(out.contains("PLAIN=\"value\""));
        // Backslash, double-quote and newline are all escaped so a dotenv
        // loader reads exactly one line per key.
        assert!(out.contains("TRICKY=\"a \\\"quote\\\" and a \\\\ and\\nnewline\""));
        assert!(
            !out.contains("newline\nnewline"),
            "raw newline must not split the value across lines"
        );
    }

    #[test]
    fn dotenv_empty_env_is_just_the_header() {
        let out = render_dotenv(&BTreeMap::new());
        assert_eq!(
            out,
            "# Generated by switchboard for the ePHPm preview. Do not commit.\n"
        );
    }

    // ── preview_url ─────────────────────────────────────────────────

    #[test]
    fn preview_url_default() {
        assert_eq!(
            preview_url("pr-1.app.preview.ephpm.dev", None),
            "https://pr-1.app.preview.ephpm.dev"
        );
    }

    #[test]
    fn preview_url_latest() {
        assert_eq!(
            preview_url("pr-1.app.preview.ephpm.dev", Some("8.5")),
            "https://pr-1.app.preview.ephpm.dev"
        );
    }

    #[test]
    fn preview_url_php84() {
        assert_eq!(
            preview_url("pr-1.app.preview.ephpm.dev", Some("8.4")),
            "https://pr-1.app.preview.ephpm.dev:8084"
        );
    }

    #[test]
    fn preview_url_php83() {
        assert_eq!(
            preview_url("pr-1.app.preview.ephpm.dev", Some("8.3")),
            "https://pr-1.app.preview.ephpm.dev:8083"
        );
    }

    #[test]
    fn preview_url_non_8x_version_has_no_port() {
        // A version that isn't "8.<minor>" (e.g. a hypothetical 7.4 or a
        // major-only "9") can't be mapped to the 808x port scheme, so it
        // falls back to the default port-less https URL rather than emitting
        // a bogus port.
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("7.4")),
            "https://h.preview.ephpm.dev"
        );
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("9")),
            "https://h.preview.ephpm.dev"
        );
        // Non-numeric minor also falls back rather than panicking.
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("8.x")),
            "https://h.preview.ephpm.dev"
        );
    }

    #[test]
    fn preview_url_maps_arbitrary_8x_minor() {
        // The port formula is 8080 + minor, so 8.6 → :8086 generalizes beyond
        // the two currently-shipped older versions.
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("8.6")),
            "https://h.preview.ephpm.dev:8086"
        );
    }

    #[tokio::test]
    async fn health_disabled_when_timeout_zero() {
        let secrets = Secrets::default();
        let ctx = DeployContext {
            sites_dir: Path::new("/tmp"),
            preview_domain: "preview.ephpm.dev",
            sites_domain_suffix: Some(".preview.ephpm.dev"),
            site_overrides_dir: None,
            composer: "composer",
            ephpm_bin: Path::new("ephpm"),
            ephpm_config: Path::new("/etc/ephpm/ephpm.toml"),
            secrets: &secrets,
            fetch_token: None,
            health_timeout: Duration::ZERO,
            health_interval: Duration::from_secs(1),
        };
        assert!(!wait_healthy("https://example.invalid", "/", &ctx).await);
    }

    // ── the per-site override the deploy publishes (#3, then #4) ────────

    /// A deploy context pointing at one tempdir, with the overrides directory
    /// either configured or deliberately absent.
    fn override_ctx<'a>(
        sites: &'a Path,
        overrides: Option<&'a Path>,
        secrets: &'a Secrets,
    ) -> DeployContext<'a> {
        DeployContext {
            sites_dir: sites,
            preview_domain: "preview.ephpm.dev",
            sites_domain_suffix: Some(".preview.ephpm.dev"),
            site_overrides_dir: overrides,
            composer: "composer",
            ephpm_bin: Path::new("ephpm"),
            ephpm_config: Path::new("/etc/ephpm/ephpm.toml"),
            secrets,
            fetch_token: None,
            health_timeout: Duration::ZERO,
            health_interval: Duration::from_secs(1),
        }
    }

    /// A checkout carrying the generated prepend, and the validated override
    /// for it — the shape `deploy_preview` assembles at step (5).
    fn staged_override(checkout: &Path, docroot: &str) -> site_override::SiteOverride {
        std::fs::create_dir_all(checkout.join("public")).unwrap();
        std::fs::write(checkout.join(PREPEND_FILE), b"<?php // generated").unwrap();
        site_override::SiteOverride {
            document_root: site_override::validate_docroot(checkout, docroot).unwrap(),
            auto_prepend_file: Some(
                site_override::validate_prepend(checkout, PREPEND_FILE).unwrap(),
            ),
        }
    }

    #[tokio::test]
    async fn subdirectory_docroot_publishes_an_override_file() {
        let dir = tempfile::tempdir().unwrap();
        let overrides = dir.path().join("overrides");
        let checkout = dir.path().join("checkout");
        std::fs::create_dir_all(&checkout).unwrap();
        let secrets = Secrets::default();
        let ctx = override_ctx(dir.path(), Some(&overrides), &secrets);

        apply_site_override(
            &ctx,
            "app-pr-1",
            &staged_override(&checkout, "public"),
            "app-pr-1.preview.ephpm.dev",
        )
        .await
        .unwrap();

        let written = tokio::fs::read_to_string(overrides.join("app-pr-1.toml"))
            .await
            .unwrap();
        assert!(written.contains("document_root = \"public\""), "{written}");
        assert!(
            written.contains(&format!("auto_prepend_file = \"{PREPEND_FILE}\"")),
            "{written}"
        );
    }

    /// A redeploy that goes back to `docroot: "."` must not leave the previous
    /// `document_root` behind — ePHPm would keep serving a subdirectory this
    /// checkout may no longer have, and as of ephpm#472 a declaration it cannot
    /// resolve takes the site to a 503.
    ///
    /// The file is no longer *removed* for `.`, it is rewritten without the
    /// key: it still has to carry `auto_prepend_file`, which is precisely what
    /// a `docroot: "."` preview needs (switchboard#4).
    #[tokio::test]
    async fn container_docroot_clears_a_stale_document_root_but_keeps_the_override() {
        let dir = tempfile::tempdir().unwrap();
        let overrides = dir.path().join("overrides");
        let checkout = dir.path().join("checkout");
        std::fs::create_dir_all(&checkout).unwrap();
        tokio::fs::create_dir_all(&overrides).await.unwrap();
        let path = overrides.join("app-pr-1.toml");
        tokio::fs::write(&path, "document_root = \"public\"\n")
            .await
            .unwrap();

        let secrets = Secrets::default();
        let ctx = override_ctx(dir.path(), Some(&overrides), &secrets);
        apply_site_override(
            &ctx,
            "app-pr-1",
            &staged_override(&checkout, "."),
            "app-pr-1.preview.ephpm.dev",
        )
        .await
        .unwrap();

        let written = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(
            !written.contains("document_root"),
            "the stale narrowing must be gone: {written}"
        );
        assert!(
            written.contains("auto_prepend_file"),
            "but the file must survive to carry the env prepend: {written}"
        );
    }

    /// Without `--site-overrides-dir` there is nowhere to publish either the
    /// docroot or the prepend. That is a warning, not a failure: the preview
    /// still works, served from its repository root with `env:` arriving only
    /// through the generated `.env`. The deploy must not error.
    #[tokio::test]
    async fn missing_overrides_dir_warns_but_does_not_fail_the_deploy() {
        let dir = tempfile::tempdir().unwrap();
        let checkout = dir.path().join("checkout");
        std::fs::create_dir_all(&checkout).unwrap();
        let secrets = Secrets::default();
        let ctx = override_ctx(dir.path(), None, &secrets);
        apply_site_override(
            &ctx,
            "app-pr-1",
            &staged_override(&checkout, "public"),
            "app-pr-1.preview.ephpm.dev",
        )
        .await
        .expect("an unconfigured overrides dir must not fail the deploy");
    }

    // ── build/seed run through `ephpm exec --site` (the root-RCE fix) ────

    fn sandbox() -> SandboxExec<'static> {
        SandboxExec {
            ephpm_bin: Path::new("/usr/local/bin/ephpm"),
            ephpm_config: Path::new("/etc/ephpm/ephpm.toml"),
            site_key: "app-pr-1",
        }
    }

    /// A build step must become `ephpm exec --config … --site <key> -- sh -c
    /// "cd <container> && <step>"` — never a bare `sh -c`. The working directory
    /// is the container root, where `composer.json` lives.
    #[test]
    fn build_step_becomes_an_ephpm_exec_invocation() {
        let argv = sandbox().argv(Path::new("/var/www/sites/app-pr-1"), "composer install");
        assert_eq!(
            argv,
            vec![
                "exec".to_owned(),
                "--config".to_owned(),
                "/etc/ephpm/ephpm.toml".to_owned(),
                "--site".to_owned(),
                "app-pr-1".to_owned(),
                "--".to_owned(),
                "sh".to_owned(),
                "-c".to_owned(),
                "cd '/var/www/sites/app-pr-1' && composer install".to_owned(),
            ]
        );
    }

    /// A seed step runs at the document root (`site_dir/<docroot>`) — same
    /// sandbox, different `cd`.
    #[test]
    fn seed_step_runs_at_the_document_root_under_the_sandbox() {
        let argv = sandbox().argv(
            Path::new("/var/www/sites/app-pr-1/public"),
            "php artisan migrate --force",
        );
        assert_eq!(argv[0], "exec");
        assert_eq!(argv[3], "--site");
        assert_eq!(argv[4], "app-pr-1");
        assert_eq!(argv[5], "--");
        assert_eq!(argv[6], "sh");
        assert_eq!(
            argv[8],
            "cd '/var/www/sites/app-pr-1/public' && php artisan migrate --force"
        );
    }

    /// The whole point: no build/seed path spawns a bare `sh`/`composer` — every
    /// tenant command is fronted by `ephpm exec`, whose program is `ephpm_bin`.
    #[test]
    fn the_sandbox_command_program_is_the_ephpm_binary() {
        let cmd = sandbox().command(Path::new("/var/www/sites/app-pr-1"), "true");
        let program = cmd.as_std().get_program().to_string_lossy().into_owned();
        assert_eq!(program, "/usr/local/bin/ephpm");
    }

    /// A workdir carrying a single quote is still one safe shell word.
    #[test]
    fn workdir_with_a_quote_is_escaped() {
        assert_eq!(posix_single_quote("/a'b"), "'/a'\\''b'");
        let argv = sandbox().argv(Path::new("/a'b"), "true");
        assert_eq!(argv[8], "cd '/a'\\''b' && true");
    }

    #[test]
    fn help_text_detects_the_exec_subcommand() {
        let with = "Commands:\n  serve  Run the server\n  exec   Run in a sandbox\n  kv  KV\n";
        assert!(help_advertises_exec(with));
        // An ePHPm predating #484: no exec line. (A stray mention of the word
        // "exec" inside another description must not count — only a subcommand
        // line, name first.)
        let without =
            "Commands:\n  serve  Run the server\n  kv  Inspect the store (can exec queries)\n";
        assert!(!help_advertises_exec(without));
    }

    /// Fail-closed: an `ephpm` that cannot even be spawned refuses the deploy
    /// rather than letting build/seed fall back to root.
    #[tokio::test]
    async fn ensure_sandboxed_exec_errors_on_a_missing_binary() {
        let err = ensure_sandboxed_exec(Path::new(
            "/nonexistent/switchboard-probe/definitely-not-ephpm",
        ))
        .await
        .expect_err("a missing ephpm must fail the deploy, not bypass the sandbox");
        assert!(err.to_string().contains("--help") || err.to_string().contains("does not support"));
    }

    /// Fail-closed against a real binary that runs but lacks `exec`: a fake
    /// `ephpm` whose `--help` advertises no `exec` subcommand must be refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_sandboxed_exec_refuses_an_ephpm_without_exec() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("ephpm-old");
        // Prints a help without an `exec` subcommand, like an ePHPm pre-#484.
        std::fs::write(
            &bin,
            "#!/bin/sh\nprintf 'Commands:\\n  serve  Run\\n  kv  KV\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!ephpm_exec_supported(&bin).await.unwrap());
        let err = ensure_sandboxed_exec(&bin)
            .await
            .expect_err("an ephpm without `exec` must refuse the deploy");
        assert!(err.to_string().contains("does not support"), "{err}");
    }

    /// The positive side of the probe: a fake `ephpm` that DOES advertise `exec`
    /// is accepted, so the gate does not refuse a correctly-upgraded node.
    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_sandboxed_exec_accepts_an_ephpm_with_exec() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("ephpm-new");
        std::fs::write(
            &bin,
            "#!/bin/sh\nprintf 'Commands:\\n  serve  Run\\n  exec  Sandboxed exec\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(ephpm_exec_supported(&bin).await.unwrap());
        ensure_sandboxed_exec(&bin)
            .await
            .expect("an ephpm advertising `exec` must be accepted");
    }

    // ── authenticated checkout fetch (private repos, issue #26) ─────────

    /// Decode a `Basic <base64>` value back to its `user:pass` form.
    fn decode_basic(header_value: &str) -> String {
        use base64::Engine as _;
        let b64 = header_value
            .strip_prefix("Authorization: Basic ")
            .expect("extraheader must be an Authorization: Basic value");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("the credential must be valid base64");
        String::from_utf8(bytes).expect("the credential must be UTF-8")
    }

    /// **The core Part A assertion.** A token produces a scoped
    /// `-c http.extraheader=Authorization: Basic base64("x-access-token:<token>")`
    /// — the exact credential GitHub documents for App installation tokens.
    #[test]
    fn a_token_becomes_a_scoped_extraheader_basic_credential() {
        let token = "ghs_EXAMPLEinstallationtoken0000000000";
        let cfg = fetch_auth_config(Some(token));

        // Exactly `-c` + one `http.extraheader=...` value, so it applies to a
        // single git process rather than being persisted.
        assert_eq!(cfg.len(), 2, "expected `-c <value>`, got {cfg:?}");
        assert_eq!(cfg[0], "-c");
        let value = cfg[1]
            .strip_prefix("http.extraheader=")
            .expect("the -c value must set http.extraheader");
        assert_eq!(
            decode_basic(value),
            format!("x-access-token:{token}"),
            "the credential must be x-access-token:<token>"
        );
    }

    /// The public-repo path carries **no** credential — the fetch is
    /// unauthenticated exactly as it is today.
    #[test]
    fn no_token_means_no_credential() {
        assert!(
            fetch_auth_config(None).is_empty(),
            "a public-repo fetch must carry no -c http.extraheader argument"
        );
    }

    /// The credential must never reach a log line or error message. The only
    /// string a failed fetch builds is `fetch_args.join(" ")`; the token lives
    /// in the separate `auth` prefix and must not appear there.
    #[test]
    fn the_token_is_kept_out_of_the_error_and_log_surface() {
        let token = "ghs_supersecretvalue";
        let auth = fetch_auth_config(Some(token));
        let fetch_args = ["fetch", "--depth", "1", "origin", "deadbeef"];

        // The redacted description a failure prints — must be token-free.
        let logged = fetch_args.join(" ");
        assert!(
            !logged.contains(token),
            "the token must not appear in the fetch's error/log string: {logged}"
        );
        // And the credential genuinely lives in the auth prefix (so the test
        // above is meaningful, not vacuous). It is base64-encoded there, so the
        // raw token string does not even appear literally — decode to confirm.
        let value = auth[1].strip_prefix("http.extraheader=").unwrap();
        assert!(
            decode_basic(value).contains(token),
            "sanity: the token is carried (base64-encoded) by the auth prefix"
        );
        assert!(
            !auth[1].contains(token),
            "the token is base64-encoded in the header, never literal"
        );
    }

    /// The private-repo hint fires only when no token was available, and names
    /// the credential + `contents: read` so a private-repo failure is
    /// actionable rather than a bare git error.
    #[test]
    fn private_repo_hint_only_when_unauthenticated() {
        assert_eq!(private_repo_hint(true), "", "a token was present: no hint");
        let hint = private_repo_hint(false);
        assert!(hint.contains("PRIVATE"));
        assert!(hint.contains("contents: read"));
        assert!(hint.contains("--app-id") && hint.contains("--app-key"));
    }

    /// Whether `git` is runnable in this environment; the integration tests
    /// below skip (rather than fail) when it is not, matching how the symlink
    /// tests skip on a platform that refuses symlinks.
    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    /// Build a bare repo carrying one commit and a `refs/pull/1/head` ref, and
    /// return its `file://` URL and the commit SHA — a stand-in for the base
    /// repo `fetch_checkout` pulls a PR head from.
    fn fixture_remote(root: &Path) -> (String, String) {
        let bare = root.join("remote.git");
        std::fs::create_dir_all(&bare).unwrap();
        git_in(&bare, &["init", "--quiet", "--bare"]);

        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        git_in(&work, &["init", "--quiet"]);
        std::fs::write(work.join("index.php"), b"<?php echo 'preview';").unwrap();
        git_in(&work, &["add", "."]);
        git_in(&work, &["commit", "--quiet", "-m", "seed"]);
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&work)
            .output()
            .unwrap();
        let sha = String::from_utf8(out.stdout).unwrap().trim().to_owned();

        // file:// forces git's transport (so --depth works) and never applies
        // http.extraheader — which is exactly why it is a clean probe that the
        // -c credential is not persisted.
        let url = format!("file://{}", bare.to_string_lossy().replace('\\', "/"));
        git_in(&work, &["push", "--quiet", &url, "HEAD:refs/pull/1/head"]);
        (url, sha)
    }

    fn make_pr_request(url: &str, sha: &str) -> PreviewRequest {
        PreviewRequest {
            label: "app-pr-1".into(),
            repo_full_name: "ephpm/app".into(),
            owner: "ephpm".into(),
            repo_name: "app".into(),
            pr_number: 1,
            fetch_url: url.to_owned(),
            fetch_ref: Some("refs/pull/1/head".into()),
            branch: None,
            sha: sha.to_owned(),
            installation_id: Some(42),
            fork: false,
        }
    }

    /// **The "not persisted" integration test.** A fetch carrying a token
    /// checks the code out AND leaves no trace of the credential in the
    /// repository's persisted `.git/config`. The `-c` scoping is what makes this
    /// hold — a `git config http.extraheader ...` would have written it in.
    #[tokio::test]
    async fn an_authenticated_fetch_checks_out_and_never_persists_the_token() {
        if !git_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let (url, sha) = fixture_remote(root.path());
        let req = make_pr_request(&url, &sha);
        let dest = root.path().join("checkout");

        let token = "ghs_TOKEN_that_must_not_be_persisted_0001";
        fetch_checkout(&req, &dest, Some(token))
            .await
            .expect("the checkout must succeed");

        // The code is there…
        assert!(
            dest.join("index.php").is_file(),
            "the PR head must be checked out"
        );
        // …and the token is nowhere in the persisted git config.
        let config = std::fs::read_to_string(dest.join(".git").join("config")).unwrap();
        assert!(
            !config.contains(token),
            "the installation token must NOT be written into .git/config: {config}"
        );
        assert!(
            !config.contains("extraheader"),
            "no extraheader must be persisted — the credential is `-c`-scoped: {config}"
        );
    }

    /// **The public-repo path still works.** With no token the same fetch
    /// succeeds against a repo that needs no credential — today's behaviour is
    /// unchanged.
    #[tokio::test]
    async fn a_public_repo_still_fetches_without_a_token() {
        if !git_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let (url, sha) = fixture_remote(root.path());
        let req = make_pr_request(&url, &sha);
        let dest = root.path().join("checkout");

        fetch_checkout(&req, &dest, None)
            .await
            .expect("a public fetch needs no credential");
        assert!(dest.join("index.php").is_file());
        let config = std::fs::read_to_string(dest.join(".git").join("config")).unwrap();
        assert!(!config.contains("extraheader"));
    }

    // ── the swapped tree is handed to the tenant before the build (#28 404) ──

    /// The tenant owner is DERIVED from `sites_dir`, never hardcoded: whoever
    /// owns the sites directory is who each preview under it is chowned to.
    #[cfg(unix)]
    #[test]
    fn tenant_owner_is_read_from_sites_dir() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let md = std::fs::metadata(dir.path()).unwrap();
        assert_eq!(
            tenant_owner(dir.path()).unwrap(),
            (md.uid(), md.gid()),
            "the tenant owner must be exactly sites_dir's own uid/gid"
        );
    }

    /// End-to-end of the fix's mechanism: after the swap, the whole site tree is
    /// chowned to the owner derived from `sites_dir`. A non-root test cannot
    /// chown to a *different* uid, but `sites_dir` is owned by the test's own
    /// uid, so this exercises the real derive-then-apply path (a chown-to-self,
    /// which is permitted) across a populated tree and asserts it succeeds —
    /// which is exactly what unblocks the sandboxed build.
    #[cfg(unix)]
    #[tokio::test]
    async fn chown_hands_the_whole_swapped_tree_to_the_tenant_owner() {
        use std::os::unix::fs::MetadataExt as _;

        let sites = tempfile::tempdir().unwrap();
        let want = std::fs::metadata(sites.path()).unwrap();
        let site_dir = sites.path().join("app-pr-1");
        // A small container: docroot, a nested dir, and a couple of files —
        // exactly the shape a build would need to write into.
        std::fs::create_dir_all(site_dir.join("public")).unwrap();
        std::fs::create_dir_all(site_dir.join("vendor/pkg")).unwrap();
        std::fs::write(site_dir.join("composer.json"), "{}").unwrap();
        std::fs::write(site_dir.join("public/index.php"), "<?php").unwrap();
        std::fs::write(site_dir.join("vendor/pkg/a.php"), "<?php").unwrap();

        chown_site_tree_to_tenant(sites.path(), &site_dir)
            .await
            .expect("chowning the swapped tree to the tenant owner must succeed");

        // Every node now carries the derived owner (== the test uid here).
        for rel in [
            "",
            "composer.json",
            "public",
            "public/index.php",
            "vendor/pkg/a.php",
        ] {
            let md = std::fs::symlink_metadata(site_dir.join(rel)).unwrap();
            assert_eq!(
                (md.uid(), md.gid()),
                (want.uid(), want.gid()),
                "{rel:?} must be owned by the tenant (sites_dir's owner)"
            );
        }
    }

    /// Fail-closed: a `sites_dir` that does not exist cannot yield a tenant
    /// owner, so the deploy fails loudly rather than building a tree it never
    /// handed over.
    #[cfg(unix)]
    #[tokio::test]
    async fn chown_fails_loudly_when_sites_dir_owner_is_unreadable() {
        let missing = Path::new("/nonexistent/switchboard-probe/sites-dir");
        let dir = tempfile::tempdir().unwrap();
        let site_dir = dir.path().join("app-pr-1");
        std::fs::create_dir_all(&site_dir).unwrap();
        chown_site_tree_to_tenant(missing, &site_dir)
            .await
            .expect_err("an unstattable sites_dir must fail the deploy, not proceed");
    }

    /// Symlink safety: the walk that drives the chown includes each symlink
    /// (chowned as a link via `lchown`) but NEVER visits a symlink's target and
    /// NEVER descends through a symlinked directory. A `chown -R` that followed a
    /// symlink planted in attacker-influenced PR content is the #484 privesc
    /// class; this asserts we do not.
    #[cfg(unix)]
    #[test]
    fn walk_is_symlink_safe() {
        let outside = tempfile::tempdir().unwrap();
        // A file and a directory-with-a-child that live OUTSIDE the deploy tree.
        std::fs::write(outside.path().join("secret"), "root-owned").unwrap();
        std::fs::create_dir_all(outside.path().join("etc")).unwrap();
        std::fs::write(outside.path().join("etc/shadow"), "x").unwrap();

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("sub")).unwrap();
        std::fs::write(root.path().join("sub/real.php"), "<?php").unwrap();
        // Attacker-planted symlinks in the fetched checkout.
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("evil-file"))
            .unwrap();
        std::os::unix::fs::symlink(outside.path().join("etc"), root.path().join("evil-dir"))
            .unwrap();

        let touched = walk_no_follow(root.path()).unwrap();

        // The symlinks themselves are touched (so they get lchown'd as links)…
        assert!(touched.contains(&root.path().join("evil-file")));
        assert!(touched.contains(&root.path().join("evil-dir")));
        // …but NOTHING outside the tree is: not the target file, not the
        // symlinked directory's contents.
        assert!(
            touched.iter().all(|p| !p.starts_with(outside.path())),
            "the walk must never step outside the deploy tree via a symlink: {touched:?}"
        );
        assert!(
            !touched.contains(&root.path().join("evil-dir").join("shadow")),
            "a symlinked directory must not be descended into"
        );
        // Real content is still fully covered.
        assert!(touched.contains(&root.path().to_path_buf()));
        assert!(touched.contains(&root.path().join("sub")));
        assert!(touched.contains(&root.path().join("sub/real.php")));
    }

    /// The chown itself must not follow the planted symlinks either: a
    /// chown-to-self across the tree above succeeds and leaves the OUTSIDE
    /// targets untouched (their ownership is the test uid regardless, but the
    /// operation completing without error over a tree full of dangling/hostile
    /// links is the property — `lchown` never dereferences).
    #[cfg(unix)]
    #[test]
    fn chown_tree_over_symlinks_does_not_follow_them() {
        use std::os::unix::fs::MetadataExt as _;
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.php"), "<?php").unwrap();
        // A dangling symlink: if the chown dereferenced it, the lchown would
        // instead try to chown a nonexistent target and could error.
        std::os::unix::fs::symlink(
            "/nonexistent/switchboard-probe/x",
            root.path().join("dangling"),
        )
        .unwrap();
        let md = std::fs::metadata(root.path()).unwrap();
        chown_tree_no_follow(root.path(), md.uid(), md.gid())
            .expect("lchown over a dangling symlink must succeed (it never dereferences)");
    }

    /// The real cross-uid proof, exercised for real when the test runs
    /// privileged (as root / with `CAP_CHOWN`) and **skipped otherwise** so it is
    /// safe in an unprivileged CI or on a developer machine. It chowns a
    /// populated tree — including a symlink that escapes to a file OUTSIDE the
    /// tree — to a foreign uid and asserts: every real node moved to the foreign
    /// uid, the symlink itself moved (it was `lchown`ed as a link), and the
    /// symlink's outside target did **not** move. That is precisely the property
    /// that lets the sandboxed build (running as that foreign/tenant uid) write
    /// its own container while a planted symlink cannot redirect ownership out of
    /// the tree.
    #[cfg(unix)]
    #[test]
    fn chown_moves_ownership_to_a_foreign_uid_when_privileged() {
        use std::os::unix::fs::{MetadataExt as _, lchown};

        const FOREIGN_UID: u32 = 60000;
        const FOREIGN_GID: u32 = 60000;

        // Capability probe: only root / CAP_CHOWN may chown to a foreign uid.
        let probe = tempfile::NamedTempFile::new().unwrap();
        if lchown(probe.path(), Some(FOREIGN_UID), Some(FOREIGN_GID)).is_err() {
            eprintln!(
                "skipping chown_moves_ownership_to_a_foreign_uid_when_privileged: \
                 not privileged to chown to a foreign uid (need root/CAP_CHOWN)"
            );
            return;
        }

        // A file OUTSIDE the deploy tree, owned by the current (root) uid.
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret");
        std::fs::write(&outside_file, "outside").unwrap();
        let outside_owner_before = std::fs::symlink_metadata(&outside_file).unwrap().uid();

        // The swapped site tree, with a symlink escaping to that outside file.
        let site = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(site.path().join("public")).unwrap();
        std::fs::write(site.path().join("public/index.php"), "<?php").unwrap();
        std::os::unix::fs::symlink(&outside_file, site.path().join("evil")).unwrap();

        chown_tree_no_follow(site.path(), FOREIGN_UID, FOREIGN_GID).unwrap();

        // Real nodes moved to the foreign (tenant) uid…
        for rel in ["", "public", "public/index.php", "evil"] {
            let md = std::fs::symlink_metadata(site.path().join(rel)).unwrap();
            assert_eq!(
                (md.uid(), md.gid()),
                (FOREIGN_UID, FOREIGN_GID),
                "{rel:?} must have moved to the tenant uid"
            );
        }
        // …but the symlink's OUTSIDE target did NOT move: lchown never followed
        // it. This is the #484 privesc class, not reproduced.
        assert_eq!(
            std::fs::symlink_metadata(&outside_file).unwrap().uid(),
            outside_owner_before,
            "the chown must not have followed the symlink out of the tree"
        );
    }
}
