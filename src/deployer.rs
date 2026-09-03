//! Preview deployment pipeline: clone, load manifest, build, materialize env,
//! atomic swap, seed, and health-gate.
//!
//! The order is a contract (see [`deploy_preview`]): everything that mutates
//! the checkout (`build:`, env materialization) happens BEFORE the atomic swap
//! into `sites_dir`; everything that needs the site live (`seed:`, the health
//! poll) happens AFTER.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::process::Command;

use crate::manifest::AppManifest;
use crate::secrets::Secrets;
use crate::site_override::{self, DocumentRoot};

/// Generated file (at the checkout/site root) that exports the resolved preview
/// env into PHP via `putenv`/`$_ENV`/`$_SERVER`.
///
/// **Not auto-loaded.** ePHPm has no per-site `auto_prepend_file` channel — the
/// per-site override file it does read understands `document_root` and nothing
/// else — so an app that wants this must `require_once` it (switchboard#4). It
/// is written regardless because that require is the documented workaround and
/// needs the file to exist.
const PREPEND_FILE: &str = ".ephpm-preview-prepend.php";
/// Generated dotenv file (checkout/site root) for framework-native `.env`
/// loaders.
///
/// Written for **every** docroot shape. It used to be skipped for
/// `docroot: "."` on the grounds that the project root is web-served — but the
/// file is dot-prefixed, and ePHPm's `hidden_files` default is `deny`, so it is
/// a 403 either way (verified against the live preview cluster). Skipping it
/// left `docroot: "."` apps — the common shape, including WordPress — with no
/// `env:` delivery path at all (switchboard#4).
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
    /// Switchboard's own secret store for `${secret.NAME}` resolution.
    pub secrets: &'a Secrets,
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
/// 3. Run `build:` commands in the checkout, in order (failures logged, deploy
///    continues — matching the POC's composer behavior).
/// 4. Materialize `env:` — resolve `${secret.NAME}` from switchboard's own
///    secret store and write it where the app can read it.
/// 5. Write (or clear) the per-site document-root override, **before** the swap
///    so the vhost is never briefly served with its container as the web root.
/// 6. Atomic swap the checkout into `sites_dir`.
/// 7. Run `seed:` commands with `$PREVIEW_URL`/`$PREVIEW_HOST`/`$PR` set.
/// 8. Poll `health:` until it returns 200 or the timeout elapses, so the PR
///    comment is only posted once the site is ready.
///
/// # Errors
///
/// Returns an error if cloning, manifest loading (present-but-invalid),
/// document-root validation, or the atomic swap fails.
pub async fn deploy_preview(
    req: &PreviewRequest,
    ctx: &DeployContext<'_>,
) -> anyhow::Result<DeployResult> {
    let start = Instant::now();
    let hostname = req.preview_host(ctx.preview_domain);
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
    fetch_checkout(req, &tmp_dir).await?;

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

    // (3) Run build: commands (or fall back to implicit composer install).
    run_build(&manifest, &tmp_dir, ctx.composer, &hostname).await;

    // (4) Materialize env: resolve secrets and write env for the app to read.
    // Reference the FINAL (post-swap) prepend path in the effective ini.
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

    // Remove .git to save disk before the swap.
    let git_dir = tmp_dir.join(".git");
    if git_dir.exists() {
        tokio::fs::remove_dir_all(&git_dir).await.ok();
    }

    // (5) The per-site document-root override, written BEFORE the swap.
    //
    // Order matters: ePHPm resolves a vhost's roots on first request and caches
    // them briefly, so writing the override after the swap leaves a window in
    // which a fresh preview serves its container — `vendor/`, `config/`,
    // `storage/logs/*.log` and all. Writing it first means the directory
    // appears already carrying its web root. ePHPm validates the declaration
    // against the container, and until the swap the container does not exist,
    // so it simply serves nothing for that host in the meantime.
    apply_document_root(ctx, &site_key, &document_root, &hostname).await?;

    // (6) Atomic swap: remove old site dir (if any), rename tmp into place.
    if site_dir.exists() {
        tokio::fs::remove_dir_all(&site_dir)
            .await
            .context("failed to remove old preview")?;
    }
    tokio::fs::rename(&tmp_dir, &site_dir)
        .await
        .context("failed to move preview into place")?;

    // (7) Run seed: commands now that the site is live and its per-site DB can
    // be created on first access.
    let preview_url = preview_url(&hostname, Some(manifest.php.as_str()));
    run_seed(&manifest, &site_dir, &preview_url, &hostname, req.pr_number).await;

    // (8) Health-gate: only report ready once the site serves a 200.
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
async fn fetch_checkout(req: &PreviewRequest, dest: &Path) -> anyhow::Result<()> {
    let Some(pull_ref) = req.fetch_ref.as_deref() else {
        return clone_branch(&req.fetch_url, req.branch.as_deref(), &req.sha, dest).await;
    };

    tokio::fs::create_dir_all(dest)
        .await
        .with_context(|| format!("failed to create {}", dest.display()))?;
    run_git(dest, &["init", "--quiet"]).await?;
    run_git(dest, &["remote", "add", "origin", &req.fetch_url]).await?;

    // Exact SHA first.
    if run_git(dest, &["fetch", "--depth", "1", "origin", &req.sha])
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
    run_git(dest, &["fetch", "--depth", "1", "origin", pull_ref])
        .await
        .with_context(|| format!("failed to fetch {pull_ref} from {}", req.fetch_url))?;
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
async fn clone_branch(
    clone_url: &str,
    branch: Option<&str>,
    sha: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    if let Some(branch) = branch {
        let status = Command::new("git")
            .args(["clone", "--depth", "1", "--branch", branch, clone_url])
            .arg(dest)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("failed to run git clone")?;
        if status.success() {
            return Ok(());
        }
        let _ = tokio::fs::remove_dir_all(dest).await;
    }

    let status = Command::new("git")
        .args(["clone", "--depth", "1", clone_url])
        .arg(dest)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .context("git clone fallback failed")?;
    anyhow::ensure!(status.success(), "git clone failed for {clone_url}");

    run_git(dest, &["checkout", "--quiet", "--detach", sha]).await
}

/// Run `git` in `dir`, erroring on a non-zero exit.
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

/// Run the manifest's `build:` commands in order. If the manifest declares no
/// build steps, fall back to an implicit `composer install` when a
/// `composer.json` exists (POC compatibility). Failures are logged and the
/// deploy continues.
async fn run_build(manifest: &AppManifest, checkout: &Path, composer: &str, hostname: &str) {
    if manifest.build.is_empty() {
        if checkout.join("composer.json").exists() {
            tracing::info!(%hostname, "no build steps declared — running implicit composer install");
            let status = Command::new(composer)
                .args([
                    "install",
                    "--no-dev",
                    "--no-interaction",
                    "--optimize-autoloader",
                    "--quiet",
                ])
                .current_dir(checkout)
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
        tracing::info!(%hostname, step = i + 1, command = %cmd, "running build step");
        let status = Command::new("sh")
            .args(["-c", cmd])
            .current_dir(checkout)
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

/// Publish (or clear) the preview's document root through ePHPm's per-site
/// override file.
///
/// Three outcomes, all of them stated in the log rather than inferred:
///
/// * declaration is `"."` → any stale override from a previous deploy is
///   removed, so the site does not keep serving a subdirectory this checkout may
///   no longer have;
/// * declaration is a subdirectory and `--site-overrides-dir` is set → the
///   override is written;
/// * declaration is a subdirectory and `--site-overrides-dir` is **not** set →
///   a `warn!`, because ePHPm will serve the whole checkout and that is the
///   exposure switchboard#3 is about. Not an error: a docroot-less preview is
///   still a working preview, and failing every Laravel deploy on a node the
///   operator has not finished configuring is worse than saying so loudly.
///
/// # Errors
///
/// Returns an error if the override file cannot be written or removed.
async fn apply_document_root(
    ctx: &DeployContext<'_>,
    site_key: &str,
    document_root: &DocumentRoot,
    hostname: &str,
) -> anyhow::Result<()> {
    let Some(overrides_dir) = ctx.site_overrides_dir else {
        if document_root.needs_override_file() {
            tracing::warn!(
                %hostname,
                docroot = document_root.declared(),
                "docroot cannot be honoured: --site-overrides-dir is not \
                 configured, so ePHPm will serve the whole checkout — including \
                 vendor/, config/ and storage/logs/. Set it to ePHPm's \
                 [server] site_overrides_dir (a directory OUTSIDE sites_dir)"
            );
        }
        return Ok(());
    };

    if document_root.needs_override_file() {
        let path = site_override::write_override(overrides_dir, site_key, document_root).await?;
        tracing::info!(
            %hostname,
            site_key,
            docroot = document_root.declared(),
            path = %path.display(),
            "wrote per-site document-root override"
        );
    } else {
        site_override::remove_override(overrides_dir, site_key).await?;
        tracing::debug!(
            %hostname,
            site_key,
            "docroot is the repository root — no override file (any stale one removed)"
        );
    }
    Ok(())
}

/// Resolve `env:` (including `${secret.NAME}` references) and write it where the
/// app can read it: a `.env` file for framework-native dotenv loaders, plus a
/// PHP prepend an app can `require_once`. Also writes a non-secret sidecar
/// exposing the effective manifest.
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

    // The PHP prepend: written so the documented `require_once` workaround has
    // something to require. Nothing loads it automatically — see PREPEND_FILE.
    let prepend = render_php_prepend(&resolved);
    tokio::fs::write(checkout.join(PREPEND_FILE), prepend)
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
    // `ini` is recorded exactly as the manifest declared it. It used to gain a
    // synthesized `auto_prepend_file` entry pointing at the prepend — which read
    // like a wiring step and was none: ePHPm does not read this file, and
    // `ini:` is advisory in v1. A key nothing acts on is worse than an absent
    // one, so it is gone (switchboard#4).
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
        "prepend_auto_loaded": false,
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
        "materialized preview environment (.env + prepend)"
    );
    Ok(())
}

/// Render the PHP auto-prepend that exports env via putenv/$_ENV/$_SERVER.
fn render_php_prepend(env: &BTreeMap<String, String>) -> String {
    let mut php = String::from(
        "<?php\n// Generated by switchboard for the ePHPm preview. Do not commit.\n\
         $__ephpm_preview_env = [\n",
    );
    for (key, value) in env {
        php.push_str(&format!(
            "    '{}' => '{}',\n",
            php_single_quote_escape(key),
            php_single_quote_escape(value)
        ));
    }
    php.push_str(
        "];\nforeach ($__ephpm_preview_env as $__k => $__v) {\n\
         \x20   putenv(\"$__k=$__v\");\n\
         \x20   $_ENV[$__k] = $__v;\n\
         \x20   $_SERVER[$__k] = $__v;\n\
         }\nunset($__k, $__v);\n",
    );
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

/// Run the manifest's `seed:` commands in order, in the live site directory,
/// with `$PREVIEW_URL`/`$PREVIEW_HOST`/`$PR` set. Failures are logged and the
/// deploy continues.
async fn run_seed(
    manifest: &AppManifest,
    site_dir: &Path,
    preview_url: &str,
    hostname: &str,
    pr_number: u64,
) {
    let workdir = site_dir.join(&manifest.docroot);
    for (i, cmd) in manifest.seed.iter().enumerate() {
        tracing::info!(%hostname, step = i + 1, command = %cmd, "running seed step");
        let status = Command::new("sh")
            .args(["-c", cmd])
            .current_dir(&workdir)
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
        // The sidecar used to carry a synthesized `auto_prepend_file` entry
        // that read like wiring and was none — ePHPm never reads this file.
        assert!(
            !sidecar.contains("auto_prepend_file"),
            "the sidecar must not imply an ini entry nothing applies"
        );
        assert!(
            sidecar.contains("\"prepend_auto_loaded\": false"),
            "the sidecar must state plainly that nothing loads the prepend"
        );
    }

    /// switchboard#4. `docroot: "."` is the common shape (WordPress, most
    /// bespoke apps) and used to get **no** `env:` delivery at all: no `.env`
    /// was written and nothing auto-loads the prepend. The `.env` is written
    /// for every docroot now — it is dot-prefixed, and ePHPm's `hidden_files`
    /// default is `deny`, so it is a 403 over HTTP either way.
    #[tokio::test]
    async fn dotenv_is_written_for_a_root_docroot_too() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = AppManifest::from_yaml_str("version: 1\nenv:\n  K: \"v\"\n").unwrap();
        assert_eq!(manifest.docroot, ".", "this test is about the `.` shape");
        let secrets = Secrets::default();
        let req = make_request();
        let prepend_hint = dir.path().join(PREPEND_FILE);
        materialize_env(
            &req.repo_full_name,
            &manifest,
            &secrets,
            dir.path(),
            &prepend_hint,
            false,
        )
        .await
        .unwrap();
        assert!(dir.path().join(PREPEND_FILE).exists());
        let dotenv = tokio::fs::read_to_string(dir.path().join(DOTENV_FILE))
            .await
            .expect("a `docroot: \".\"` preview must still get its env: values");
        assert!(dotenv.contains("K=\"v\""), "{dotenv}");
    }

    /// Every generated file is dot-prefixed, which is what makes writing them
    /// into a web-served repository root defensible: ePHPm's `hidden_files`
    /// default is `deny` (403). If one ever stops being a dotfile, this fails.
    #[test]
    fn generated_files_are_all_hidden_from_http() {
        for name in [PREPEND_FILE, DOTENV_FILE, SIDECAR_FILE] {
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
        // WordPress getenv() and Laravel env() see the values.
        let mut env = BTreeMap::new();
        env.insert("APP_ENV".to_string(), "preview".to_string());
        let php = render_php_prepend(&env);
        assert!(php.starts_with("<?php"));
        assert!(php.contains("'APP_ENV' => 'preview'"));
        assert!(php.contains("putenv("));
        assert!(php.contains("$_ENV["));
        assert!(php.contains("$_SERVER["));
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
            secrets: &secrets,
            health_timeout: Duration::ZERO,
            health_interval: Duration::from_secs(1),
        };
        assert!(!wait_healthy("https://example.invalid", "/", &ctx).await);
    }

    // ── the document-root override the deploy now publishes (#3) ────────

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
            secrets,
            health_timeout: Duration::ZERO,
            health_interval: Duration::from_secs(1),
        }
    }

    #[tokio::test]
    async fn subdirectory_docroot_publishes_an_override_file() {
        let dir = tempfile::tempdir().unwrap();
        let overrides = dir.path().join("overrides");
        let secrets = Secrets::default();
        let ctx = override_ctx(dir.path(), Some(&overrides), &secrets);
        let root = crate::site_override::DocumentRoot::Subdirectory {
            declared: "public".into(),
            resolved: dir.path().to_path_buf(),
        };

        apply_document_root(&ctx, "app-pr-1", &root, "app-pr-1.preview.ephpm.dev")
            .await
            .unwrap();

        let written = tokio::fs::read_to_string(overrides.join("app-pr-1.toml"))
            .await
            .unwrap();
        assert!(written.contains("document_root = \"public\""), "{written}");
    }

    /// A redeploy that goes back to `docroot: "."` must not leave the previous
    /// override behind — ePHPm would keep serving a subdirectory this checkout
    /// may no longer have, and its rejection of a stale one is silent.
    #[tokio::test]
    async fn container_docroot_clears_a_stale_override() {
        let dir = tempfile::tempdir().unwrap();
        let overrides = dir.path().join("overrides");
        tokio::fs::create_dir_all(&overrides).await.unwrap();
        let stale = overrides.join("app-pr-1.toml");
        tokio::fs::write(&stale, "document_root = \"public\"\n")
            .await
            .unwrap();

        let secrets = Secrets::default();
        let ctx = override_ctx(dir.path(), Some(&overrides), &secrets);
        apply_document_root(
            &ctx,
            "app-pr-1",
            &crate::site_override::DocumentRoot::Container,
            "app-pr-1.preview.ephpm.dev",
        )
        .await
        .unwrap();

        assert!(!stale.exists(), "a stale override must be removed");
    }

    /// Without `--site-overrides-dir` there is nowhere to publish the docroot.
    /// That is a warning, not a failure: the preview still works, it is just
    /// served from its repository root. The deploy must not error.
    #[tokio::test]
    async fn missing_overrides_dir_warns_but_does_not_fail_the_deploy() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Secrets::default();
        let ctx = override_ctx(dir.path(), None, &secrets);
        let root = crate::site_override::DocumentRoot::Subdirectory {
            declared: "public".into(),
            resolved: dir.path().to_path_buf(),
        };
        apply_document_root(&ctx, "app-pr-1", &root, "app-pr-1.preview.ephpm.dev")
            .await
            .expect("an unconfigured overrides dir must not fail the deploy");
    }
}
