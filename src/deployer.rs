//! Preview provisioning: clone, load manifest, build, materialize env, atomic
//! swap, write the operator override, seed, and health-gate — plus teardown.
//!
//! The pipeline order is a contract (see [`deploy_preview`]): everything that
//! mutates the checkout (`build:`, env materialization) happens BEFORE the
//! atomic swap into `sites_dir`; everything that needs the site live (`seed:`,
//! the health poll) happens AFTER.
//!
//! Inputs come from a validated [`Job`] (switchboard-api's job file), not a
//! webhook payload. The clone authenticates with an in-memory installation
//! token via `GIT_ASKPASS` and fetches the PR head through `refs/pull/<n>/head`
//! from the *base* repository, so fork and deleted-fork PRs work without
//! trusting a third-party clone URL.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::process::Command;

use crate::app_auth::InstallationToken;
use crate::git_askpass::{Askpass, authenticated_url};
use crate::job::Job;
use crate::manifest::AppManifest;
use crate::secrets::Secrets;
use crate::site::canonical_site_key;

/// Generated PHP auto-prepend (checkout/site root) exporting the resolved
/// preview env via `putenv`/`$_ENV`/`$_SERVER`.
const PREPEND_FILE: &str = ".ephpm-preview-prepend.php";
/// Generated dotenv (checkout/site root) for framework-native `.env` loaders.
/// Only written when the docroot is not the project root, so it is never served.
const DOTENV_FILE: &str = ".env";
/// Non-secret sidecar: env KEYS only, never values.
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

/// Non-repo inputs to a deploy/teardown: daemon config plus the secret store and
/// the askpass helper.
pub struct DeployContext<'a> {
    /// ePHPm `[server] sites_dir` — previews are swapped in as `<sites_dir>/<key>`.
    pub sites_dir: &'a Path,
    /// Preview domain suffix (`<label>.<preview_domain>`).
    pub preview_domain: &'a str,
    /// ePHPm `[server] sites_domain_suffix`, if any — for canonical key parity.
    pub sites_domain_suffix: Option<&'a str>,
    /// ePHPm `[server] site_overrides_dir` — where `<key>.toml` is written.
    pub site_overrides_dir: Option<&'a Path>,
    /// ePHPm `[db.sqlite] dir` — where `<key>.db` lives (for teardown).
    pub sqlite_dir: Option<&'a Path>,
    /// Base for ePHPm's per-vhost state root (default: system temp).
    pub vhost_temp_base: Option<&'a Path>,
    /// Composer command (system PHP — see issue #400).
    pub composer: &'a str,
    /// Switchboard's own secret store.
    pub secrets: &'a Secrets,
    /// Resolve `${secret.NAME}` into a fork PR's env. Non-forks always resolve.
    pub fork_secrets: bool,
    /// `GIT_ASKPASS` helper carrying the token to `git` via the environment.
    pub askpass: &'a Askpass,
    /// How long to poll `health:` for a 200. Zero disables the gate.
    pub health_timeout: Duration,
    /// Interval between health poll attempts.
    pub health_interval: Duration,
}

/// Result of a successful deployment.
pub struct DeployResult {
    /// The canonical site key (vhost directory name, DB/override basename).
    pub site_key: String,
    /// The preview hostname (`<label>.<preview_domain>`).
    pub hostname: String,
    /// The full preview URL (accounts for the PHP-version port map).
    pub preview_url: String,
    /// Detected framework.
    pub framework: Framework,
    /// Time taken.
    pub duration: Duration,
    /// PHP version from the manifest.
    pub php_version: Option<String>,
    /// Whether the health check passed within the timeout.
    pub healthy: bool,
}

/// Derive the canonical site key for a job, or fail if the host is not a valid
/// vhost key. Shared by deploy and teardown so both name the same directory.
///
/// # Errors
///
/// Returns an error if `<label>.<preview_domain>` does not normalize to a valid
/// ePHPm site key.
pub fn site_key_for(job: &Job, ctx: &DeployContext<'_>) -> anyhow::Result<String> {
    let host = crate::preview::preview_host(&job.preview.label, ctx.preview_domain);
    canonical_site_key(&host, ctx.sites_domain_suffix)
        .with_context(|| format!("preview host {host:?} is not a valid site key"))
}

/// Deploy a preview for a validated job.
///
/// # Errors
///
/// Returns an error if key derivation, cloning, manifest loading, or the atomic
/// swap fails. (`build:`/`seed:` step failures are logged and do not fail the
/// deploy; the health gate reports readiness separately.)
pub async fn deploy_preview(
    job: &Job,
    ctx: &DeployContext<'_>,
    token: Option<&InstallationToken>,
) -> anyhow::Result<DeployResult> {
    let start = Instant::now();
    let site_key = site_key_for(job, ctx)?;
    let hostname = crate::preview::preview_host(&job.preview.label, ctx.preview_domain);
    let site_dir = ctx.sites_dir.join(&site_key);
    let is_fork = job.pull_request.fork;

    tracing::info!(
        repo = %job.repository.full_name,
        pr = job.pull_request.number,
        branch = %job.pull_request.head.ref_name,
        site_key = %site_key,
        fork = is_fork,
        "deploying preview"
    );

    // (1) Clone to a temp dir first, then swap into place.
    let tmp_dir = site_dir.with_extension("tmp");
    if tmp_dir.exists() {
        tokio::fs::remove_dir_all(&tmp_dir).await.ok();
    }
    clone_checkout(job, ctx, token, &tmp_dir).await?;

    // (2) Detect framework + load manifest.
    let framework = detect_framework(&tmp_dir).await;
    let manifest = AppManifest::load(&tmp_dir, framework).await?;
    let websocket = manifest.websocket_enabled(&tmp_dir);
    tracing::info!(
        %site_key,
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

    // (3) Build.
    run_build(&manifest, &tmp_dir, ctx.composer, &site_key).await;

    // (4) Materialize env. Forks get NO secrets unless explicitly allowed —
    // building untrusted code with the operator's secrets is the hole this
    // closes (the old code resolved secrets for every PR).
    let resolve_secrets = !is_fork || ctx.fork_secrets;
    if is_fork && !resolve_secrets {
        tracing::warn!(%site_key, "fork PR: withholding operator secrets from the preview env");
    }
    let secret_store = resolve_secrets.then_some(ctx.secrets);
    let final_prepend = site_dir.join(PREPEND_FILE);
    materialize_env(
        job,
        &manifest,
        secret_store,
        &tmp_dir,
        &final_prepend,
        websocket,
    )
    .await?;

    // Remove .git before the swap to save disk.
    let git_dir = tmp_dir.join(".git");
    if git_dir.exists() {
        tokio::fs::remove_dir_all(&git_dir).await.ok();
    }

    // (5) Atomic swap.
    if site_dir.exists() {
        tokio::fs::remove_dir_all(&site_dir)
            .await
            .context("failed to remove old preview")?;
    }
    tokio::fs::rename(&tmp_dir, &site_dir)
        .await
        .context("failed to move preview into place")?;

    // (5b) Operator-owned docroot override (#391): only when the manifest
    // declares a non-default docroot AND an overrides dir is configured. The
    // file lives OUTSIDE the tenant tree, so it is trusted; the tenant's repo
    // never influences routing.
    write_docroot_override(ctx, &site_key, &manifest.docroot);

    // (6) Seed now that the site is live and its per-site DB can be created on
    // first access.
    let preview_url = preview_url(&hostname, Some(manifest.php.as_str()));
    run_seed(
        &manifest,
        &site_dir,
        &preview_url,
        &site_key,
        job.pull_request.number,
    )
    .await;

    // (7) Health-gate.
    let healthy = wait_healthy(&preview_url, &manifest.health, ctx).await;

    let duration = start.elapsed();
    tracing::info!(%site_key, framework = framework.as_str(), healthy, duration_ms = duration.as_millis(), "preview deployed");

    Ok(DeployResult {
        site_key,
        hostname,
        preview_url,
        framework,
        duration,
        php_version: Some(manifest.php),
        healthy,
    })
}

/// Clone the PR head into `dest`. Preferred path: `git fetch <base-repo>
/// refs/pull/<n>/head` (resolves the head from the base repo, works for forks
/// and deleted forks) then check out `FETCH_HEAD`. Falls back to a shallow
/// branch clone of the effective clone URL + checkout of the head SHA.
///
/// All network `git` invocations authenticate via `GIT_ASKPASS` when a token is
/// present. Every value that reaches `git` is passed as an argv element (never a
/// shell string) and was validated in [`Job::validate`].
async fn clone_checkout(
    job: &Job,
    ctx: &DeployContext<'_>,
    token: Option<&InstallationToken>,
    dest: &Path,
) -> anyhow::Result<()> {
    let sha = &job.pull_request.head.sha;
    let pull_ref = &job.pull_request.head.pull_ref;
    let base_url = &job.repository.clone_url;

    // Preferred: pull_ref from the base repo.
    tokio::fs::create_dir_all(dest)
        .await
        .context("failed to create checkout dir")?;
    let init_ok = run_git(ctx, token, dest, &["init", "-q"], false)
        .await
        .is_ok();
    if init_ok {
        let fetch_url = fetch_url(base_url, token);
        let fetched = run_git(
            ctx,
            token,
            dest,
            &["fetch", "--depth", "1", &fetch_url, pull_ref],
            true,
        )
        .await;
        if fetched.is_ok()
            && run_git(ctx, token, dest, &["checkout", "-q", "FETCH_HEAD"], false)
                .await
                .is_ok()
        {
            tracing::info!(sha = %sha, "checked out PR head via pull_ref");
            return Ok(());
        }
        tracing::warn!("pull_ref fetch/checkout failed — falling back to branch clone");
    }

    // Fallback: shallow branch clone of the effective URL, then checkout SHA.
    let _ = tokio::fs::remove_dir_all(dest).await;
    let clone_url = fetch_url(job.effective_clone_url(), token);
    let branch = &job.pull_request.head.ref_name;
    run_git(
        ctx,
        token,
        Path::new("."),
        &[
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            &clone_url,
            &dest.to_string_lossy(),
        ],
        true,
    )
    .await
    .context("git clone fallback failed")?;
    // Best-effort exact-SHA checkout (the branch tip may have moved).
    let _ = run_git(ctx, token, dest, &["checkout", "-q", sha], false).await;
    Ok(())
}

/// The fetch/clone URL: token-authenticated form when a token is present, plain
/// otherwise (public repos need no auth).
fn fetch_url(https_url: &str, token: Option<&InstallationToken>) -> String {
    if token.is_some() {
        authenticated_url(https_url)
    } else {
        https_url.to_string()
    }
}

/// Run a `git` command in `dir`, applying the askpass token when one exists.
/// `capture_stderr` controls whether stderr is surfaced in the error.
async fn run_git(
    ctx: &DeployContext<'_>,
    token: Option<&InstallationToken>,
    dir: &Path,
    args: &[&str],
    capture_stderr: bool,
) -> anyhow::Result<()> {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(dir).stdout(Stdio::null());
    cmd.stderr(if capture_stderr {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    if let Some(token) = token {
        // SAFETY-of-secrets: the token goes into the child's ENV (via the
        // askpass helper), never argv, and is never logged.
        ctx.askpass.apply(cmd.as_std_mut(), token);
    }
    let output = cmd.output().await.context("failed to run git")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = if capture_stderr {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    } else {
        String::new()
    };
    anyhow::bail!(
        "git {} failed: {stderr}",
        args.first().copied().unwrap_or("?")
    );
}

/// Run `build:` in order, or an implicit `composer install` when none declared.
///
/// The build runs the SYSTEM composer/PHP (`ctx.composer`), not `ephpm php`.
/// Issue #400 (Composer aborting under `ephpm php`) is Windows-only, so the
/// Linux daemon is not actually bitten — but the daemon deliberately has no
/// `ephpm php` build path, so builds can never regress into it. Failures are
/// logged and the deploy continues so the PR still gets a (broken) preview to
/// inspect.
async fn run_build(manifest: &AppManifest, checkout: &Path, composer: &str, site_key: &str) {
    if manifest.build.is_empty() {
        if checkout.join("composer.json").exists() {
            tracing::info!(%site_key, "no build steps — running implicit composer install (system PHP)");
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
            if !matches!(status, Ok(s) if s.success()) {
                tracing::warn!(%site_key, "composer install failed — deploying without dependencies");
            }
        }
        return;
    }

    for (i, cmd) in manifest.build.iter().enumerate() {
        tracing::info!(%site_key, step = i + 1, command = %cmd, "running build step");
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
            Ok(_) => tracing::warn!(%site_key, step = i + 1, "build step failed — continuing"),
            Err(e) => {
                tracing::warn!(%site_key, step = i + 1, %e, "build step could not run — continuing")
            }
        }
    }
}

/// Resolve `env:` and write it where the app can read it. When `secrets` is
/// `None` (a fork PR without `fork_secrets`), every `${secret.NAME}` resolves to
/// empty — the operator's store is never consulted.
async fn materialize_env(
    job: &Job,
    manifest: &AppManifest,
    secrets: Option<&Secrets>,
    checkout: &Path,
    final_prepend: &Path,
    websocket: bool,
) -> anyhow::Result<()> {
    let repo = &job.repository.full_name;
    let empty = Secrets::default();
    let store = secrets.unwrap_or(&empty);
    let mut resolved: BTreeMap<String, String> = BTreeMap::new();
    for (key, raw) in &manifest.env {
        let mut missing = Vec::new();
        let value = store.substitute(repo, raw, &mut missing);
        for name in missing {
            tracing::warn!(env_key = %key, secret = %name, "referenced secret not found — substituting empty");
        }
        resolved.insert(key.clone(), value);
    }

    let prepend = render_php_prepend(&resolved);
    tokio::fs::write(checkout.join(PREPEND_FILE), prepend)
        .await
        .context("failed to write preview env prepend")?;

    if manifest.docroot != "." {
        let dotenv = render_dotenv(&resolved);
        tokio::fs::write(checkout.join(DOTENV_FILE), dotenv)
            .await
            .context("failed to write preview .env")?;
    }

    let mut ini = manifest.ini.clone();
    ini.entry("auto_prepend_file".to_string())
        .or_insert_with(|| final_prepend.to_string_lossy().into_owned());

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
        "ini": ini,
        "env_keys": resolved.keys().collect::<Vec<_>>(),
    });
    tokio::fs::write(
        checkout.join(SIDECAR_FILE),
        serde_json::to_vec_pretty(&sidecar).context("failed to serialize preview sidecar")?,
    )
    .await
    .context("failed to write preview sidecar")?;

    tracing::info!(
        env_count = resolved.len(),
        dotenv = manifest.docroot != ".",
        "materialized preview environment"
    );
    Ok(())
}

/// Write the operator-owned per-site docroot override (`<key>.toml`) when a
/// non-default docroot is declared and an overrides dir is configured.
///
/// Best-effort and logged, never fatal: an override write failure degrades the
/// preview to serving the container (ePHPm's default), it does not sink the
/// deploy. The file lives outside `sites_dir` — a tenant cannot write it, which
/// is the property that makes ePHPm trust it (#391).
fn write_docroot_override(ctx: &DeployContext<'_>, site_key: &str, docroot: &str) {
    if docroot == "." {
        return;
    }
    let Some(dir) = ctx.site_overrides_dir else {
        tracing::warn!(%site_key, %docroot, "docroot override requested but no site_overrides_dir — ePHPm will serve the container");
        return;
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!(%site_key, %e, "failed to create site_overrides_dir");
        return;
    }
    let path = override_file_path(dir, site_key);
    // TOML string escaping for a path value: backslash and quote. document_root
    // is relative to the container.
    let escaped = docroot.replace('\\', "\\\\").replace('"', "\\\"");
    let body = format!(
        "# Generated by switchboard for site {site_key}. Operator-owned; do not edit by hand.\n\
         document_root = \"{escaped}\"\n"
    );
    match std::fs::write(&path, body) {
        Ok(()) => {
            tracing::info!(%site_key, path = %path.display(), document_root = %docroot, "wrote docroot override")
        }
        Err(e) => tracing::warn!(%site_key, %e, "failed to write docroot override"),
    }
}

/// The override file for a site: `<overrides_dir>/<key>.toml`.
fn override_file_path(overrides_dir: &Path, site_key: &str) -> PathBuf {
    overrides_dir.join(format!("{site_key}.toml"))
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

/// Run `seed:` in order, in the live site, with `$PREVIEW_URL`/`$PREVIEW_HOST`/
/// `$PR` set. Failures are logged and the deploy continues.
///
/// Seeding that must touch the database has to go over HTTP into the running
/// site (as `ephpm/wordpress-sample` does): a `sh -c` child has no `$_SERVER`
/// DB credentials and `ephpm php -r 'ephpm_db_query(...)'` reports no database.
async fn run_seed(
    manifest: &AppManifest,
    site_dir: &Path,
    preview_url: &str,
    site_key: &str,
    pr_number: u64,
) {
    let workdir = site_dir.join(&manifest.docroot);
    for (i, cmd) in manifest.seed.iter().enumerate() {
        tracing::info!(%site_key, step = i + 1, command = %cmd, "running seed step");
        let status = Command::new("sh")
            .args(["-c", cmd])
            .current_dir(&workdir)
            .env("PREVIEW_URL", preview_url)
            .env("PREVIEW_HOST", site_key)
            .env("PR", pr_number.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .await;
        match status {
            Ok(s) if s.success() => {}
            Ok(_) => tracing::warn!(%site_key, step = i + 1, "seed step failed — continuing"),
            Err(e) => {
                tracing::warn!(%site_key, step = i + 1, %e, "seed step could not run — continuing")
            }
        }
    }
}

/// Poll `<preview_url><health_path>` until it returns 200 or the timeout
/// elapses. A zero timeout disables the gate.
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

/// Build the full preview URL, accounting for PHP-version port mapping.
/// Default/latest (8.5) uses 443; older versions get 808x (8.4 → :8084).
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

// ── teardown ────────────────────────────────────────────────────────────────

/// Everything a teardown must remove for one preview. Grouped so the
/// completeness invariant (vhost + DB + temp + override) can be asserted.
#[derive(Debug)]
pub struct TeardownTargets {
    /// `<sites_dir>/<key>` — the vhost checkout.
    pub vhost_dir: PathBuf,
    /// `<sqlite_dir>/<key>.db` and its `-wal`/`-shm`/`-journal` siblings. Empty
    /// when no `sqlite_dir` is configured.
    pub db_files: Vec<PathBuf>,
    /// The exact per-vhost state root ePHPm derives (`<temp>/ephpm-vhosts/<key>-<digest>`).
    pub state_root: PathBuf,
    /// `<overrides_dir>/<key>.toml`, when an overrides dir is configured.
    pub override_file: Option<PathBuf>,
}

/// Compute the teardown targets for a site key. Pure — no I/O — so the
/// completeness of the set is unit-testable.
#[must_use]
pub fn teardown_targets(site_key: &str, ctx: &DeployContext<'_>) -> TeardownTargets {
    let vhost_dir = ctx.sites_dir.join(site_key);

    let db_files = ctx.sqlite_dir.map_or_else(Vec::new, |dir| {
        // The main file plus the Turso/SQLite sidecars that must go with it.
        ["", "-wal", "-shm", "-journal"]
            .iter()
            .map(|suffix| dir.join(format!("{site_key}.db{suffix}")))
            .collect()
    });

    let state_root = vhost_state_root(&vhost_dir, ctx.vhost_temp_base);
    let override_file = ctx
        .site_overrides_dir
        .map(|dir| override_file_path(dir, site_key));

    TeardownTargets {
        vhost_dir,
        db_files,
        state_root,
        override_file,
    }
}

/// Remove a preview: the vhost directory, the per-site database (which lives
/// OUTSIDE the vhost — `rm -rf` on the vhost alone leaks it), the per-vhost
/// temp/session root, and the operator override file.
///
/// Best-effort per target and idempotent — GitHub sends `closed` for PRs that
/// never deployed, and a partially-provisioned preview must still tear down
/// cleanly. Missing targets are not errors.
///
/// # Errors
///
/// Returns an error only if key derivation fails (an invalid preview host);
/// individual removals are logged, not propagated.
pub async fn teardown_preview(job: &Job, ctx: &DeployContext<'_>) -> anyhow::Result<()> {
    let site_key = site_key_for(job, ctx)?;
    let targets = teardown_targets(&site_key, ctx);
    tracing::info!(%site_key, "tearing down preview");

    remove_dir_if_present(&targets.vhost_dir, &site_key, "vhost directory").await;

    for db in &targets.db_files {
        remove_file_if_present(db, &site_key, "per-site database").await;
    }

    // Exact state root, plus a prefix-glob fallback in case the temp base or the
    // hash differ between the two processes. The label prefix is the site key
    // (unique per tenant), so the glob can never match another tenant's dir.
    remove_dir_if_present(&targets.state_root, &site_key, "vhost state root").await;
    remove_state_root_by_prefix(&site_key, ctx).await;

    if let Some(override_file) = &targets.override_file {
        remove_file_if_present(override_file, &site_key, "docroot override").await;
    }

    tracing::info!(%site_key, "preview torn down");
    Ok(())
}

async fn remove_dir_if_present(path: &Path, site_key: &str, what: &str) {
    if !path.exists() {
        return;
    }
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => tracing::info!(%site_key, path = %path.display(), "removed {what}"),
        Err(e) => tracing::warn!(%site_key, path = %path.display(), %e, "failed to remove {what}"),
    }
}

async fn remove_file_if_present(path: &Path, site_key: &str, what: &str) {
    if !path.exists() {
        return;
    }
    match tokio::fs::remove_file(path).await {
        Ok(()) => tracing::info!(%site_key, path = %path.display(), "removed {what}"),
        Err(e) => tracing::warn!(%site_key, path = %path.display(), %e, "failed to remove {what}"),
    }
}

/// Fallback: remove any `<temp>/ephpm-vhosts/<sanitized-key>-*` directory, in
/// case the reproduced digest differs from ePHPm's. Safe because the prefix is
/// the site key, unique per tenant.
async fn remove_state_root_by_prefix(site_key: &str, ctx: &DeployContext<'_>) {
    let base = vhost_temp_base(ctx.vhost_temp_base).join("ephpm-vhosts");
    let prefix = format!("{}-", sanitize_path_label(site_key));
    let Ok(mut entries) = tokio::fs::read_dir(&base).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(&prefix) {
            remove_dir_if_present(&entry.path(), site_key, "vhost state root (prefix match)").await;
        }
    }
}

/// The base for per-vhost state (`ctx.vhost_temp_base` or the system temp).
fn vhost_temp_base(configured: Option<&Path>) -> PathBuf {
    configured.map_or_else(std::env::temp_dir, Path::to_path_buf)
}

/// Reproduce ePHPm's `vhost_state_root` (`crates/ephpm-server/src/router.rs`):
/// `<temp>/ephpm-vhosts/<label>-<digest:016x>`, where `label` is the sanitized
/// final path component of the site **container** and `digest` is a
/// `DefaultHasher` over the container path.
///
/// This couples the daemon to ePHPm's derivation; if the two disagree (a
/// different `TMPDIR`, or a std-hasher change across Rust releases), the exact
/// path misses — which is why teardown also removes by the (unique) label
/// prefix. The DB file, override, and vhost directory — the persistent leaks —
/// are named deterministically and do not depend on this.
fn vhost_state_root(container: &Path, temp_base: Option<&Path>) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    container.hash(&mut hasher);
    let digest = hasher.finish();
    let label = container
        .file_name()
        .and_then(|s| s.to_str())
        .map_or_else(|| "site".to_string(), sanitize_path_label);
    vhost_temp_base(temp_base)
        .join("ephpm-vhosts")
        .join(format!("{label}-{digest:016x}"))
}

/// Reduce a label to a conservative `[A-Za-z0-9._-]` set (≤64 chars). Ported
/// from ePHPm's `sanitize_path_label`.
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

    fn job_from(json: serde_json::Value) -> Job {
        Job::parse(serde_json::to_vec(&json).unwrap().as_slice(), "github.com").unwrap()
    }

    fn deploy_job(action: &str, intent: &str, label: &str) -> Job {
        job_from(serde_json::json!({
            "schema": 1,
            "job_id": "1787456737243-b81167e5b47a38b9",
            "delivery_id": "aaaaaaaa-1111-2222-3333-000000000001",
            "event": "pull_request",
            "action": action,
            "intent": intent,
            "preview": { "label": label },
            "repository": {
                "full_name": "ephpm/wordpress-sample",
                "owner": "ephpm",
                "name": "wordpress-sample",
                "clone_url": "https://github.com/ephpm/wordpress-sample.git"
            },
            "pull_request": {
                "number": 7,
                "fork": false,
                "head": {
                    "ref": "feature/live",
                    "sha": "0123456789abcdef0123456789abcdef01234567",
                    "clone_url": "https://github.com/ephpm/wordpress-sample.git",
                    "repo_full_name": "ephpm/wordpress-sample",
                    "pull_ref": "refs/pull/7/head"
                },
                "base": { "ref": "main" }
            },
            "installation_id": 999
        }))
    }

    struct Ctx {
        sites: tempfile::TempDir,
        overrides: tempfile::TempDir,
        dbs: tempfile::TempDir,
        temp: tempfile::TempDir,
        secrets: Secrets,
        askpass: Askpass,
    }

    impl Ctx {
        fn new() -> Self {
            Self {
                sites: tempfile::tempdir().unwrap(),
                overrides: tempfile::tempdir().unwrap(),
                dbs: tempfile::tempdir().unwrap(),
                temp: tempfile::tempdir().unwrap(),
                secrets: Secrets::default(),
                askpass: Askpass::create().unwrap(),
            }
        }
        fn ctx(&self) -> DeployContext<'_> {
            DeployContext {
                sites_dir: self.sites.path(),
                preview_domain: "preview.ephpm.dev",
                sites_domain_suffix: None,
                site_overrides_dir: Some(self.overrides.path()),
                sqlite_dir: Some(self.dbs.path()),
                vhost_temp_base: Some(self.temp.path()),
                composer: "composer",
                secrets: &self.secrets,
                fork_secrets: false,
                askpass: &self.askpass,
                health_timeout: Duration::ZERO,
                health_interval: Duration::from_secs(1),
            }
        }
    }

    #[test]
    fn site_key_is_full_host_without_suffix() {
        let c = Ctx::new();
        let job = deploy_job("opened", "deploy", "ephpm-wordpress-sample-pr-7");
        assert_eq!(
            site_key_for(&job, &c.ctx()).unwrap(),
            "ephpm-wordpress-sample-pr-7.preview.ephpm.dev"
        );
    }

    #[test]
    fn teardown_targets_cover_db_temp_override_and_vhost() {
        let c = Ctx::new();
        let job = deploy_job("closed", "teardown", "ephpm-wordpress-sample-pr-7");
        let ctx = c.ctx();
        let key = site_key_for(&job, &ctx).unwrap();
        let t = teardown_targets(&key, &ctx);

        // vhost dir
        assert_eq!(t.vhost_dir, c.sites.path().join(&key));
        // DB main file + sidecars, deduped
        let main_db = c.dbs.path().join(format!("{key}.db"));
        assert!(t.db_files.contains(&main_db), "must target <key>.db");
        assert!(
            t.db_files
                .iter()
                .any(|p| p.to_string_lossy().ends_with(".db-wal"))
        );
        assert!(
            t.db_files
                .iter()
                .any(|p| p.to_string_lossy().ends_with(".db-shm"))
        );
        // exactly one main .db (no duplicate from the chain)
        assert_eq!(t.db_files.iter().filter(|p| **p == main_db).count(), 1);
        // temp state root under our temp base
        assert!(t.state_root.starts_with(c.temp.path().join("ephpm-vhosts")));
        // override
        assert_eq!(
            t.override_file,
            Some(c.overrides.path().join(format!("{key}.toml")))
        );
    }

    #[tokio::test]
    async fn teardown_removes_everything() {
        let c = Ctx::new();
        let job = deploy_job("closed", "teardown", "ephpm-wordpress-sample-pr-7");
        let ctx = c.ctx();
        let key = site_key_for(&job, &ctx).unwrap();
        let t = teardown_targets(&key, &ctx);

        // Materialize every target on disk.
        tokio::fs::create_dir_all(t.vhost_dir.join("wp-content"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(t.state_root.join("sessions"))
            .await
            .unwrap();
        for db in &t.db_files {
            tokio::fs::write(db, b"db").await.unwrap();
        }
        tokio::fs::write(
            t.override_file.as_ref().unwrap(),
            b"document_root = \"web\"\n",
        )
        .await
        .unwrap();

        teardown_preview(&job, &ctx).await.unwrap();

        assert!(!t.vhost_dir.exists(), "vhost dir must be gone");
        assert!(!t.state_root.exists(), "state root must be gone");
        assert!(
            !t.override_file.as_ref().unwrap().exists(),
            "override must be gone"
        );
        for db in &t.db_files {
            assert!(!db.exists(), "db sidecar must be gone: {}", db.display());
        }
    }

    #[tokio::test]
    async fn teardown_of_absent_preview_is_ok() {
        let c = Ctx::new();
        let job = deploy_job("closed", "teardown", "ephpm-never-deployed-pr-1");
        teardown_preview(&job, &c.ctx())
            .await
            .expect("absent teardown must succeed");
    }

    #[tokio::test]
    async fn teardown_prefix_fallback_removes_mismatched_digest() {
        let c = Ctx::new();
        let job = deploy_job("closed", "teardown", "ephpm-app-pr-3");
        let ctx = c.ctx();
        let key = site_key_for(&job, &ctx).unwrap();
        // Simulate ePHPm having created a state root with a DIFFERENT digest
        // than the daemon reproduces (e.g. a std-hasher change).
        let rogue = c
            .temp
            .path()
            .join("ephpm-vhosts")
            .join(format!("{}-deadbeefdeadbeef", sanitize_path_label(&key)));
        tokio::fs::create_dir_all(&rogue).await.unwrap();
        teardown_preview(&job, &ctx).await.unwrap();
        assert!(
            !rogue.exists(),
            "prefix fallback must remove the mismatched-digest state root"
        );
    }

    #[test]
    fn override_written_only_for_nondefault_docroot() {
        let c = Ctx::new();
        let ctx = c.ctx();
        // docroot "." → no file
        write_docroot_override(&ctx, "site-a", ".");
        assert!(!c.overrides.path().join("site-a.toml").exists());
        // docroot "web" → file with document_root
        write_docroot_override(&ctx, "site-b", "web");
        let body = std::fs::read_to_string(c.overrides.path().join("site-b.toml")).unwrap();
        assert!(body.contains("document_root = \"web\""));
    }

    // ── framework detection ─────────────────────────────────────────
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
    async fn detect_generic() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.php"), "<?php")
            .await
            .unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Generic);
    }

    // ── env materialization ─────────────────────────────────────────
    fn wp_env_manifest() -> AppManifest {
        AppManifest::from_yaml_str(
            "version: 1\ndocroot: \"public\"\nenv:\n  WP_ENVIRONMENT_TYPE: \"staging\"\n  \
             SOME_KEY: \"${secret.some_key}\"\n  MISSING: \"${secret.absent}\"\n",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn materialize_resolves_secrets_for_non_fork() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = wp_env_manifest();
        let mut default = BTreeMap::new();
        default.insert("some_key".to_string(), "resolved-secret".to_string());
        let secrets = Secrets::from_maps(default, BTreeMap::new());
        let job = deploy_job("opened", "deploy", "ephpm-app-pr-7");
        let final_prepend = dir.path().join("site").join(PREPEND_FILE);

        materialize_env(
            &job,
            &manifest,
            Some(&secrets),
            dir.path(),
            &final_prepend,
            false,
        )
        .await
        .unwrap();

        let prepend = tokio::fs::read_to_string(dir.path().join(PREPEND_FILE))
            .await
            .unwrap();
        assert!(prepend.contains("'SOME_KEY' => 'resolved-secret'"));
        assert!(prepend.contains("'MISSING' => ''"));
        let sidecar = tokio::fs::read_to_string(dir.path().join(SIDECAR_FILE))
            .await
            .unwrap();
        assert!(
            !sidecar.contains("resolved-secret"),
            "sidecar must not leak secret values"
        );
    }

    #[tokio::test]
    async fn materialize_withholds_secrets_when_store_is_none() {
        // The fork path: secrets = None → every reference resolves empty even
        // though a store exists elsewhere. This is the fork-secret-exposure fix.
        let dir = tempfile::tempdir().unwrap();
        let manifest = wp_env_manifest();
        let job = deploy_job("opened", "deploy", "ephpm-app-pr-7");
        let final_prepend = dir.path().join(PREPEND_FILE);
        materialize_env(&job, &manifest, None, dir.path(), &final_prepend, false)
            .await
            .unwrap();
        let prepend = tokio::fs::read_to_string(dir.path().join(PREPEND_FILE))
            .await
            .unwrap();
        assert!(
            prepend.contains("'SOME_KEY' => ''"),
            "fork must not receive the secret"
        );
    }

    #[test]
    fn php_escaping_is_safe() {
        let mut env = BTreeMap::new();
        env.insert("K".to_string(), "it's a \\ backslash".to_string());
        let php = render_php_prepend(&env);
        assert!(php.contains("'K' => 'it\\'s a \\\\ backslash'"));
    }

    // ── preview_url ─────────────────────────────────────────────────
    #[test]
    fn preview_url_default_and_ports() {
        assert_eq!(
            preview_url("h.preview.ephpm.dev", None),
            "https://h.preview.ephpm.dev"
        );
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("8.5")),
            "https://h.preview.ephpm.dev"
        );
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("8.4")),
            "https://h.preview.ephpm.dev:8084"
        );
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("8.3")),
            "https://h.preview.ephpm.dev:8083"
        );
        assert_eq!(
            preview_url("h.preview.ephpm.dev", Some("7.4")),
            "https://h.preview.ephpm.dev"
        );
    }

    #[tokio::test]
    async fn health_disabled_when_timeout_zero() {
        let c = Ctx::new();
        assert!(!wait_healthy("https://example.invalid", "/", &c.ctx()).await);
    }

    #[test]
    fn state_root_is_container_derived_and_stable() {
        let container = Path::new("/var/www/sites/ephpm-app-pr-1.preview.ephpm.dev");
        let a = vhost_state_root(container, Some(Path::new("/tmp")));
        let b = vhost_state_root(container, Some(Path::new("/tmp")));
        assert_eq!(
            a, b,
            "same container must map to same state root across calls"
        );
        assert!(a.starts_with("/tmp/ephpm-vhosts"));
    }
}
