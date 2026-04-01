//! Preview deployment: clone, detect framework, build, deploy to sites_dir.

use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use anyhow::Context;
use serde::Deserialize;
use tokio::process::Command;

use crate::webhook::PullRequestEvent;

/// Parsed `ephpm.json` from the repo root.
#[derive(Debug, Deserialize, Default)]
pub struct EphpmConfig {
    /// Script to run after composer install for database seeding.
    #[serde(default)]
    pub seed: Option<String>,

    /// PHP version to use (determines which ephpm port handles requests).
    #[serde(default)]
    pub php: Option<String>,
}

impl EphpmConfig {
    /// Read `ephpm.json` from the given directory, or return defaults if not found.
    async fn load(dir: &Path) -> Self {
        let path = dir.join("ephpm.json");
        let Ok(contents) = tokio::fs::read_to_string(&path).await else {
            return Self::default();
        };
        match serde_json::from_str(&contents) {
            Ok(config) => {
                tracing::info!(path = %path.display(), "loaded ephpm.json");
                config
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), %e, "failed to parse ephpm.json, using defaults");
                Self::default()
            }
        }
    }
}

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

/// Result of a successful deployment.
pub struct DeployResult {
    /// The preview hostname.
    pub hostname: String,
    /// Detected framework.
    pub framework: Framework,
    /// Time taken to deploy.
    pub duration: std::time::Duration,
    /// PHP version from `ephpm.json` (None = use default/latest).
    pub php_version: Option<String>,
}

/// Deploy a preview for a pull request event.
///
/// 1. Clone the repo at the PR's head SHA
/// 2. Detect the PHP framework
/// 3. Run `composer install` if `composer.json` exists
/// 4. Copy to the sites directory
///
/// # Errors
///
/// Returns an error if cloning, building, or deploying fails.
pub async fn deploy_preview(
    event: &PullRequestEvent,
    sites_dir: &Path,
    preview_domain: &str,
    composer: &str,
) -> anyhow::Result<DeployResult> {
    let start = Instant::now();
    let hostname = event.preview_host(preview_domain);
    let site_dir = sites_dir.join(&hostname);
    let clone_url = event.clone_url();
    let branch = &event.pull_request.head.ref_name;
    let sha = &event.pull_request.head.sha;

    tracing::info!(
        repo = %event.repository.full_name,
        pr = event.number,
        branch = %branch,
        hostname = %hostname,
        "deploying preview"
    );

    // Clone to a temp directory first, then move into place.
    let tmp_dir = site_dir.with_extension("tmp");
    if tmp_dir.exists() {
        tokio::fs::remove_dir_all(&tmp_dir).await.ok();
    }

    // Shallow clone at specific SHA for speed.
    let status = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", branch, clone_url])
        .arg(&tmp_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .context("failed to run git clone")?;

    if !status.success() {
        // Branch clone failed — try full clone + checkout (handles force pushes).
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
        let status = Command::new("git")
            .args(["clone", "--depth", "1", clone_url])
            .arg(&tmp_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("git clone fallback failed")?;
        anyhow::ensure!(status.success(), "git clone failed for {clone_url}");

        let status = Command::new("git")
            .args(["checkout", sha])
            .current_dir(&tmp_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        anyhow::ensure!(status.success(), "git checkout {sha} failed");
    }

    // Detect framework and load ephpm.json config.
    let framework = detect_framework(&tmp_dir).await;
    let ephpm_config = EphpmConfig::load(&tmp_dir).await;
    tracing::info!(
        %hostname,
        framework = framework.as_str(),
        php = ?ephpm_config.php,
        seed = ?ephpm_config.seed,
        "detected framework + config"
    );

    // Run composer install if composer.json exists.
    if tmp_dir.join("composer.json").exists() {
        tracing::info!(%hostname, "running composer install");
        let status = Command::new(composer)
            .args(["install", "--no-dev", "--no-interaction", "--optimize-autoloader", "--quiet"])
            .current_dir(&tmp_dir)
            .env("COMPOSER_NO_INTERACTION", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("failed to run composer install")?;

        if !status.success() {
            tracing::warn!(%hostname, "composer install failed — deploying without dependencies");
        }
    }

    // Run seed script if configured in ephpm.json.
    if let Some(ref seed_cmd) = ephpm_config.seed {
        let preview_url = preview_url(&hostname, ephpm_config.php.as_deref());
        tracing::info!(%hostname, seed = %seed_cmd, "running seed script");
        let status = Command::new("sh")
            .args(["-c", seed_cmd])
            .current_dir(&tmp_dir)
            .env("PREVIEW_URL", &preview_url)
            .env("PREVIEW_HOST", &hostname)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("failed to run seed script")?;

        if !status.success() {
            tracing::warn!(%hostname, seed = %seed_cmd, "seed script failed — deploying without seed");
        }
    }

    // Remove .git directory to save disk space.
    let git_dir = tmp_dir.join(".git");
    if git_dir.exists() {
        tokio::fs::remove_dir_all(&git_dir).await.ok();
    }

    // Atomic swap: remove old site dir (if exists), rename tmp into place.
    if site_dir.exists() {
        tokio::fs::remove_dir_all(&site_dir)
            .await
            .context("failed to remove old preview")?;
    }
    tokio::fs::rename(&tmp_dir, &site_dir)
        .await
        .context("failed to move preview into place")?;

    let duration = start.elapsed();
    tracing::info!(
        %hostname,
        framework = framework.as_str(),
        duration_ms = duration.as_millis(),
        "preview deployed"
    );

    Ok(DeployResult {
        hostname,
        framework,
        duration,
        php_version: ephpm_config.php,
    })
}

/// Build the full preview URL, accounting for PHP version port mapping.
///
/// Default/latest PHP uses port 443 (no port in URL).
/// Older versions get their own port: 8.4 → :8084, 8.3 → :8083.
#[must_use]
pub fn preview_url(hostname: &str, php_version: Option<&str>) -> String {
    match php_version {
        None | Some("8.5") => format!("https://{hostname}"),
        Some(v) => {
            // Map version "8.X" to port 808X (e.g., 8.4 → 8084, 8.3 → 8083)
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

/// Remove a preview deployment.
///
/// # Errors
///
/// Returns an error if the directory cannot be removed.
pub async fn teardown_preview(
    event: &PullRequestEvent,
    sites_dir: &Path,
    preview_domain: &str,
) -> anyhow::Result<()> {
    let hostname = event.preview_host(preview_domain);
    let site_dir = sites_dir.join(&hostname);

    if site_dir.exists() {
        tokio::fs::remove_dir_all(&site_dir)
            .await
            .context("failed to remove preview directory")?;
        tracing::info!(%hostname, "preview torn down");
    } else {
        tracing::debug!(%hostname, "preview directory not found (already removed?)");
    }

    Ok(())
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
        tokio::fs::write(dir.path().join("wp-config-sample.php"), "<?php").await.unwrap();
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
        tokio::fs::write(dir.path().join("artisan"), "#!/usr/bin/env php").await.unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}").await.unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Laravel);
    }

    #[tokio::test]
    async fn detect_generic() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.php"), "<?php echo 'hi';").await.unwrap();
        assert_eq!(detect_framework(dir.path()).await, Framework::Generic);
    }

    // ── ephpm.json ──────────────────────────────────────────────────

    #[tokio::test]
    async fn ephpm_json_with_seed_and_php() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("ephpm.json"),
            r#"{"seed": "scripts/seed.sh", "php": "8.4"}"#,
        )
        .await
        .unwrap();
        let config = EphpmConfig::load(dir.path()).await;
        assert_eq!(config.seed.as_deref(), Some("scripts/seed.sh"));
        assert_eq!(config.php.as_deref(), Some("8.4"));
    }

    #[tokio::test]
    async fn ephpm_json_missing_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = EphpmConfig::load(dir.path()).await;
        assert!(config.seed.is_none());
        assert!(config.php.is_none());
    }

    #[tokio::test]
    async fn ephpm_json_partial() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("ephpm.json"),
            r#"{"seed": "make seed"}"#,
        )
        .await
        .unwrap();
        let config = EphpmConfig::load(dir.path()).await;
        assert_eq!(config.seed.as_deref(), Some("make seed"));
        assert!(config.php.is_none());
    }

    #[tokio::test]
    async fn ephpm_json_invalid_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("ephpm.json"), "not json!!!").await.unwrap();
        let config = EphpmConfig::load(dir.path()).await;
        assert!(config.seed.is_none());
        assert!(config.php.is_none());
    }

    // ── preview_url ─────────────────────────────────────────────────

    #[test]
    fn preview_url_default() {
        let url = preview_url("pr-1.app.preview.ephpm.dev", None);
        assert_eq!(url, "https://pr-1.app.preview.ephpm.dev");
    }

    #[test]
    fn preview_url_latest() {
        let url = preview_url("pr-1.app.preview.ephpm.dev", Some("8.5"));
        assert_eq!(url, "https://pr-1.app.preview.ephpm.dev");
    }

    #[test]
    fn preview_url_php84() {
        let url = preview_url("pr-1.app.preview.ephpm.dev", Some("8.4"));
        assert_eq!(url, "https://pr-1.app.preview.ephpm.dev:8084");
    }

    #[test]
    fn preview_url_php83() {
        let url = preview_url("pr-1.app.preview.ephpm.dev", Some("8.3"));
        assert_eq!(url, "https://pr-1.app.preview.ephpm.dev:8083");
    }
}
