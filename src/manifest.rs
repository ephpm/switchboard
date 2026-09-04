//! The `ephpm.yaml` application manifest — the deploy contract an app repo
//! ships to describe how switchboard should build, seed, and serve its
//! preview.
//!
//! The schema is a **contract**: the demo app repo (`ephpm/wordpress-sample`)
//! ships an `ephpm.yaml` matching it exactly. Parse to these fields; do not
//! invent new ones. When no manifest is present we synthesize a sensible one
//! from the detected framework so unconfigured repos still get a useful
//! preview.
//!
//! ```yaml
//! version: 1
//! php: "8.5"
//! docroot: "."
//! build:
//!   - "composer install --no-dev --optimize-autoloader --no-interaction"
//! services:
//!   database: "turso"   # "turso" | false
//!   kv: true
//!   websocket: true     # default: auto-detect (websocket.php at docroot)
//! seed:
//!   - "wp core install --url=$PREVIEW_URL ..."
//! env:
//!   WP_ENVIRONMENT_TYPE: "staging"
//!   SOME_KEY: "${secret.some_key}"
//! health: "/"
//! ini:
//!   memory_limit: "256M"
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

use crate::deployer::Framework;

/// The only manifest schema version this build understands.
const SUPPORTED_VERSION: u32 = 1;

/// Every filename [`AppManifest::load`] will read a manifest from, in
/// precedence order.
///
/// This list is also exactly what [`quarantine_manifests`] moves out of the
/// served checkout, and a test pins the two together — a fourth accepted
/// filename that is not in this constant would be readable over HTTP the day it
/// ships (switchboard#16).
pub const MANIFEST_FILENAMES: [&str; 3] = [YAML_MANIFESTS[0], YAML_MANIFESTS[1], JSON_MANIFEST];

/// The YAML spellings, in precedence order.
const YAML_MANIFESTS: [&str; 2] = ["ephpm.yaml", "ephpm.yml"];

/// The deprecated POC config.
const JSON_MANIFEST: &str = "ephpm.json";

/// Where the deploy parks the manifest once it has been read.
///
/// Dot-prefixed **and** kept inside the container: ePHPm's `hidden_files`
/// default is `deny`, and its check rejects a dot-prefixed segment anywhere in
/// the request path (`has_hidden_segment`), so `/.switchboard/ephpm.yaml` is a
/// 403 even when the container itself is the web root. Keeping it inside the
/// container also means the existing teardown — which removes
/// `<sites_dir>/<key>/` wholesale — still reaps it, and an operator debugging a
/// preview can still read the manifest the deploy actually used.
pub const MANIFEST_ARCHIVE_DIR: &str = ".switchboard";

/// A parsed (or synthesized) `ephpm.yaml` application manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct AppManifest {
    /// Schema version. Required; only [`SUPPORTED_VERSION`] is accepted.
    pub version: u32,

    /// PHP version for this preview. One running instance serves one version;
    /// this is recorded (and drives the preview URL port map) but multi-version
    /// routing is a future concern.
    #[serde(default = "default_php")]
    pub php: String,

    /// Document root, relative to the repo root.
    #[serde(default = "default_docroot")]
    pub docroot: String,

    /// Shell commands run in the checkout, in order, BEFORE the site goes live.
    #[serde(default)]
    pub build: Vec<String>,

    /// Declared backing services.
    #[serde(default)]
    pub services: Services,

    /// Shell commands run AFTER the site serves and its per-site DB exists.
    /// `$PREVIEW_URL`, `$PREVIEW_HOST`, and `$PR` are provided in the env.
    #[serde(default)]
    pub seed: Vec<String>,

    /// Environment variables. Values are literals or `${secret.NAME}`
    /// references resolved from switchboard's own secret store.
    #[serde(default)]
    pub env: BTreeMap<String, String>,

    /// HTTP path polled for a 200 before the deploy is reported "ready".
    #[serde(default = "default_health")]
    pub health: String,

    /// PHP ini overrides for this preview (advisory in v1 — surfaced, not
    /// enforced by switchboard; ePHPm's preview config owns the running server).
    #[serde(default)]
    pub ini: BTreeMap<String, String>,
}

fn default_php() -> String {
    "8.5".to_string()
}

fn default_docroot() -> String {
    ".".to_string()
}

fn default_health() -> String {
    "/".to_string()
}

/// Declared backing services for a preview.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Services {
    /// Database engine, or disabled. `"turso"` (default) or `false`.
    pub database: DatabaseService,
    /// Whether the embedded KV store is requested.
    pub kv: bool,
    /// Whether native WebSockets are requested. `None` means auto-detect:
    /// true if `websocket.php` exists at the docroot (see
    /// [`AppManifest::websocket_enabled`]).
    pub websocket: Option<bool>,
}

impl Default for Services {
    fn default() -> Self {
        Self {
            database: DatabaseService::Turso,
            kv: true,
            websocket: None,
        }
    }
}

/// The database service selection: the Turso engine, or explicitly disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseService {
    /// The embedded Turso (SQLite-compatible) engine — the default.
    Turso,
    /// Database explicitly disabled (`database: false`).
    Disabled,
}

impl DatabaseService {
    /// Human-readable label for logs and the sidecar manifest.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Turso => "turso",
            Self::Disabled => "disabled",
        }
    }
}

impl<'de> Deserialize<'de> for DatabaseService {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept either a string ("turso") or a bool (false).
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Str(String),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Bool(true) => Ok(Self::Turso),
            Raw::Bool(false) => Ok(Self::Disabled),
            Raw::Str(s) if s.eq_ignore_ascii_case("turso") => Ok(Self::Turso),
            Raw::Str(s) if s.eq_ignore_ascii_case("false") || s.eq_ignore_ascii_case("none") => {
                Ok(Self::Disabled)
            }
            Raw::Str(s) => Err(serde::de::Error::custom(format!(
                "unknown database service {s:?} (expected \"turso\" or false)"
            ))),
        }
    }
}

impl AppManifest {
    /// Parse a manifest from YAML text, validating the schema version.
    ///
    /// # Errors
    ///
    /// Returns an error if the YAML is malformed or declares an unsupported
    /// `version`.
    pub fn from_yaml_str(yaml: &str) -> anyhow::Result<Self> {
        let manifest: Self =
            serde_yml::from_str(yaml).context("failed to parse ephpm.yaml manifest")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Reject unsupported schema versions.
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == SUPPORTED_VERSION,
            "unsupported ephpm.yaml version {} (this build understands version {SUPPORTED_VERSION})",
            self.version,
        );
        Ok(())
    }

    /// A minimal manifest carrying only the schema defaults.
    fn minimal() -> Self {
        Self {
            version: SUPPORTED_VERSION,
            php: default_php(),
            docroot: default_docroot(),
            build: Vec::new(),
            services: Services::default(),
            seed: Vec::new(),
            env: BTreeMap::new(),
            health: default_health(),
            ini: BTreeMap::new(),
        }
    }

    /// Synthesize a manifest from the detected framework when the repo ships no
    /// `ephpm.yaml`. Mirrors the conventional layout and bootstrap for each
    /// framework so an unconfigured repo still gets a useful preview.
    #[must_use]
    pub fn from_framework(framework: Framework) -> Self {
        let mut manifest = Self::minimal();
        let composer = "composer install --no-dev --optimize-autoloader --no-interaction";
        match framework {
            Framework::WordPress => {
                manifest.seed = vec![
                    "wp core install --url=$PREVIEW_URL --title=\"Preview PR $PR\" \
                     --admin_user=admin --admin_password=admin \
                     --admin_email=admin@example.com --skip-email"
                        .to_string(),
                ];
            }
            Framework::Laravel => {
                manifest.docroot = "public".to_string();
                manifest.build = vec![
                    composer.to_string(),
                    "php artisan key:generate --force".to_string(),
                ];
                manifest.seed = vec!["php artisan migrate --force".to_string()];
            }
            Framework::Symfony => {
                manifest.docroot = "public".to_string();
                manifest.build = vec![composer.to_string()];
            }
            Framework::Drupal => {
                manifest.docroot = "web".to_string();
                manifest.build = vec![composer.to_string()];
            }
            Framework::Generic => {}
        }
        manifest
    }

    /// Migrate a legacy (deprecated) `ephpm.json` POC config into a manifest,
    /// preserving its `seed`/`php` behavior on top of the framework defaults.
    #[must_use]
    pub fn from_legacy_json(legacy: &LegacyEphpmConfig, framework: Framework) -> Self {
        let mut manifest = Self::from_framework(framework);
        if let Some(php) = &legacy.php {
            manifest.php = php.clone();
        }
        if let Some(seed) = &legacy.seed {
            // The POC modeled `seed` as a single shell string.
            manifest.seed = vec![seed.clone()];
        }
        manifest
    }

    /// Load the manifest for a checked-out repo.
    ///
    /// Precedence: `ephpm.yaml` → `ephpm.yml` → deprecated `ephpm.json` →
    /// framework-synthesized defaults.
    ///
    /// # Errors
    ///
    /// Returns an error only when a YAML manifest is present but invalid (bad
    /// syntax or unsupported version) — a broken contract must not silently
    /// deploy the wrong thing. A missing manifest is not an error.
    pub async fn load(dir: &Path, framework: Framework) -> anyhow::Result<Self> {
        for name in YAML_MANIFESTS {
            let path = dir.join(name);
            if let Ok(contents) = tokio::fs::read_to_string(&path).await {
                tracing::info!(path = %path.display(), "loaded ephpm.yaml manifest");
                return Self::from_yaml_str(&contents)
                    .with_context(|| format!("in {}", path.display()));
            }
        }

        let json_path = dir.join(JSON_MANIFEST);
        if let Ok(contents) = tokio::fs::read_to_string(&json_path).await {
            match serde_json::from_str::<LegacyEphpmConfig>(&contents) {
                Ok(legacy) => {
                    tracing::warn!(
                        path = %json_path.display(),
                        "ephpm.json is deprecated — migrate to ephpm.yaml"
                    );
                    return Ok(Self::from_legacy_json(&legacy, framework));
                }
                Err(e) => {
                    tracing::warn!(
                        path = %json_path.display(),
                        %e,
                        "failed to parse ephpm.json — falling back to framework defaults"
                    );
                }
            }
        }

        tracing::info!(
            framework = framework.as_str(),
            "no app manifest found — synthesizing from framework defaults"
        );
        Ok(Self::from_framework(framework))
    }

    /// Whether WebSockets are enabled for this preview: the explicit
    /// `services.websocket` value, or auto-detected from `websocket.php` at the
    /// docroot.
    #[must_use]
    pub fn websocket_enabled(&self, checkout_root: &Path) -> bool {
        match self.services.websocket {
            Some(explicit) => explicit,
            None => checkout_root
                .join(&self.docroot)
                .join("websocket.php")
                .exists(),
        }
    }
}

/// Move every deploy manifest out of the checkout root, once it has been read.
///
/// # Why
///
/// `ephpm.yaml` is a plain, non-dot-prefixed file at the repository root, and
/// for an app declaring `docroot: "."` — WordPress, and most bespoke apps — the
/// repository root *is* the web root. So the manifest was served: confirmed
/// live on the preview cluster, `GET /ephpm.yaml` → **200 with full contents**,
/// exposing the build commands, the enabled services, and the whole seed
/// sequence (switchboard#16).
///
/// The per-site document-root override (switchboard#14) does not close this.
/// Two independent reasons: a node that has not configured
/// `--site-overrides-dir` never writes one, and even a fully-wired node cannot
/// move a file that the manifest itself placed *inside* the declared web root.
/// A file that must not be public has to stop being in a served directory —
/// there is no configuration that fixes it from outside.
///
/// # Ordering
///
/// Called after `build:` (which runs in the checkout and may legitimately read
/// the manifest) and **before** the atomic swap into `sites_dir`, so the file
/// is never present in a live web root even momentarily. `seed:` runs after the
/// swap and therefore sees the archived location, not the original path — a
/// seed step that reads `./ephpm.yaml` must read
/// `.switchboard/ephpm.yaml` instead. Nothing else in switchboard re-reads the
/// manifest: the deploy parses it once into an owned [`AppManifest`], a
/// redeploy fetches a fresh checkout, and teardown never looks at it.
///
/// # Fail-closed, but never fail the deploy over the archive
///
/// Archiving is best-effort; *removal from the served root* is not. If the
/// manifest cannot be moved into [`MANIFEST_ARCHIVE_DIR`] (a repo shipping its
/// own `.switchboard` file, a cross-device quirk) it is deleted instead and the
/// deploy warns. Only when it can be neither moved nor deleted does the deploy
/// fail — publishing it is not an option.
///
/// Returns the filenames that were taken out of the served root.
///
/// # Errors
///
/// Returns an error only when a manifest exists in the served root and can be
/// neither relocated nor removed.
pub async fn quarantine_manifests(container: &Path) -> anyhow::Result<Vec<String>> {
    let archive = container.join(MANIFEST_ARCHIVE_DIR);
    let mut removed = Vec::new();

    for name in MANIFEST_FILENAMES {
        let src = container.join(name);
        // `symlink_metadata` so a manifest that is a dangling symlink still
        // counts as present — it would be a 404, but leaving tenant-controlled
        // links in the served root is not something to decide by accident.
        match tokio::fs::symlink_metadata(&src).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("failed to stat {}", src.display()));
            }
        }

        let dest = archive.join(name);
        let archived = match tokio::fs::create_dir_all(&archive).await {
            Ok(()) => tokio::fs::rename(&src, &dest).await.is_ok(),
            Err(_) => false,
        };

        if archived {
            tracing::info!(
                manifest = name,
                path = %dest.display(),
                "moved the deploy manifest out of the served root"
            );
        } else {
            remove_path(&src).await.with_context(|| {
                format!(
                    "refusing to publish {}: it could be neither archived into {} \
                     nor removed",
                    src.display(),
                    archive.display()
                )
            })?;
            tracing::warn!(
                manifest = name,
                path = %src.display(),
                archive = %archive.display(),
                "could not archive the deploy manifest — deleted it instead so it \
                 is not served"
            );
        }
        removed.push(name.to_string());
    }

    Ok(removed)
}

/// Remove a path whether it is a file, a symlink, or a directory.
async fn remove_path(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => tokio::fs::remove_dir_all(path).await,
    }
}

/// The legacy, deprecated `ephpm.json` POC config. Kept only so the POC's
/// `seed`/`php` behavior survives the migration to `ephpm.yaml`.
#[derive(Debug, Deserialize, Default)]
pub struct LegacyEphpmConfig {
    /// Single shell command run for database seeding (POC shape).
    #[serde(default)]
    pub seed: Option<String>,
    /// PHP version.
    #[serde(default)]
    pub php: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `ephpm/wordpress-sample` ships — inlined as a fixture so the
    /// test never depends on that repo at build time.
    const WORDPRESS_SAMPLE_YAML: &str = r#"
version: 1
php: "8.5"
docroot: "."
build:
  - "composer install --no-dev --optimize-autoloader --no-interaction"
services:
  database: "turso"
  kv: true
  websocket: true
seed:
  - "wp core install --url=$PREVIEW_URL --title=\"Preview\" --admin_user=admin --admin_password=admin --admin_email=admin@example.com --skip-email"
env:
  WP_ENVIRONMENT_TYPE: "staging"
  SOME_KEY: "${secret.some_key}"
health: "/"
ini:
  memory_limit: "256M"
"#;

    #[test]
    fn parse_full_manifest() {
        let m = AppManifest::from_yaml_str(WORDPRESS_SAMPLE_YAML).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.php, "8.5");
        assert_eq!(m.docroot, ".");
        assert_eq!(m.build.len(), 1);
        assert!(m.build[0].contains("composer install"));
        assert_eq!(m.services.database, DatabaseService::Turso);
        assert!(m.services.kv);
        assert_eq!(m.services.websocket, Some(true));
        assert_eq!(m.seed.len(), 1);
        assert!(m.seed[0].contains("wp core install"));
        assert_eq!(m.env.get("WP_ENVIRONMENT_TYPE").unwrap(), "staging");
        assert_eq!(m.env.get("SOME_KEY").unwrap(), "${secret.some_key}");
        assert_eq!(m.health, "/");
        assert_eq!(m.ini.get("memory_limit").unwrap(), "256M");
    }

    #[test]
    fn parse_minimal_manifest_uses_defaults() {
        let m = AppManifest::from_yaml_str("version: 1\n").unwrap();
        assert_eq!(m.php, "8.5");
        assert_eq!(m.docroot, ".");
        assert!(m.build.is_empty());
        assert_eq!(m.services.database, DatabaseService::Turso);
        assert!(m.services.kv);
        assert_eq!(m.services.websocket, None);
        assert!(m.seed.is_empty());
        assert!(m.env.is_empty());
        assert_eq!(m.health, "/");
        assert!(m.ini.is_empty());
    }

    #[test]
    fn unknown_version_rejected() {
        let err = AppManifest::from_yaml_str("version: 2\n").unwrap_err();
        assert!(err.to_string().contains("unsupported ephpm.yaml version 2"));
    }

    #[test]
    fn missing_version_rejected() {
        // `version` is required — a manifest without it is malformed.
        assert!(AppManifest::from_yaml_str("php: \"8.5\"\n").is_err());
    }

    #[test]
    fn database_false_disables() {
        let m = AppManifest::from_yaml_str("version: 1\nservices:\n  database: false\n").unwrap();
        assert_eq!(m.services.database, DatabaseService::Disabled);
    }

    #[test]
    fn database_unknown_value_rejected() {
        let err =
            AppManifest::from_yaml_str("version: 1\nservices:\n  database: mysql\n").unwrap_err();
        // The full error chain names the offending field and value.
        assert!(format!("{err:#}").to_lowercase().contains("database"));
    }

    #[test]
    fn framework_default_wordpress() {
        let m = AppManifest::from_framework(Framework::WordPress);
        assert_eq!(m.docroot, ".");
        assert_eq!(m.services.database, DatabaseService::Turso);
        assert!(m.services.kv);
        assert_eq!(m.seed.len(), 1);
        assert!(m.seed[0].contains("wp core install"));
        assert!(m.build.is_empty());
    }

    #[test]
    fn framework_default_laravel() {
        let m = AppManifest::from_framework(Framework::Laravel);
        assert_eq!(m.docroot, "public");
        assert!(m.build.iter().any(|c| c.contains("composer install")));
        assert!(m.build.iter().any(|c| c.contains("key:generate")));
        assert!(m.seed.iter().any(|c| c.contains("migrate")));
    }

    #[test]
    fn framework_default_generic_is_minimal() {
        let m = AppManifest::from_framework(Framework::Generic);
        assert_eq!(m.docroot, ".");
        assert!(m.build.is_empty());
        assert!(m.seed.is_empty());
    }

    #[test]
    fn framework_default_symfony() {
        let m = AppManifest::from_framework(Framework::Symfony);
        assert_eq!(m.docroot, "public");
        assert!(m.build.iter().any(|c| c.contains("composer install")));
        // Symfony has no framework-supplied seed step.
        assert!(m.seed.is_empty());
    }

    #[test]
    fn framework_default_drupal() {
        let m = AppManifest::from_framework(Framework::Drupal);
        assert_eq!(m.docroot, "web");
        assert!(m.build.iter().any(|c| c.contains("composer install")));
    }

    #[test]
    fn database_none_string_disables() {
        // The DatabaseService deserializer accepts the string "none" as an
        // alias for disabled, alongside the bool `false`.
        let m = AppManifest::from_yaml_str("version: 1\nservices:\n  database: none\n").unwrap();
        assert_eq!(m.services.database, DatabaseService::Disabled);
        assert_eq!(m.services.database.as_str(), "disabled");
    }

    #[test]
    fn database_turso_string_case_insensitive() {
        let m = AppManifest::from_yaml_str("version: 1\nservices:\n  database: TURSO\n").unwrap();
        assert_eq!(m.services.database, DatabaseService::Turso);
        assert_eq!(m.services.database.as_str(), "turso");
    }

    #[test]
    fn websocket_explicit_true_parses() {
        let m = AppManifest::from_yaml_str("version: 1\nservices:\n  websocket: true\n").unwrap();
        assert_eq!(m.services.websocket, Some(true));
        // Explicit true wins with no file present on disk.
        assert!(m.websocket_enabled(Path::new("/nonexistent")));
    }

    #[test]
    fn legacy_json_without_overrides_keeps_framework_defaults() {
        // A legacy config with neither php nor seed set must leave the
        // framework-synthesized values (WordPress seed, default php) intact.
        let legacy = LegacyEphpmConfig::default();
        let m = AppManifest::from_legacy_json(&legacy, Framework::WordPress);
        assert_eq!(m.php, "8.5");
        assert_eq!(m.seed.len(), 1);
        assert!(m.seed[0].contains("wp core install"));
    }

    #[test]
    fn legacy_json_preserves_seed_and_php() {
        let legacy = LegacyEphpmConfig {
            seed: Some("scripts/seed.sh".to_string()),
            php: Some("8.4".to_string()),
        };
        let m = AppManifest::from_legacy_json(&legacy, Framework::WordPress);
        assert_eq!(m.php, "8.4");
        assert_eq!(m.seed, vec!["scripts/seed.sh".to_string()]);
    }

    #[tokio::test]
    async fn load_prefers_yaml_over_json() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("ephpm.yaml"), "version: 1\nphp: \"8.3\"\n")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("ephpm.json"), r#"{"php": "8.4"}"#)
            .await
            .unwrap();
        let m = AppManifest::load(dir.path(), Framework::Generic)
            .await
            .unwrap();
        assert_eq!(m.php, "8.3");
    }

    #[tokio::test]
    async fn load_falls_back_to_framework_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let m = AppManifest::load(dir.path(), Framework::Laravel)
            .await
            .unwrap();
        assert_eq!(m.docroot, "public");
    }

    #[tokio::test]
    async fn load_migrates_legacy_json() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("ephpm.json"),
            r#"{"seed": "make seed", "php": "8.4"}"#,
        )
        .await
        .unwrap();
        let m = AppManifest::load(dir.path(), Framework::Generic)
            .await
            .unwrap();
        assert_eq!(m.php, "8.4");
        assert_eq!(m.seed, vec!["make seed".to_string()]);
    }

    #[tokio::test]
    async fn load_errors_on_invalid_yaml_version() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("ephpm.yaml"), "version: 99\n")
            .await
            .unwrap();
        assert!(
            AppManifest::load(dir.path(), Framework::Generic)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn websocket_autodetect_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let m = AppManifest::from_yaml_str("version: 1\n").unwrap();
        assert!(!m.websocket_enabled(dir.path()));
        tokio::fs::write(dir.path().join("websocket.php"), "<?php")
            .await
            .unwrap();
        assert!(m.websocket_enabled(dir.path()));
    }

    // ── switchboard#16: the manifest must not be publicly served ───────

    /// Reproduces the two rules that together decide whether an HTTP request
    /// can reach a file in a container ePHPm serves as the web root
    /// (`docroot: "."`):
    ///
    /// 1. **hidden files** — `[server.static_files] hidden_files` defaults to
    ///    `deny`, and ePHPm's `has_hidden_segment` rejects a dot-prefixed
    ///    segment *anywhere* in the request path, not just the last one;
    /// 2. **containment** — `serve_file` canonicalizes and requires the target
    ///    to stay inside the document root.
    ///
    /// This is what the issue actually measured (`GET /ephpm.yaml` → 200), and
    /// it is as close to an end-to-end HTTP assertion as a test without a
    /// running ePHPm can get.
    fn servable_from_web_root(web_root: &Path, request_path: &str) -> bool {
        let trimmed = request_path.trim_start_matches('/');
        if trimmed
            .split('/')
            .any(|s| s.starts_with('.') && s != "." && s != "..")
        {
            return false; // 403 by the hidden-file rule
        }
        let mut candidate = web_root.to_path_buf();
        for segment in trimmed.split('/') {
            candidate.push(segment);
        }
        let (Ok(target), Ok(root)) = (candidate.canonicalize(), web_root.canonicalize()) else {
            return false;
        };
        target.starts_with(&root) && target.is_file()
    }

    /// A `docroot: "."` checkout carrying every manifest spelling — the
    /// `wordpress-sample` shape, which is where switchboard#16 was confirmed
    /// live.
    async fn checkout_with_manifests() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("ephpm.yaml"),
            "version: 1\ndocroot: \".\"\nseed:\n  - \"wp core install --admin_password=admin\"\n",
        )
        .await
        .unwrap();
        tokio::fs::write(dir.path().join("ephpm.json"), r#"{"php": "8.4"}"#)
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("index.php"), "<?php // app")
            .await
            .unwrap();
        dir
    }

    /// **The regression test for switchboard#16.**
    ///
    /// Before the fix `GET /ephpm.yaml` returned 200 with the build commands,
    /// the services and the whole seed sequence. After it there is no request
    /// path that reaches any manifest, while the app itself still serves.
    #[tokio::test]
    async fn no_manifest_is_reachable_over_http_after_quarantine() {
        let dir = checkout_with_manifests().await;
        let root = dir.path();

        // The "before": this is exactly the exposure the issue reported.
        assert!(
            servable_from_web_root(root, "/ephpm.yaml"),
            "the un-quarantined manifest must be servable — otherwise the \
             assertion below could pass for the wrong reason"
        );

        let moved = quarantine_manifests(root).await.unwrap();
        assert_eq!(
            moved,
            vec!["ephpm.yaml".to_string(), "ephpm.json".to_string()]
        );

        for path in [
            "/ephpm.yaml",
            "/ephpm.yml",
            "/ephpm.json",
            // The archive is dot-prefixed, so ePHPm denies it even though it
            // lives inside the served container.
            "/.switchboard/ephpm.yaml",
            "/.switchboard/ephpm.json",
        ] {
            assert!(
                !servable_from_web_root(root, path),
                "{path} must not be reachable after the deploy manifest is quarantined"
            );
        }

        // ...and the app is untouched.
        assert!(servable_from_web_root(root, "/index.php"));
    }

    /// The manifest is *relocated*, not destroyed: an operator debugging a
    /// preview can still read exactly what the deploy used.
    #[tokio::test]
    async fn quarantine_preserves_the_manifest_off_the_served_root() {
        let dir = checkout_with_manifests().await;
        quarantine_manifests(dir.path()).await.unwrap();

        let archived = dir.path().join(MANIFEST_ARCHIVE_DIR).join("ephpm.yaml");
        let text = tokio::fs::read_to_string(&archived)
            .await
            .expect("the manifest must survive at its archived path");
        assert!(text.contains("wp core install"));
        assert!(!dir.path().join("ephpm.yaml").exists());
    }

    /// Quarantining a checkout with no manifest at all (the framework-defaults
    /// path) is a no-op, not an error.
    #[tokio::test]
    async fn quarantine_without_a_manifest_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        assert!(quarantine_manifests(dir.path()).await.unwrap().is_empty());
        assert!(
            !dir.path().join(MANIFEST_ARCHIVE_DIR).exists(),
            "no manifest means no archive directory to create"
        );
    }

    /// If the archive cannot be created — a repo shipping its own
    /// `.switchboard` *file* — the manifest is deleted rather than served. The
    /// debug copy is the thing that is expendable; the exposure is not.
    #[tokio::test]
    async fn manifest_is_deleted_when_it_cannot_be_archived() {
        let dir = checkout_with_manifests().await;
        tokio::fs::write(dir.path().join(MANIFEST_ARCHIVE_DIR), "not a directory")
            .await
            .unwrap();

        quarantine_manifests(dir.path()).await.unwrap();

        assert!(
            !dir.path().join("ephpm.yaml").exists(),
            "a manifest that cannot be archived must still leave the served root"
        );
        assert!(!servable_from_web_root(dir.path(), "/ephpm.yaml"));
    }

    /// Every filename the loader will read must also be one the deploy takes
    /// out of the served root. A fourth accepted spelling that is not in
    /// [`MANIFEST_FILENAMES`] would be a 200 the day it ships.
    #[tokio::test]
    async fn every_loadable_manifest_filename_is_quarantined() {
        for name in MANIFEST_FILENAMES {
            let dir = tempfile::tempdir().unwrap();
            let body = if name.ends_with(".json") {
                r#"{"php": "8.4"}"#.to_string()
            } else {
                "version: 1\n".to_string()
            };
            tokio::fs::write(dir.path().join(name), &body)
                .await
                .unwrap();

            // The loader reads it...
            AppManifest::load(dir.path(), Framework::Generic)
                .await
                .unwrap();
            // ...and the deploy then takes it out of the served root.
            assert_eq!(
                quarantine_manifests(dir.path()).await.unwrap(),
                vec![name.to_string()]
            );
            assert!(!dir.path().join(name).exists(), "{name} was left served");
        }
    }

    /// The archive directory has to be dot-prefixed — that is the entire reason
    /// it is safe to keep it inside a container ePHPm may serve as the web root.
    #[test]
    fn manifest_archive_is_hidden_from_http() {
        assert!(MANIFEST_ARCHIVE_DIR.starts_with('.'));
    }

    #[test]
    fn websocket_explicit_overrides_autodetect() {
        let m = AppManifest::from_yaml_str("version: 1\nservices:\n  websocket: false\n").unwrap();
        // Even if a websocket.php existed, explicit false wins. Use a path that
        // does not matter because the explicit value short-circuits.
        assert!(!m.websocket_enabled(Path::new("/nonexistent")));
    }
}
