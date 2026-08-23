//! Switchboard daemon configuration.
//!
//! The daemon is a queue worker, not an HTTP server: there is no listen address
//! and no webhook secret (signature verification moved to switchboard-api). It
//! gains the queue directory it watches, the paths it must clean up on
//! teardown, and an explicit fork policy.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "switchboard",
    version,
    about = "Preview-deployment daemon for ePHPm — consumes switchboard-api job files"
)]
pub struct Config {
    /// Directory the daemon watches for job files, i.e. switchboard-api's
    /// `<vhost>/.switchboard/queue`. Configured explicitly and NOT derived from
    /// `sites_dir` — switchboard-api's own vhost is not a preview.
    #[arg(long, env = "SWITCHBOARD_QUEUE_DIR")]
    pub queue_dir: PathBuf,

    /// Seconds between queue scans. inotify is not used; short polling is
    /// sufficient because the directory is only ever written by `rename()`.
    #[arg(long, default_value_t = 2, env = "SWITCHBOARD_POLL_INTERVAL_SECS")]
    pub poll_interval_secs: u64,

    /// GitHub App private key path (PEM). Must be `0600` and owned by the daemon
    /// uid. The key never leaves memory once loaded; the minted token is never
    /// written to disk or logged.
    #[arg(long, env = "SWITCHBOARD_APP_KEY")]
    pub app_key: PathBuf,

    /// GitHub App ID.
    #[arg(long, env = "SWITCHBOARD_APP_ID")]
    pub app_id: u64,

    /// GitHub host clone URLs must belong to (set for GHES). Also selects the
    /// API base: `github.com` → `api.github.com`, otherwise `https://<host>/api/v3`.
    #[arg(long, default_value = "github.com", env = "SWITCHBOARD_GITHUB_HOST")]
    pub github_host: String,

    /// ePHPm sites directory. Previews are checked out into
    /// `sites_dir/<site-key>/`.
    #[arg(long, default_value = "/var/www/sites", env = "SWITCHBOARD_SITES_DIR")]
    pub sites_dir: PathBuf,

    /// Preview domain suffix. The preview host is `<label>.<preview_domain>`.
    #[arg(
        long,
        default_value = "preview.ephpm.dev",
        env = "SWITCHBOARD_PREVIEW_DOMAIN"
    )]
    pub preview_domain: String,

    /// ePHPm's `[server] sites_domain_suffix` (must begin with a dot, e.g.
    /// `.preview.ephpm.dev`), if set. The daemon uses it to derive the SAME
    /// canonical site key ePHPm derives from the `Host` header. Leave unset when
    /// ePHPm has no suffix — the vhost directory is then named by the full FQDN.
    #[arg(long, env = "SWITCHBOARD_SITES_DOMAIN_SUFFIX")]
    pub sites_domain_suffix: Option<String>,

    /// ePHPm's `[server] site_overrides_dir`. When set AND a manifest declares a
    /// non-default `docroot`, the daemon writes `<site-key>.toml` here (the #391
    /// operator-owned override mechanism). Must be OUTSIDE `sites_dir` — the same
    /// constraint ePHPm enforces. Unset disables docroot overrides.
    #[arg(long, env = "SWITCHBOARD_SITE_OVERRIDES_DIR")]
    pub site_overrides_dir: Option<PathBuf>,

    /// ePHPm's `[db.sqlite] dir` — where per-site databases live as
    /// `<site-key>.db`. Needed so teardown removes a closed PR's database, which
    /// lives OUTSIDE the vhost directory. Unset skips DB teardown (with a warn).
    #[arg(long, env = "SWITCHBOARD_SQLITE_DIR")]
    pub sqlite_dir: Option<PathBuf>,

    /// Base directory under which ePHPm places per-vhost state
    /// (`<base>/ephpm-vhosts/<label>-<digest>`). Defaults to the system temp
    /// directory — the same `std::env::temp_dir()` ePHPm uses. Set this only if
    /// ePHPm runs with a different `TMPDIR` than the daemon.
    #[arg(long, env = "SWITCHBOARD_VHOST_TEMP_BASE")]
    pub vhost_temp_base: Option<PathBuf>,

    /// Composer command (or path). Used for the implicit `composer install`
    /// when a manifest declares no `build:` steps. This runs the SYSTEM
    /// composer/PHP, not `ephpm php`: issue #400 (Composer aborting under
    /// `ephpm php`) is a Windows-only php-sdk problem (Schannel-linked curl), so
    /// the Linux daemon is unaffected — but building against the system PHP keeps
    /// it that way and avoids coupling builds to the embedded SAPI.
    #[arg(long, default_value = "composer", env = "SWITCHBOARD_COMPOSER")]
    pub composer: String,

    /// Switchboard's own secrets file (YAML) for resolving `${secret.NAME}`
    /// references in a manifest's `env:`. Secrets can also come from
    /// `SWITCHBOARD_SECRET_*` env vars.
    #[arg(long, env = "SWITCHBOARD_SECRETS_FILE")]
    pub secrets_file: Option<PathBuf>,

    /// Deploy pull requests from forks. Off by default: a fork's head is code
    /// from outside the org, and building it is a decision. Fork TEARDOWNS are
    /// always processed regardless (removing a preview is safe). Mirrors
    /// switchboard-api's `SWITCHBOARD_ALLOW_FORKS` as a second, independent gate.
    #[arg(long, env = "SWITCHBOARD_ALLOW_FORK_DEPLOY")]
    pub allow_fork_deploy: bool,

    /// Resolve operator `${secret.NAME}` values into a fork PR's preview
    /// environment. Off by default even when fork deploys are allowed: building
    /// untrusted code with your secrets in the environment is the hole this
    /// closes. Non-fork PRs always get secrets.
    #[arg(long, env = "SWITCHBOARD_FORK_SECRETS")]
    pub fork_secrets: bool,

    /// Seconds to poll a preview's `health:` path for HTTP 200 before reporting
    /// ready. Zero disables the health gate.
    #[arg(long, default_value_t = 60, env = "SWITCHBOARD_HEALTH_TIMEOUT_SECS")]
    pub health_timeout_secs: u64,

    /// Seconds between health-check poll attempts.
    #[arg(long, default_value_t = 2, env = "SWITCHBOARD_HEALTH_INTERVAL_SECS")]
    pub health_interval_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three flags with no default and no `Option`.
    const REQUIRED: &[&str] = &[
        "switchboard",
        "--queue-dir",
        "/var/www/sites/switchboard/.switchboard/queue",
        "--app-key",
        "/etc/switchboard/app.pem",
        "--app-id",
        "12345",
    ];

    fn parse(extra: &[&str]) -> Config {
        let args = REQUIRED.iter().chain(extra.iter());
        Config::try_parse_from(args).expect("expected a valid config parse")
    }

    #[test]
    fn defaults_applied_when_only_required_given() {
        let c = parse(&[]);
        assert_eq!(c.poll_interval_secs, 2);
        assert_eq!(c.sites_dir, PathBuf::from("/var/www/sites"));
        assert_eq!(c.preview_domain, "preview.ephpm.dev");
        assert_eq!(c.github_host, "github.com");
        assert_eq!(c.composer, "composer");
        assert_eq!(c.health_timeout_secs, 60);
        assert!(c.secrets_file.is_none());
        assert!(c.sites_domain_suffix.is_none());
        assert!(c.site_overrides_dir.is_none());
        assert!(c.sqlite_dir.is_none());
        // Fork gates are OFF by default — the security-relevant defaults.
        assert!(!c.allow_fork_deploy);
        assert!(!c.fork_secrets);
        assert_eq!(c.app_key, PathBuf::from("/etc/switchboard/app.pem"));
        assert_eq!(c.app_id, 12345);
    }

    #[test]
    fn explicit_flags_override_defaults() {
        let c = parse(&[
            "--sites-dir",
            "/srv/previews",
            "--preview-domain",
            "pr.example.com",
            "--sites-domain-suffix",
            ".pr.example.com",
            "--site-overrides-dir",
            "/var/lib/ephpm/overrides",
            "--sqlite-dir",
            "/var/lib/ephpm/dbs",
            "--allow-fork-deploy",
            "--fork-secrets",
        ]);
        assert_eq!(c.sites_dir, PathBuf::from("/srv/previews"));
        assert_eq!(c.preview_domain, "pr.example.com");
        assert_eq!(c.sites_domain_suffix.as_deref(), Some(".pr.example.com"));
        assert_eq!(
            c.site_overrides_dir,
            Some(PathBuf::from("/var/lib/ephpm/overrides"))
        );
        assert_eq!(c.sqlite_dir, Some(PathBuf::from("/var/lib/ephpm/dbs")));
        assert!(c.allow_fork_deploy);
        assert!(c.fork_secrets);
    }

    #[test]
    fn missing_required_flag_is_an_error() {
        let args = ["switchboard", "--app-key", "/k", "--app-id", "1"];
        assert!(Config::try_parse_from(args).is_err());
    }

    #[test]
    fn non_numeric_app_id_is_rejected() {
        let args = [
            "switchboard",
            "--queue-dir",
            "/q",
            "--app-key",
            "/k",
            "--app-id",
            "not-a-number",
        ];
        assert!(Config::try_parse_from(args).is_err());
    }
}
