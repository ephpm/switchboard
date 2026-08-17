//! Switchboard configuration.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "switchboard",
    version,
    about = "GitHub webhook handler for ePHPm preview deployments"
)]
pub struct Config {
    /// HTTP listen address for receiving webhooks.
    #[arg(long, default_value = "0.0.0.0:9090", env = "SWITCHBOARD_LISTEN")]
    pub listen: String,

    /// GitHub App webhook secret for signature verification.
    #[arg(long, env = "SWITCHBOARD_WEBHOOK_SECRET")]
    pub webhook_secret: String,

    /// GitHub App private key path (PEM file).
    #[arg(long, env = "SWITCHBOARD_APP_KEY")]
    pub app_key: PathBuf,

    /// GitHub App ID.
    #[arg(long, env = "SWITCHBOARD_APP_ID")]
    pub app_id: u64,

    /// ePHPm sites directory where previews are deployed.
    #[arg(long, default_value = "/var/www/sites", env = "SWITCHBOARD_SITES_DIR")]
    pub sites_dir: PathBuf,

    /// Preview domain suffix (e.g., "preview.ephpm.dev").
    /// PR previews get: `pr-{number}.{repo}.{suffix}`
    #[arg(
        long,
        default_value = "preview.ephpm.dev",
        env = "SWITCHBOARD_PREVIEW_DOMAIN"
    )]
    pub preview_domain: String,

    /// Composer command (or path to binary).
    #[arg(long, default_value = "composer", env = "SWITCHBOARD_COMPOSER")]
    pub composer: String,

    /// Path to switchboard's secrets file (YAML) for resolving `${secret.NAME}`
    /// references in an app manifest's `env:` map. Optional — secrets can also
    /// come from `SWITCHBOARD_SECRET_*` environment variables.
    #[arg(long, env = "SWITCHBOARD_SECRETS_FILE")]
    pub secrets_file: Option<PathBuf>,

    /// Seconds to poll a preview's `health:` path for HTTP 200 before reporting
    /// the deploy ready. Zero disables the health gate.
    #[arg(long, default_value_t = 60, env = "SWITCHBOARD_HEALTH_TIMEOUT_SECS")]
    pub health_timeout_secs: u64,

    /// Seconds between health-check poll attempts.
    #[arg(long, default_value_t = 2, env = "SWITCHBOARD_HEALTH_INTERVAL_SECS")]
    pub health_interval_secs: u64,
}
