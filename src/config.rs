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
    #[arg(long, default_value = "preview.ephpm.dev", env = "SWITCHBOARD_PREVIEW_DOMAIN")]
    pub preview_domain: String,

    /// Composer command (or path to binary).
    #[arg(long, default_value = "composer", env = "SWITCHBOARD_COMPOSER")]
    pub composer: String,
}
