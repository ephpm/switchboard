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

#[cfg(test)]
mod tests {
    use super::*;

    /// The three flags with no default and no `Option` — a parse must supply
    /// them or fail. Kept as a helper so each test states only what it varies.
    const REQUIRED: &[&str] = &[
        "switchboard",
        "--webhook-secret",
        "s3cr3t",
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
        assert_eq!(c.listen, "0.0.0.0:9090");
        assert_eq!(c.sites_dir, PathBuf::from("/var/www/sites"));
        assert_eq!(c.preview_domain, "preview.ephpm.dev");
        assert_eq!(c.composer, "composer");
        assert_eq!(c.health_timeout_secs, 60);
        assert_eq!(c.health_interval_secs, 2);
        // Optional-with-no-default stays None.
        assert!(c.secrets_file.is_none());
        // Required values round-trip.
        assert_eq!(c.webhook_secret, "s3cr3t");
        assert_eq!(c.app_key, PathBuf::from("/etc/switchboard/app.pem"));
        assert_eq!(c.app_id, 12345);
    }

    #[test]
    fn explicit_flags_override_defaults() {
        let c = parse(&[
            "--listen",
            "127.0.0.1:1234",
            "--sites-dir",
            "/srv/previews",
            "--preview-domain",
            "pr.example.com",
            "--composer",
            "/usr/local/bin/composer",
            "--secrets-file",
            "/etc/switchboard/secrets.yaml",
            "--health-timeout-secs",
            "5",
            "--health-interval-secs",
            "1",
        ]);
        assert_eq!(c.listen, "127.0.0.1:1234");
        assert_eq!(c.sites_dir, PathBuf::from("/srv/previews"));
        assert_eq!(c.preview_domain, "pr.example.com");
        assert_eq!(c.composer, "/usr/local/bin/composer");
        assert_eq!(
            c.secrets_file,
            Some(PathBuf::from("/etc/switchboard/secrets.yaml"))
        );
        assert_eq!(c.health_timeout_secs, 5);
        assert_eq!(c.health_interval_secs, 1);
    }

    #[test]
    fn missing_required_flag_is_an_error() {
        // Drop --app-id (and its value) — parsing must fail rather than
        // silently defaulting a security-relevant field.
        let args = ["switchboard", "--webhook-secret", "x", "--app-key", "/k"];
        assert!(Config::try_parse_from(args).is_err());
    }

    #[test]
    fn non_numeric_app_id_is_rejected() {
        // app_id is a u64; a non-numeric value must fail parsing, not truncate.
        let args = [
            "switchboard",
            "--webhook-secret",
            "x",
            "--app-key",
            "/k",
            "--app-id",
            "not-a-number",
        ];
        assert!(Config::try_parse_from(args).is_err());
    }
}
