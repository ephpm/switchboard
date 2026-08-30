//! Switchboard configuration.
//!
//! Every knob is a CLI flag with an `SWITCHBOARD_*` environment fallback, which
//! is what a systemd unit wants: `EnvironmentFile=` for the deployment-specific
//! values and no config file to keep in sync.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "switchboard",
    version,
    about = "Preview-deployment daemon for ePHPm — consumes job files, kicks drain, provisions previews"
)]
pub struct Config {
    // ── queue ──────────────────────────────────────────────────────────
    /// switchboard-api's state directory — the `.switchboard/` directory inside
    /// the API vhost. Jobs are consumed from `<state_dir>/queue/`.
    #[arg(long, env = "SWITCHBOARD_STATE_DIR")]
    pub state_dir: PathBuf,

    /// Seconds between queue scans.
    #[arg(long, default_value_t = 2, env = "SWITCHBOARD_QUEUE_INTERVAL_SECS")]
    pub queue_interval_secs: u64,

    // ── drain kick ─────────────────────────────────────────────────────
    /// Seconds between drain kicks. **Zero disables the kick entirely**, which
    /// is the correct setting for a single-node deployment with nothing to fan
    /// out to.
    #[arg(long, default_value_t = 2, env = "SWITCHBOARD_DRAIN_INTERVAL_SECS")]
    pub drain_interval_secs: u64,

    /// `host:port` of the local ePHPm instance serving switchboard-api.
    #[arg(long, default_value = "127.0.0.1:8080", env = "SWITCHBOARD_DRAIN_ADDR")]
    pub drain_addr: String,

    /// The switchboard-api vhost, sent as the `Host` header of the kick. There
    /// is no sensible default — required whenever the kick is enabled.
    #[arg(long, env = "SWITCHBOARD_DRAIN_HOST")]
    pub drain_host: Option<String>,

    /// File holding the shared drain secret (the API's
    /// `.switchboard/drain_secret`), sent as `X-Drain-Token`. Required whenever
    /// the kick is enabled.
    #[arg(long, env = "SWITCHBOARD_DRAIN_TOKEN_FILE")]
    pub drain_token_file: Option<PathBuf>,

    // ── provisioning ───────────────────────────────────────────────────
    /// ePHPm sites directory where previews are deployed. Each preview lands at
    /// `<sites_dir>/<preview.label>/`.
    #[arg(long, default_value = "/var/www/sites", env = "SWITCHBOARD_SITES_DIR")]
    pub sites_dir: PathBuf,

    /// Preview domain suffix. The preview host is `<preview.label>.<suffix>`.
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

    // ── GitHub reporting (optional) ────────────────────────────────────
    /// GitHub App private key path (PEM file). Omit to run without GitHub
    /// reporting — deploys still happen, they are just not reported on the PR.
    #[arg(long, env = "SWITCHBOARD_APP_KEY")]
    pub app_key: Option<PathBuf>,

    /// GitHub App ID. Omit together with `--app-key` to disable reporting.
    #[arg(long, env = "SWITCHBOARD_APP_ID")]
    pub app_id: Option<u64>,

    // ── cluster coordination (KV) ──────────────────────────────────────
    /// `host:port` of ePHPm's RESP listener (`[kv.redis_compat] listen`).
    ///
    /// Setting this **enables exactly-once coordination**: every node in the
    /// cluster deploys the same preview, but only the one that wins an atomic
    /// `SET … NX` claim in the replicated KV posts the PR comment and creates
    /// the deployment status. Omit it for a single-node deployment, where the
    /// daemon reports directly (there is no one to race).
    #[arg(long, env = "SWITCHBOARD_KV_ADDR")]
    pub kv_addr: Option<String>,

    /// RESP AUTH username — ePHPm's per-site scoping uses the vhost host here,
    /// which for switchboard is the `switchboard-api` host (the same value as
    /// `--drain-host`). With it, the daemon's claim keys land in exactly the
    /// gossip-replicated keyspace `switchboard-api` already writes to. Omit to
    /// use the one-argument `AUTH <password>` (`requirepass`) form.
    #[arg(long, env = "SWITCHBOARD_KV_AUTH_USER")]
    pub kv_auth_user: Option<String>,

    /// File holding ePHPm's `[kv] secret`. The daemon derives the per-site RESP
    /// password as `HMAC-SHA256(secret, --kv-auth-user)` — the same derivation
    /// ePHPm uses — so the operator never has to precompute it. Requires
    /// `--kv-auth-user`. Mutually exclusive with `--kv-password-file`.
    #[arg(long, env = "SWITCHBOARD_KV_SECRET_FILE")]
    pub kv_secret_file: Option<PathBuf>,

    /// File holding a literal RESP password — either a `requirepass` value or an
    /// already-derived per-site password. Mutually exclusive with
    /// `--kv-secret-file`.
    #[arg(long, env = "SWITCHBOARD_KV_PASSWORD_FILE")]
    pub kv_password_file: Option<PathBuf>,

    /// TTL (seconds) stamped on each exactly-once claim key. Bounds key
    /// accumulation in the KV and lets a claim left by a crashed node be re-won
    /// later. The default is generous — a claim only needs to outlive the
    /// slowest node's deploy of one generation.
    #[arg(long, default_value_t = 21_600, env = "SWITCHBOARD_KV_CLAIM_TTL_SECS")]
    pub kv_claim_ttl_secs: u64,

    // ── legacy webhook receiver (off by default) ───────────────────────
    /// Run the legacy in-process webhook receiver.
    ///
    /// Receiving webhooks moved to `ephpm/switchboard-api`, which runs as a
    /// vhost inside ePHPm; the daemon's input is the job queue. The old
    /// receiver is kept compiled but **off** so a deployment that has not
    /// migrated yet can turn it back on with one flag.
    #[arg(
        long,
        default_value_t = false,
        env = "SWITCHBOARD_WEBHOOK_SERVER_ENABLED"
    )]
    pub webhook_server_enabled: bool,

    /// HTTP listen address for the legacy webhook receiver.
    #[arg(long, default_value = "0.0.0.0:9090", env = "SWITCHBOARD_LISTEN")]
    pub listen: String,

    /// GitHub App webhook secret for signature verification. Required when
    /// `--webhook-server-enabled` is set.
    #[arg(long, env = "SWITCHBOARD_WEBHOOK_SECRET")]
    pub webhook_secret: Option<String>,
}

impl Config {
    /// Whether the periodic drain kick is enabled. A zero interval means
    /// "single node, nothing to fan out to".
    #[must_use]
    pub fn drain_enabled(&self) -> bool {
        self.drain_interval_secs > 0
    }

    /// Whether GitHub reporting is possible. Both halves of the App credential
    /// are needed; neither alone is useful.
    #[must_use]
    pub fn github_reporting_enabled(&self) -> bool {
        self.app_id.is_some() && self.app_key.is_some()
    }

    /// Whether cluster-wide exactly-once coordination is enabled. Keyed on the
    /// KV address alone: with it, a claim gates every report; without it, the
    /// daemon reports directly (single-node, nothing to race).
    #[must_use]
    pub fn coordination_enabled(&self) -> bool {
        self.kv_addr.is_some()
    }

    /// Check the combinations clap cannot express.
    ///
    /// # Errors
    ///
    /// Returns an error when the drain kick is enabled without a vhost or token
    /// file, or the legacy webhook receiver is enabled without a secret.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.drain_enabled() {
            anyhow::ensure!(
                self.drain_host.is_some(),
                "--drain-host is required when --drain-interval-secs is non-zero \
                 (set it to 0 to disable the drain kick)"
            );
            anyhow::ensure!(
                self.drain_token_file.is_some(),
                "--drain-token-file is required when --drain-interval-secs is non-zero \
                 (set it to 0 to disable the drain kick)"
            );
        }
        if self.webhook_server_enabled {
            anyhow::ensure!(
                self.webhook_secret.is_some(),
                "--webhook-secret is required when --webhook-server-enabled is set"
            );
        }
        // A half-configured App is a silent no-op waiting to happen; say so.
        anyhow::ensure!(
            self.app_id.is_some() == self.app_key.is_some(),
            "--app-id and --app-key must be given together (or both omitted to \
             run without GitHub reporting)"
        );
        // KV coordination: the two password sources are mutually exclusive, an
        // auth credential is meaningless without an address to send it to, and
        // the secret-file derivation needs a username to derive against.
        anyhow::ensure!(
            !(self.kv_secret_file.is_some() && self.kv_password_file.is_some()),
            "--kv-secret-file and --kv-password-file are mutually exclusive"
        );
        if self.kv_addr.is_none() {
            anyhow::ensure!(
                self.kv_auth_user.is_none()
                    && self.kv_secret_file.is_none()
                    && self.kv_password_file.is_none(),
                "--kv-auth-user / --kv-secret-file / --kv-password-file need \
                 --kv-addr (the RESP listener to authenticate to)"
            );
        }
        anyhow::ensure!(
            self.kv_secret_file.is_none() || self.kv_auth_user.is_some(),
            "--kv-secret-file needs --kv-auth-user to derive the per-site password"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one flag with no default and no `Option`: a parse must supply it.
    const REQUIRED: &[&str] = &["switchboard", "--state-dir", "/srv/api/.switchboard"];

    fn parse(extra: &[&str]) -> Config {
        let args = REQUIRED.iter().chain(extra.iter());
        Config::try_parse_from(args).expect("expected a valid config parse")
    }

    /// A parse with the drain kick switched off — the smallest config that
    /// validates. Used by tests that are about something other than draining.
    fn parse_single_node(extra: &[&str]) -> Config {
        let mut args = vec!["--drain-interval-secs", "0"];
        args.extend_from_slice(extra);
        parse(&args)
    }

    #[test]
    fn defaults_applied_when_only_required_given() {
        let c = parse(&[]);
        assert_eq!(c.state_dir, PathBuf::from("/srv/api/.switchboard"));
        assert_eq!(c.queue_interval_secs, 2);
        assert_eq!(c.sites_dir, PathBuf::from("/var/www/sites"));
        assert_eq!(c.preview_domain, "preview.ephpm.dev");
        assert_eq!(c.composer, "composer");
        assert_eq!(c.health_timeout_secs, 60);
        assert_eq!(c.health_interval_secs, 2);
        assert!(c.secrets_file.is_none());
    }

    #[test]
    fn drain_defaults_to_two_seconds_on_loopback() {
        let c = parse(&[]);
        assert_eq!(c.drain_interval_secs, 2, "the documented default is 2s");
        assert_eq!(c.drain_addr, "127.0.0.1:8080");
        assert!(c.drain_enabled());
        // No default host or token file — they are deployment-specific.
        assert!(c.drain_host.is_none());
        assert!(c.drain_token_file.is_none());
    }

    #[test]
    fn zero_drain_interval_disables_the_kick() {
        let c = parse(&["--drain-interval-secs", "0"]);
        assert!(
            !c.drain_enabled(),
            "0 must disable the kick outright (single-node mode)"
        );
        // ...and with the kick off, host/token are not required.
        c.validate()
            .expect("single-node config must validate without drain settings");
    }

    #[test]
    fn drain_enabled_requires_host_and_token_file() {
        let missing_both = parse(&[]);
        assert!(
            missing_both.validate().is_err(),
            "an enabled kick with no vhost must not start"
        );

        let missing_token = parse(&["--drain-host", "switchboard.example"]);
        assert!(missing_token.validate().is_err());

        let complete = parse(&[
            "--drain-host",
            "switchboard.example",
            "--drain-token-file",
            "/srv/api/.switchboard/drain_secret",
        ]);
        complete
            .validate()
            .expect("a complete config must validate");
        assert_eq!(complete.drain_host.as_deref(), Some("switchboard.example"));
        assert_eq!(
            complete.drain_token_file,
            Some(PathBuf::from("/srv/api/.switchboard/drain_secret"))
        );
    }

    #[test]
    fn webhook_server_is_off_by_default() {
        let c = parse_single_node(&[]);
        assert!(
            !c.webhook_server_enabled,
            "receiving webhooks belongs to switchboard-api now"
        );
        // With the server off, no webhook secret is needed.
        c.validate().unwrap();
    }

    #[test]
    fn enabling_the_webhook_server_requires_a_secret() {
        let c = parse_single_node(&["--webhook-server-enabled"]);
        assert!(c.webhook_server_enabled);
        assert!(
            c.validate().is_err(),
            "an unauthenticated webhook endpoint must not start"
        );

        let c = parse_single_node(&["--webhook-server-enabled", "--webhook-secret", "s3cr3t"]);
        c.validate().unwrap();
        assert_eq!(c.listen, "0.0.0.0:9090");
    }

    #[test]
    fn github_reporting_is_optional_but_all_or_nothing() {
        let none = parse_single_node(&[]);
        assert!(
            !none.github_reporting_enabled(),
            "no App credentials must degrade, not fail"
        );
        none.validate().unwrap();

        let half = parse_single_node(&["--app-id", "12345"]);
        assert!(
            half.validate().is_err(),
            "a half-configured App would silently never report"
        );

        let full =
            parse_single_node(&["--app-id", "12345", "--app-key", "/etc/switchboard/app.pem"]);
        full.validate().unwrap();
        assert!(full.github_reporting_enabled());
        assert_eq!(full.app_id, Some(12345));
    }

    #[test]
    fn coordination_is_off_without_a_kv_addr() {
        let c = parse_single_node(&[]);
        assert!(
            !c.coordination_enabled(),
            "no --kv-addr must mean single-node direct reporting"
        );
        assert_eq!(c.kv_claim_ttl_secs, 21_600, "the documented default TTL");
        c.validate().unwrap();
    }

    #[test]
    fn kv_addr_enables_coordination() {
        let c = parse_single_node(&["--kv-addr", "127.0.0.1:6379"]);
        assert!(c.coordination_enabled());
        c.validate().unwrap();
    }

    #[test]
    fn kv_auth_without_addr_is_rejected() {
        // An AUTH credential with nowhere to send it is a misconfiguration, not
        // a silent no-op.
        let c = parse_single_node(&["--kv-secret-file", "/etc/ephpm/kv.secret"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn kv_secret_file_requires_auth_user() {
        let c = parse_single_node(&["--kv-addr", "127.0.0.1:6379", "--kv-secret-file", "/s"]);
        let err = c
            .validate()
            .expect_err("secret file with no auth user must fail");
        assert!(err.to_string().contains("--kv-auth-user"), "{err}");

        let ok = parse_single_node(&[
            "--kv-addr",
            "127.0.0.1:6379",
            "--kv-auth-user",
            "switchboard.ephpm.dev",
            "--kv-secret-file",
            "/etc/ephpm/kv.secret",
        ]);
        ok.validate().unwrap();
    }

    #[test]
    fn kv_secret_and_password_files_are_mutually_exclusive() {
        let c = parse_single_node(&[
            "--kv-addr",
            "127.0.0.1:6379",
            "--kv-auth-user",
            "h",
            "--kv-secret-file",
            "/a",
            "--kv-password-file",
            "/b",
        ]);
        assert!(
            c.validate().is_err(),
            "two password sources must not both be set"
        );
    }

    #[test]
    fn missing_state_dir_is_an_error() {
        // The queue is the daemon's only input; there is nothing sensible to
        // default it to.
        assert!(Config::try_parse_from(["switchboard"]).is_err());
    }

    #[test]
    fn non_numeric_app_id_is_rejected() {
        let args = [
            "switchboard",
            "--state-dir",
            "/s",
            "--app-id",
            "not-a-number",
        ];
        assert!(Config::try_parse_from(args).is_err());
    }

    #[test]
    fn explicit_flags_override_defaults() {
        let c = parse(&[
            "--queue-interval-secs",
            "5",
            "--drain-interval-secs",
            "10",
            "--drain-addr",
            "127.0.0.1:9999",
            "--drain-host",
            "sb.example",
            "--drain-token-file",
            "/run/drain",
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
        assert_eq!(c.queue_interval_secs, 5);
        assert_eq!(c.drain_interval_secs, 10);
        assert_eq!(c.drain_addr, "127.0.0.1:9999");
        assert_eq!(c.sites_dir, PathBuf::from("/srv/previews"));
        assert_eq!(c.preview_domain, "pr.example.com");
        assert_eq!(c.composer, "/usr/local/bin/composer");
        assert_eq!(
            c.secrets_file,
            Some(PathBuf::from("/etc/switchboard/secrets.yaml"))
        );
        assert_eq!(c.health_timeout_secs, 5);
        assert_eq!(c.health_interval_secs, 1);
        c.validate().unwrap();
    }
}
