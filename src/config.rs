//! Switchboard configuration.
//!
//! Every knob is a CLI flag with an `SWITCHBOARD_*` environment fallback, which
//! is what a systemd unit wants: `EnvironmentFile=` for the deployment-specific
//! values and no config file to keep in sync.

use std::path::PathBuf;
use std::time::Duration;

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

    /// Discard a **deploy** job that has waited longer than this in the queue
    /// instead of applying it. Zero disables the bound.
    ///
    /// A job file states what was true when it was written; a queue can hold
    /// that statement indefinitely, and a restart drains it as if it were
    /// current. That is switchboard#18: a `pull_request/opened` job two days
    /// old was applied on restart and provisioned a preview for a pull request
    /// that had already merged.
    ///
    /// The default is an hour — far beyond any plausible backlog for a daemon
    /// that scans every couple of seconds, and short enough that a queue
    /// drained after real downtime does not replay yesterday's intentions. The
    /// cost of the bound is a deploy that never happens if a node is down
    /// longer than it, recovered by the next push or an operator re-drain; the
    /// cost of not having it is a preview for a merged PR. Teardown jobs are
    /// never discarded by age — an old teardown is still correct.
    #[arg(long, default_value_t = 3600, env = "SWITCHBOARD_MAX_JOB_AGE_SECS")]
    pub max_job_age_secs: u64,

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
    /// `<sites_dir>/<site-key>/`, where the site key is derived from the preview
    /// host exactly as ePHPm derives it — see [`crate::site_key`].
    #[arg(long, default_value = "/var/www/sites", env = "SWITCHBOARD_SITES_DIR")]
    pub sites_dir: PathBuf,

    /// Preview domain suffix. The preview host is `<preview.label>.<suffix>`.
    #[arg(
        long,
        default_value = "preview.ephpm.dev",
        env = "SWITCHBOARD_PREVIEW_DOMAIN"
    )]
    pub preview_domain: String,

    /// ePHPm's `[server] sites_domain_suffix` **as configured on the node this
    /// daemon provisions**.
    ///
    /// This is not a preference — it decides the name of every per-site artifact
    /// (see [`crate::site_key`]), and getting it wrong provisions a preview into
    /// a directory ePHPm never resolves. Defaults to `.<preview-domain>`, which
    /// is the configuration the preview cluster runs and the one that yields the
    /// short `<label>/` directory names. Pass an **empty string** for a node
    /// whose `ephpm.toml` sets no suffix; the site key is then the full preview
    /// FQDN and directories are named accordingly.
    #[arg(long, env = "SWITCHBOARD_SITES_DOMAIN_SUFFIX")]
    pub sites_domain_suffix: Option<String>,

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

    // ── teardown (per-site artifacts outside sites_dir) ────────────────
    /// ePHPm's `[db.sqlite].dir`, where each preview's `<label>.db` (and its
    /// `-wal`/`-shm`/`-journal` companions) lives. Teardown removes them.
    ///
    /// **Required** unless `--allow-incomplete-teardown` is set: a daemon that
    /// does not know this path cannot remove a tenant's database when its PR
    /// closes, and used to report the teardown as a success anyway
    /// (switchboard#17).
    #[arg(long, env = "SWITCHBOARD_SQLITE_DIR")]
    pub sqlite_dir: Option<PathBuf>,

    /// ePHPm's `site_overrides_dir`, where each preview's `<label>.toml`
    /// docroot override lives. Teardown removes it.
    ///
    /// **Required** unless `--allow-incomplete-teardown` is set — and unset it
    /// also means a manifest's `docroot:` cannot be honoured on the deploy
    /// side, so it is the same "this node is not fully wired to ePHPm" fact
    /// twice.
    #[arg(long, env = "SWITCHBOARD_SITE_OVERRIDES_DIR")]
    pub site_overrides_dir: Option<PathBuf>,

    /// Run with an incomplete teardown: start even though `--sqlite-dir` or
    /// `--site-overrides-dir` is unset, and let teardown report success while
    /// leaving those artifacts on disk.
    ///
    /// This is an acknowledgement, not a feature. The paths are ePHPm's
    /// configuration and the daemon cannot derive them, so the only way to make
    /// "teardown left a tenant database behind" impossible to reach by accident
    /// is to refuse to start without them. An operator whose nodes genuinely
    /// have no per-site databases (or no override directory) says so here, once,
    /// and gets a `WARN` per teardown naming what was not removed.
    #[arg(
        long,
        default_value_t = false,
        env = "SWITCHBOARD_ALLOW_INCOMPLETE_TEARDOWN"
    )]
    pub allow_incomplete_teardown: bool,

    /// The directory ePHPm keeps per-vhost temp/session state roots in.
    /// Defaults to this process's `<system temp>/ephpm-vhosts`, which matches
    /// ePHPm's own default when both processes see the same `TMPDIR` — set it
    /// explicitly when they don't (e.g. systemd `PrivateTmp`, or ePHPm running
    /// with a different `TMPDIR`).
    #[arg(long, env = "SWITCHBOARD_VHOST_TEMP_BASE")]
    pub vhost_temp_base: Option<PathBuf>,

    // ── fork policy ────────────────────────────────────────────────────
    /// Deploy pull requests from forks. Off by default: a fork PR is untrusted
    /// code, and this daemon is the process that actually builds it. This is a
    /// second gate under switchboard-api's `SWITCHBOARD_ALLOW_FORKS` — the API
    /// refusing to *queue* fork deploys does not substitute for the daemon
    /// refusing to *run* them. Fork teardowns are always processed.
    #[arg(long, default_value_t = false, env = "SWITCHBOARD_ALLOW_FORK_DEPLOY")]
    pub allow_fork_deploy: bool,

    /// Resolve `${secret.NAME}` operator secrets into fork deploys. Off by
    /// default even when `--allow-fork-deploy` is set: building untrusted code
    /// and handing it the operator's secret store are two separate decisions.
    /// Without this flag a fork deploy proceeds with every secret reference
    /// expanding to the empty string.
    #[arg(long, default_value_t = false, env = "SWITCHBOARD_FORK_SECRETS")]
    pub fork_secrets: bool,

    // ── GitHub reporting (optional) ────────────────────────────────────
    /// GitHub App private key path (PEM file). Omit to run without GitHub
    /// reporting — deploys still happen, they are just not reported on the PR.
    #[arg(long, env = "SWITCHBOARD_APP_KEY")]
    pub app_key: Option<PathBuf>,

    /// GitHub App ID. Omit together with `--app-key` to disable reporting.
    #[arg(long, env = "SWITCHBOARD_APP_ID")]
    pub app_id: Option<u64>,

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

    /// How long a deploy job may wait in the queue before it is discarded
    /// rather than applied, or `None` when the bound is disabled.
    #[must_use]
    pub fn max_job_age(&self) -> Option<Duration> {
        (self.max_job_age_secs > 0).then(|| Duration::from_secs(self.max_job_age_secs))
    }

    /// Whether GitHub reporting is possible. Both halves of the App credential
    /// are needed; neither alone is useful.
    #[must_use]
    pub fn github_reporting_enabled(&self) -> bool {
        self.app_id.is_some() && self.app_key.is_some()
    }

    /// ePHPm's `sites_domain_suffix` for this node, resolved.
    ///
    /// Unset means "the node's suffix matches our preview domain", the
    /// configuration the preview cluster runs — so the default is
    /// `.<preview-domain>` rather than `None`. An explicitly empty value means
    /// the node genuinely has no suffix, in which case the site key is the full
    /// preview FQDN. See [`crate::site_key`].
    #[must_use]
    pub fn effective_sites_domain_suffix(&self) -> Option<String> {
        match self.sites_domain_suffix.as_deref() {
            None => Some(format!(".{}", self.preview_domain.trim_matches('.'))),
            Some(explicit) if explicit.trim().is_empty() => None,
            Some(explicit) => Some(explicit.trim().to_ascii_lowercase()),
        }
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
        // --fork-secrets only means something for a deploy that is allowed to
        // run; on its own it is dead configuration that *reads* like a policy.
        anyhow::ensure!(
            !self.fork_secrets || self.allow_fork_deploy,
            "--fork-secrets has no effect without --allow-fork-deploy — set \
             both to build forks with operator secrets, or neither"
        );
        // A daemon that cannot remove a tenant's database when its PR closes is
        // a data-retention problem, and the live preview cluster hit it exactly
        // this way: a hand-provisioned systemd unit passed neither path, so
        // every webhook teardown left `<key>.db` + `-wal` on disk and reported
        // success (switchboard#17). The unit is not in this repo, so a
        // config-only fix is undiscoverable — refuse to start instead, and make
        // the operator's "yes, I know" an explicit flag.
        if !self.allow_incomplete_teardown {
            let mut missing: Vec<&str> = Vec::new();
            if self.sqlite_dir.is_none() {
                missing.push("--sqlite-dir (SWITCHBOARD_SQLITE_DIR, ePHPm's [db.sqlite].dir)");
            }
            if self.site_overrides_dir.is_none() {
                missing.push(
                    "--site-overrides-dir (SWITCHBOARD_SITE_OVERRIDES_DIR, ePHPm's \
                     [server] site_overrides_dir)",
                );
            }
            anyhow::ensure!(
                missing.is_empty(),
                "teardown would be incomplete: {} not configured. Teardown removes \
                 each preview's per-site database and docroot override from these \
                 directories; without them a closed PR leaves its tenant database \
                 on disk. Set them, or pass --allow-incomplete-teardown \
                 (SWITCHBOARD_ALLOW_INCOMPLETE_TEARDOWN=true) to accept that.",
                missing.join(" and ")
            );
        }
        // ePHPm rejects a `sites_domain_suffix` without a leading dot at config
        // load (#397: `Host: <suffix>` otherwise strips to the empty string and
        // `sites_dir.join("")` is the whole fleet). A daemon configured with a
        // suffix ePHPm would refuse is a daemon deriving keys no server will
        // ever agree with, so refuse it here too rather than provisioning into
        // directories nobody serves.
        if let Some(suffix) = self.effective_sites_domain_suffix() {
            anyhow::ensure!(
                suffix.starts_with('.'),
                "--sites-domain-suffix {suffix:?} must begin with a dot — ePHPm \
                 refuses a dotless suffix at config load (ephpm#397), so a key \
                 derived from one would never match a served vhost"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one flag with no default and no `Option`: a parse must supply it.
    const REQUIRED: &[&str] = &["switchboard", "--state-dir", "/srv/api/.switchboard"];

    /// The two teardown roots [`Config::validate`] now insists on (#17). Not
    /// needed to *parse* — only to pass validation without acknowledging an
    /// incomplete teardown.
    const TEARDOWN_ROOTS: &[&str] = &[
        "--sqlite-dir",
        "/var/lib/ephpm-web/db",
        "--site-overrides-dir",
        "/etc/ephpm/sites",
    ];

    fn parse(extra: &[&str]) -> Config {
        let args = REQUIRED.iter().chain(extra.iter());
        Config::try_parse_from(args).expect("expected a valid config parse")
    }

    /// A parse whose teardown is complete. Used by every test that calls
    /// `validate()` about something other than the teardown gate itself.
    fn parse_complete(extra: &[&str]) -> Config {
        let mut args = TEARDOWN_ROOTS.to_vec();
        args.extend_from_slice(extra);
        parse(&args)
    }

    /// A complete parse with the drain kick switched off — the smallest config
    /// that validates. Used by tests that are about something other than
    /// draining.
    fn parse_single_node(extra: &[&str]) -> Config {
        let mut args = vec!["--drain-interval-secs", "0"];
        args.extend_from_slice(extra);
        parse_complete(&args)
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
        // The teardown roots have no defaults — their locations are ePHPm's
        // configuration and cannot be derived. They *parse* as absent and are
        // then refused by validate() unless the operator acknowledges an
        // incomplete teardown (#17). The vhost temp base is different: its
        // default is real, and applied at use time.
        assert!(c.sqlite_dir.is_none());
        assert!(c.site_overrides_dir.is_none());
        assert!(c.vhost_temp_base.is_none());
        assert!(!c.allow_incomplete_teardown, "incompleteness is opt-in");
    }

    // ── teardown completeness (#17) ─────────────────────────────────────

    /// The live cluster's configuration: a unit passing neither teardown root.
    /// It used to start happily and abandon a tenant database on every closed
    /// PR; now it does not start at all.
    #[test]
    fn missing_teardown_roots_refuse_to_start() {
        let c = parse(&["--drain-interval-secs", "0"]);
        let err = c
            .validate()
            .expect_err("a daemon that cannot reap tenant databases must not start");
        let msg = err.to_string();
        assert!(msg.contains("--sqlite-dir"), "{msg}");
        assert!(msg.contains("--site-overrides-dir"), "{msg}");
        // The message has to carry the way out, or the operator's only option
        // is to guess.
        assert!(msg.contains("--allow-incomplete-teardown"), "{msg}");
    }

    #[test]
    fn one_missing_teardown_root_is_still_refused_and_named_alone() {
        let c = parse(&[
            "--drain-interval-secs",
            "0",
            "--site-overrides-dir",
            "/etc/ephpm/sites",
        ]);
        let msg = c.validate().unwrap_err().to_string();
        assert!(msg.contains("--sqlite-dir"), "{msg}");
        assert!(
            !msg.contains("--site-overrides-dir ("),
            "a configured root must not be listed as missing: {msg}"
        );
    }

    /// Both roots set is the shape the preview cluster's unit must move to.
    #[test]
    fn both_teardown_roots_validate() {
        parse_single_node(&[]).validate().unwrap();
    }

    /// The acknowledged escape hatch, for a deployment with no per-site
    /// databases at all.
    #[test]
    fn acknowledged_incomplete_teardown_starts() {
        let c = parse(&["--drain-interval-secs", "0", "--allow-incomplete-teardown"]);
        assert!(c.allow_incomplete_teardown);
        c.validate()
            .expect("an explicit acknowledgement is a valid deployment");
    }

    // ── the site-key derivation's one input (#13) ───────────────────────

    /// Unset means "the node's suffix is our preview domain" — the shape the
    /// preview cluster actually runs, and the one that keeps vhost directories
    /// named by the short label.
    #[test]
    fn sites_domain_suffix_defaults_to_the_preview_domain() {
        let c = parse_single_node(&[]);
        assert_eq!(
            c.effective_sites_domain_suffix().as_deref(),
            Some(".preview.ephpm.dev")
        );
        let c = parse_single_node(&["--preview-domain", "pr.example.com"]);
        assert_eq!(
            c.effective_sites_domain_suffix().as_deref(),
            Some(".pr.example.com")
        );
    }

    /// An explicitly empty value is how an operator says "this node's
    /// ephpm.toml sets no suffix" — the switchboard#13 configuration. The site
    /// key is then the full preview FQDN.
    #[test]
    fn empty_sites_domain_suffix_means_the_node_has_none() {
        let c = parse_single_node(&["--sites-domain-suffix", ""]);
        assert_eq!(c.effective_sites_domain_suffix(), None);
        c.validate()
            .expect("an absent suffix is a valid deployment");
    }

    #[test]
    fn explicit_sites_domain_suffix_overrides_the_preview_domain() {
        let c = parse_single_node(&["--sites-domain-suffix", ".Internal.Example"]);
        assert_eq!(
            c.effective_sites_domain_suffix().as_deref(),
            Some(".internal.example"),
            "the suffix is compared against a lowercased host, so it is lowercased too"
        );
    }

    /// ePHPm refuses a dotless suffix at config load (#397 — `Host: <suffix>`
    /// strips to the empty string and `sites_dir.join("")` is the whole fleet).
    /// A daemon configured with one would derive keys no server agrees with.
    #[test]
    fn dotless_sites_domain_suffix_is_refused() {
        let c = parse_single_node(&["--sites-domain-suffix", "preview.ephpm.dev"]);
        let err = c
            .validate()
            .expect_err("a dotless suffix must not be accepted");
        assert!(err.to_string().contains("must begin with a dot"), "{err}");
    }

    #[test]
    fn teardown_knobs_parse() {
        let c = parse(&[
            "--drain-interval-secs",
            "0",
            "--sqlite-dir",
            "/var/lib/ephpm/sqlite",
            "--site-overrides-dir",
            "/etc/ephpm/sites",
            "--vhost-temp-base",
            "/tmp/ephpm-vhosts",
        ]);
        assert_eq!(c.sqlite_dir, Some(PathBuf::from("/var/lib/ephpm/sqlite")));
        assert_eq!(
            c.site_overrides_dir,
            Some(PathBuf::from("/etc/ephpm/sites"))
        );
        assert_eq!(c.vhost_temp_base, Some(PathBuf::from("/tmp/ephpm-vhosts")));
        c.validate().unwrap();
    }

    // ── claim-time job validation (#18) ─────────────────────────────────

    #[test]
    fn stale_deploy_jobs_are_bounded_by_default() {
        let c = parse(&[]);
        assert_eq!(
            c.max_job_age_secs, 3600,
            "the documented default is an hour"
        );
        assert_eq!(c.max_job_age(), Some(std::time::Duration::from_secs(3600)));
    }

    #[test]
    fn a_zero_max_job_age_disables_the_bound() {
        let c = parse(&["--max-job-age-secs", "0"]);
        assert_eq!(
            c.max_job_age(),
            None,
            "0 must disable the bound, not discard everything"
        );
    }

    #[test]
    fn max_job_age_is_configurable() {
        let c = parse(&["--max-job-age-secs", "300"]);
        assert_eq!(c.max_job_age(), Some(std::time::Duration::from_secs(300)));
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
        let c = parse_complete(&["--drain-interval-secs", "0"]);
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
        let missing_both = parse_complete(&[]);
        assert!(
            missing_both.validate().is_err(),
            "an enabled kick with no vhost must not start"
        );

        let missing_token = parse_complete(&["--drain-host", "switchboard.example"]);
        assert!(missing_token.validate().is_err());

        let complete = parse_complete(&[
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
    fn fork_policy_defaults_to_deny_everything() {
        let c = parse_single_node(&[]);
        assert!(!c.allow_fork_deploy, "fork deploys must be opt-in");
        assert!(!c.fork_secrets, "fork secrets must be opt-in");
        c.validate().unwrap();
    }

    #[test]
    fn fork_secrets_without_allow_fork_deploy_is_rejected() {
        let c = parse_single_node(&["--fork-secrets"]);
        assert!(
            c.validate().is_err(),
            "--fork-secrets alone is dead configuration that reads like policy"
        );
    }

    #[test]
    fn fork_flags_parse_together() {
        let c = parse_single_node(&["--allow-fork-deploy", "--fork-secrets"]);
        assert!(c.allow_fork_deploy);
        assert!(c.fork_secrets);
        c.validate().unwrap();

        // Allowing the deploy without the secrets is the expected middle
        // setting and must validate.
        let c = parse_single_node(&["--allow-fork-deploy"]);
        assert!(c.allow_fork_deploy);
        assert!(!c.fork_secrets);
        c.validate().unwrap();
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
        let c = parse_complete(&[
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
