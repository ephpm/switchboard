# switchboard

The preview-deployment daemon for an ePHPm cluster. A small Rust binary that
runs as a systemd unit beside ePHPm on every node, consumes job files from a
local queue, provisions PR previews into `sites_dir`, and reports them on the
pull request.

## What this is (and what it is no longer)

switchboard began as **one** binary that received GitHub webhooks *and*
provisioned previews. It has been split in two:

| Component | Language | Runs as | Responsibility |
|---|---|---|---|
| [`ephpm/switchboard-api`](https://github.com/ephpm/switchboard-api) | PHP | a confined vhost **inside** ePHPm | receive webhooks, verify signatures, write job files |
| **switchboard** (this repo) | Rust | a systemd unit beside ePHPm | consume jobs, check out repos, provision previews, kick drain, report to GitHub |

The split is forced by ePHPm's own isolation model and turns it into a property
worth having. In `sites_dir` mode ePHPm applies `open_basedir` per request, so
the API — the component exposed to the internet, accepting unauthenticated
POSTs — provably cannot reach `sites_dir`, cannot run a deploy, and holds no
credential that can write to a GitHub repository. **The daemon does all of that
and never listens on a public port.**

The old in-process webhook receiver is still compiled in but is **off by
default**; see [`--webhook-server-enabled`](#legacy-webhook-receiver).

## What the daemon does

### 1. Consume the job queue

Jobs are schema-1 JSON documents the API writes to `<state_dir>/queue/`. The
contract — field reference, validation rules, and the consumption protocol — is
owned by switchboard-api's README, sections **"The job file contract"** and
**"How the daemon should consume the queue"**. This daemon implements it:

* **Arrival order is `sort()`.** Filenames are `<13-digit millis>-<16 hex>.json`,
  so a lexicographic sort of `readdir` is chronological.
* **Claim with `link()`, not `rename()`.** `link()` fails with `EEXIST` when
  another worker already claimed the job; `rename()` would overwrite silently
  and both callers would believe they won. The queue entry is unlinked once the
  link succeeds.
* **`schema` must equal 1.** Anything else is rejected rather than guessed at.
* **Act on `intent`** (`deploy` / `teardown`), never on the raw GitHub `action`.
* **Coalescing is the daemon's job.** Rapid pushes produce several jobs for one
  `preview.label`; the newest wins and the rest are discarded.
* **Delete on success, leave on failure.** A failed job stays in
  `queue/claimed/` for inspection rather than being retried forever.

`preview.label` is **authoritative and never recomputed** — with
`--preview-domain` appended it is the preview host ePHPm resolves.

#### A claimed job is re-checked against current state

A job file states what was true when switchboard-api wrote it, and a queue can
hold that statement indefinitely. A `pull_request/opened` job that had sat
unclaimed for two days was applied during a restart and provisioned a preview
for a pull request that had already **merged** — restarts are exactly when this
fires, because a restart drains a backlog of statements about the past.

So a **deploy** job is validated at *claim* time, not trusted from *enqueue*
time. Two checks, deliberately different in kind:

| Check | Cost | Fails |
|---|---|---|
| **Age** — has this job been sitting in the queue longer than `--max-job-age-secs`? | offline arithmetic on the filename's timestamp | closed (discards the job) |
| **PR state** — is the pull request still open, per GitHub *now*? | one API call, needs the App credentials | **open** (applies the job) |

The age bound runs on every node, including one with no GitHub App configured
(the e2e cluster). The state check is authoritative but best-effort: a GitHub
outage, a rate limit, or a `state` value this daemon does not recognise applies
the job with a `WARN` rather than dropping it, because refusing to deploy
because a third party is unreachable is its own kind of drift.

A discarded job is **resolved, not failed**: it is cleared from `claimed/` like
a successful one, with the reason logged at `WARN`.

**Teardown jobs are never validated.** A teardown is idempotent, removes drift
rather than creating it, and is never wrong to apply late — the preview it names
should not exist either way. Refusing a stale one would strand exactly the
artifacts teardown exists to remove, the same reasoning that makes fork
teardowns unconditional.

### The site key

Every per-site artifact is named by the **canonical site key**, which is ePHPm's
derivation, not switchboard's (`src/site_key.rs`): the preview host, normalized,
with ePHPm's `[server] sites_domain_suffix` stripped. So:

| `[server] sites_domain_suffix` on the node | `--sites-domain-suffix` | Site key for `blog-pr-7.preview.ephpm.dev` |
|---|---|---|
| `.preview.ephpm.dev` (what the preview cluster runs) | *(default)* | `blog-pr-7` |
| unset | `""` | `blog-pr-7.preview.ephpm.dev` |

Getting this wrong does not error — it provisions the preview into a directory
ePHPm never resolves, and per ePHPm's fail-closed rule such a request gets no
per-site database and no `DB_*` credentials. That is why the suffix is an
explicit, validated flag rather than an assumption. The daemon logs the
resolved derivation at startup.

A **deploy** fetches `refs/pull/<n>/head` at the recorded `head.sha` from the
**base** repository (which works for forks, and for deleted forks, without
trusting a third-party clone URL), materializes the app's `env:` and the
manifest's `docroot:` override, installs the result at `<sites_dir>/<key>/` by
staging into `<key>.tmp` and renaming, and only then runs the manifest's
`build:` and `seed:` steps — sandboxed (see below).

Before the swap the deploy takes the manifest itself out of the served root:
`ephpm.yaml` / `ephpm.yml` / `ephpm.json` are moved to `<site>/.switchboard/`.
They are ordinary, non-dot-prefixed files at the repository root, and for an app
declaring `docroot: "."` — WordPress, and most bespoke apps — the repository
root *is* the web root, so `GET /ephpm.yaml` returned 200 with the build
commands, the enabled services and the whole seed sequence (switchboard#16). The
archive is dot-prefixed, so ePHPm's `hidden_files` default (`deny`) makes it a
403; it is inside the site directory, so the existing teardown reaps it. A
`build:` or `seed:` step that wants the manifest must read
`.switchboard/ephpm.yaml`.

### `build:` and `seed:` run sandboxed, not as root

`build:` and `seed:` execute **untrusted code from a pull request**. They used
to run as **root** via `sh -c` — a confirmed root-RCE on the preview cluster.
Every such step now runs through ePHPm's sandboxed execution primitive
(`ephpm exec --site`, ephpm#484):

```text
ephpm exec --config <ephpm.toml> --site <key> -- sh -c "cd <workdir> && <step>"
```

which drops to the tenant uid, applies a Landlock filesystem scope (the vhost
container + its private temp/session root, and nothing else — not `/etc/ephpm`,
not `/root`), and arms the host's uid-keyed egress firewall. `build:` runs at the
container root (where `composer.json` lives); `seed:` runs at the document root.
The step's environment (`PREVIEW_URL`, `PREVIEW_HOST`, `PR`,
`COMPOSER_NO_INTERACTION`, …) is inherited through `ephpm exec`. This is why
`build:` moved to **after** the atomic swap: `ephpm exec --site <key>` sandboxes
a command in the *existing* vhost directory, which does not exist until the swap.

**This fails closed.** If the configured `ephpm` (`--ephpm-bin`) does not support
`exec` — an ePHPm predating #484 — a deploy **refuses** rather than falling back
to running the step as root. There is deliberately no unsandboxed fallback. That
makes the rollout order a hard requirement: **deploy the ePHPm carrying #484 to a
node before deploying this switchboard to it.** In the wrong order switchboard
refuses to deploy previews (the safe direction) until ePHPm is upgraded.

A **teardown** removes everything the preview left on this node, each derived
from the site key by exact path — never a glob wider than the one site:

* `<sites_dir>/<key>/` (and a leftover `<key>.tmp` staging directory);
* the per-site database `<key>.db` + `-wal`/`-shm`/`-journal` under
  `--sqlite-dir` (ePHPm's `[db.sqlite].dir`) — the dominant disk consumer on a
  WordPress preview;
* the `<key>.toml` docroot override under `--site-overrides-dir`;
* the per-vhost temp/session state root under `--vhost-temp-base` (default:
  this process's `<system temp>/ephpm-vhosts`, matching ePHPm's default). The
  directory name embeds a hash ePHPm computed over the container path; the
  daemon reproduces it and additionally sweeps for this site's exact name
  shape (`<key>-<16 hex>`), so a hash it cannot reproduce still gets reaped;
* switchboard-**api**'s desired-state marker at `<state_dir>/applied/<label>`
  — the record of what this node last materialized into its own queue. This
  one is keyed by the preview **label**, not by the site key (they differ on
  a node with no `sites_domain_suffix`). Nothing else reaps it, so a removed
  preview used to leave a "this site should exist" record behind on every
  node. A marker recording a **deploy** newer than the teardown is left
  alone: that is current desired state, not drift.

In cluster mode every node's daemon runs the same teardown against its own
disk, which is the complete story — each node reaps its own replicas.

### Teardown is complete or it fails

`--sqlite-dir` and `--site-overrides-dir` have no defaults — they are ePHPm's
configuration and the daemon cannot derive them — so the daemon **refuses to
start** without them. Leaving them unset used to be a quiet skip: the vhost
directory went away, the tenant's `<key>.db` and `-wal` stayed on disk, and the
teardown reported success. That is data retention, not untidiness, and the live
preview cluster ran that way for weeks because its systemd unit (which is not in
this repo) passed neither flag.

Set both, or acknowledge the gap explicitly with `--allow-incomplete-teardown`.
With the acknowledgement the daemon starts, every teardown logs a `WARN` naming
the artifact classes it did not attempt, and the job still succeeds. Without it,
a teardown that cannot reach an artifact class removes everything it *can*, then
**fails** with a message naming exactly what it left — so the job stays in
`queue/claimed/` for an operator instead of disappearing.

### 2. Kick `/drain`

switchboard-api is a PHP vhost: it only runs when a request arrives, so it has
no timer of its own. Work it must do off the webhook path needs someone to call
it, and this daemon is already running on every node. On each
`--drain-interval-secs` it sends:

```
GET http://<drain_addr>/drain
Host: <drain_host>
X-Drain-Token: <trimmed contents of drain_token_file>
```

The token is re-read per kick, so the shared secret can be rotated without
restarting the daemon, and is trimmed — a secret written with `echo` carries a
trailing newline that would otherwise be sent as part of the header.

A refused connection or a non-200 is a `WARN` and the loop carries on; a missed
kick is picked up by the next one. **Set `--drain-interval-secs 0` to disable
the kick entirely** — the correct setting for a single-node deployment with
nothing to fan out to.

### 3. Report to GitHub

The daemon mints an installation token from the GitHub App private key, posts
(or updates) the preview comment on the PR, and creates the Deployment status.
The comment is *sticky*: it carries a hidden `<!-- switchboard-preview -->`
marker, so a later push updates the same comment in place rather than appending
a new one.

**Reporting degrades rather than fails.** With no App credentials configured,
startup logs one `INFO` line and every deploy proceeds normally — it is just not
reported on the pull request. This is what the e2e cluster, which has no App
installed, runs with.

**Deduplication is the hidden marker, not coordination.** Every node reconciles
the same preview and every node reports, but before creating a comment the
daemon lists the PR's comments and looks for the hidden
`<!-- switchboard-preview -->` marker; if it finds one it *updates that comment
in place*. So N nodes converge on a single comment, and a later push refreshes
it rather than appending. This needs no shared state and no KV listener — the
operator keeps ePHPm's RESP listener (`[kv.redis_compat]`) off.

Honest limit: the find-then-create is not atomic across nodes, so two nodes that
both list *before* either has created can momentarily post two comments. It is a
sub-second window and self-heals — the next push finds one of them by its marker
and updates it, converging back to one.

## Configuration

Every knob is a CLI flag with an `SWITCHBOARD_*` environment fallback, which is
what a systemd unit wants: `EnvironmentFile=` for deployment-specific values and
no config file to keep in sync. `switchboard --help` prints the same list.

### Queue

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--state-dir` | `SWITCHBOARD_STATE_DIR` | *(required)* | switchboard-api's `.switchboard/` directory. Jobs are consumed from `<state_dir>/queue/`. |
| `--queue-interval-secs` | `SWITCHBOARD_QUEUE_INTERVAL_SECS` | `2` | Seconds between queue scans. |
| `--max-job-age-secs` | `SWITCHBOARD_MAX_JOB_AGE_SECS` | `3600` | Discard a **deploy** job that has waited longer than this in the queue rather than applying it. **`0` disables the bound.** Teardown jobs are never discarded by age. See [A claimed job is re-checked against current state](#a-claimed-job-is-re-checked-against-current-state). |

### Drain kick

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--drain-interval-secs` | `SWITCHBOARD_DRAIN_INTERVAL_SECS` | `2` | Seconds between kicks. **`0` disables the kick entirely.** |
| `--drain-addr` | `SWITCHBOARD_DRAIN_ADDR` | `127.0.0.1:8080` | `host:port` of the local ePHPm instance. |
| `--drain-host` | `SWITCHBOARD_DRAIN_HOST` | *(none)* | The switchboard-api vhost, sent as the `Host` header. **Required when the interval is non-zero.** |
| `--drain-token-file` | `SWITCHBOARD_DRAIN_TOKEN_FILE` | *(none)* | File holding the shared secret (the API's `.switchboard/drain_secret`), sent as `X-Drain-Token`. **Required when the interval is non-zero.** |

A missing or empty token file fails at **startup**, not silently every two
seconds forever.

### Provisioning

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--sites-dir` | `SWITCHBOARD_SITES_DIR` | `/var/www/sites` | ePHPm's sites directory. Previews land at `<sites_dir>/<site-key>/`. |
| `--preview-domain` | `SWITCHBOARD_PREVIEW_DOMAIN` | `preview.ephpm.dev` | Suffix appended to the label to form the preview host. |
| `--sites-domain-suffix` | `SWITCHBOARD_SITES_DOMAIN_SUFFIX` | `.<preview-domain>` | ePHPm's `[server] sites_domain_suffix` **on this node**. Decides the site key (see above). Pass `""` for a node that configures no suffix. Must begin with a dot — ePHPm refuses a dotless one (ephpm#397). |
| `--composer` | `SWITCHBOARD_COMPOSER` | `composer` | Composer command or path. |
| `--ephpm-bin` | `SWITCHBOARD_EPHPM_BIN` | `ephpm` | The `ephpm` binary used to run `build:`/`seed:` steps sandboxed (`ephpm exec --site`). Must support `exec` (ephpm#484) — a deploy **refuses** otherwise rather than running steps as root. Set an absolute path if it is not on the daemon's `PATH`. |
| `--ephpm-config` | `SWITCHBOARD_EPHPM_CONFIG` | `/etc/ephpm/ephpm.toml` | The node's `ephpm.toml`, passed to `ephpm exec --config`. Must be the same config the running server uses, so the sandbox resolves the same per-site boundary. |
| `--secrets-file` | `SWITCHBOARD_SECRETS_FILE` | *(none)* | YAML secret store for `${secret.NAME}` references in a manifest's `env:`. |
| `--health-timeout-secs` | `SWITCHBOARD_HEALTH_TIMEOUT_SECS` | `60` | How long to poll the manifest's `health:` path for a 200. `0` disables the gate. |
| `--health-interval-secs` | `SWITCHBOARD_HEALTH_INTERVAL_SECS` | `2` | Seconds between health polls. |
| `--sqlite-dir` | `SWITCHBOARD_SQLITE_DIR` | *(none)* | ePHPm's `[db.sqlite].dir`. Teardown removes the preview's `<key>.db` (+ journal files) from here. **Required** unless `--allow-incomplete-teardown` is set — see [Teardown is complete or it fails](#teardown-is-complete-or-it-fails). |
| `--site-overrides-dir` | `SWITCHBOARD_SITE_OVERRIDES_DIR` | *(none)* | ePHPm's `[server] site_overrides_dir` — a directory **outside** `sites_dir` (ePHPm refuses to start otherwise). The deploy writes each preview's `<key>.toml` document-root override here and teardown removes it. **Required** unless `--allow-incomplete-teardown` is set. Unset it also means a manifest's `docroot:` cannot be honoured and ePHPm serves the whole checkout. |
| `--allow-incomplete-teardown` | `SWITCHBOARD_ALLOW_INCOMPLETE_TEARDOWN` | `false` | Start without the two roots above, and let teardown report success while leaving those artifacts on disk (a `WARN` per teardown names them). An acknowledgement, not a feature. |
| `--vhost-temp-base` | `SWITCHBOARD_VHOST_TEMP_BASE` | `<system temp>/ephpm-vhosts` | Where ePHPm keeps per-vhost temp/session state roots. Set explicitly when the daemon and ePHPm do not share a temp dir (`PrivateTmp`, differing `TMPDIR`). |

Secrets can also come from `SWITCHBOARD_SECRET_<NAME>` environment variables
(folded into the default scope, lowercased; the file wins on conflict).

### Fork policy

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--allow-fork-deploy` | `SWITCHBOARD_ALLOW_FORK_DEPLOY` | `false` | Deploy pull requests from forks. Without it a fork deploy job **fails** with a clear message. |
| `--fork-secrets` | `SWITCHBOARD_FORK_SECRETS` | `false` | Resolve `${secret.NAME}` operator secrets into fork deploys. Requires `--allow-fork-deploy`; setting it alone is a startup error. |

The job file carries `pull_request.fork` (emitted by switchboard-api since its
first release); a schema-1 document **without** the field is treated as a fork,
because no legitimate producer omits it. This gate is deliberately a second one
under the API's `SWITCHBOARD_ALLOW_FORKS`: the API decides what gets *queued*,
but this daemon is the process that holds the secret store and builds the code,
so it decides again. Building untrusted code and handing it operator secrets
are two separate decisions, hence two flags — with `--allow-fork-deploy` alone,
a fork builds but every `${secret.NAME}` expands to the empty string (with a
name-only warning). Fork **teardowns** are always processed; refusing them
would strand previews on disk.

### GitHub reporting (optional)

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--app-id` | `SWITCHBOARD_APP_ID` | *(none)* | GitHub App ID. |
| `--app-key` | `SWITCHBOARD_APP_KEY` | *(none)* | GitHub App private key (PEM path). |

Omit **both** to run without reporting. Supplying exactly one is a startup
error: a half-configured App would silently never report.

Comments are deduplicated cluster-wide by the hidden marker (see
[Report to GitHub](#3-report-to-github)); no shared state or KV listener is
involved.

### Legacy webhook receiver

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--webhook-server-enabled` | `SWITCHBOARD_WEBHOOK_SERVER_ENABLED` | `false` | Run the in-process `/webhook` receiver. Kept for deployments that have not migrated to switchboard-api. |
| `--listen` | `SWITCHBOARD_LISTEN` | `0.0.0.0:9090` | Listen address for that receiver. |
| `--webhook-secret` | `SWITCHBOARD_WEBHOOK_SECRET` | *(none)* | HMAC secret. **Required when the receiver is enabled** — an unauthenticated webhook endpoint will not start. |

## Running

```bash
switchboard \
  --state-dir /var/www/sites/switchboard/.switchboard \
  --sites-dir /var/www/sites \
  --preview-domain preview.ephpm.dev \
  --sqlite-dir /var/lib/ephpm-web/db \
  --site-overrides-dir /etc/ephpm/sites \
  --drain-host switchboard.ephpm.dev \
  --drain-token-file /var/www/sites/switchboard/.switchboard/drain_secret \
  --app-id 123456 \
  --app-key /etc/switchboard/app.pem
```

The two teardown roots must match ePHPm's `[db.sqlite].dir` and
`[server] site_overrides_dir` on the same node; the daemon will not start
without them (or `--allow-incomplete-teardown`).

The same invocation runs on every node in a cluster; the PR comment is
deduplicated by its hidden marker, so all nodes converge on one comment.

Single node, no GitHub App, no per-site databases to reap:

```bash
switchboard --state-dir /var/www/sites/switchboard/.switchboard \
            --drain-interval-secs 0 \
            --allow-incomplete-teardown
```

Logging is `tracing` with an `RUST_LOG`-style `EnvFilter`; the default is
`info,switchboard=debug`.

## Build and test

```bash
cargo build --release        # → target/release/switchboard
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, and a `cargo check`
pinned to the crate's MSRV on the ephpm org's self-hosted fleet.

## Source map

| File | What it does |
|---|---|
| `src/main.rs` | Startup, the queue loop, the drain loop, GitHub token minting, the legacy receiver |
| `src/config.rs` | Every flag and env var, plus the cross-field validation clap cannot express |
| `src/job.rs` | The schema-1 job document: parse, validate, convert to a `PreviewRequest` |
| `src/queue.rs` | Scan, claim (`link`+`unlink`), coalesce per label, complete; the enqueue timestamp a claimed job carries |
| `src/validate.rs` | Claim-time re-validation of a deploy job: the queue-age bound and the current-PR-state check |
| `src/drain.rs` | The `/drain` kick and the shared-secret file |
| `src/deployer.rs` | The provisioning pipeline: fetch → manifest → env → quarantine the manifest → atomic swap → build → seed → health. `build:`/`seed:` run sandboxed via `ephpm exec --site` (fail-closed if unsupported). |
| `src/teardown.rs` | Preview teardown: vhost dir, per-site database, override file, vhost temp/session state root, the API's `applied/` marker — and the refusal to call a partial teardown a success |
| `src/manifest.rs` | The `ephpm.yaml` app manifest schema, and moving it out of the served root once read |
| `src/secrets.rs` | `${secret.NAME}` resolution from switchboard's own store |
| `src/github.rs` | PR comments and Deployment statuses (sticky via the hidden marker) |
| `src/webhook.rs` | Signature verification and payload types for the legacy receiver |
