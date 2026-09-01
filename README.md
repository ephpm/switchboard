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

`preview.label` is **authoritative and never recomputed** — it names the
directory under `sites_dir` and, with `--preview-domain` appended, the host
ePHPm resolves.

A **deploy** fetches `refs/pull/<n>/head` at the recorded `head.sha` from the
**base** repository (which works for forks, and for deleted forks, without
trusting a third-party clone URL), builds per the app's `ephpm.yaml` manifest,
and installs the result at `<sites_dir>/<label>/` by staging into
`<label>.tmp` and renaming.

A **teardown** removes everything the preview left on this node, each derived
from the label by exact path — never a glob wider than the one site:

* `<sites_dir>/<label>/` (and a leftover `<label>.tmp` staging directory);
* the per-site database `<label>.db` + `-wal`/`-shm`/`-journal` under
  `--sqlite-dir` (ePHPm's `[db.sqlite].dir`) — the dominant disk consumer on a
  WordPress preview;
* the `<label>.toml` docroot override under `--site-overrides-dir`;
* the per-vhost temp/session state root under `--vhost-temp-base` (default:
  this process's `<system temp>/ephpm-vhosts`, matching ePHPm's default). The
  directory name embeds a hash ePHPm computed over the container path; the
  daemon reproduces it and additionally sweeps for this label's exact name
  shape (`<label>-<16 hex>`), so a hash it cannot reproduce still gets reaped.

Leave `--sqlite-dir` / `--site-overrides-dir` unset and those artifacts are
left in place (logged, not silent). In cluster mode every node's daemon runs
the same teardown against its own disk, which is the complete story — each
node reaps its own replicas.

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
| `--sites-dir` | `SWITCHBOARD_SITES_DIR` | `/var/www/sites` | ePHPm's sites directory. Previews land at `<sites_dir>/<preview.label>/`. |
| `--preview-domain` | `SWITCHBOARD_PREVIEW_DOMAIN` | `preview.ephpm.dev` | Suffix appended to the label to form the preview host. |
| `--composer` | `SWITCHBOARD_COMPOSER` | `composer` | Composer command or path. |
| `--secrets-file` | `SWITCHBOARD_SECRETS_FILE` | *(none)* | YAML secret store for `${secret.NAME}` references in a manifest's `env:`. |
| `--health-timeout-secs` | `SWITCHBOARD_HEALTH_TIMEOUT_SECS` | `60` | How long to poll the manifest's `health:` path for a 200. `0` disables the gate. |
| `--health-interval-secs` | `SWITCHBOARD_HEALTH_INTERVAL_SECS` | `2` | Seconds between health polls. |
| `--sqlite-dir` | `SWITCHBOARD_SQLITE_DIR` | *(none)* | ePHPm's `[db.sqlite].dir`. Teardown removes the preview's `<label>.db` (+ journal files) from here; unset, databases accumulate. |
| `--site-overrides-dir` | `SWITCHBOARD_SITE_OVERRIDES_DIR` | *(none)* | ePHPm's `site_overrides_dir`. Teardown removes the preview's `<label>.toml` from here. |
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
  --drain-host switchboard.ephpm.dev \
  --drain-token-file /var/www/sites/switchboard/.switchboard/drain_secret \
  --app-id 123456 \
  --app-key /etc/switchboard/app.pem
```

The same invocation runs on every node in a cluster; the PR comment is
deduplicated by its hidden marker, so all nodes converge on one comment.

Single node, no GitHub App:

```bash
switchboard --state-dir /var/www/sites/switchboard/.switchboard \
            --drain-interval-secs 0
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
| `src/queue.rs` | Scan, claim (`link`+`unlink`), coalesce per label, complete |
| `src/drain.rs` | The `/drain` kick and the shared-secret file |
| `src/deployer.rs` | The provisioning pipeline: fetch → manifest → build → env → atomic swap → seed → health |
| `src/teardown.rs` | Preview teardown: vhost dir, per-site database, override file, vhost temp/session state root |
| `src/manifest.rs` | The `ephpm.yaml` app manifest schema |
| `src/secrets.rs` | `${secret.NAME}` resolution from switchboard's own store |
| `src/github.rs` | PR comments and Deployment statuses (sticky via the hidden marker) |
| `src/webhook.rs` | Signature verification and payload types for the legacy receiver |
