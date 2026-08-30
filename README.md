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
`<label>.tmp` and renaming. A **teardown** removes `<sites_dir>/<label>/`. The
preview's per-site database is left in place — database teardown is out of
scope.

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

#### Exactly-once across the cluster

In a NodeBalancer-fronted cluster a webhook lands on one node, but
switchboard-api publishes desired state into ePHPm's **gossip-replicated** KV
and every node's `/drain` turns that back into its own queue — so **every node
deploys the same preview**. That is what we want (the preview survives any one
node dying), but it means every node would also post the PR comment. Three
nodes, three duplicate comments.

The fix is a cluster-wide claim: before reporting, a node does an atomic
`SET switchboard:pr-comment:<owner>/<repo>:<pr>:<sha> <node> NX EX <ttl>`
against ePHPm's RESP listener — the same replicated store, and the same
`set_nx` primitive, that ePHPm's ACME-leader and SQLite-primary elections use.
Only the node whose claim lands first posts; the rest see the key present and
stay quiet. The claim is scoped to the head SHA, so a *new* push mints a *new*
claim and the winner updates the sticky comment for that commit — an old claim
never suppresses a real update. If the report then fails, the claim is released
so another node can retry rather than the PR losing its comment for that commit.

This is enabled by pointing the daemon at the KV with `--kv-addr` (see
[Cluster coordination](#cluster-coordination)). **Without `--kv-addr` the daemon
reports directly** — correct for a single node, where there is nothing to race.
When coordination is on but the KV cannot be reached, a node steps back rather
than post: a missed comment self-heals on the next push; a triplicate does not.

Honest limit: `set_nx` is best-effort cluster-wide, not linearizable across a
partition — two partitioned nodes can both win, the same residual race the ACME
tie-break carries. The hidden-marker "find existing comment before creating" is
the backstop: a second poster that can already see the first comment updates it
instead of duplicating.

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

Secrets can also come from `SWITCHBOARD_SECRET_<NAME>` environment variables
(folded into the default scope, lowercased; the file wins on conflict).

### GitHub reporting (optional)

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--app-id` | `SWITCHBOARD_APP_ID` | *(none)* | GitHub App ID. |
| `--app-key` | `SWITCHBOARD_APP_KEY` | *(none)* | GitHub App private key (PEM path). |

Omit **both** to run without reporting. Supplying exactly one is a startup
error: a half-configured App would silently never report.

### Cluster coordination

Needed only when more than one node reports the same preview. Enabled by
`--kv-addr`; without it the daemon reports directly (single node).

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--kv-addr` | `SWITCHBOARD_KV_ADDR` | *(none)* | `host:port` of ePHPm's RESP listener (`[kv.redis_compat] listen`). **Setting it enables exactly-once reporting.** |
| `--kv-auth-user` | `SWITCHBOARD_KV_AUTH_USER` | *(none)* | RESP AUTH username for ePHPm's per-site scoping — the switchboard-api vhost host (usually the same value as `--drain-host`). Omit for the one-argument `requirepass` form. |
| `--kv-secret-file` | `SWITCHBOARD_KV_SECRET_FILE` | *(none)* | File holding ePHPm's `[kv] secret`; the daemon derives the per-site password as `HMAC-SHA256(secret, --kv-auth-user)`. Requires `--kv-auth-user`. |
| `--kv-password-file` | `SWITCHBOARD_KV_PASSWORD_FILE` | *(none)* | File holding a literal RESP password. Mutually exclusive with `--kv-secret-file`. |
| `--kv-claim-ttl-secs` | `SWITCHBOARD_KV_CLAIM_TTL_SECS` | `21600` | TTL on each claim key — bounds key accumulation and lets a crashed node's claim be re-won. |

The credential is read from a **file** (never a flag or env value) so it stays
out of process listings and logs. For a multi-tenant preview cluster (which is
the norm — previews use `sites_dir`), ePHPm's RESP listener requires per-site
AUTH, so the usual setup is `--kv-auth-user <switchboard-api host>` plus
`--kv-secret-file` pointing at the same `[kv] secret` ePHPm is configured with.

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
  --app-key /etc/switchboard/app.pem \
  --kv-addr 127.0.0.1:6379 \
  --kv-auth-user switchboard.ephpm.dev \
  --kv-secret-file /etc/ephpm/secrets/kv.secret
```

The three `--kv-*` flags are what make a multi-node cluster post one comment
instead of one per node; drop them for a single node.

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
| `src/manifest.rs` | The `ephpm.yaml` app manifest schema |
| `src/secrets.rs` | `${secret.NAME}` resolution from switchboard's own store |
| `src/github.rs` | PR comments and Deployment statuses |
| `src/coordinator.rs` | Cluster-wide exactly-once claim (`SET … NX`) over ePHPm's replicated KV, so only one node reports each preview |
| `src/webhook.rs` | Signature verification and payload types for the legacy receiver |
