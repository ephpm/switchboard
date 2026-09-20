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
trusting a third-party clone URL). The fetch is **authenticated** with a
short-lived GitHub App installation token (the same credential used for
reporting), injected as a transient `http.extraheader` scoped to that one git
process — never written into the checkout's persisted git config and never
logged — so **private** repositories can be previewed. When no App credentials
are configured the fetch stays unauthenticated: public repos still work, and a
private repo fails with a clear "configure `--app-id`/`--app-key` and grant the
installation `contents: read`" message. The deploy then materializes the app's
`env:`, publishes the
manifest's `docroot:` **and** the generated env prepend as ePHPm's per-site
override, installs the result at `<sites_dir>/<key>/` by staging into `<key>.tmp`
and renaming, and only then runs the manifest's `build:` and `seed:` steps —
sandboxed (see below).

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
* the `<key>.toml` per-site override (document root + `auto_prepend_file`)
  under `--site-overrides-dir`;
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

### Pre-serve static-analysis gate

A preview builds and serves **untrusted pull-request code**. With
`--analyze-config` set, switchboard screens that code before it goes live: after
the checkout is materialized and **before** the atomic swap makes the vhost
routable (and before `build:`/`seed:` execute any of it), it runs

```text
ephpm analyze <checkout> --config <operator-policy.yml> --format sarif
```

over the pristine tree and **refuses to publish on a bad verdict**. On a
redeploy the previous, known-good container stays live untouched, because the
swap simply never happens.

- **Off by default.** With no `--analyze-config` the gate is disabled and deploys
  behave exactly as before (startup logs one `WARN`). This is the safe rollout
  default: the analyzers ship in a recent `ephpm`, and a node on an older binary
  must not have every preview blocked. The gate is live only once
  `--analyze-config` is set **and** the node's `--ephpm-bin` supports `analyze`.
- **The policy is the operator's, never the PR's.** `--config` is passed
  explicitly, which overrides `ephpm analyze`'s auto-discovery of a
  `.ephpm-analyze.yml` **inside the checkout** — otherwise a malicious PR could
  ship `enable: []` to neuter its own gate. Keep the policy file outside any
  tenant docroot, and use absolute paths inside it.
- **Screens the pristine code.** The gate runs before switchboard injects the
  resolved `env:` (`.env` + prepend), so the analyzer never scans switchboard's
  *own* secrets — only the pull request's code.
- **Fail closed.** Exit `0` publishes; exit `2` (quarantine) and `3` (deny)
  block; exit `1` (analyzer error), any other code, a timeout, and a binary that
  will not spawn **all block**. A gate that cannot run must not wave code
  through. The wall-clock timeout is `--analyze-timeout-secs` (default 180s).
- **Blocked previews are reported.** The block is posted into the PR's sticky
  comment — the verdict, the finding count, and the top ~10 findings (rule, file,
  line, message) — and the GitHub deployment status is set to **failure**. The
  job is left in `queue/claimed/` for inspection (marked failed), not cleared as
  a success; a later push re-runs the gate and refreshes the comment.
- **Scanned once per commit, cluster-wide.** switchboard runs on every node and
  each materializes the same checkout, so a naive gate would re-scan the identical
  commit N times. The verdict is a pure function of (repo, PR head SHA, gate
  config), so it is deduplicated through ePHPm's **gossip-replicated** KV: the
  first node to scan a commit publishes its verdict under
  `analyze:verdict:<repo>:<pr>:<head_sha>:<cfg_hash>` (TTL
  `--analyze-verdict-ttl-secs`), and its peers reuse it — reconstructing the
  identical block comment from the stored findings — instead of re-scanning.
  `cfg_hash` is a fingerprint of the operator policy file, so editing the policy
  re-scans everywhere. There is **no lock or leader wait**: if two nodes miss at
  once and both scan, the result is identical, so the only cost is a redundant
  scan — the same looseness the PR-comment dedup accepts.
- **Verdicts live in a switchboard-private namespace, not the preview's.** The
  cache is stored under a reserved AUTH site (`\x1f`-prefixed, provably not a
  valid preview site key) that **no preview tenant can authenticate to** — a
  tenant's `ephpm_kv_*` is auto-scoped by ePHPm to its own resolved site key, so
  it can only ever reach that one keyspace. switchboard holds the KV secret and
  can address the reserved namespace; the running (untrusted) app cannot read or
  write it. This is what prevents cache poisoning: were verdicts kept in the
  preview's own keyspace, a malicious app could `ephpm_kv_set` a forged `Passed`
  for a future commit it authors (it knows the repo/PR/SHA, and the config
  fingerprint is derivable from the public policy) and bypass the gate on peers.
- **Fail closed on the gate, fail *safe* on the dedup.** A KV **read** error scans
  locally (never skip the gate because coordination failed); a KV **write** error
  proceeds with the local verdict (never block a deploy because publishing the
  shared verdict failed). Coordination failure degrades to "each node scans
  itself", never to "serve unscanned". The shared cache is active only when
  `--analyze-config` **and** `--kv-secret-file` are both set (the KV secret derives
  the per-site RESP password); without the secret, each node scans independently.

A **reviewed example policy** is in
[`docs/analyze-gate.example.yml`](docs/analyze-gate.example.yml). It enables the
six **native** analyzers — `writable-exec`, `obfuscation-scan`, `secrets-scan`,
`composer-scripts`, `dangerous-sinks`, `wp-vuln` — which are a fast file-walk
(~2.6s on a 2000-file WordPress-scale tree, cold), so previews stay snappy.

**Opt-in: `opcode-scan`.** It is deliberately left out of the default policy. It
compiles every PHP file through ePHPm's embedded Zend engine (~+5–15s on a full
WordPress tree), turning *suspected* sink findings into *confirmed* ones at a real
latency cost. A node that wants that stronger detection adds `opcode-scan` to both
`enable` and `required` in its policy file, accepting the extra per-preview time.
`wp-vuln` stays out of `required` in the example because its feed is optional — a
missing feed must skip, not gate. These analyzers require an `ephpm` build that
includes them (`writable-exec`/`obfuscation-scan`/`secrets-scan`/`composer-scripts`
landed recently); the gate stays off until `--analyze-config` is set and the
nodes run an `ephpm` that has them.

### Preview privacy: the access gate

A **private** repo's preview must not be world-readable. It isn't: switchboard
gates it (ephpm#487/#491). The enforcement lives in ePHPm — a per-site
`preview-gate` middleware that redirects unauthenticated visitors to a GitHub
login, runs on the static **and** PHP paths, and fails closed — because that is
the request-phase layer that covers static files too, which an
`auto_prepend_file` check never could. switchboard is the control plane:

- **Gating policy.** A private repo (`repository.private`, defaulting to private
  when the job payload omits it — fail closed) is **always** gated. A public repo
  is ungated by default, gated only with `--gate-public-previews`.
- **Activation.** For a gated preview switchboard writes a `[preview_auth]`
  section into the same per-site override it already writes `document_root` /
  `auto_prepend_file` into — carrying a `session_secret` **reference** (never the
  key) and the issuer's `login_url`.
- **Share links.** With `--share-link`, switchboard mints a short-lived,
  per-preview, revocable `via:"share"` HS256 capability token for people without
  repo access and posts `…/?ephpm_share=<token>` in the PR comment, with the
  bearer-capability warning stated plainly.
- **Revocation.** On teardown switchboard bumps the per-site epoch
  (`preview:share:epoch`) in the preview's KV keyspace, killing every outstanding
  share link (best-effort; needs `--kv-secret-file`).
- **Fail closed.** A gated preview whose session secret cannot be resolved (or
  that has nowhere to write the gate, i.e. no `--site-overrides-dir`) **fails the
  deploy** — never an ungated open preview.

The full design, threat model, operator config, and rollout ordering are in
[`docs/preview-access-gate.md`](docs/preview-access-gate.md). The one-time fleet
setup (the GitHub OAuth App and `EPHPM_PREVIEW_SESSION_SECRET`) is ePHPm node
config, described there.

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
| `--site-overrides-dir` | `SWITCHBOARD_SITE_OVERRIDES_DIR` | *(none)* | ePHPm's `[server] site_overrides_dir` — a directory **outside** `sites_dir` (ePHPm refuses to start otherwise). The deploy writes each preview's `<key>.toml` override here — its `document_root` and the `auto_prepend_file` that delivers the manifest's `env:` to PHP — and teardown removes it. Written atomically (temp + rename): as of ephpm#472 a half-written override takes that site to a 503, not to a warning. **Required** unless `--allow-incomplete-teardown` is set. Unset it also means a manifest's `docroot:` cannot be honoured (ePHPm serves the whole checkout) and its `env:` reaches PHP only through the generated `.env`. |
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

### Pre-serve analyze gate

See [Pre-serve static-analysis gate](#pre-serve-static-analysis-gate) for what
this does and [`docs/analyze-gate.example.yml`](docs/analyze-gate.example.yml) for
a reviewed example policy.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--analyze-config` | `SWITCHBOARD_ANALYZE_CONFIG` | *(none)* | Operator `ephpm analyze` policy file. **Unset disables the gate** (deploys behave as before; startup `WARN`s). When set, every deploy runs `ephpm analyze <checkout> --config <this> --format sarif` before the swap and blocks on a bad verdict. Passed with an explicit `--config` so a PR's own `.ephpm-analyze.yml` cannot neuter it — keep it **outside** any tenant docroot, with absolute paths inside. |
| `--analyze-timeout-secs` | `SWITCHBOARD_ANALYZE_TIMEOUT_SECS` | `180` | Wall-clock timeout for one `ephpm analyze` run. A run that exceeds it is killed and the deploy is **blocked** (fail closed). Only consulted when `--analyze-config` is set. |
| `--analyze-verdict-ttl-secs` | `SWITCHBOARD_ANALYZE_VERDICT_TTL_SECS` | `86400` | TTL for a verdict published to the cluster-shared cache. The head SHA is the real invalidator; the TTL just GCs old entries. The shared cache needs `--kv-secret-file` too; without it each node scans independently. |

Exit-code contract (from `ephpm analyze`): `0` publishes; `2` (quarantine) and
`3` (deny) block; `1` (analyzer error), any other code, and a timeout all block
(fail closed). The gate reuses `--ephpm-bin`, which must support `analyze`. When
`--kv-secret-file` is set the verdict is deduplicated cluster-wide (scanned once
per commit; peers reuse the shared verdict, fail-safe to per-node scanning).

### Preview access gate (ephpm#487/#491)

See [Preview privacy: the access gate](#preview-privacy-the-access-gate) for what
these do; the full design is in
[`docs/preview-access-gate.md`](docs/preview-access-gate.md).

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--gate-public-previews` | `SWITCHBOARD_GATE_PUBLIC_PREVIEWS` | `false` | Gate **public** repos' previews too. Private repos are *always* gated regardless. |
| `--preview-session-secret-ref` | `SWITCHBOARD_PREVIEW_SESSION_SECRET_REF` | `env:EPHPM_PREVIEW_SESSION_SECRET` | The `session_secret` **reference** (`env:NAME` / `file:/abs` / literal) written into a gated preview's `[preview_auth]` and resolved to mint share tokens. Must be the **same** reference the `github-auth` issuer uses and must resolve to ≥ 32 bytes — a gated deploy whose secret does not resolve **fails** (fail closed). The resolved value must be identical in the ePHPm and switchboard environments. |
| `--share-link` | `SWITCHBOARD_SHARE_LINK` | `false` | Mint a temporary shareable-URL capability and post it in the PR comment for each **gated** deploy. Opt-in: a share link is a bearer capability. |
| `--share-link-ttl-secs` | `SWITCHBOARD_SHARE_LINK_TTL_SECS` | `86400` | TTL for a minted share link. Kept short — expiry is the primary control. |
| `--kv-secret-file` | `SWITCHBOARD_KV_SECRET_FILE` | *(none)* | File holding ePHPm's `[kv] secret`, used to derive the per-site RESP password for two cluster-shared KV uses: **teardown bumps the share-link revocation epoch**, and the **analyze gate deduplicates its verdict** across nodes. Unset disables both (revocation falls back to override + checkout removal on this node; the analyze gate scans on every node). |
| `--kv-addr` | `SWITCHBOARD_KV_ADDR` | `127.0.0.1:6379` | ePHPm's KV RESP listener (`[kv.redis_compat] listen`). Only used for revocation when `--kv-secret-file` is set. |

The one-time fleet setup this pairs with — the GitHub OAuth App, the global
`github-auth` mount, and `EPHPM_PREVIEW_SESSION_SECRET` (≥ 32 bytes) in the ePHPm
**and** switchboard environments — is ePHPm node config, not switchboard's; it is
described in [`docs/preview-access-gate.md`](docs/preview-access-gate.md).

### Reconcile (level-triggered convergence)

The drain/queue path is **edge-triggered** on the `switchboard:gen` counter: a
node only re-walks desired state when the counter advances past its own cursor.
Because `gen` is a *separate* gossip key from the content it guards, an increment
that is lost or not-yet-replicated leaves a node "current" at a generation whose
teardown it never materialized — so the torn-down preview stays served, its
database and `<key>.toml` override on disk, every health check green. This is the
class of fault behind override counts drifting between nodes and orphaned
overrides lingering as 404s.

The reconcile pass is the **level-triggered** backstop, and its authority is
**GitHub PR state** — needing no KV and no ePHPm-side change (the preview nodes
keep ePHPm's RESP listener off). On its own interval, independent of `gen`, it
lists every preview directory, parses each site key `<owner>-<repo>-pr-<N>` back
to its pull request, and asks GitHub whether that PR is still open. **Open (or an
unrecognised state) ⇒ keep; merged or closed ⇒ prune.** GitHub is more
authoritative than the KV index (which has a lost-update window), and a preview
that has fallen off every other signal is still correctly classified by the one
fact that actually decides whether it should exist. Re-*deploying* a missing but
still-open preview is deliberately left to the webhook path; this pass only
removes what GitHub says is gone.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--reconcile-interval-secs` | `SWITCHBOARD_RECONCILE_INTERVAL_SECS` | `0` | Seconds between reconcile passes. **`0` disables it.** Requires `--app-id`/`--app-key` (the pass queries GitHub); a backstop, not the hot path, so a cadence well above the drain tick (e.g. 30–60s) is right. |
| `--reconcile-prune` | `SWITCHBOARD_RECONCILE_PRUNE` | `false` | Actually remove orphaned previews (PRs merged/closed). **Off by default**: until set, the pass is observability-only and logs each orphan it *would* prune at `WARN`. |
| `--reconcile-keep-sites` | `SWITCHBOARD_RECONCILE_KEEP_SITES` | *(empty)* | Comma-separated vhost directory names never pruned — the node's infra/test sites (e.g. `site-a,site-b,preview.ephpm.dev`). The API's own site key is always protected in addition. (Belt-and-braces: a non-`<owner>-<repo>-pr-<N>` directory never parses as a preview, so it is never a prune candidate regardless.) |
| `--reconcile-owner` | `SWITCHBOARD_RECONCILE_OWNER` | `ephpm` | The GitHub owner/org previews belong to — the leading segment of `<owner>-<repo>-pr-<N>`, and the owner PR state is queried under. |

Rollout is fail-safe: enable the interval first and read the dry-run `WOULD
prune` logs; turn on `--reconcile-prune` once they look right. Uncertainty always
resolves to **keep** — a site key that does not parse as `<owner>-<repo>-pr-<N>`
(an infra vhost, or a hashed/overflow label) is skipped, a per-PR GitHub read
error keeps that preview, and a failure to mint the installation token aborts the
whole pass so a total GitHub outage prunes **nothing**.

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
| `src/deployer.rs` | The provisioning pipeline: fetch → manifest → **analyze gate** → env → quarantine the manifest → per-site override → atomic swap → chown to tenant → build → seed → health. `build:`/`seed:` run sandboxed via `ephpm exec --site` (fail-closed if unsupported). |
| `src/analyze.rs` | The pre-serve static-analysis gate: run `ephpm analyze` over the pristine checkout, the pure exit-code→proceed/block decision, SARIF finding parsing, the fail-closed contract, and the cluster-wide verdict dedup (pure `plan_from_lookup`, cacheable `CachedVerdict`) |
| `src/site_override.rs` | The per-site override ePHPm reads: validating `docroot:` and the env prepend against ePHPm's own containment rules, the `[preview_auth]` gate section, rendering the TOML, and writing it atomically |
| `src/preview_auth.rs` | The access-gate control plane: gating policy, session-secret resolution (fail closed), wire-compatible HS256 share-token minting, and the per-site KV password derivation |
| `src/kv.rs` | A tiny RESP2 client for ePHPm's gossip-replicated KV: bumping the share-link revocation epoch on teardown (`KvRevoker`) and the cluster-shared analyze verdict cache (`VerdictCache`, GET/SET-EX) — both best-effort |
| `src/teardown.rs` | Preview teardown: vhost dir, per-site database, override file, vhost temp/session state root, the API's `applied/` marker, the share-link revocation epoch — and the refusal to call a partial teardown a success |
| `src/manifest.rs` | The `ephpm.yaml` app manifest schema, and moving it out of the served root once read |
| `src/secrets.rs` | `${secret.NAME}` resolution from switchboard's own store |
| `src/github.rs` | PR comments and Deployment statuses (sticky via the hidden marker) |
| `src/webhook.rs` | Signature verification and payload types for the legacy receiver |
