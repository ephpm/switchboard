# switchboard

The **preview-deployment daemon** for ePHPm. It consumes job files written by
[`ephpm/switchboard-api`](https://github.com/ephpm/switchboard-api), checks out
pull-request branches, provisions preview sites into an ePHPm instance's
`sites_dir`, and reports status back to GitHub through the Deployments API.

It is **not an HTTP server**. It receives no webhooks and holds no webhook
secret. That half moved to switchboard-api.

## The split

`ephpm/switchboard` was once one binary that received webhooks *and* provisioned
previews. It is now two components:

| Component | Language | Runs as | Responsibility |
|---|---|---|---|
| **switchboard-api** | PHP (PSR-15) | a confined vhost inside ePHPm | receive webhooks, verify the signature, dedupe, write a job file |
| **switchboard** (this repo) | Rust | a systemd unit beside ePHPm | pick up jobs, mint GitHub tokens, check out repos, provision previews, report to GitHub |

The split is forced by ePHPm's `open_basedir` confinement and turned into a
property worth having: the internet-facing component that accepts
unauthenticated POSTs provably cannot reach the filesystem outside its own vhost,
cannot run a deploy, and **holds no credential that can write to a GitHub
repository**. All of that lives here, in the unconfined daemon — including the
GitHub App private key.

Both processes run as the **same uid** by design (the API writes the queue
directory the daemon reads), so filesystem permissions do not separate them. The
protection is that only switchboard-api can write into `queue/`, and it only does
so for an HMAC-verified delivery. **The queue is the daemon's trust boundary.**

See switchboard-api's `README.md` ("The job file contract") and `MIGRATION.md`
for the full contract and what moved where.

## Lifecycle

```
watch queue/ ──▶ claim (hardlink) ──▶ coalesce per label ──▶ dispatch on intent
                                                                 │
                                       ┌─────────────────────────┴───────────┐
                                    deploy                                teardown
                                       │                                     │
                    create Deployment (queued)                    remove vhost dir
                    in_progress                                    remove <key>.db (+ -wal/-shm)
                    clone (pull_ref, GIT_ASKPASS)                  remove vhost temp/session root
                    build:  (system composer/PHP)                 remove <key>.toml override
                    materialize env: (no secrets for forks)       Deployment ▶ inactive
                    atomic swap into sites_dir
                    write <key>.toml docroot override (#391)
                    seed:  (over HTTP — see below)
                    health-gate
                    Deployment ▶ success (environment_url) / failure (+ comment)
```

### Queue consumption

Job filenames are `<13-digit millis>-<16 hex>.json`, so **lexicographic order
equals arrival order** — the daemon scans, sorts, and processes in order with no
need to open every file first. Polling on a short interval is sufficient; the
directory is only ever written by `rename()`, so a scan never sees a partial
file.

- **Claim with `link()`**, not `rename()`. `rename()` overwrites silently, so two
  workers would both believe they won; `link()` fails with `EEXIST`. A processed
  job is deleted from `claimed/` on success and **retained there for inspection
  on failure**.
- **Coalescing is the daemon's job.** Rapid pushes produce several `synchronize`
  jobs for one `preview.label`; only the newest matters. The daemon dispatches
  the newest file per label and drops the older ones. Because filenames sort
  chronologically, a later `teardown` correctly supersedes an earlier `deploy`.
- **Schema is checked first.** An unrecognized `schema` is rejected rather than
  deserialized optimistically.

### Job validation (defense in depth)

Every job is re-validated even though switchboard-api already validated it — "the
API validated it" is a claim about another codebase, and the queue is the trust
boundary. A signed payload is authentic, not harmless: `head.ref`, `head.sha`,
owner/repo names, the clone URL, and `pull_ref` are all re-checked against strict
patterns before any value reaches `git`. A ref like `--upload-pack=/bin/sh` never
runs. Every `git` invocation passes arguments as an argv vector, never a shell
string.

### GitHub App tokens are minted in memory

The daemon loads the App private key from a `0600` path (it refuses to start if
the key is group/world-readable), signs a short-lived JWT, and exchanges it for a
~60-minute installation token. The token is wrapped in a type that **redacts
itself in logs**, is never written to disk, and reaches `git` through
`GIT_ASKPASS` in the environment — never argv (world-visible via `ps`). The clone
URL carries the non-secret `x-access-token` username so `git` only ever prompts
for the password, which the askpass helper supplies from an environment variable.

### Reporting to GitHub

The daemon **creates the Deployment as its first action** on a deploy job, before
cloning, so even a build that fails shows up on the PR. It then posts
`in_progress` → `success` (with the preview URL as `environment_url`, which
renders GitHub's native "View deployment" box) or `failure`. Because a `failure`
deployment carries no log, a failed build **also** posts a PR comment with the
error, carrying an `**ePHPm Preview**` marker so it is updated in place rather
than duplicated on each push. Teardown marks the environment `inactive`.

If the job carries no `installation_id`, the daemon cannot report — it logs a
warning and still provisions the preview (public repos need no token).

## Provisioning details, and three constraints worth stating

### The canonical site key

A preview's directory, its per-site database, its temp/session root, and its
docroot override are all keyed off **one** canonical site key — the same value
ePHPm derives from the `Host` header (`Router::resolve_site`). Two producers of
that key is exactly how ePHPm issues #290/#291 happened (one tenant, two
databases), so the daemon *ports* ePHPm's derivation rather than inventing one:
the preview host is `<label>.<preview_domain>`, and the key is that host with
`[server] sites_domain_suffix` stripped (when configured) — validated by the same
rules as `is_valid_site_key`. Set `--sites-domain-suffix` to match ePHPm's, or
leave both unset and the vhost directory is named by the full FQDN.

### Fork PRs get no secrets by default

`materialize_env` resolves `${secret.NAME}` from the operator's store into the
preview environment. Building **untrusted fork code with your secrets in the
environment** was a real hole in the pre-split code, which deployed fork PRs with
no gate at all. Now:

- Fork **deploys** are refused unless `--allow-fork-deploy` (a second gate over
  switchboard-api's own `SWITCHBOARD_ALLOW_FORKS`).
- Even when a fork deploy is allowed, it gets **no operator secrets** unless
  `--fork-secrets` is also set. Non-fork PRs always get secrets.
- Fork **teardowns** are always processed (removing a preview is safe).

### `build:` uses system PHP, not `ephpm php` (issue #400)

The implicit `composer install` and any `build:` step run against the **system**
`composer`/PHP (`--composer`), never `ephpm php`. Issue #400 (Composer aborting
under `ephpm php`) is a **Windows-only** php-sdk problem — the Windows build links
curl against Schannel, which trips an upstream Composer platform-parser regex — so
the Linux daemon is not actually bitten. The daemon nonetheless has **no**
`ephpm php` build path by design, so builds can't regress into it; if you point
`--composer` at a wrapper that shells `ephpm php`, that guarantee is on you.

### `seed:` cannot reach the database from a shell

`seed:` steps run as `sh -c` children with `$PREVIEW_URL`/`$PREVIEW_HOST`/`$PR`
set. A shell child has **no** `$_SERVER` database credentials (ePHPm injects
those per HTTP request), and `ephpm php -r 'ephpm_db_query(...)'` reports no
database. **Database seeding must go over HTTP into the running site** — issue a
request that triggers the app's own install/migrate path, the way
`ephpm/wordpress-sample` does. The health gate runs after `seed:`, so a seed step
that curls the preview will find it serving.

### The docroot override (#391)

When a manifest declares a non-default `docroot` and `--site-overrides-dir` is
configured, the daemon writes `<overrides-dir>/<key>.toml` with `document_root`.
This is ePHPm's #391 mechanism: the file lives **outside** `sites_dir` (a
directory no tenant can write), which is why ePHPm trusts it. ePHPm rejects an
overrides dir placed inside `sites_dir`, so configure it as a sibling. Without an
overrides dir, a non-default docroot is logged and ePHPm serves the container.

### Teardown removes everything

A per-site database lives at `<sqlite-dir>/<key>.db` — **outside** the vhost
directory — so `rm -rf` on the vhost alone leaks a closed PR's data. Teardown
removes, for the canonical key:

1. `sites_dir/<key>/` — the vhost checkout,
2. `<sqlite-dir>/<key>.db` and its `-wal`/`-shm`/`-journal` siblings,
3. the per-vhost temp/session root (`<temp>/ephpm-vhosts/<key>-<digest>`),
4. `<overrides-dir>/<key>.toml`.

The temp-root name embeds a hash ePHPm computes over the container path; the
daemon reproduces it, and *also* removes by the unique `<key>-` prefix as a
fallback in case the hash differs across processes (a different `TMPDIR` or a std
hasher change). The DB, override, and vhost directory — the persistent leaks —
are named deterministically and do not depend on that hash.

## Configuration

All flags have an `SWITCHBOARD_*` environment equivalent. `--queue-dir`,
`--app-key`, and `--app-id` are required.

| Flag / env | Default | Purpose |
|---|---|---|
| `--queue-dir` / `SWITCHBOARD_QUEUE_DIR` | — | The `<vhost>/.switchboard/queue` directory to watch. Configured explicitly, not derived from `sites_dir`. |
| `--poll-interval-secs` / `…_POLL_INTERVAL_SECS` | `2` | Seconds between queue scans. |
| `--app-key` / `SWITCHBOARD_APP_KEY` | — | GitHub App private key (PEM). Must be `0600` and owned by the daemon uid. |
| `--app-id` / `SWITCHBOARD_APP_ID` | — | GitHub App id. |
| `--github-host` / `SWITCHBOARD_GITHUB_HOST` | `github.com` | Host clone URLs must belong to; also selects the API base (GHES → `/api/v3`). |
| `--sites-dir` / `SWITCHBOARD_SITES_DIR` | `/var/www/sites` | ePHPm `[server] sites_dir`. |
| `--preview-domain` / `…_PREVIEW_DOMAIN` | `preview.ephpm.dev` | Preview host is `<label>.<preview_domain>`. |
| `--sites-domain-suffix` / `…_SITES_DOMAIN_SUFFIX` | unset | ePHPm `[server] sites_domain_suffix` (leading dot). Set it to match ePHPm so the site key agrees. |
| `--site-overrides-dir` / `…_SITE_OVERRIDES_DIR` | unset | ePHPm `[server] site_overrides_dir` (outside `sites_dir`). Enables docroot overrides. |
| `--sqlite-dir` / `SWITCHBOARD_SQLITE_DIR` | unset | ePHPm `[db.sqlite] dir`. Needed so teardown removes `<key>.db`. |
| `--vhost-temp-base` / `…_VHOST_TEMP_BASE` | system temp | Base for ePHPm's per-vhost state. Set only if ePHPm's `TMPDIR` differs. |
| `--composer` / `SWITCHBOARD_COMPOSER` | `composer` | System composer command (see #400). |
| `--secrets-file` / `SWITCHBOARD_SECRETS_FILE` | unset | YAML store for `${secret.NAME}` (also `SWITCHBOARD_SECRET_*`). |
| `--allow-fork-deploy` / `…_ALLOW_FORK_DEPLOY` | off | Deploy fork PRs (defense-in-depth over switchboard-api). |
| `--fork-secrets` / `SWITCHBOARD_FORK_SECRETS` | off | Give allowed fork deploys the operator secrets. |
| `--health-timeout-secs` / `…_HEALTH_TIMEOUT_SECS` | `60` | Poll `health:` for a 200 before reporting ready. `0` disables. |
| `--health-interval-secs` / `…_HEALTH_INTERVAL_SECS` | `2` | Health poll interval. |

### Example systemd unit

```ini
[Service]
User=switchboard
Environment=SWITCHBOARD_QUEUE_DIR=/var/www/sites/switchboard/.switchboard/queue
Environment=SWITCHBOARD_APP_KEY=/etc/switchboard/app.pem
Environment=SWITCHBOARD_APP_ID=123456
Environment=SWITCHBOARD_SITES_DIR=/var/www/sites
Environment=SWITCHBOARD_PREVIEW_DOMAIN=preview.ephpm.dev
Environment=SWITCHBOARD_SITE_OVERRIDES_DIR=/var/lib/ephpm/site-overrides
Environment=SWITCHBOARD_SQLITE_DIR=/var/lib/ephpm/dbs
Environment=SWITCHBOARD_SECRETS_FILE=/etc/switchboard/secrets.yaml
ExecStart=/usr/local/bin/switchboard
Restart=on-failure
```

## The `ephpm.yaml` manifest

Unchanged from before the split — the schema is a fixed contract (`src/manifest.rs`;
parse to those fields, do not invent new ones). It is read from the *checkout*,
which only this daemon has; switchboard-api never reads a repository's contents.

## Building & testing

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Requires a C compiler on `PATH` (transitive build scripts / rustls' `ring`).
Runtime requires `git` and `openssl` on `PATH`. Linux is the supported target;
the module compiles on other platforms but the `GIT_ASKPASS` helper and the key
permission check are Unix-only.
