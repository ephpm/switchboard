# Making your PHP app work as a preview

You have a PHP repo. You want every pull request to get a live URL. This page
is what your app has to do to work on a switchboard-driven preview host.

You do not need to know how ePHPm works internally. You *do* need to know six
things about the environment, because it is not a normal PHP host:

1. Your preview is a **virtual host inside one shared PHP process**, not a
   container and not a chroot. Other people's previews run in the same process
   as yours.
2. Credentials arrive in **`$_SERVER`** — not `$_ENV`, not `getenv()`.
3. `open_basedir` confines you to your own checkout. `shell_exec` and friends
   are gone.
4. **Persistent connections are disabled.** Redis `pconnect`, mysqli `p:`.
5. `docroot:` is your web root — but only when the operator has configured
   `--site-overrides-dir` on the preview host.
6. Build and seed commands run **outside** ePHPm, so they cannot reach your
   preview's database directly.

Each of those has a workaround or a recipe below.

---

## How this page was checked

Everything marked **Verified** was executed against a running ePHPm build (PHP
8.5.7, `sites_dir` multi-tenant mode) or read directly in the source of
[`ephpm/ephpm`](https://github.com/ephpm/ephpm) at `2ca6535` and this repo at
`ca203ff`. Anything not verifiable from here is labelled **Not tested** or
**Planned**. If you find a claim here that the host does not honour, that is a
bug in this page — file it.

---

## 1. `ephpm.yaml` — the manifest

Put `ephpm.yaml` (or `ephpm.yml`) in your repository root. Every field is
optional except `version`. With no manifest at all, switchboard synthesizes one
from your detected framework, so an unconfigured repo still gets a preview.

```yaml
version: 1                       # required — only 1 is accepted
php: "8.5"                       # default "8.5"
docroot: "."                     # default "." — see the caveat below
build:                           # default [] — run after the swap, sandboxed
  - "composer install --no-dev --optimize-autoloader --no-interaction"
services:
  database: "turso"              # default "turso"; false / "none" to disable
  kv: true                       # default true
  websocket: true                # default: auto-detect websocket.php at docroot
seed:                            # default [] — run after the site is live
  - "wp core install --url=$PREVIEW_URL ..."
env:                             # default {} — literals or ${secret.NAME}
  APP_ENV: "staging"
  API_TOKEN: "${secret.api_token}"
health: "/"                      # default "/" — polled for a 200
ini:                             # default {} — advisory in v1, see below
  memory_limit: "256M"
```

**Verified** against `src/manifest.rs`. Parsing is strict about the things that
matter and forgiving about the rest:

| Field | Type | Default | Semantics |
|---|---|---|---|
| `version` | int | **required** | Only `1`. A missing or unknown version **fails the deploy** — a broken contract must not silently deploy the wrong thing. |
| `php` | string | `"8.5"` | Selects which PHP instance serves you. `8.5` → `https://<host>`; older minors get a port: `8.4` → `:8084`, `8.3` → `:8083` (formula `8080 + minor`). A version that is not `8.<minor>` falls back to the default URL rather than emitting a bogus port. |
| `docroot` | string | `"."` | Relative to the repo root, and **the web root ePHPm serves** — switchboard publishes it as ePHPm's per-site document-root override. Also sets the WebSocket auto-detect path and the working directory of `seed:` steps. A value ePHPm would refuse (`..`, absolute, non-existent) **fails the deploy**. The default `"."` means your **entire repository is web-served** — supported, warned about on every deploy, and narrowed only by declaring a subdirectory. See [§5](#5-docroot-is-your-web-root). |
| `build` | list of strings | `[]` | Shell commands run in order at the container root, **after** the atomic swap, each **sandboxed** via `ephpm exec --site` (tenant uid + Landlock + egress firewall — see [§8](#8-build-and-seed-run-sandboxed-outside-an-ephpm-request)), never as root. A failing step is logged and the deploy **continues**. If `build` is empty and a `composer.json` exists, an implicit `composer install --no-dev --no-interaction --optimize-autoloader --quiet` runs instead. |
| `services.database` | `"turso"` \| `false` | `"turso"` | `"turso"` (case-insensitive), `true`, `false`, or `"none"`. Any other string is a parse error naming the field. |
| `services.kv` | bool | `true` | Requests the embedded KV store. |
| `services.websocket` | bool | *auto* | Unset means: enabled if `websocket.php` exists at `<repo>/<docroot>`. An explicit `true`/`false` always wins. |
| `seed` | list of strings | `[]` | Shell commands run **after** the swap, **sandboxed** via `ephpm exec --site` (see [§8](#8-build-and-seed-run-sandboxed-outside-an-ephpm-request)), with the working directory `<site>/<docroot>`, and `$PREVIEW_URL`, `$PREVIEW_HOST`, `$PR` in the environment. Failures are logged and the deploy continues. |
| `env` | map | `{}` | Values are literals or `${secret.NAME}`. See [§3](#3-the-env-block-and-what-actually-reaches-php). |
| `health` | string | `"/"` | Appended to the preview URL and polled for HTTP 200 before the deploy is reported ready. |
| `ini` | map | `{}` | **Advisory in v1.** Recorded in a sidecar file; nothing applies it to the running server. Setting `memory_limit` here does nothing today. |

`ephpm.json` is a deprecated POC format. It is still read (only `seed` as a
single string, and `php`) and logs a deprecation warning. Precedence:
`ephpm.yaml` → `ephpm.yml` → `ephpm.json` → framework defaults.

### If you ship no manifest

**Verified** in `AppManifest::from_framework`. Detection order: `wp-config.php`
or `wp-config-sample.php` → WordPress; then `composer.json` containing
`laravel/framework` / `drupal/core` / `symfony/framework-bundle`; then an
`artisan` file → Laravel; otherwise generic PHP.

| Detected | `docroot` | `build` | `seed` |
|---|---|---|---|
| WordPress | `.` | *(implicit composer if `composer.json`)* | `wp core install …` |
| Laravel | `public` | `composer install …`, `php artisan key:generate --force` | `php artisan migrate --force` |
| Symfony | `public` | `composer install …` | — |
| Drupal | `web` | `composer install …` | — |
| Generic | `.` | *(implicit composer if `composer.json`)* | — |

The Laravel/Symfony/Drupal rows depend on the operator having configured
`--site-overrides-dir` — read [§5](#5-docroot-is-your-web-root). Read
[§8](#8-build-and-seed-run-sandboxed-outside-an-ephpm-request) before relying on
their `seed:` steps.

`ephpm/wordpress-sample` ships a conforming manifest —
[`ephpm.yaml`](https://github.com/ephpm/wordpress-sample/blob/main/ephpm.yaml)
is the reference example.

### Secrets

`${secret.NAME}` is resolved from **switchboard's own** secret store — the
operator's config, never anything in your repository. Resolution is fail-safe: a
missing secret logs a name-only warning and expands to the empty string; the
deploy is not failed. Text around the reference passes through, so
`"prefix-${secret.token}"` works, and several references in one value all
resolve.

Ask the operator to add a secret; you cannot supply one from the repo.

---

## 2. Read `$_SERVER`, not `getenv()`

**This is the single thing most likely to break your app.**

ePHPm injects your preview's database and KV credentials through the SAPI's
`register_server_variables` hook. They land in `$_SERVER` and **only** in
`$_SERVER`. There is deliberately no `sapi_module.getenv` handler: the process
environment is shared by every worker thread serving every tenant, so putting
one tenant's credentials there would be a cross-tenant leak.

**Verified** by running this on a live vhost:

```
DB_HOST:         $_SERVER=SET  $_ENV=absent  getenv=false
DB_USER:         $_SERVER=SET  $_ENV=absent  getenv=false
DB_PASSWORD:     $_SERVER=SET  $_ENV=absent  getenv=false
EPHPM_REDIS_HOST:$_SERVER=SET  $_ENV=absent  getenv=false
```

So:

```php
$_SERVER['DB_PASSWORD']   // the value
getenv('DB_PASSWORD')     // false
$_ENV['DB_PASSWORD']      // undefined
```

### It is worse than "absent": it can be *wrong*

`variables_order` is `EGPCS` — that is PHP's own compiled-in default, which ePHPm
does not override (an operator's `[php] ini_file` or `ini_overrides` could). So
`$_ENV` **is** populated — from the ePHPm process's real environment. If the
host process happens to have a variable with a name you also expect
(`DATABASE_URL` is a realistic collision), `getenv()`
returns that unrelated value instead of failing loudly. During verification the
host process had an unrelated `DATABASE_URL` set, and `getenv('DATABASE_URL')`
returned it while `$_SERVER['DATABASE_URL']` held the correct per-site DSN.
Prefer `$_SERVER` explicitly rather than assuming a falsy `getenv()` will tell
you something is missing.

### Laravel and Symfony: `env()` already works

**Verified** in upstream source, not assumed. `vlucas/phpdotenv`'s
`RepositoryBuilder::DEFAULT_ADAPTERS` is:

```php
private const DEFAULT_ADAPTERS = [
    ServerConstAdapter::class,   // $_SERVER  ← consulted first
    EnvConstAdapter::class,      // $_ENV
];
```

and Laravel's `Illuminate\Support\Env::getRepository()` appends
`PutenvAdapter` *after* those, so `putenv` is lowest priority:

```php
$builder = RepositoryBuilder::createWithDefaultAdapters();
if (static::$putenv) { $builder = $builder->addAdapter(PutenvAdapter::class); }
```

`$_SERVER` is read first. `env('DB_PASSWORD')` therefore returns the injected
value and **beats** a conflicting process-environment variable. Symfony's
`Dotenv`/`$_SERVER` handling is the same shape.

Two Laravel-specific traps remain, and they are Laravel's, not ePHPm's:

- `php artisan config:cache` freezes whatever `env()` returned **at cache
  time**. Credentials rotate on every restart of the host (see below), so a
  cached config will point at a dead password. Do not run `config:cache` in
  `build:`.
- Outside `config/*.php`, `env()` returns `null` once config is cached. Read
  `config('database.connections…')`, or `$_SERVER` directly.

### The credentials rotate

The per-site database password is `HMAC-SHA256(master_secret, site_key)` where
the master secret is 32 random bytes generated in memory at host startup and
never written to disk. **Restarting the host changes every site's password.**
Read it from `$_SERVER` on every request; never bake it into `wp-config.php`,
`.env`, or a cached config.

---

## 3. The `env:` block, and what actually reaches PHP

This is the least intuitive part of the contract, so it is worth being precise.
**Verified** in `src/deployer.rs::materialize_env`.

At deploy time switchboard resolves your `env:` map and writes, at your
repository root:

| File | When | Web-reachable? |
|---|---|---|
| `.env` | always | No — dot-prefixed paths return **403** |
| `.ephpm-preview-prepend.php` | always | No — **403** |
| `.switchboard-preview.json` | always (env **keys** only, never values) | No — **403** |
| `.switchboard/ephpm.yaml` | always — this is where your manifest is moved to | No — **403** |

All of them are dot-prefixed, and ePHPm's `hidden_files` default is `deny`
(it rejects a dot-prefixed segment *anywhere* in the request path), so none of
them is readable over HTTP even when your repository root *is* the web root.
That is what makes writing the `.env` there safe — and it is why your manifest
is relocated rather than left at `./ephpm.yaml`, where it was being served
(switchboard#16).

So:

- **Any app whose framework reads a `.env`** (Laravel, Symfony, Drupal, and
  anything using `vlucas/phpdotenv` or `symfony/dotenv`) gets its `env:` values
  with no work. ⚠️ **switchboard overwrites `.env`.** If your repo commits one,
  it is replaced by the preview's — put preview values in `env:`. The deploy
  logs a warning when it replaces a committed file.
- **Apps that do not read a `.env`** (WordPress, most bespoke apps) need one
  line — see below. There is no `auto_prepend_file` on this host:
  ePHPm's per-site override channel understands `document_root` and nothing
  else, so nothing loads the prepend for you
  ([switchboard#4](https://github.com/ephpm/switchboard/issues/4) tracks
  closing that, which needs a change in ePHPm itself).
  **Verified:** `ini_get('auto_prepend_file')` on a live preview returns `''`.

### If your framework does not read `.env` — load the prepend yourself

**Verified working** on a live preview:

```php
// wp-config.php (or your front controller), at the very top
$__preview = __DIR__ . '/.ephpm-preview-prepend.php';
if (is_file($__preview)) {
    require_once $__preview;   // sets putenv() + $_ENV + $_SERVER
}
```

Measured before and after that line on a live vhost:

```
before: getenv=false     server=NULL
after:  getenv='staging' server='staging' env='staging'
```

The file is generated only on the preview host, so the `is_file` guard keeps
this a no-op in development and production. It is not web-reachable (403), so
including it does not expose your secrets.

*(A first-class fix belongs in switchboard/ePHPm rather than in every app — see
[§11](#11-known-gaps-and-in-flight-work).)*

---

## 4. Database

Your preview gets its **own** database file — an embedded, SQLite-compatible
Turso database, one per virtual host. Nothing is shared with other previews.
There is no MySQL server and no PostgreSQL server on the host.

Two ways to reach it. Both resolve to the same backend and the same file.

### Path A — stock `pdo_mysql` (compatibility)

ePHPm runs one MySQL-wire listener that speaks to your database, and injects a
per-site credential into your requests. Your ORM does not know anything changed.

**Verified** injected keys, per request, in per-site mode:

| Variable | Value |
|---|---|
| `DB_CONNECTION` | `mysql` |
| `DB_HOST` / `DB_PORT` | the listener's host and port (e.g. `127.0.0.1` / `3306`) |
| `DB_DATABASE`, `DB_NAME` | your site key |
| `DB_USER`, `DB_USERNAME` | your site key |
| `DB_PASSWORD` | HMAC-derived, rotates per host restart |
| `DATABASE_URL` | `mysql://<key>:<password>@<host>:<port>/<key>` |

Note both spellings are provided: `DB_DATABASE`/`DB_USERNAME` (Laravel's names)
and `DB_NAME`/`DB_USER`. This is the **per-site** shape; a single-site ePHPm
deployment fronting a real MySQL/Postgres server injects a smaller set
(`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_CONNECTION`,
`DATABASE_URL`) — so do not hard-code the presence of `DB_DATABASE`.

```php
$pdo = new PDO(
    "mysql:host={$_SERVER['DB_HOST']};port={$_SERVER['DB_PORT']};dbname={$_SERVER['DB_NAME']}",
    $_SERVER['DB_USER'],
    $_SERVER['DB_PASSWORD'],
);
```

**Verified end to end** on a live preview: `pdo_mysql` connect + query
succeeded, and presenting a *neighbour's* username with our password was
refused before any of that site's data was touched:

```
SQLSTATE[HY000] [1698] Authenticate failed, user: "laravel-pr-2.preview.test"
```

The username is a claim; the credential is the identity. Details:
[Multi-tenant `pdo_mysql`](https://ephpm.dev/guides/multi-tenant-pdo-mysql/).

### Path B — the native bridge (no socket, no credential)

ePHPm exposes `ephpm_db_*` functions in-process. No wire protocol, no
connection setup, nothing to authenticate. Install the adapter for your stack
rather than calling the raw functions:

| Package | For |
|---|---|
| [`ephpm/db`](https://github.com/ephpm/db) | base library, typed `Connection` |
| [`ephpm/db-wordpress`](https://github.com/ephpm/db-wordpress) | `wp-content/db.php` drop-in (wpdb) |
| [`ephpm/db-laravel`](https://github.com/ephpm/db-laravel) | `'driver' => 'ephpm'` |
| [`ephpm/db-doctrine`](https://github.com/ephpm/db-doctrine) | DBAL 4 (not DBAL 3) |
| [`ephpm/mysqli-shim`](https://github.com/ephpm/mysqli-shim) | userland `mysqli` surface |

These are distributed from their GitHub repos as Composer `vcs` repositories,
**not Packagist**.

**Verified** on a live preview: `ephpm_db_query` created a table, inserted, and
read it back, and the same rows were then visible over `pdo_mysql`.

### Which to choose

Use **Path A** if you want zero code change and your framework already speaks
PDO. Use **Path B** if you want to skip the per-request connection setup and the
wire round trip, or if your adapter already exists (WordPress and Laravel both
do). The `wordpress-sample` showcase uses Path B.

### SQL dialect

It is SQLite underneath, with MySQL wire translation on Path A. Vendor-specific
MySQL SQL (stored procedures, `ENUM` semantics, MySQL-only functions) will not
all survive. Keep preview seed data simple, and if your app has MySQL-only
migrations, that is the thing most likely to fail first.

---

## 5. `docroot:` is your web root

`docroot:` now decides what the preview serves. At deploy time switchboard
translates it into ePHPm's per-site document-root override — an
**operator-owned** file outside your checkout (`[server] site_overrides_dir`, a
`<site-key>.toml` carrying `document_root = "public"`). ePHPm deliberately never
reads a document root from inside your repository, because a tenant must not be
able to re-point its own web root; switchboard is the trusted party that
translates your manifest into that file.

So for `docroot: "public"`:

```
GET /                          → your front controller (public/index.php)
GET /vendor/secret.txt         → 404   (outside the web root)
GET /storage/logs/laravel.log  → 404   (outside the web root)
GET /composer.json             → 404   (outside the web root)
```

This is what the WordPress case (`docroot: "."`) always did — its repository
root *is* its web root, so nothing changes for it.

### `docroot: "."` publishes your whole repository

`docroot: "."` is still supported and is still the default: WordPress genuinely
serves from its repository root. But be clear about what it means — **every
non-dot-prefixed file in your checkout is public**, including anything a
`build:` step wrote. There is no override, on any node, that narrows a web root
you declared to be the repository root. The deploy logs a warning saying so on
every `docroot: "."` deploy.

Two things switchboard does about it, and one it cannot:

* your `ephpm.yaml` (and `ephpm.yml` / `ephpm.json`) is **moved to
  `.switchboard/` before the site goes live**, so it is never served. It used to
  be: `GET /ephpm.yaml` returned 200 with your build commands, your enabled
  services and your entire seed sequence (switchboard#16). Both `build:` and
  `seed:` run **after** the manifest is moved (and after the atomic swap), so a
  step that needs the manifest must read it at `.switchboard/ephpm.yaml`, not
  `./ephpm.yaml`;
* everything switchboard itself generates (`.env`, the prepend, the sidecar) is
  dot-prefixed and therefore already a 403;
* it cannot vet **your** files. A `docroot: "."` preview publishes
  `composer.json`, `README.md`, any `*.sql` dump, any log a build step left, and
  anything else you commit. Declare a `docroot:` subdirectory if you have
  anything at the root you would not paste into a public issue.

### Rules your `docroot:` must satisfy

The deploy **fails loudly** rather than silently serving your whole checkout if
`docroot:` is anything ePHPm would refuse:

* a plain relative path (`public`, `web`, `app/htdocs`) — no `..`, no leading
  `/`, no drive letter, no backslashes;
* characters from `[A-Za-z0-9._/-]` only;
* it must **exist** in the checkout as fetched, and be a directory. `docroot:`
  is validated **before** `build:` runs (and before the swap), so a web root that
  only a `build:` step would create is not supported — commit the directory (even
  empty) or have your framework ship it.
* a symlink is fine as long as it resolves inside your checkout.

### Two things to check with your operator

1. `--site-overrides-dir` must be configured on the preview host. If it is not,
   there is nowhere to publish your `docroot:`, ePHPm serves your whole
   checkout, and the deploy logs a warning saying exactly that. A preview whose
   `/vendor/composer.json` returns 200 is the symptom.
2. Everything above your web root is now unreachable — but that is a property of
   the override, not of your repository. Keep treating a checkout as public
   anyway: truncate `storage/logs` in a `build:` step and never commit secrets.

---

## 6. What is restricted, and what will break

Your preview shares one OS process and one uid with every other preview. The
boundary is `open_basedir` plus a function denylist, applied per request.

On a multi-tenant host these are **on by default** — the three switches
(`open_basedir`, `disable_shell_exec`, `multi_tenant_hardening`) each resolve to
`true` when `sites_dir` is set. **Verified** by reading them back from a live
request.

### `open_basedir`

Set per request to exactly two entries: **your site container** and **your
private temp/session root**. Not the shared `/tmp`. Measured:

```
open_basedir = <sites_dir>/<site-key> : <tmp>/ephpm-vhosts/<site-key>-<hash>
```

(The site key is your preview host with the host's domain suffix stripped —
`ephpm-my-app-pr-42`, not the full FQDN, on the standard preview cluster.)

Note this is the **container**, not your `docroot:` — so PHP can still
`require` from above your web root, which is exactly what a front-controller
app needs. `docroot:` narrows what HTTP serves, not what PHP can open.

and reading a neighbouring site's `.env` by absolute path returned `false`
(**verified**). `sys_temp_dir`, `upload_tmp_dir` and `session.save_path` are
pointed inside that private root so uploads, `tmpfile()` and sessions all land
somewhere permitted.

Practical effect: you cannot read or write anything outside your own checkout.
No `/etc`, no shared cache directory, no sibling preview.

### Disabled functions

**Verified** — the exact `disable_functions` read back from a live preview:

```
exec, passthru, shell_exec, system, proc_open, popen,
pcntl_exec, pcntl_fork, pcntl_signal, pcntl_alarm, pcntl_wait, pcntl_waitpid,
pcntl_async_signals, pcntl_signal_dispatch, pcntl_sigprocmask,
pcntl_sigwaitinfo, pcntl_sigtimedwait,
posix_kill, posix_setuid, posix_setgid, posix_seteuid, posix_setegid,
pfsockopen, fsockopen,
shm_attach, shm_get_var, shm_put_var, shm_remove, shm_detach, shm_has_var,
sem_get, sem_acquire, sem_release, sem_remove,
msg_get_queue, msg_send, msg_receive, msg_remove_queue, msg_set_queue,
msg_stat_queue,
dl, mail,
opcache_reset, opcache_compile_file, opcache_invalidate, opcache_get_status,
opcache_get_configuration, opcache_is_script_cached
```

Still callable, and **verified** so: `putenv`, `stream_socket_client`,
`curl_init`, `symlink`, `link`.

That is one host's `disable_functions`, not a fixed contract — two subsets of it
are conditional, so read the value back rather than assuming:

- **`fsockopen`** is disabled by default but is deliberately *restored* when the
  operator sets `network_egress_externally_managed = true` (i.e. egress is
  policed outside PHP). `pfsockopen` stays disabled either way.
- **`opcache_invalidate`, `opcache_get_status`, `opcache_get_configuration`,
  `opcache_is_script_cached`** are disabled only when `[opcache]
  cluster_invalidation` is off. That knob defaults to `cluster.enabled`, so on a
  clustered preview host these four remain **callable**. `opcache_reset` and
  `opcache_compile_file` are always disabled.

An operator can also add entries of their own, so the effective list is only ever
a superset of the above. Read it with `ini_get('disable_functions')`.

What this costs you in practice:

- **No shelling out at runtime.** Anything that calls `exec`/`proc_open` from a
  request — image tooling that shells to `convert`, `wkhtmltopdf`, a
  queue worker that spawns a child, a "system info" admin page — will fail. Use
  a PHP-native path or drop the feature from the preview.
- **No `mail()`.** Mail-sending flows must be stubbed or routed through an API
  over HTTP (curl still works).
- **No `opcache_*`.** Deployment tooling that resets OPcache will fatal.
- **`dl()` is gone**, so you cannot load a PHP extension at runtime.
- **`fsockopen` is gone**, but `stream_socket_client` and curl are not — most
  HTTP clients (Guzzle, WordPress `WP_Http`) use one of those and keep working.

### ⚠️ Persistent connections are disabled

This deserves its own callout because the failure is confusing: your code is
correct, the library is correct, and the connection still refuses to open.

`multi_tenant_hardening` sets `mysqli.allow_persistent = 0` (**verified**:
`ini_get('mysqli.allow_persistent')` returns `'0'`), along with
`pgsql.allow_persistent = 0` and `odbc.allow_persistent = 0`, and removes
`pfsockopen`. Persistent handles are keyed without a tenant component, so one
preview could inherit another's connection — that is the reason, and it is not
negotiable on a shared host.

Breaks:

- `mysqli` with a `p:` host prefix
- phpredis `pconnect` / `Redis::pconnect`
- anything built on `pfsockopen`

Does **not** break: ordinary PDO connections, `stream_socket_client`, curl.

⚠️ **PDO is the exception, and it is not enforced.** `PDO::ATTR_PERSISTENT` has
no global ini equivalent, so the host **cannot** switch it off — ePHPm's source
calls this a documented residual. Do not read "persistent connections are
disabled" as "PDO persistence is safely blocked for me": nothing blocks it, and
a pooled PDO handle on a shared host is exactly the cross-tenant reuse the rest
of this section exists to prevent. Turn it off yourself.

If your app enables persistent connections by config, turn them off for the
preview.

### Extensions

You cannot add extensions to a preview (`dl` is disabled and `extension=` is
operator config).

**Not tested** — reported by the [`ephpm/php-sdk`](https://github.com/ephpm/php-sdk)
build, which is the authority: Linux builds carry `bcmath, bz2, calendar, ctype,
curl, dom, exif, fileinfo, filter, ftp, gd, gettext, gmp, hash, iconv, intl,
mbstring, mysqli, mysqlnd, opcache, openssl, pcntl, pcre, pdo, pdo_mysql,
pdo_pgsql, pdo_sqlite, pgsql, phar, posix, session, shmop, simplexml, soap,
sockets, sodium, sqlite3, sysv*, tokenizer, xml, xmlreader, xmlwriter, xsl,
zip, zlib`. Notably absent from the base build: `apcu`, `redis`, `igbinary`,
`msgpack`, `mongodb` (built separately as shared objects), and `imagick`.

Do not take that list on faith for a specific host — the reliable check is to
deploy a one-line preview and read it:

```php
<?php header('Content-Type: text/plain');
echo implode("\n", get_loaded_extensions());
```

### Rate limits

A preview host commonly runs ePHPm's preview preset, which applies per-IP and
per-site limits and stamps every response with `X-Ephpm-Preview: 1`. **Verified**
in ePHPm's config source, the preset's unset-knob defaults are: 256 max
connections, 32 per IP, 10 req/s per IP (burst 50), and **5 req/s per site
(burst 20)**.

If your app fires a burst of sub-requests, or you crawl your own preview during
seeding, you will see 429s. That is the limiter, not your app. Check for
`X-Ephpm-Preview: 1` to know you are on a preview and can degrade accordingly.
**Not tested** here whether a given host enables the preset — ask the operator,
or look for the header.

---

## 7. Sessions and WebSockets

### Sessions work out of the box

**Verified** on a live preview across two requests sharing a cookie jar: the
stock `files` handler, with `session.save_path` pointed at your vhost's private
directory, and the counter incremented correctly.

```
id=5983d827…  n=1  handler=files
save_path=<tmp>/ephpm-vhosts/<your-host>-<hash>/sessions
files=["sess_5983d827…"]
```

No other preview can read that directory — it is the only temp entry in your
`open_basedir` and it appears in no one else's.

You only need [`ephpm/session-handler`](https://github.com/ephpm/session-handler)
(sessions in the KV store) if you want sessions to survive across a clustered,
multi-node host. For a single-node preview the default is fine.

### WebSockets

**Verified** in ePHPm's config source. Native WebSockets are opt-in on the
server (`[server.websocket] enabled` defaults to `false`), and are HTTP/1.1
only. When enabled:

- The entrypoint is resolved from `websocket_files` — default `["websocket.php"]`
  — **against your vhost's document root**, i.e. your repo root today.
- The first name that exists wins, and receives every event for connections
  upgraded on your vhost: `connect`, `message`, `disconnect`, distinguished by
  `$_SERVER['WS_EVENT']`.
- If no name matches, an upgrade request gets **404**. It never falls through
  to `index.php` or the fallback chain, so a site that has not opted in cannot
  accidentally serve one.

In the manifest, `services.websocket` unset means "auto-detect
`<docroot>/websocket.php`". Since the served document root is the repo root
today, put `websocket.php` at the **repo root** and set `services.websocket:
true` explicitly if your `docroot` is anything but `.`.

Details: [Native WebSockets](https://ephpm.dev/guides/websockets/).

---

## 8. Build and seed run sandboxed, outside an ePHPm request

`build:` and `seed:` are shell commands, not ePHPm requests. They are **not** run
as root: switchboard runs each one through ePHPm's sandboxed execution primitive
(`ephpm exec --site <your key>`), which drops to the unprivileged tenant uid,
confines the filesystem to your vhost with Landlock, and puts your command behind
the host's per-tenant **egress firewall**. `build:` runs at your container root
(where `composer.json` is); `seed:` runs at your document root. That means:

- They get **no** `$_SERVER['DB_*']`. There is no way for a shell command to
  learn your preview's database password — it exists only in the server's
  memory and is minted per request.
- Your preview's own database and KV listeners are on `127.0.0.1`, and the
  egress firewall **drops loopback** for the tenant uid — so a `seed:` step
  cannot reach them directly even by guessing the port. Touch the database the
  way a request does (below), not with `mysql -h 127.0.0.1`.
- `ephpm php` (the bundled CLI) does not help: it is a separate process with no
  server config. **Verified** — `ephpm php -r 'ephpm_db_query("SELECT 1")'`
  returns `ephpm_db: no embedded database is active (requires [db.sqlite])`.
- A system `php` binary, if the host has one, has no ePHPm SAPI at all, so a
  `db-wordpress` / `db-laravel` drop-in will not function under it.

So: **anything that must touch your preview's database has to run as an HTTP
request to your own preview.** That is the pattern `ephpm/wordpress-sample`
uses — its seed step drives in-docroot generator scripts over HTTP so every
insert runs through the drop-in.

```yaml
seed:
  # Runs as a plain shell command — reaches the DB only via HTTP.
  - "curl -fsS --max-time 300 \"$PREVIEW_URL/preview-seed.php?token=$SEED_TOKEN\""
```

Guard that endpoint (a token you also pass in `env:`, and delete or 404 it once
seeded) — your preview URL is reachable by anyone who can guess it unless the
operator has an auth gate in front.

Things that are fine in `build:` because they do not need the database:
`composer install`, asset builds, `php artisan key:generate`. Things that are
**not**: `php artisan migrate`, `wp core install`, any data seeding. The
framework defaults switchboard synthesizes for Laravel put `php artisan migrate
--force` in `seed:` — on the current host that step cannot reach the database.

The health gate polls `health:` for a 200 for up to the operator's timeout
(default 60s, 2s interval) before the preview is reported ready. Failures in
`build:` and `seed:` do **not** fail the deploy — check the health status, and
make `health:` a path that is only 200 once your app is genuinely usable.

---

## 9. Recipes

### WordPress

The happy path — repo root is the web root, so nothing about §5 applies.

```yaml
version: 1
php: "8.5"
docroot: "."
services:
  database: "turso"
  kv: true
seed:
  - "curl -fsS \"$PREVIEW_URL/preview-install.php?token=$INSTALL_TOKEN\""
env:
  WP_ENVIRONMENT_TYPE: "staging"
  INSTALL_TOKEN: "${secret.install_token}"
health: "/"
```

In `wp-config.php`, top of file:

```php
// Preview env (see §3) — no-op outside the preview host.
$__preview = __DIR__ . '/.ephpm-preview-prepend.php';
if (is_file($__preview)) { require_once $__preview; }

// Database: either the drop-in (recommended) or these constants.
if (isset($_SERVER['DB_HOST'])) {
    define('DB_HOST',     $_SERVER['DB_HOST'] . ':' . $_SERVER['DB_PORT']);
    define('DB_NAME',     $_SERVER['DB_NAME']);
    define('DB_USER',     $_SERVER['DB_USER']);
    define('DB_PASSWORD', $_SERVER['DB_PASSWORD']);
}
```

Recommended packages: [`ephpm/db-wordpress`](https://github.com/ephpm/db-wordpress)
(`wp-content/db.php` drop-in) and
[`ephpm/cache-wordpress`](https://github.com/ephpm/cache-wordpress)
(`object-cache.php` drop-in). With the db drop-in you do not need the
`define()` block at all.

Watch out for: plugins that shell out (§6), plugins that call `mail()`, and —
if you install themes or plugins at runtime — confirming `zip` is actually
present on your host rather than assuming it (§6).

### Laravel

```yaml
version: 1
php: "8.5"
docroot: "public"           # the web root ePHPm serves
build:
  - "composer install --no-dev --optimize-autoloader --no-interaction"
  - "php artisan key:generate --force"
seed:
  - "curl -fsS \"$PREVIEW_URL/preview-migrate.php?token=$MIGRATE_TOKEN\""
env:
  APP_ENV: "staging"
  APP_DEBUG: "false"
  SESSION_DRIVER: "file"
  CACHE_STORE: "file"
  MIGRATE_TOKEN: "${secret.migrate_token}"
health: "/"
```

- Confirm with your operator that `--site-overrides-dir` is configured; without
  it `docroot: public` cannot be published and the preview serves the whole
  checkout (§5).
- **Do not** run `php artisan config:cache` — it freezes rotating credentials
  (§2).
- `env('DB_PASSWORD')` works (verified adapter order, §2). Leave
  `config/database.php` on the default `mysql` connection: `DB_CONNECTION`,
  `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USERNAME`, `DB_PASSWORD` are all
  injected under exactly the names Laravel reads.
- Or install [`ephpm/db-laravel`](https://github.com/ephpm/db-laravel) and set
  `'driver' => 'ephpm'` to skip the wire entirely.
- Cache: [`ephpm/cache-laravel`](https://github.com/ephpm/cache-laravel) for the
  native KV, or leave `CACHE_STORE=file`. Do **not** point `REDIS_HOST` at
  anything without reading §10 — there is no Redis server; the RESP listener
  needs the `EPHPM_REDIS_*` credentials mapped across (below).
- Queues: no `pcntl`, no shelling out, so a `queue:work` worker is not viable in
  a preview. Use `QUEUE_CONNECTION=sync`.
- Octane: [`ephpm/octane-driver`](https://github.com/ephpm/octane-driver) exists,
  but worker mode is a different runtime shape than the per-request preview
  path — **not tested** as part of this guide.

### Symfony

Same shape as Laravel.

```yaml
version: 1
php: "8.5"
docroot: "public"
build:
  - "composer install --no-dev --optimize-autoloader --no-interaction"
env:
  APP_ENV: "prod"
  APP_DEBUG: "0"
health: "/"
```

- Same `--site-overrides-dir` prerequisite as Laravel (§5).
- `DATABASE_URL` is injected into `$_SERVER`, which Symfony's `Dotenv`
  respects. Beware the collision described in §2: prefer an explicit
  `$_SERVER['DATABASE_URL']` read if you are debugging a wrong-DSN symptom.
- Doctrine: [`ephpm/db-doctrine`](https://github.com/ephpm/db-doctrine) (DBAL 4
  only) if you want the native bridge.
- `bin/console doctrine:migrations:migrate` in `seed:` will **not** reach the
  database (§8). Trigger migrations over HTTP.

### Bespoke apps

The shortest working manifest is:

```yaml
version: 1
```

That gives you PHP 8.5, the repo root as web root, an implicit `composer
install` if you have a `composer.json`, a per-site database, the KV store, and
`/` as the health path.

Checklist for anything hand-rolled:

- Read credentials from `$_SERVER`, with a fallback for local dev.
- Put your entrypoint at the repo root, or name its directory in `docroot:` (§5).
- No `exec`, no `mail`, no persistent connections.
- Anything needing the database at deploy time goes over HTTP (§8).
- Assume every non-dotfile in your repo is web-readable.

---

## 10. KV / Redis, and the naming asymmetry

You get an embedded KV store. There is **no Redis server** — the store is
in-process, with a RESP-compatible listener in front of it for clients that
speak Redis.

### Path A — native

Install a package and forget about connections:
[`ephpm/cache`](https://github.com/ephpm/cache) (PSR-6/PSR-16),
[`ephpm/cache-laravel`](https://github.com/ephpm/cache-laravel),
[`ephpm/cache-symfony`](https://github.com/ephpm/cache-symfony),
[`ephpm/cache-wordpress`](https://github.com/ephpm/cache-wordpress),
[`ephpm/predis-connection`](https://github.com/ephpm/predis-connection) (a
Predis `Connection` backend, so `Predis\Client` keeps working),
[`ephpm/session-handler`](https://github.com/ephpm/session-handler).

**Verified**: `ephpm_kv_set` / `ephpm_kv_get` round-tripped on a live preview.

### Path B — RESP, with the injected credentials

**Verified** injected keys:

| Variable | Meaning |
|---|---|
| `EPHPM_REDIS_HOST` | listener host |
| `EPHPM_REDIS_PORT` | listener port |
| `EPHPM_REDIS_USERNAME` | your site key — the AUTH username |
| `EPHPM_REDIS_PASSWORD` | HMAC-derived, rotates per host restart |

⚠️ **The naming is asymmetric and it will bite you.** The database variables use
the conventional names your framework already reads (`DB_HOST`, `DB_DATABASE`,
`DATABASE_URL`). The KV variables do **not** — they are `EPHPM_`-prefixed,
while Laravel reads `REDIS_HOST`/`REDIS_PORT`/`REDIS_PASSWORD` and
`REDIS_USERNAME`. Nothing bridges the two for you.

The KV listener also requires a **two-argument** `AUTH <username> <password>` in
multi-tenant mode; a one-argument `AUTH <password>` is rejected. Clients
configured with only a password will fail to authenticate.

Map them yourself. The `env:` block cannot do it (values are literals or
secrets, not references to injected variables), so do it in PHP:

```php
// config/database.php — Laravel
'redis' => [
    'default' => [
        'host'     => $_SERVER['EPHPM_REDIS_HOST']     ?? env('REDIS_HOST', '127.0.0.1'),
        'port'     => $_SERVER['EPHPM_REDIS_PORT']     ?? env('REDIS_PORT', 6379),
        'username' => $_SERVER['EPHPM_REDIS_USERNAME'] ?? env('REDIS_USERNAME'),
        'password' => $_SERVER['EPHPM_REDIS_PASSWORD'] ?? env('REDIS_PASSWORD'),
        'database' => 0,
        'persistent' => false,   // §6 — persistent connections are disabled
    ],
],
```

Remember `pconnect` is disabled (§6), so phpredis must be configured
non-persistent.

Honestly: on a preview, **Path A is less work**. Use the native cache package
and skip the mapping entirely.

Details: [KV from PHP](https://ephpm.dev/guides/kv-from-php/).

---

## 11. Known gaps and in-flight work

Labelled so you do not build on them.

| Item | Status |
|---|---|
| Your `ephpm.yaml` at the web root | **Moved, not served.** The deploy relocates `ephpm.yaml` / `ephpm.yml` / `ephpm.json` to `.switchboard/` before the site goes live. It used to be a public 200 on `docroot: "."` sites. Both `build:` and `seed:` now run after the move (and after the swap), so either that reads the manifest must use the new path. [switchboard#16](https://github.com/ephpm/switchboard/issues/16). |
| `docroot: "."` | **Supported, and it publishes your whole repository.** Warned on every deploy. Nothing narrows it except declaring a subdirectory — switchboard removes its own artifacts and your manifest, but cannot vet your files. |
| Per-site document root (`docroot:` routing) | **Shipped both sides.** ePHPm reads an operator-owned override outside the tenant checkout (`[server] site_overrides_dir`); switchboard generates it from your `ephpm.yaml` `docroot:`. **Requires the operator to set `--site-overrides-dir`** — unset, ePHPm serves the whole checkout and the deploy warns. |
| `auto_prepend_file` per site | **Not available.** ePHPm's per-site override channel understands `document_root` and nothing else, so the generated `.ephpm-preview-prepend.php` is never auto-loaded. Apps that need it `require_once` it (§3). [switchboard#4](https://github.com/ephpm/switchboard/issues/4). |
| `ini:` block | **Advisory only.** Recorded in a sidecar; nothing applies it. `memory_limit` in your manifest does nothing. The deploy warns when you set it. |
| `env:` | Delivered via a generated `.env` for every `docroot:` shape. **Overwrites a committed `.env`** (logged). Apps that do not read a `.env` need the one-line `require_once` in §3. |
| Auth gate for private previews | **Not available.** Middleware for gating previews behind HTTP Basic / signed session cookies / GitHub OAuth was proposed upstream (ePHPm PRs #387, #388, #389) and **closed unmerged** — there is no basic-auth, session-cookie or OAuth builtin today. Assume your preview URL is public. |
| Seeding via KV-sourced credentials in multi-tenant mode | **Not possible today** (ePHPm issue #384) — the RESP listener has no operator-scoped path in multi-tenant mode. |
| Clustered / multi-node previews | Per-site database isolation is **single-node only**. |
| `build:` / `seed:` failures | Logged, not fatal. Use `health:` as your real gate. |

---

## Cross-references

This page is deliberately app-facing. The server's own behaviour is documented
upstream — go there rather than trusting a paraphrase:

- [Virtual hosts](https://ephpm.dev/guides/virtual-hosts/) — vhost resolution, isolation model
- [Multi-tenant `pdo_mysql`](https://ephpm.dev/guides/multi-tenant-pdo-mysql/) — per-site credentials, threat model
- [Database from PHP](https://ephpm.dev/guides/db-from-php/) — the `ephpm_db_*` bridge
- [KV from PHP](https://ephpm.dev/guides/kv-from-php/) — the KV store and RESP listener
- [Native WebSockets](https://ephpm.dev/guides/websockets/)
- [WordPress](https://ephpm.dev/guides/wordpress/) · [Laravel](https://ephpm.dev/guides/laravel/)
- [Configuration reference](https://ephpm.dev/reference/config/) — every server knob
- [PHP packages](https://ephpm.dev/reference/php-packages/) — the Composer adapters
