# Preview access gate — design (switchboard#26, Part B)

## Status

**Specified, not implemented in switchboard.** The clean enforcement point is in
**ePHPm**, not switchboard, so this PR delivers Part A (authenticated fetch) and
this written design for Part B. The enforcement change is tracked as a companion
ePHPm issue; the switchboard-side piece (generate a per-preview credential, write
it into the per-site override, surface it in the PR comment) lands **after** that
ePHPm key exists — writing it sooner would be an inert, bypassable gate, which is
worse than an honestly-documented gap.

## The problem

A deployed preview serves to anyone who resolves `*.preview.ephpm.dev`. Once
switchboard can check out **private** repositories (Part A of #26), that preview
is a private repo's code and content served to the whole internet. Fetching
private code is pointless if the result is world-readable, so the two are one
decision.

## Threat model

**What the gate defends:** *preview privacy.* It stops a random internet visitor
— someone who knows or guesses the preview hostname — from reading a preview's
pages, assets, or uploaded content. The intended audience (the PR author and
reviewers, i.e. people with read access to the base repo) can still reach it,
because the credential is posted in the PR comment, which only they can see.

**What it explicitly does NOT defend:**

- It is **not** hardened multi-tenant isolation. Tenant isolation between
  previews is a separate, existing property (per-vhost `open_basedir`, per-site
  DB/KV credentials, the `ephpm exec` sandbox). This gate is only about *who may
  make an HTTP request to a preview*.
- It does **not** protect against someone who already has read access to the
  base repo — they are the intended audience and can see the credential.
- It does **not** resist a determined attacker who compromises a reviewer's
  GitHub account or the PR comment stream. That is an account-security problem,
  not a preview-privacy one.
- It is **not** a substitute for keeping genuinely sensitive data out of a
  preview environment.

## Why enforcement belongs in ePHPm, not switchboard

A correct gate has two hard requirements, and switchboard can satisfy neither on
its own today:

1. **It must cover the static-file path as well as the PHP path, and fail
   closed.** A preview serves static assets (JS/CSS/images) and — for a
   `docroot: "."` WordPress checkout — arbitrary non-PHP files (`.txt`, `.sql`
   dumps, uploads) directly off disk, *without* running any PHP. A gate that only
   runs in PHP leaves all of that ungated. ePHPm already has exactly the right
   primitive: the **request-phase middleware** chain runs on both the PHP path
   (`Router::handle_php`) **and** the static-file path
   (`Router::static_request_phase`, ephpm#395), *before the file's bytes are read
   from disk*, and it **fails closed**. A `RESPOND` verdict (e.g. a `401`) short-
   circuits the whole request.

2. **The credential must be per-preview.** Every preview needs its own secret so
   that leaking one does not open the others, and so a credential can rotate per
   deploy.

switchboard's only per-site configuration channel into ePHPm is the two-key
per-site **override file** (`document_root`, `auto_prepend_file`). That schema is
**deliberately closed** (see `ephpm-server/src/site_overrides.rs`): an arbitrary
key is a tenant-influenced sandbox-escape surface, so it is not switchboard's to
extend from the outside. And ePHPm's `[[middleware]]` mounts are **global** (one
chain for the whole server, matched only by a path glob) — they have no per-vhost
credential channel. So the enforcement layer must be added inside ePHPm.

### Why not the tempting switchboard-only shortcut

switchboard already writes an `auto_prepend_file` (the env prepend) that ePHPm
runs before every request. It is tempting to add a Basic-auth check to that PHP
prepend. **Rejected:** `auto_prepend_file` runs only on the **PHP** path, so it
leaves every static asset and non-PHP file ungated. That is a *bypassable*
control, and the issue is explicit that a bypassable gate is worse than an
honest gap. The prepend is the wrong layer for a security boundary.

## Chosen mechanism

**Per-preview HTTP Basic auth, enforced by an ePHPm request-phase gate that runs
on both the static and PHP paths and fails closed. The credential is generated
by switchboard and posted in the PR comment.**

- **Credential:** a random, per-preview secret. Basic auth username can be the
  site key; the password is a switchboard-generated high-entropy token, stored
  in switchboard's own state and rotated per deploy. (It is deliberately *not*
  ePHPm's per-site `HMAC(master_secret, site_key)` password — that one rotates on
  every host restart, so it could not be posted in a durable PR comment.)
- **Surfacing:** the credential goes in the sticky PR comment, which is visible
  only to users with read access to the base repo. The comment already exists;
  it gains a "This preview is private — sign in with …" line.
- **Enforcement (ePHPm, companion issue):** a request-phase gate, fed a per-site
  expected credential, returns `401 WWW-Authenticate: Basic` for any request
  whose `Authorization` header does not match. It runs ahead of both the static
  and PHP serving paths and fails closed.

### How the per-site credential reaches ePHPm

Two candidate shapes for the companion ePHPm change; the issue picks one:

1. **A new per-site override key** — e.g. `require_basic_auth = "<user>:<bcrypt-
   or-hmac-of-password>"` (or a token) in `<site_overrides_dir>/<key>.toml`. The
   override loader already validates and fail-closes per site, and switchboard
   already writes this file. This is the smallest, most consistent change: the
   credential travels the exact channel `document_root` and `auto_prepend_file`
   already do. The value is a *verifier* (hash), never the plaintext, so the
   operator-owned file does not itself store a reusable secret.

2. **A per-site binding for a builtin auth middleware** — expose the resolved
   site key to the middleware `RequestCtx` and let a builtin `preview_auth` /
   `api_key`-style module look the expected credential up from a per-site source.
   More flexible, more surface; heavier than preview-privacy warrants.

Preference: **option 1** (new override key). It reuses the existing per-site
config path, keeps the two-parser contract intact, and needs no new middleware
wiring.

## Alternatives weighed

| Option | Verdict |
|---|---|
| **Shared per-preview token in URL/cookie** (magic link) | Workable, but tokens in URLs leak via `Referer`, browser history and access logs; needs cookie-setting logic and a redirect dance. More moving parts than Basic auth for the same protection. Secondary. |
| **Basic auth, per-preview generated credential** (chosen) | Zero client state, works for browsers *and* `curl`/CI, trivial to enforce in the request phase on both paths, credential fits naturally in the PR comment. |
| **IP allowlist** | Reviewers are on dynamic/varied IPs (home, mobile, CI); an allowlist that fits a public preview audience is impractical. Could be an *optional add-on* for a fixed-office deployment, not the default. |
| **GitHub-OAuth-gated** (tie the gate to actual repo read access) | Strongest — authorizes against real GitHub permissions rather than a shared secret — but needs an OAuth app, a callback handler, a session store, and per-repo authorization checks. Overkill for preview-privacy; a good future upgrade if the shared-secret model proves too coarse. |

## Scope split

- **This PR (switchboard):** Part A only — the authenticated fetch — plus this
  design.
- **Companion ePHPm issue:** the request-phase per-site access gate (option 1
  above): a new per-site override key carrying a Basic-auth verifier, enforced on
  both the static and PHP paths, failing closed, with unit tests that a request
  with no/!wrong credential gets `401` and a request with the right credential is
  served (asserting the before-state: ungated today).
- **Follow-up switchboard PR (after the ePHPm key ships):** generate the
  per-preview credential, write the verifier into the per-site override, post the
  plaintext credential in the PR comment, and rotate it per deploy. Gated behind
  an explicit opt-in until the enforcing ePHPm is known to be deployed to the
  node (same rollout-ordering discipline as the `ephpm exec` fail-closed check).
