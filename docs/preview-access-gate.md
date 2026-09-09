# Preview access gate — switchboard's control-plane half (switchboard#26, Part B)

## Status

**Implemented.** ePHPm ships the enforcement (a per-site `preview-gate`
middleware) and verification/revocation (ephpm/ephpm#487, merged in #491);
switchboard ships the control plane described here: it decides which previews to
gate, writes the `[preview_auth]` activation into the per-site override, mints
temporary shareable-URL capability tokens, and revokes them on teardown.

> **Design note — this supersedes the original plan.** An earlier revision of
> this document proposed **per-preview HTTP Basic auth** with a switchboard-
> generated credential written into a new override key. That is not what shipped.
> ePHPm implemented a stronger mechanism — a **GitHub-OAuth login gate** that
> authorizes against real repo read access, plus revocable HS256 **share tokens**
> for people without repo access — and switchboard drives *that*. The threat
> model below still holds; the mechanism section is rewritten to match the code.

## The problem

A deployed preview serves to anyone who resolves `*.preview.ephpm.dev`. Once
switchboard can check out **private** repositories (Part A of #26), that preview
is a private repo's code and content served to the whole internet. Fetching
private code is pointless if the result is world-readable, so the two are one
decision — and a private preview that comes up ungated is the exact exposure this
feature exists to prevent. Every path where gating could silently not happen must
instead **fail the deploy loudly** (see "Fail closed").

## Threat model

**What the gate defends:** *preview privacy.* It stops a random internet visitor
— someone who knows or guesses the preview hostname — from reading a preview's
pages, assets, or uploaded content. The intended audience reaches it by signing
in with GitHub (they are authorized automatically if they have read access to the
base repo), or via a temporary share link handed out by a repo member.

**What it explicitly does NOT defend:**

- It is **not** hardened multi-tenant isolation. Tenant isolation between
  previews is a separate, existing property (per-vhost `open_basedir`, per-site
  DB/KV credentials, the `ephpm exec` sandbox). This gate is only about *who may
  make an HTTP request to a preview*.
- A **share link is a bearer capability**: anyone who has the link is in until it
  expires or is revoked, without signing in. That is the point (sharing with
  people who cannot authenticate) and is a *weaker* property than the OAuth gate;
  it is stated in every PR comment that carries one.
- It does **not** resist a compromised reviewer GitHub account or a leaked PR
  comment stream. That is account security, not preview privacy.
- It is **not** a substitute for keeping genuinely sensitive data out of a
  preview environment.

## Why enforcement belongs in ePHPm, not switchboard

Unchanged from the original analysis, and the reason the mechanism is split:

1. **The gate must cover the static-file path as well as PHP, and fail closed.**
   A preview serves static assets and — for a `docroot: "."` checkout — arbitrary
   non-PHP files directly off disk without running any PHP. ePHPm's request-phase
   middleware runs on both `Router::handle_php` **and**
   `Router::static_request_phase` (ephpm#395), before a file's bytes are read, and
   fails closed. An `auto_prepend_file` Basic-auth check (the tempting
   switchboard-only shortcut) would run on the PHP path only and leave every
   static file ungated — a bypassable control, rejected.
2. **The gate must be per-preview.** A preview fleet mints a new vhost per PR, and
   ePHPm has no runtime config reload. The per-site **override file**, re-read
   every `SITE_CONFIG_TTL` (~2 s), is switchboard's only per-preview channel; a
   global `[[middleware]]` mount cannot be turned on for a brand-new preview
   without a restart. So activation rides the override file, and ePHPm made
   `preview_auth` a typed section in it (ephpm#487).

## Chosen mechanism (as shipped)

**A GitHub-OAuth login gate, activated per preview through the `[preview_auth]`
override section, plus revocable HS256 share-link capabilities.** ePHPm mints the
OAuth session and verifies both grant paths through one `Hs256Policy`;
switchboard activates the gate and mints share links.

### 1. Gating policy (switchboard)

- **Private repo → gate ON, always.** Its code is not world-readable, so neither
  is its preview. Repo visibility comes from `repository.private` in the job/
  webhook payload (`JobRepository::private`), which **defaults to private when
  absent** (fail closed).
- **Public repo → ungated by default**, gated only when the operator sets
  `--gate-public-previews` (e.g. to keep unreleased work off the open internet).

### 2. Activation (switchboard writes `[preview_auth]`)

For a gated preview switchboard writes, into the same
`<site_overrides_dir>/<site-key>.toml` it already writes `document_root` /
`auto_prepend_file` into:

```toml
[preview_auth]
session_secret = "env:EPHPM_PREVIEW_SESSION_SECRET"   # a REFERENCE, never the key
login_url      = "/_ephpm/auth/github/login"
```

`session_secret` is a **reference** (`env:NAME` / `file:/abs` / a literal),
resolved by both the `github-auth` issuer and the gate — one source of truth, the
secret never in the tenant-adjacent file or the served tree. switchboard writes
the same reference it resolves for minting.

### 3. Share links (switchboard mints)

A share link is a `via:"share"` HS256 capability token, wire-compatible with
`ephpm_middleware_builtins::preview_gate::mint_share_token`, carrying `site` (the
canonical site key — per-preview), `via:"share"`, a random `jti`, `iat`, and a
short `exp`. Handed out as `https://<preview-host>/?ephpm_share=<token>`. Minting
is opt-in (`--share-link`) because a bearer capability posted on every PR is a
choice, not a default; only the token travels in the URL, never the secret.

### 4. Revocation (switchboard, on teardown)

On teardown, removing the override + checkout already stops the gate on this
node. Because the per-vhost KV is gossip-replicated and a preview can be
redeployed, switchboard also bumps the per-site epoch — `preview:share:epoch =
now` in the preview's own KV keyspace (AUTH'd as the site with
`HMAC-SHA256([kv] secret, site)`) — which refuses every share token issued
before that instant, cluster-wide. Best-effort: an unreachable KV is a `warn!`,
never a teardown failure; skipped entirely when `--kv-secret-file` is unset.

## Fail closed

The one decision that, gotten wrong, publishes private code — so every silent-
not-happen path is a hard deploy failure instead:

- A gated preview whose `session_secret` reference does not resolve to ≥ 32 bytes
  **fails the deploy** (`resolve_preview_gate`) rather than shipping an open
  preview or one ePHPm will 503.
- A gated preview with **no `--site-overrides-dir`** — nowhere to deliver the
  gate — **fails the deploy** (`apply_site_override`). An ungated (public) preview
  in the same situation only warns, because it was already public.
- Repo visibility **defaults to private** when the job payload omits `private`.

## Operator configuration

One-time, per fleet (ePHPm node config — **not** switchboard, stated here for
completeness):

1. Register **one** GitHub OAuth App for the fleet and mount `github-auth`
   globally in `ephpm.toml` with its `client_id`/`client_secret`, the per-repo
   access target, `session_secret = "env:EPHPM_PREVIEW_SESSION_SECRET"`, and for a
   wildcard fleet the apex-flow knobs `redirect_uri` (the one fixed callback host)
   and `cookie_domain`.
2. Set `EPHPM_PREVIEW_SESSION_SECRET` (≥ 32 bytes) in the ePHPm **and** switchboard
   process environments — both must resolve the reference to identical bytes for a
   switchboard-minted share token to verify in the gate.

switchboard flags:

| Flag / env | Default | Purpose |
|---|---|---|
| `--gate-public-previews` / `SWITCHBOARD_GATE_PUBLIC_PREVIEWS` | off | gate public repos too (private are always gated) |
| `--preview-session-secret-ref` / `SWITCHBOARD_PREVIEW_SESSION_SECRET_REF` | `env:EPHPM_PREVIEW_SESSION_SECRET` | the reference written into the override and resolved to mint share tokens |
| `--share-link` / `SWITCHBOARD_SHARE_LINK` | off | mint + post a share link per gated deploy |
| `--share-link-ttl-secs` / `SWITCHBOARD_SHARE_LINK_TTL_SECS` | `86400` | share-link TTL (kept short) |
| `--kv-secret-file` / `SWITCHBOARD_KV_SECRET_FILE` | unset | ePHPm's `[kv] secret`, for teardown epoch revocation (unset skips it) |
| `--kv-addr` / `SWITCHBOARD_KV_ADDR` | `127.0.0.1:6379` | ePHPm's KV RESP listener |

## Rollout ordering

Only write `[preview_auth]` once an ePHPm that **enforces** it is deployed to the
node. An older ePHPm treats the unknown section leniently (ignored, reported) and
would serve the preview ungated — so the fleet upgrades ePHPm first, then starts
writing the key. Same discipline `document_root`/`auto_prepend_file` and the
`ephpm exec` fail-closed check already follow.

## Alternatives weighed

| Option | Verdict |
|---|---|
| **Per-preview HTTP Basic auth** (the original plan here) | Superseded. Works for browsers and `curl`, but a shared per-preview secret is coarser than authorizing against real repo access, and it does not give the "log in with GitHub" UX the OAuth gate does. ePHPm shipped OAuth instead. |
| **GitHub-OAuth login gate** (shipped) | Authorizes against real GitHub repo-read permission; no shared secret to hand out for the primary path; enforced request-phase on both static and PHP paths, fail closed. |
| **Revocable share tokens** (shipped, secondary) | For people without repo access. A short-lived, per-preview, revocable bearer capability — explicitly weaker, explicitly labelled. |
| **IP allowlist** | Reviewers are on varied IPs; impractical as a default. Possible optional add-on for a fixed-office deployment. |
