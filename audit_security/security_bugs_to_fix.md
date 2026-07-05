# Security Bugs To Fix — OpenAuthFederated + Consuming Apps

Master fix list, most severe first. Built from the 7 per-scope reports in this
directory (`OpenAuthFederated.txt` plus one `.txt` per consuming app). Covers both
the library's own bugs and each app's app-side security bugs. Misuse of the library
that has a security impact is included here too **and** detailed per app in
`web_apps_calling_us_incorrectly.md`.

**Totals:** 60 security-relevant findings across 7 scopes —
**1 CRITICAL, 6 HIGH, ~21 MEDIUM, ~32 LOW** (1 INFO excluded).
Library scope: 13 findings (2 HIGH). App scopes: 47.
The single most important theme: **every app ships a "local / dev / identify-don't-gate"
mode that trusts an unauthenticated default principal while the server binds all
interfaces** — that pattern is the root of the CRITICAL and three of the HIGH app bugs.
The library itself is well-hardened; its two HIGH items are design gaps, not missing basics.

---

## Fix order

| # | Sev | Scope | Bug (short) | Source file(s) + lines | Fix (one line) | Report |
|---|-----|-------|-------------|------------------------|----------------|--------|
| 1 | CRITICAL | Large File Bridge | Dev-auth bypass → unauthenticated remote admin (no loopback/mode guard; binds 0.0.0.0; CORS lets curl through) | `backend/src/modules/auth/identify.ts:17-30`, `main.ts:121` | Gate dev-auth to loopback+explicit flag; bind 127.0.0.1 in local mode; fail closed | Large_File_Bridge.txt |
| 2 | HIGH | Large File Bridge | No filesystem confinement — any principal reads ANY host file incl. the Google client secret | `backend/src/modules/fs/paths.ts:13-26`, `media/media.service.ts:26-61` | Confine to an allow-listed root via realpath prefix check; reject symlink escapes | Large_File_Bridge.txt |
| 3 | HIGH | Email Delivery Hero | Unauthenticated package installation (brew/npm) executed on the host | `install.controller.ts:31-77` | Require admin role; remove/telemetry-gate host package execution | Email_Delivery_Hero.txt |
| 4 | HIGH | Philosophers Stone | "local" default mode grants full admin to any remote caller (guard never re-checks loopback) | `backend/src/modules/auth/jwt-auth.guard.ts` | Require loopback for local-mode admin; bind 127.0.0.1; default to gated mode | Philosophers_Stone.txt |
| 5 | HIGH | Marketing AI | Bearer access token persisted to `localStorage` (breaks in-memory-only contract; XSS token theft) | `code/ui/lib/auth.js` | Keep token in memory only; rely on the HttpOnly rotating cookie | Marketing_AI.txt |
| 6 | HIGH | **library** | `audience`/`issuer` token isolation is documented but NOT enforced in embedded verify | `auth-backend/src/frontend.ts:211-215,665`, `verify.ts:22-29,160-194` | Carry audience through `configureEmbeddedVerification`; enforce aud+iss by default | OpenAuthFederated.txt #1 |
| 7 | HIGH | **library** | Grants baked at sign-in, never re-resolved — deprovision/role-change latency = session lifetime | `auth-backend/src/frontend.ts:1216,849-866,1303-1334` | Re-resolve grants on mint past a max grant-age; expire on loss of membership | OpenAuthFederated.txt #2 |
| 8 | MEDIUM | Email Delivery Hero | Unauthenticated OS scheduler control + `os.label` path traversal → arbitrary plist write + `launchctl load` (borders HIGH) | `schedule-config.store.ts:152-157`, `os-artifact.ts:87-89,328-338` | Require admin; sanitize label; write only within the managed dir | Email_Delivery_Hero.txt |
| 9 | MEDIUM | Email Delivery Hero | Unauthenticated audit/domain endpoints = DNS-probe & amplification proxy (attacker-supplied hostnames) | `audit.controller.ts:72-275` | Require auth; rate-limit; validate/allowlist target hostnames | Email_Delivery_Hero.txt |
| 10 | MEDIUM | Philosophers Stone | Communities default to `world_read = true` (broad disclosure) | `packages/shared/src/schemas.ts` | Default private; require explicit opt-in to world-readable | Philosophers_Stone.txt |
| 11 | MEDIUM | Internal Web App | Loopback gate on process-spawning route trusts spoofable `Host` header | `backend/src/modules/open/open.controller.ts` | Check socket remote address, not Host; require admin | Internal_Web_App.txt |
| 12 | MEDIUM | Internal Web App | Webhook handler forks `verifyWebhook`, drops timestamp/replay protection | `backend/src/modules/webhooks/webhooks.controller.ts` | Use library `verifyWebhook` over raw body (has timestamp tolerance) | Internal_Web_App.txt |
| 13 | MEDIUM | Large File Bridge | CORS reflects ANY localhost origin with `credentials:true` in local mode | `backend/src/main.ts:47-59,91` | Pin an explicit origin allowlist even in local mode | Large_File_Bridge.txt |
| 14 | MEDIUM | Large File Bridge | Unauthenticated `/api/client-log` with unbounded `events[]` (disk DoS + fault-trail forging) | `backend/src/modules/clientlog/clientlog.router.ts` | Require auth; cap size/rate; sanitize newlines | Large_File_Bridge.txt |
| 15 | MEDIUM | **library** | Session-store read failure fails OPEN — falls back to cookie, bypasses revocation/inactivity/expiry | `auth-backend/src/frontend.ts:799-803` | Add `sessionStoreFailMode` defaulting to fail-closed | OpenAuthFederated.txt #3 |
| 16 | MEDIUM | **library** | Revocation / "sign out everywhere" / inactivity timeout are silent no-ops without an opt-in `sessionStore` | `auth-backend/src/frontend.ts:1401-1420,733-804` | Default a store, or warn loudly at construction when absent | OpenAuthFederated.txt #4 |
| 17 | MEDIUM | **library** | `sessionStoreMigrate` can resurrect a revoked session from a still-valid cookie | `auth-backend/src/frontend.ts:785-796` | Bound migration by cookie-age cutoff + per-user migration marker | OpenAuthFederated.txt #5 |
| 18 | MEDIUM | Philosophers Stone | `cookieSecure` and security headers default OFF in server mode | `backend/src/modules/auth/auth-frontend.ts` | Default Secure + headers on; opt out only for local http | Philosophers_Stone.txt |
| 19 | MEDIUM | Large File Bridge | `cookieSecure` defaults false; shipped `.env` pins `COOKIE_SECURE=false` | `backend/src/modules/auth/auth-frontend.ts:102,134` + `.env` | Default true; never ship a non-Secure prod cookie | Large_File_Bridge.txt |
| 20 | MEDIUM | The Starbucks | Login gate degrades to domain-only; the `security.yaml` member roster does not actually gate login | `backend/src/config/app-config.ts:26-31`, `auth.strategy.ts:60-81` | Enforce the individual-email allowlist at login, fail closed when empty | The_Starbucks.txt |
| 21 | MEDIUM | *misuse — all apps* | Session TTL set to ~10 months with inactivity timeout disabled/equalized (no idle logout) | see per-app auth-frontend configs | Cut TTL; set a real inactivity timeout with a store | (all app reports) |
| 22 | MEDIUM | *misuse — 4 apps* | `requireHostedDomain` not enabled on Workspace-gated apps (hd claim unenforced) | Internal / LFB / EDH / Phil auth-frontend | Set `requireHostedDomain: true` | (per-app reports) |
| 23 | LOW | *app scaffolding — 4 apps* | Unauthenticated client-error/client-log endpoint → log forging (newline injection) + flood DoS | LFB, EDH, Phil, Starbucks `health`/`clientlog` controllers | Require auth or strict rate-limit; strip control chars | (per-app reports) |
| 24 | LOW | *app scaffolding — 3 apps* | Unauthenticated health/auth-config endpoint discloses creds-file path / OS username / devAuth state | LFB, EDH, Starbucks `health` controllers | Remove disclosure or require admin | (per-app reports) |
| 25 | LOW | Philosophers Stone | `/tmp` state-dir fallback can expose the HS256 signing secret | `backend/src/config/state-dir.ts` | Refuse world-readable state dirs; write 0700/0600 | Philosophers_Stone.txt |
| 26 | LOW | Philosophers Stone | CORS reflects any localhost origin with credentials | `backend/src/main.ts` | Explicit origin allowlist | Philosophers_Stone.txt |
| 27 | LOW | Email Delivery Hero | MTA-STS policy fetch is SSRF with `rejectUnauthorized:false` (gated behind default-off flag) | `mta-sts.check.ts:235,516-541` | Validate/allowlist target; never disable TLS verification | Email_Delivery_Hero.txt |
| 28 | LOW | Email Delivery Hero | CSRF-style side effects via no-body simple POST endpoints | `main.ts:61-75`, `scheduler.controller.ts:48-79` | Require a custom header / CSRF token on state-changing POSTs | Email_Delivery_Hero.txt |
| 29 | LOW | Marketing AI | Terminal error handler returns raw `err.message` to clients (info disclosure) | `code/src/server.ts` | Return generic message; log detail server-side | Marketing_AI.txt |
| 30 | LOW | Marketing AI | Process-spawn launch endpoint (`npm run dev`) gated by requireAuth but not admin | `code/src/server.ts` | Require admin role | Marketing_AI.txt |
| 31 | LOW | Marketing AI | `/v1` public allowlist uses unanchored `startsWith` prefix match | `code/src/server.ts` | Anchor/exact-match public routes | Marketing_AI.txt |
| 32 | LOW | Large File Bridge | Media grant is 6h, path-in-URL, not bound to user/session | `backend/src/modules/media/media.service.ts:37-61` | Shorten TTL; bind grant to user+session | Large_File_Bridge.txt |
| 33 | LOW | Internal Web App | `resolveGrants` unwired — real users are read-only, admin/write routes unreachable (availability + latent over-grant on wiring) | `backend/src/modules/auth/auth-frontend.ts` | Wire group→role mapping; review before enabling | Internal_Web_App.txt |
| 34 | LOW | Internal Web App | Stale comment claims a non-existent "HS256 dev secret in dev mode" | `backend/src/modules/auth/auth.strategy.ts` | Delete misleading comment | Internal_Web_App.txt |
| 35 | LOW | The Starbucks | Shared notes/resources deletes have no actor capture/audit and no write policy | `backend/src/modules/notes/notes.controller.ts:38-43` | Add per-item write policy + audit log | The_Starbucks.txt |
| 36 | LOW | The Starbucks | Code committed outside `/code` (charter): native Swift app + signed `.app` bundle | `mac_tools/code/` | Move under `/code` or a separate repo; don't commit built bundles | The_Starbucks.txt |
| 37 | LOW | **library** | Google id_token verification does not pin `algorithms` (inconsistent with every other path) | `auth-backend/src/frontend.ts:1114-1117` | Add `algorithms: ["RS256"]` | OpenAuthFederated.txt #6 |
| 38 | LOW | **library** | Machine (M2M/API-key) tokens are not audience-bound | `auth-backend/src/client.ts:499-502` | Forward + enforce audience (with #6/#1) | OpenAuthFederated.txt #7 |
| 39 | LOW | **library** | SAML response-envelope signature off by default (residual XML Signature Wrapping) | `auth-backend/src/saml.ts:46-54,82-114` | Document loudly; consider default-on with Google opt-out | OpenAuthFederated.txt #8 |
| 40 | LOW | **library** | Default in-memory replay/session stores don't span processes (multi-instance replay/inconsistency) | `auth-backend/src/saml.ts:125-139`, `frontend.ts:621` | Require a shared store for multi-instance | OpenAuthFederated.txt #9 |
| 41 | LOW | **library** | `assertSafeIssuer` permits any https host with empty allowlist (SSRF if issuer is tenant-derived) | `auth-backend/src/verify.ts:105-119` | Recommend/require `jwksAllowedHosts`; block private IP literals | OpenAuthFederated.txt #10 |
| 42 | LOW | **library** | Oversized request-body guard keeps buffering the stream (memory DoS) | `auth-backend/src/frontend.ts:382-385,420-423` | `req.destroy()` on cap breach | OpenAuthFederated.txt #11 |
| 43 | LOW | **library** | Sign-in logs retain company domain + unsalted SHA-256 email hash (correlation/enumeration on log leak) | `auth-backend/src/frontend.ts:345-352` | HMAC with a per-deploy secret; drop domain | OpenAuthFederated.txt #12 |
| 44 | LOW | **library** + Marketing AI | Charter naming-rule: the word "Clerk" appears in code comments/docstrings | `auth-backend/src/frontend.ts` (11), `index.ts:81`, `session-store.ts`; Marketing `code/ui/lib/auth.js:10` | Replace with generic phrasing; add CI grep | OpenAuthFederated.txt #13, Marketing_AI.txt |

---

## CRITICAL

### 1. Large File Bridge — dev-auth bypass = unauthenticated remote admin
`identify.ts` accepts a "dev" identity without checking that the request came from
loopback or that an explicit dev flag is set, `main.ts` binds `0.0.0.0`, and CORS is
permissive in local mode. Anyone on the network can `curl` the API as an admin and,
combined with **#2**, read any file on the host — including the Google OAuth client
secret. Fix all three together: gate dev-auth behind loopback + an explicit env flag,
bind `127.0.0.1` when local, and keep CORS fail-closed.

## HIGH

### 2. Large File Bridge — no filesystem confinement
File/media paths are not confined to an allow-listed root, so any authenticated (or
bypassed, per #1) principal can read arbitrary host files. Enforce a realpath prefix
check against a configured root and reject symlink escapes.

### 3. Email Delivery Hero — unauthenticated host package installation
`install.controller.ts` runs `brew`/`npm` installs on the host with no role check. A
network peer can drive host package execution. Require admin and, ideally, remove
host-level package execution from a network-reachable endpoint entirely.

### 4. Philosophers Stone — local mode grants admin to any remote caller
"local" is the **default** mode; the guard hands the DEFAULT_USER full admin without
re-verifying the request is from loopback, while `app.listen(port)` binds all
interfaces. A default install on a reachable network gives peers full read/write/delete.
Same fix family as #1.

### 5. Marketing AI — access token in localStorage
`code/ui/lib/auth.js` persists the Bearer access token to `localStorage`, breaking the
library's in-memory-only contract and exposing the token to any XSS. Keep it in memory;
the HttpOnly rotating cookie already survives reloads.

### 6. Library — audience/issuer isolation not enforced (embedded)
The `audience` option is documented as the control that stops two apps sharing a secret
from accepting each other's tokens, but embedded `verifyToken` never enforces `aud`
(and `iss` defaults to a shared constant). The real protection today is a distinct
per-app `sessionSecret`. Carry audience through `configureEmbeddedVerification` and
enforce aud+iss by default, and fix the doc. See `OpenAuthFederated.txt` #1.

### 7. Library — stale grants, deprovision latency = session lifetime
Grants are resolved once at sign-in and every later access token is minted from that
baked set, so a demoted/offboarded user keeps elevated tokens until max lifetime (or the
inactivity timeout, which only exists with a store). Add on-mint grant re-resolution
past a max grant-age. See `OpenAuthFederated.txt` #2.

## Systemic MEDIUM patterns (see the roll-up of misuse in `web_apps_calling_us_incorrectly.md`)

- **~10-month session TTL with idle timeout disabled** in 5 of 6 apps — captured
  sessions stay valid for the better part of a year. The library default is 7 days; every
  app overrode it. Consider making the library warn on multi-month TTLs.
- **`requireHostedDomain` off** in 4 apps — a consumer Google account on an allowlisted
  email domain can sign in without Workspace membership.
- **Unauthenticated `client-error`/`client-log` + `auth-config` health endpoints** copied
  across 4 apps — log forging, flood DoS, and creds-path disclosure. Fix the shared scaffold.
- **Unauthenticated / loopback-spoofable "run a process / install a package" routes** in
  Marketing, Internal, EDH — treat any code-execution route as admin-only + loopback-verified.

MEDIUM and LOW items not called out above are in the table and detailed in each
per-scope `.txt` report.
