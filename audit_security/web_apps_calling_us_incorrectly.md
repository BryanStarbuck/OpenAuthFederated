# Web Apps Calling OpenAuthFederated Incorrectly

Every place a consuming app uses the library's API incorrectly, or leans on a config
that weakens a guarantee. Grouped by app. This is the feedback to send each app team;
the security-impacting rows also appear in `security_bugs_to_fix.md`.

**Scope:** 6 consuming apps audited (Internal Web App, Marketing AI, Large File Bridge,
Email Delivery Hero, Philosophers Stone, The Starbucks). **~22 misuse findings.**
None of the six forks the library's token verification, and five of six use a distinct
`cookiePrefix`, an out-of-repo `sessionSecret`, and unmodified `verifyToken` — so the
misuse is concentrated in **config that weakens defaults**, not in wrong wiring. The most
consequential single misuse is Marketing AI persisting the access token to `localStorage`.

Note: several findings are actually **library footguns** — the app followed a documented
default and still ended up less safe (audience-not-enforced, no-store-means-no-revocation,
multi-month TTL allowed silently). Those are collected in "Patterns across apps" so the
library team can decide whether to change a default or make the footgun impossible.

---

## Internal Web App (`~/BGit/all/app`)

| Sev | What they do wrong | Correct usage | Risk | Source + lines |
|-----|--------------------|---------------|------|----------------|
| MEDIUM | Session TTL **and** inactivity timeout both set to ~10 months (idle expiry disabled) | Short TTL + a real inactivity timeout backed by the sessionStore | Captured session valid ~10 months; no idle logout | `backend/src/modules/auth/auth-frontend.ts` |
| MEDIUM | `requireHostedDomain` not enabled on a Workspace-gated app | Set `requireHostedDomain: true` | Consumer Google account on the email domain signs in without Workspace membership | `backend/src/modules/auth/auth-frontend.ts` |
| MEDIUM | Webhook handler forks the library's `verifyWebhook`, dropping timestamp/replay protection | Call library `verifyWebhook(rawBody, headers, secret)` (has timestamp tolerance + constant-time compare) | Replayable webhook events that drive RBAC | `backend/src/modules/webhooks/webhooks.controller.ts` |
| LOW | No per-app `audience` set or enforced | Set `audience` on mint **and** pass it on verify (once the library forwards it) | No aud isolation from sibling apps | `backend/src/modules/auth/auth-frontend.ts` |
| LOW | `resolveGrants` unwired — all real users read-only | Map Workspace groups → roles before enabling write routes | Admin routes unreachable now; over-grant risk when wired carelessly | `backend/src/modules/auth/auth-frontend.ts` |

## Marketing AI (`~/BGit/all/marketing/ai`)

| Sev | What they do wrong | Correct usage | Risk | Source + lines |
|-----|--------------------|---------------|------|----------------|
| HIGH | Access token persisted to `localStorage` | Keep the token in memory (the SDK does); rely on the HttpOnly rotating cookie | XSS steals a valid Bearer token | `code/ui/lib/auth.js` |
| MEDIUM | Session TTL + inactivity timeout both ~10 months | Short TTL + real idle timeout | Long-lived captured session | `code/src/lib/config.ts`, `auth_frontend.ts` |
| LOW | Forbidden "Clerk" reference in a source comment | Generic phrasing | Charter/branding violation | `code/ui/lib/auth.js:10` |

*(Marketing AI otherwise calls the library correctly: issuer+audience enforced on mint AND
verify, HMAC raw-body webhook verify, least-privilege resolveGrants, distinct `oaf_mai`
prefix, FileSessionStore revocation, no forked verification.)*

## Large File Bridge (`~/BGit/Bryan_git/LargeFileBridge`)

| Sev | What they do wrong | Correct usage | Risk | Source + lines |
|-----|--------------------|---------------|------|----------------|
| MEDIUM | `requireHostedDomain` never set on a Workspace-gated app | `requireHostedDomain: true` | hd claim unenforced | `backend/src/modules/auth/auth-frontend.ts:114-136` |
| MEDIUM | `allowedDomains` degrades to `gmail.com`/bare domains when individuals are allow-listed | Use an individual-email allowlist in a guard/resolveGrants, never a broad domain | Any Google account on that domain can sign in | `backend/src/modules/security/security.service.ts:78-85` |
| MEDIUM | `cookieSecure` defaults false; shipped `.env` pins `COOKIE_SECURE=false` | Default true; false only for local http | Non-Secure session cookie in prod | `backend/src/modules/auth/auth-frontend.ts:102,134` + `.env` |
| LOW | ~10-month session TTL, inactivity timeout disabled | Short TTL + idle timeout | Long-lived captured session | `backend/src/modules/auth/auth-frontend.ts:113,129-132` |

## Email Delivery Hero (`~/BGit/Bryan_git/EmailDeliveryHero`)

| Sev | What they do wrong | Correct usage | Risk | Source + lines |
|-----|--------------------|---------------|------|----------------|
| MEDIUM | ~10-month session TTL with inactivity timeout set equal to it (idle sessions never expire) | Short TTL + smaller idle timeout | No idle logout | `auth-frontend.ts:129,154,156` |
| LOW | Token `audience` never enforced (no audience at mint or verify) | Set + enforce audience | No aud isolation | `auth.strategy.ts:65` |
| LOW | `requireHostedDomain`/`hostedDomain` unset; hd not required, falls back to email string | `requireHostedDomain: true` + set `hostedDomain` | Non-Workspace account passes | `auth-frontend.ts:117-125`, `auth.strategy.ts:68-79` |

## Philosophers Stone (`~/BGit/Bryan_git/Philosophers_Stone`)

| Sev | What they do wrong | Correct usage | Risk | Source + lines |
|-----|--------------------|---------------|------|----------------|
| MEDIUM | `requireHostedDomain` off + `gmail.com` fallback defeats domain enforcement | `requireHostedDomain: true`; no broad-domain fallback | Any gmail account signs in | `backend/src/modules/auth/auth-frontend.ts` |
| MEDIUM | `cookieSecure` and security headers default OFF in server mode | Default Secure + headers on | Non-Secure cookie + missing hardening headers in prod | `backend/src/modules/auth/auth-frontend.ts` |
| LOW | JFK Social "publish" is an unauthenticated stub | Require auth + validate target before wiring the live call | Future SSRF/cred exposure | `backend/src/modules/decisions/decisions.service.ts` |

*(Otherwise correct: distinct cookiePrefix, FileSessionStore revocation, out-of-repo
generated secret, unforked verifyToken, tokens in memory not localStorage.)*

## The Starbucks (`~/BGit/Bryan_git/the_starbucks`)

| Sev | What they do wrong | Correct usage | Risk | Source + lines |
|-----|--------------------|---------------|------|----------------|
| MEDIUM | Login gate degrades to domain-only; `security.yaml` member roster does not actually gate login (the email allowlist is a separate, default-empty env var) | Enforce the individual-email allowlist at login; fail closed when empty | Private family hub silently widens to the whole `thestarbucks.com` Workspace if the env var is cleared | `backend/src/config/app-config.ts:26-31`, `auth.strategy.ts:60-81` |
| MEDIUM | ~10-month TTL with inactivity timeout neutralized (both 300 days) | Short TTL + real idle timeout | No idle logout | `backend/src/modules/auth/auth-frontend.ts:93,113-116` |

*(Otherwise correct: out-of-repo secret, issuer enforced via `configureEmbeddedVerification`
fallback, distinct `oaf_sfh` prefix, sane Secure/SameSite, FileSessionStore, global
JwtAuthGuard, server-side OwnerGuard, spawn without a shell, no tokens in localStorage. The
audience footgun is not triggered because this app configures no audience at all.)*

---

## Patterns across apps

The recurring misuses — several are really **library footguns**, flagged so the library
team can change a default or make the mistake impossible.

| Misuse pattern | Apps affected | Library change that would prevent it |
|----------------|--------------|--------------------------------------|
| **~10-month session TTL with idle timeout disabled/equalized** | 5 of 6 (Internal, Marketing, LFB, EDH, Starbucks) | Warn (or refuse) on multi-month TTLs; make an inactivity timeout that works without a full store |
| **`requireHostedDomain` off / hd not enforced** on Workspace-gated apps | 4 of 6 (Internal, LFB, EDH, Phil) | Default `requireHostedDomain: true` when `allowedDomains` looks like a Workspace domain |
| **`audience` not set/enforced** (so no cross-app token isolation) | Internal, EDH (+ every app that omits it) | Enforce configured audience automatically in embedded verify (library HIGH #1) — removes the footgun entirely |
| **`cookieSecure`/security headers off in "server"/"dev" mode** | LFB, Phil | Make Secure + headers the default; require an explicit `localHttp: true` to disable |
| **Broad `allowedDomains` where an individual-email allowlist was meant** | LFB, Starbucks | Offer a first-class `allowedEmails` allowlist so apps don't reach for a broad domain |
| **Revocation/idle expected but no `sessionStore` wired** (or fails open) | (library-side; see #3/#4) | Default a store or fail loudly (library MEDIUM #3, #4) |

**Bottom line for the library team:** the apps are wiring the library correctly in the
hard places (verification, cookies, prefixes, secrets). The misuse clusters around
*weakened config defaults* and *one documented-but-unenforced guarantee* (audience). Two
library changes — enforce `audience` by default, and warn/cap on multi-month TTLs — would
erase most of this table.
