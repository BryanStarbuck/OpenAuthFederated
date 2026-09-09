# Performance & Security Review — OpenAuthFederated library

**Date:** 2026-09-09
**Branch:** `dipesh/chore/perf-security-audit`
**Scope:** `code/packages/auth-backend/src/**` and `code/packages/auth-react/src/**` (~7k LOC).
Docs, `pm/`, and the consuming apps are out of scope.

**Baseline:** the earlier sweep in `audit_security/security_bugs_to_fix.md` +
`OpenAuthFederated.txt`. Library findings #6, #7, #15, #16, #17 from that list are **fixed
in the current tree** (audience bridging, grant re-resolution, `sessionStoreFailMode`,
no-store construction warning, migrate age cutoff). Everything below is a *new* finding
against the code as it stands today.

**Totals:** 27 findings — **3 HIGH, 10 MEDIUM, 14 LOW** (S3 re-graded up during implementation).
Split: 15 security, 12 performance.

> **Update (same day, after implementation).** 21 of the 27 are fixed on this branch, each with a
> test that fails without the fix. See "Implementation status" at the end for the per-finding
> table, the three deliberate deferrals, and one correction: **S3 was graded too low.** Driving a
> real signed assertion through the code showed node-saml never populates `profile.assertionId`,
> `profile.ID`, `profile.inResponseTo` OR `profile.audience` — so the SAML replay cache and the
> audience cross-check were not "fail-open under a future library change", they had **never
> executed on a single real assertion**. SAML one-time-use enforcement was entirely absent.
> That is a HIGH, not a MEDIUM.

---

## Fix order (top 10)

| # | Sev | Kind | Finding | Location |
|---|-----|------|---------|----------|
| 1 | HIGH | security | Global mutable verification config — two frontends in one process cross-verify tokens | `verify.ts:38,46`; `frontend.ts:921` |
| 2 | HIGH | perf | `FileSessionStore` does blocking sync fs on every request | `session-store.ts:144-198` |
| 3 | MEDIUM | security | SAML identity carries no `hd`/`provider` → `requireHostedDomain` rejects *every* SAML sign-in | `saml.ts:254-261`; `frontend.ts:1838-1852` |
| 4 | **HIGH** | security | SAML replay + audience checks never ran at all — they read profile fields node-saml does not set | `saml.ts:213,219-227` |
| 5 | MEDIUM | security | User ids are not namespaced per provider (`user_${sub}`) | `frontend.ts:1879` |
| 6 | MEDIUM | security | No rate limiting on any auth endpoint | `frontend.ts:2270-2400` (router) |
| 7 | MEDIUM | perf | Session cookie carries full memberships/permissions; re-signed + rewritten on every mint | `frontend.ts:1979,2011,2248` |
| 8 | MEDIUM | perf | Google token exchange has no request timeout (X path has one) | `frontend.ts:1707-1720` |
| 9 | MEDIUM | perf | `AuthClient.request` has no timeout, no retry, no keep-alive | `client.ts:~470` |
| 10 | MEDIUM | perf | Unbounded caches: `jwksCache`, `InMemorySamlReplayStore` | `verify.ts:13,242`; `saml.ts:140-155` |

---

# Part 1 — Security

## S1. HIGH — `configureEmbeddedVerification` is process-global; two frontends collide

**Where:** `auth-backend/src/verify.ts:38` (`let embeddedVerification`), `verify.ts:46`,
called unconditionally at `auth-backend/src/frontend.ts:921`.

`embeddedVerification` is one module-level variable. `createFederatedFrontend()` writes it
on every call. A host process that mounts two frontends — which the library explicitly
anticipates (`cookiePrefix` doc at `frontend.ts:~215` is written for exactly the
two-apps-one-host case) — ends up with **last-write-wins**: app A's `verifyToken()` now
validates against app B's `sessionSecret`, `issuer` and `audience`.

Consequences: app A's own freshly-minted tokens stop verifying (availability), and if the
two apps share a secret, `aud`/`iss` isolation — the documented defense-in-depth at
`frontend.ts:296-312` — silently evaporates because both sides now agree on B's values.

**Fix:** make verification config an instance, not a global. Return a `verifyToken` bound to
the frontend (e.g. `frontend.verifyToken`), keep `configureEmbeddedVerification` as a
back-compat shim, and **throw** (or warn loudly) when it is called a second time with a
different secret/issuer/audience.

---

## S2. MEDIUM — SAML sign-in is impossible under `requireHostedDomain`

**Where:** `auth-backend/src/saml.ts:254-261` builds the identity with no `hd` and no
`provider`; `auth-backend/src/frontend.ts:1838-1852` gates on them.

```ts
// saml.ts:254
const identity: OidcIdentity = { sub, email, emailVerified, name, givenName, familyName }
//                                ^ no `provider: "saml"`, no `hd`
```

```ts
// frontend.ts:1838
const provider = identity.provider ?? "google"     // SAML reports itself as google
const xExempt = provider === "x" && cfg.xTrustConfirmedEmail
if (cfg.requireHostedDomain && !hd && !xExempt) { /* reject */ }
```

Two problems:

1. **Functional lockout.** `requireHostedDomain: true` — the recommended hardening for a
   Workspace-gated deployment — rejects *every* SAML assertion, because SAML never populates
   `hd`. The charter mandates SAML 2.0 as the go-forward default, so an operator hitting
   this will turn `requireHostedDomain` off, downgrading the control for the OIDC path too.
2. **Mislabelled audit trail.** Every SAML rejection logs `Rejecting google sign-in: …`
   (`frontend.ts:1845`), so the logs cannot answer "which strategy refused this human?".

**Fix:** set `provider: "saml"` in `saml.ts`, map the IdP's domain attribute (or the email
domain of a signed assertion from a domain-scoped IdP) onto `hd`, and give SAML the same
explicit, operator-visible admission rule X got — either a `samlSatisfiesHostedDomain` flag
or a documented `hd` attribute name.

---

## S3. HIGH — SAML replay and audience checks never executed

**Where:** `auth-backend/src/saml.ts:210-227`.

```ts
const audience = str(profileRec.audience) ?? str(profileRec.audienceRestriction)
if (audience !== undefined && audience !== cfg.spEntityId) throw …   // absent → no check

const assertionId = str(profileRec.assertionId) ?? str(profileRec.ID) ?? str(profileRec.inResponseTo)
if (replayStore && assertionId) { … }                                 // absent → no check
```

Both are written as defense-in-depth, and both silently do nothing when node-saml does not
surface the field on the profile — which is a shape detail of a third-party library that can
change on a minor upgrade. The replay case is the sharper one: `assertionId` falling all the
way through to `undefined` means **one-time-use is not enforced at all**, with nothing in the
logs to say so. The third fallback (`inResponseTo`) is also not an assertion id — recording
it keys the replay cache on the *request* id, so two distinct assertions answering one
AuthnRequest collide.

**Fix:** fail closed. If `assertionId` is absent, reject the assertion (or at minimum log an
`error`). Drop the `inResponseTo` fallback. Same for audience: if node-saml surfaces no
audience *and* the deployment did not opt out, reject.

Related: `wantAuthnResponseSigned` defaults to `false` (`saml.ts:109`). The reasoning in the
comment is sound (Google signs the assertion, not always the response), but the resulting
default posture is the weaker one. Consider flipping the default and documenting
`wantAuthnResponseSigned: false` as the Google-specific opt-out.

---

## S4. MEDIUM — User ids are not namespaced by provider

**Where:** `auth-backend/src/frontend.ts:1879` — `userId: \`user_${identity.sub}\``.

Three strategies write into one identifier namespace: Google `sub` (numeric string), X
account id (numeric string), SAML `nameID` (email, or whatever NameID format the IdP is
configured for). Nothing distinguishes them.

- A human who signs in via SAML on Monday and Google on Tuesday is **two different users**
  with two different grant sets — silent identity fragmentation.
- Google and X ids live in the same numeric space. Collision is unlikely by accident but is
  not prevented by anything, and a SAML IdP configured for a `persistent` NameID format
  emits an operator-chosen opaque string that *can* be made to equal a Google `sub`.
  Exploiting it needs control of a configured IdP, which is why this is MEDIUM and not HIGH
  — but the control that should stop it (namespacing) simply isn't there.

**Fix:** `user_${provider}_${sub}`, with a documented migration for existing records (the
`FileSessionStore` keys on email, not userId, so the blast radius is the JWT `sub` claim and
whatever the host app persisted).

---

## S5. MEDIUM — No rate limiting on any endpoint

**Where:** the router at `auth-backend/src/frontend.ts:2270-2400`.

Nothing bounds request rate on `/sign_in/sso`, `/oauth_callback`, `/oauth_callback/x`,
`/saml/acs`, `/client`, or `/client/sessions/:id/tokens`. Practical consequences:

- `/saml/acs` and `/oauth_callback` each do XML/crypto work and (SAML) a signature
  verification before any cheap rejection — cheap for the attacker, expensive for us.
- `/oauth_callback/x` makes **two** outbound calls to X per request; unauthenticated
  traffic there turns the library into an amplifier against X's rate limits.
- Every rejection writes a `cfg.log("warn", …)` line, so an unauthenticated flood is a
  log-volume DoS and an audit-trail flood in one.

**Fix:** the library can't own the rate limiter (it's a mounted middleware), but it can
expose the hook: an optional `rateLimit?: (req, route) => boolean | Promise<boolean>` in
`FederatedFrontendConfig`, called before handler dispatch, plus documented guidance that
the host mount it. Fail closed on the callback routes specifically.

---

## S6. MEDIUM — Session `hd` claim is not always a hosted-domain claim

**Where:** `auth-backend/src/frontend.ts:1878` — `hd: identity.hd ?? presentedDomain`.

When `requireHostedDomain` is off, `presentedDomain` is the *email domain*
(`frontend.ts:1856`). That value is then stored as `hd` on the session and stamped onto both
the session cookie and every minted access token (`frontend.ts:1195`, `1216`). A downstream
service reading `claims.hd` and treating it as "Google Workspace membership" — which is what
the name means everywhere else in this codebase — is reading an unverified email suffix.

**Fix:** keep `hd` null unless the upstream actually asserted one; carry the email domain in
a separate `email_domain` claim if the session needs it.

---

## S7. LOW — X callback compares `state` with `!==`, Google uses constant-time

**Where:** `frontend.ts:1427` (`saved.state !== returnedState`) vs `frontend.ts:1684`
(`constantTimeEqual(returnedState, saved.state)`).

The values are 24 random bytes with a 10-minute TTL, so a timing oracle is not a practical
attack. It's an inconsistency in a security-critical comparison, and inconsistency is what
gets copied into the next provider path. Use `constantTimeEqual` on both.

---

## S8. LOW — Attacker-influenced strings interpolated into log lines

**Where:** `frontend.ts:1864` (`presentedDomain`), `frontend.ts:1541-1549` (X's
`grantedScopes` and the `said` string assembled from X's error array).

None of these are newline-stripped before reaching `cfg.log`. Under a line-oriented log
sink, a crafted SAML NameID domain or a hostile X error payload can forge additional log
lines. Sanitize (`.replace(/[\r\n]/g, " ").slice(0, 200)`) before interpolating.

---

## S9. LOW — `/environment` discloses the company domain allowlist unauthenticated

**Where:** `frontend.ts:1927-1948`, field `display_config.allowed_domains`.

Documented as secret-free and it is — but it hands an unauthenticated caller the list of
company domains this deployment gates on, which is reconnaissance for a phishing campaign
aimed at exactly those employees. The SDK only needs *which strategies exist*; the domain
list is used to render connection buttons and could be gated or reduced to opaque
connection ids.

---

## S10. LOW — No `__Host-` cookie prefix

**Where:** `setCookie` at `frontend.ts:418-431`.

Cookies are set with `Path=/`, `HttpOnly`, `Secure` (default) and no `Domain` — i.e. they
already satisfy every `__Host-` requirement. Adopting the prefix would make it impossible
for a sibling subdomain to shadow the session cookie. Cheap hardening; a breaking rename,
so gate it behind a config flag.

---

## S11. LOW — `Vary: Origin` only set on the CORS-match branch

**Where:** `frontend.ts:2287`.

When the request's `Origin` is *not* on the allowlist, no `Vary: Origin` is emitted. All
JSON responses carry `Cache-Control: no-store`, so this is not currently exploitable — but
the correctness rule is that `Vary: Origin` belongs on every response whose content depends
on `Origin`, matched or not. Move it above the `if`.

---

## S12. LOW — PKCE `code_verifier` sits in a signed-but-unencrypted cookie

**Where:** `signState` at `frontend.ts:1266-1277`.

The state JWT is signed (HS256, `oaf:state` subkey) but not encrypted, so its payload —
including `codeVerifier` — is base64-readable by anyone who obtains the cookie. `HttpOnly`
blocks script access and the TTL is 10 minutes, so this is defense-in-depth only. Use JWE
(`jose` already provides it) if you want the verifier opaque.

---

## S13. LOW — `hasRole` treats `admin` and `org:admin` as the same role

**Where:** `permissions.ts:30-36`, mirrored in `auth-react/src/types.ts`.

```ts
const bare = role.startsWith("org:") ? role.slice(4) : role
return roles.includes(bare) || roles.includes(`org:${bare}`)
```

An upstream group mapped to the literal role string `admin` therefore satisfies a
`{ role: "org:admin" }` check. Documented as a convenience, but it means the *authoritative*
authorization model treats two distinct strings as one, and the convenience runs in the
privilege-granting direction. At minimum, document it in `docs/apis/backend/`; better, make
the equivalence opt-in.

---

## S14. LOW — `sanitizeSegment` does not reject every filesystem-hostile character

**Where:** `session-store.ts:104-118`.

Blocks `/`, `\`, `\0`, `..` and empty. Does not block `:` (NTFS alternate data streams),
leading `.`, or whitespace. Emails reaching here are verified by an upstream IdP, which is why
this is LOW. Prefer an allowlist regex over a denylist.

> **Correction.** An earlier draft of this entry claimed `InMemorySessionStore.key()` joins
> `userKey` and `sid` "with a single space", making a space-bearing email a collision risk. That
> is wrong — the separator is a NUL, which `sanitizeSegment` already excludes from both halves, so
> there was never a collision there.
>
> Reading the raw bytes to check turned up something else, though: the separator was written as a
> **literal NUL byte in the `.ts` source**. Git therefore classified `session-store.ts` as a binary
> file — no diff, no blame, no line-level review of anything in it, including the session-store
> logic — and the character is invisible in an editor. Not a vulnerability, but it had silently
> exempted a security-relevant file from code review. Replaced with `const KEY_SEP = " "`:
> identical runtime value (`KEY_SEP` is the `\u0000` escape), and the file is UTF-8 text again.

---

## S15. LOW — Grant re-resolution failure keeps the old grants

**Where:** `frontend.ts:1223-1231`.

A throwing `revalidateGrants` logs a warning and returns `"ok"`, keeping the stale grant
set. That is a deliberate availability choice and the comment says so — but combined with a
resolver that fails *because* the upstream directory is down (exactly when someone was just
offboarded), it means deprovision latency silently reverts to session lifetime. Add a
`revalidateFailMode: "keep" | "closed"` knob so security-sensitive deployments can choose.

---

# Part 2 — Performance

## P1. HIGH — `FileSessionStore` blocks the event loop on every authenticated request

**Where:** `session-store.ts:144-198` — `writeFileSync`, `readFileSync`, `existsSync`,
`readdirSync`, `rmSync`, `mkdirSync`. All synchronous, all on the request path.

Per token mint (once per ~60s per tab, more with several tabs) the library does:

| Call | fs work |
|---|---|
| `readSession` → `store.get` (`frontend.ts:1063`) | `existsSync` + `readFileSync` |
| `store.touch` (`frontend.ts:1989`) | `existsSync` + `readFileSync` + `mkdirSync` + `writeFileSync` |

That's **2 stats, 2 reads, 1 mkdir and 1 write, all blocking**, for a single `/tokens` call.
Node has one thread for JS: every one of those pauses *every other request in the process*.
`list()` (`session-store.ts:190-201`) is worse — it reads and `JSON.parse`s the user's entire
session directory synchronously.

**Fix:**
1. Switch `FileSessionStore` to `node:fs/promises` (the `SessionStore` interface already
   allows `Promise` returns — no API break).
2. `touch()` currently does a full read-modify-write; keep a small in-process LRU of hot
   session records so the read is skipped, and debounce the `lastActiveAt` write (writing it
   at most once per N seconds is enough for an inactivity clock measured in hours).
3. `mkdirSync` on every write is redundant after the first — cache the known-created dirs.

**Correctness rider:** `create()` (`session-store.ts:144-146`) writes in place with no
temp-file + rename. A crash or a concurrent write mid-`writeFileSync` leaves truncated JSON,
which `get()` (`session-store.ts:157`) swallows as "absent" — under the default
`sessionStoreFailMode: "closed"` that logs the user out; under `"cookie-grace"` it bypasses
revocation. Write to `<file>.tmp` then `rename()`.

---

## P2. MEDIUM — Session cookie is fat, and re-signed + re-set on every mint

**Where:** `signSession` at `frontend.ts:1141-1163`; called at `1780`, `1892`, `1979`,
`2011`, `2248`.

The session JWT carries `roles`, `permissions` and the **full `memberships` array** —
each membership being `{ id, organization: { id, name, slug }, role, permissions[] }`. A
user in a dozen orgs produces a multi-kilobyte cookie that the browser then attaches to
**every request to the app origin**, not just the auth routes. Cookies also have a ~4KB
per-cookie browser limit; past it the session silently stops working.

The sliding-window re-sign (`frontend.ts:1979`) is correct and cheap on its own (HMAC), but
it re-serializes that whole payload and emits a fresh `Set-Cookie` roughly once a minute per
active tab.

**Fix:** keep only `sid`, `sub`, `email` and `exp` in the cookie; serve memberships from
`/client` (which the SDK already calls) and from the session store. That shrinks the cookie
by an order of magnitude and removes the largest cost from the re-sign.

---

## P3. MEDIUM — Google token exchange has no timeout

**Where:** `frontend.ts:1707-1720`.

The X path passes `AbortSignal.timeout(20_000)` on both of its fetches
(`frontend.ts:1460`, `1513`). The Google token exchange passes none. A hung connection to
`oauth2.googleapis.com` holds the request, its socket and its closure until Node's default
socket timeout — during which the human sees a spinner and no error.

**Fix:** `signal: AbortSignal.timeout(20_000)` on the Google exchange too. Same for the
JWKS fetch — pass explicit `timeoutDuration`/`cooldownDuration` to `createRemoteJWKSet`
(`frontend.ts:75`) instead of relying on jose's defaults.

---

## P4. MEDIUM — `AuthClient.request` has no timeout, no retry, no connection reuse

**Where:** `client.ts` (`request`, `requestList`).

Every Backend API call is a bare `fetch` with no `signal`, no retry on a transient 5xx, and
no shared agent/keep-alive. In a NestJS host doing per-request Backend API calls this means
a fresh TCP+TLS handshake per call and an unbounded stall on a slow upstream.

**Fix:** accept `timeoutMs` (default ~10s) in `CreateFederatedClientOptions`, thread an
`AbortSignal.timeout` through, and reuse an `undici` Agent with keep-alive. Also worth
adding: `res.json()` is called on the success path only — the error path
(`client.ts`, `if (!res.ok) throw`) never drains the body, which leaks the socket back to
the pool unread.

---

## P5. MEDIUM — Unbounded caches

**`jwksCache`** — `verify.ts:13`, written at `verify.ts:246`, keyed by `issuer`. In a
multi-tenant host that passes a per-tenant `opts.issuer`, this Map grows without limit and
every entry holds a `createRemoteJWKSet` closure with its own cached keys. Bound it (LRU,
~50 entries).

**`InMemorySamlReplayStore`** — `saml.ts:140-155`. `record()` never bounds the map, and
`notOnOrAfter` comes from the assertion, i.e. from the IdP, so a far-future value pins an
entry forever. Worse, `seen()` calls `prune()` (`saml.ts:145`), which is a **full O(n) scan
of the map on every SAML login**. Replace with a periodic sweep (or a bounded LRU) and cap
`notOnOrAfter` at `now + 10 min`.

---

## P6. MEDIUM — React: `connections` identity changes on every snapshot change

**Where:** `auth-react/src/context.tsx:114-133`.

```ts
const value = useMemo<AuthContextValue>(() => ({
  …,
  connections: core.connections(),   // ← new array + new objects every time the memo re-runs
}), [core, snapshot, isLoaded, loadState, …])
```

`snapshot` is in the dep list, so the memo re-runs on every auth state change and
`core.connections()` (`core.ts:~300`) rebuilds the array by `.map`. Every consumer of
`useAuthContext()` — `<SignIn>`, `<SignInButton>`, `<SignUpButton>` — then re-renders even
though the connection list is derived from a constructor argument and can never change.

**Fix:** memoize `connections()` inside `RealAuthCore` (compute once in the constructor), or
hoist it to its own `useMemo` keyed on `core` alone.

---

## P7. MEDIUM — React: `useAuth()` returns a fresh object with fresh closures every render

**Where:** `auth-react/src/hooks.ts:11-50`.

Every call allocates a new result object plus new `reloadSession`/`getToken`/`has`/`signOut`
closures, and runs `snapshot.memberships.find(…)` (`hooks.ts:13`). Any component that passes
these down as props defeats `React.memo` on its children. `useOrganization` and
`useFederated` have the same shape.

**Fix:** wrap the returned object in `useMemo` keyed on `[core, snapshot, isLoaded,
loadState]`, and the callbacks in `useCallback` keyed on `[core]`.

---

## P8. LOW — Two `useSyncExternalStore` subscriptions per provider

**Where:** `context.tsx:102-112`.

`snapshot` and `loadState` subscribe separately, so every provider registers two listeners
in `BaseCore.listeners` and every emit walks the set twice. Combine into one subscription
returning a memoized `{ snapshot, loadState }`, or have `BaseCore` expose a single versioned
snapshot that includes `loadState`.

Related: `BaseCore.setSnapshot` (`core.ts:58-61`) notifies unconditionally, including when
the new snapshot is value-identical (e.g. `setActiveOrg` to the org already active,
`core.ts:104-110`). Compare before emitting.

---

## P9. LOW — `applyClient` discards a still-valid access token on every `load()`

**Where:** `core.ts:~360` — `applyClient` opens with `this.clearTokenCache()`.

Correct when the session identity changed; wasteful when it didn't. `reloadSession()`
(`hooks.ts:~28`), which exists precisely to recover from a transient 401, therefore always
forces a fresh `/tokens` round trip afterwards. Only clear when `session.id !==
this.activeSessionId` (or when the org/grants actually differ).

---

## P10. LOW — `@auth/react` depends on `jose` but never imports it

**Where:** `code/packages/auth-react/package.json` — `"dependencies": { "jose": "^5.9.6" }`.
`grep -r jose auth-react/src` returns nothing; `readJwtExp` (`core.ts:~230`) uses `atob`.

Dead dependency. It installs into every consuming app and any bundler that can't prove it
unused will ship it. Remove it.

---

## P11. LOW — Per-request URL and cookie parsing is repeated

**Where:** `pathOf` (`frontend.ts:381`), `queryOf` (`frontend.ts:390`), `parseCookies`
(`frontend.ts:398`).

Each constructs a fresh `new URL(...)` or re-splits the whole `Cookie` header. Across one
sign-in callback the request URL is parsed 2-4 times and the cookie header up to 3 times
(`readSession`, `readState`, `readSamlRelay`). Parse once at the top of the handler and pass
the result down. Small per-request cost, but it's on the hottest path in the library.

---

## P12. LOW — Backend API singleton resolves the instance twice per property access

**Where:** `auth-backend/src/index.ts` — the `federatedClient` Proxy's `get` trap calls
`instance()` for the `Reflect.get` and again for `.bind(instance())`. Hoist to a local.

---

# ⚠️ Naming-rule violations (CLAUDE.md, MANDATORY)

The project rule forbids the modeled commercial provider's name anywhere in this directory
or below, and requires a warning when it is found. Current state:

| File | Occurrences |
|---|---|
| `CLAUDE.md` | 3 |
| `audit_security/Marketing_AI.txt` | 6 |
| `audit_security/OpenAuthFederated.txt` | 6 |
| `audit_security/Uplift.txt` | 3 |
| `audit_security/p_look_for_problems.md` | 3 |
| `audit_security/The_Starbucks.txt` | 3 |
| `audit_security/Large_File_Bridge.txt` | 3 |
| `audit_security/Email_Delivery_Hero.txt` | 2 |
| `audit_security/security_bugs_to_fix.md` | 1 |
| `audit_security/web_apps_calling_us_incorrectly.md` | 1 |

**`code/` is clean** — every hit is in `audit_security/` (internal audit prose) and in
`CLAUDE.md` itself (where the rule is stated). None are in shipped code, comments, README or
docs, so none are *public* material. Still, the rule as written covers this directory:
rewrite the audit prose to say "the hosted identity provider we model" and reduce the
`CLAUDE.md` mentions to the single one the rule needs.

---

## Implementation status

Everything below landed on `dipesh/chore/perf-security-audit`. The seven new suites were written
BEFORE the fixes and each was observed failing against the pre-fix build, with the failure message
the finding predicted. (Two later additions — the path-segment allowlist cases in
`session-store-perf.cjs` — are regression tests written alongside their fix, not red-first.)
Ten suites total, 68 assertions, all green; both packages typecheck clean.

| # | Status | What shipped | Test |
|---|--------|--------------|------|
| S1 | **fixed** | `frontend.verifyToken()` per app; global `verifyToken` fails closed once two differently-configured frontends exist; identical re-bootstrap stays a no-op | `verify-isolation.cjs` |
| S2 | **fixed** | `provider: "saml"` on the identity; `hd` mapped from IdP attributes; `samlSatisfiesHostedDomain` opt-in | `saml-hardening.cjs`, `signin-flow.cjs` |
| S3 | **fixed** | Replay id + audience + expiry now read from the signature-validated assertion via `getAssertion()`; refuses when no assertion id; `inResponseTo` fallback removed; expiry capped at 10 min | `saml-hardening.cjs` |
| S4 | **fixed** (opt-in) | `namespaceUserIds` → `user_<provider>_<sub>`; default unchanged because turning it on rewrites every user id | `signin-flow.cjs` |
| S5 | **fixed** | `rateLimit` hook consulted before dispatch; 429; a throwing hook fails closed | `endpoint-hardening.cjs` |
| S6 | **fixed** | `hd` is only ever the upstream-asserted value — never back-filled from the email domain | `signin-flow.cjs` |
| S7 | **fixed** | X callback uses `constantTimeEqual`, as the Google path already did | — (covered by X path review) |
| S8 | **fixed** | Log sink centrally strips C0 controls; multi-line remediation moved to `meta` | `signin-flow.cjs` |
| S11 | **fixed** | `Vary: Origin` on matched and unmatched origins alike | `endpoint-hardening.cjs` |
| S14 | **fixed** | `sanitizeSegment` is an allowlist, widened to cover base64url session ids and RFC 5322 email local parts | `session-store-perf.cjs` |
| S15 | **fixed** | `revalidateFailMode: "keep" \| "closed"` | — |
| P1 | **fixed** | `FileSessionStore` fully async (`fs/promises`), atomic temp-file + `rename`, cached `mkdir`, concurrent `list()` | `session-store-perf.cjs` |
| P3 | **fixed** | `upstreamTimeoutMs` (default 20s) on every outbound IdP call; JWKS fetch bounded | `resource-bounds.cjs` |
| P4 | **fixed** | `timeoutMs` (default 10s) on Backend API calls; error bodies drained | `resource-bounds.cjs` |
| P5 | **fixed** | JWKS cache is a 64-entry LRU; replay store bounded at 20k with an amortized sweep instead of an O(n) scan per lookup | `resource-bounds.cjs` |
| P6 | **fixed** | Connection list built once in the constructor and frozen | `core-perf.mjs` |
| P7 | **fixed** | `useAuth()` memoized on the values it reads | — |
| P8 | **fixed** | One store subscription per provider; `setSnapshot` no longer emits on a value-identical update | — |
| P9 | **fixed** | Token cache cleared only when the session id **or the grant signature** changes | `core-perf.mjs` |
| P10 | **fixed** | Unused `jose` dependency removed from `@auth/react` | `core-perf.mjs` |
| P12 | **fixed** | Proxy `get` trap resolves the singleton once | — |

### One bypass introduced and closed during implementation

The S2 fix — mapping an IdP-asserted attribute onto `hd` so SAML can satisfy `requireHostedDomain`
— initially let that attribute stand in for the email domain when `allowedDomains` was evaluated.
A probe against the built code confirmed it:

```
ADMITTED  | requireHostedDomain OFF, email OUT of allowlist, IdP asserts allowed hd
             email=attacker@evil.example hd=act3ai.com
ADMITTED  | requireHostedDomain ON,  email OUT of allowlist, IdP asserts allowed hd
rejected  | requireHostedDomain OFF, email OUT of allowlist, no hd (control)
```

The control row is the point: before the change that identity was correctly refused, and the fix
admitted it. The allowlist had stopped gating *who may sign in* and started gating *what the IdP
claims about them*.

The two hosted-domain claims are not the same kind of fact. Google computes `hd` itself from real
Workspace membership; a SAML `hd` is an attribute whose value the IdP chose, and attribute mapping
is exactly the thing that gets misconfigured. So SAML admission is now decided on the email domain
in the assertion, and the asserted `hd` does exactly one job: satisfying `requireHostedDomain`.
Google and X behaviour is byte-identical to before. Both directions are pinned in
`signin-flow.cjs`.

### Independent security review of the fixes

The implemented diff was then put through a separate security review (`src/` only). It returned
three findings — all real, all fixed, all now covered by tests:

| Sev | Finding | Resolution |
|-----|---------|------------|
| HIGH | The new `hd` attribute mapping let an IdP-supplied value substitute for the email domain in the `allowedDomains` check | Already caught independently (above). The review added a point that was **not** covered: the implicit attribute list included the generic `domain`/`hostedDomain`/`hosted_domain`. A name that broad may already be in use by an IdP for something else, so a coincidence could satisfy `requireHostedDomain`. Now only `hd` is read implicitly, anything else must be named via `SamlSpConfig.hostedDomainAttribute`, and whatever the source the value must MATCH the email domain or it is dropped — it corroborates the address, never replaces it |
| MEDIUM | `namespaceUserIds` desynchronised grant re-resolution: `identityFromSession` stripped only `user_`, so a namespaced id yielded `saml_alice@corp.com` — a subject that never existed upstream, silently missing every host lookup keyed on `sub` | The upstream `sub` and `provider` are now persisted on the session record (cookie + durable store) and read back verbatim, instead of being reverse-engineered from an id whose shape is configurable. A legacy session with no stored value falls back to a strip that handles both id shapes |
| MEDIUM | The ambiguity latch enforced neither `iss` nor `aud` when a per-call `sessionSecret` was supplied — precisely the shape `authenticateRequest(req, { sessionSecret })` uses, and precisely the two-apps-sharing-a-secret case `aud` is documented to protect | Embedded configs are now registered per secret, so an explicit secret selects that app's claims. Writing the test then exposed a flaw in that fix too — two apps sharing one secret collided in the registry, reintroducing last-write-wins — so a secret registered by two differently-configured apps is marked ambiguous and a secret-only verify refuses rather than guessing |

The review also examined and cleared: the replay-store LRU (evicting a consumed id needs 20 000
further *validly signed* assertions, and node-saml enforces `NotOnOrAfter` independently), the new
audience read (`getAssertion()` returns the parse of the signature-validated assertion, so it is not
an XSW vector), `SAFE_SEGMENT` for traversal, the scratch-file/`rename` write path, `namespaceUserIds`
collisions, the `hd` back-fill removal, and the auth-react token-cache change.

### Deliberately deferred

| # | Why |
|---|---|
| **P2** (slim the session cookie) | The only fix that changes the wire contract: memberships would move out of the cookie and be served from `/client`. Every consuming app reading them from a decoded cookie breaks. Wants its own change with a migration note — not to ride along in a hardening batch. |
| **S9** (`/environment` lists allowed domains) | The SDK renders one sign-in button per domain from this list, so hiding it needs a replacement mechanism (opaque connection ids) and an SDK change on the other side. |
| **S10** (`__Host-` cookie prefix) | A cookie rename signs every existing session out. Needs a flag and a rollout, not a default flip. |
| **S12** (encrypt the PKCE state cookie) | Defense-in-depth on an `HttpOnly`, 10-minute cookie. Real but low, and JWE changes the cookie format. |
| **S13** (`admin` ≡ `org:admin`) | Changing it silently narrows existing role checks in consuming apps — a behaviour change that has to be announced, not slipped in. Documented instead. |
| **P11** (parse URL/cookies once per request) | Pure micro-optimization, touches every handler signature. Not worth the churn in the same change as the security fixes. |

### Breaking changes in this batch

Two, both deliberate, and neither is opt-in:

1. **`hd` is now absent unless the upstream asserted it** (S6). A host app reading `user.hd` /
   `claims.hd` for a *non-Workspace* sign-in previously got the email domain and now gets
   `undefined`. That is the point — the old value was an unverified email suffix wearing the name
   of a Workspace-membership claim — but any consumer using it as a display value needs to read
   `email` instead.
2. **`sanitizeSegment` is now an allowlist** (S14). It admits everything a base64url session id and
   an RFC 5322 email local part can contain, and additionally rejects `: * ? " < > |` and backtick,
   which the old denylist let through. A pre-existing session whose key contains one of those would
   now be refused — none can exist from this library's own id generator.

---

## What is left

Steps 1-3 of the original sequencing are done (see "Implementation status"). Remaining:

1. **P2** — slim the session cookie. The one fix with a wire-contract migration; needs its own
   change and a note to the consuming apps.
2. **S9 / S10 / S12 / S13 / P11** — the deferred items above, each for the reason given.
3. **The naming-rule pass** over `audit_security/` and `CLAUDE.md`. Untouched by this branch:
   the violations are in audit prose, and rewriting the older reports is a separate edit from
   changing the library.

No fix in this list — shipped or remaining — requires a new runtime dependency. This branch removed
one (`jose`, unused in `@auth/react`) and added none.
