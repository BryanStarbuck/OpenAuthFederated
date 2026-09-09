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

**Totals:** 27 findings — **2 HIGH, 11 MEDIUM, 14 LOW**.
Split: 15 security, 12 performance.

---

## Fix order (top 10)

| # | Sev | Kind | Finding | Location |
|---|-----|------|---------|----------|
| 1 | HIGH | security | Global mutable verification config — two frontends in one process cross-verify tokens | `verify.ts:38,46`; `frontend.ts:921` |
| 2 | HIGH | perf | `FileSessionStore` does blocking sync fs on every request | `session-store.ts:144-198` |
| 3 | MEDIUM | security | SAML identity carries no `hd`/`provider` → `requireHostedDomain` rejects *every* SAML sign-in | `saml.ts:254-261`; `frontend.ts:1838-1852` |
| 4 | MEDIUM | security | SAML replay + audience checks fail **open** when the profile field is absent | `saml.ts:213,219-227` |
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

## S3. MEDIUM — SAML audience and replay checks fail open

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
leading `.`, or whitespace. `InMemorySessionStore.key()` (`session-store.ts:~215`) joins
`userKey` and `sid` with a single space, so an email containing a space could collide with
another user's key. Emails reaching here are verified by an upstream IdP, which is why this
is LOW. Prefer an allowlist regex (`/^[a-z0-9._%+@-]+$/i`) over a denylist.

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

## Suggested sequencing

1. **Now:** S1 (global verification state), P1 (async + atomic session store). Both are
   contained changes with no API break.
2. **Next:** S2/S3 (SAML admission + fail-closed replay), P2 (slim the session cookie),
   P3/P4 (timeouts).
3. **Then:** S4 (namespaced user ids — needs a migration note), S5 (rate-limit hook), P5
   (bounded caches), P6/P7 (React memoization).
4. **Cleanup:** the remaining LOWs, plus the naming-rule pass over `audit_security/`.

No fix in this list requires a new runtime dependency.
