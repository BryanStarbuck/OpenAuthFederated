import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto"
import type { IncomingMessage, ServerResponse } from "node:http"

import { jwtVerify, SignJWT } from "jose"

import { credentialsRemediation, loadGoogleCredentials } from "./credentials.js"
import {
  configureEmbeddedVerification,
  createEmbeddedVerifier,
  type VerifyTokenOptions,
} from "./verify.js"
import type { TokenClaims } from "./types.js"
import {
  type ActionIdentity,
  type AdmissionActions,
  type AdmissionErrorCode,
  type AdmissionMessage,
  type AdmissionPhase,
  type AdmissionResult,
  type AdmissionStep,
  type AdmissionUsers,
  type AuthenticationMethod,
  connectionIdForDomain,
  decideRestrictions,
  DEFAULT_ADMISSION_MESSAGES,
  type Identifier,
  type IdentityProvider,
  invalidIdentifierList,
  invalidRestrictions,
  invalidSignUpMode,
  type Live,
  normalizeVerdict,
  OafConfigError,
  parseEmail,
  type Restrictions,
  resolveLive,
  type SignUpMode,
  type UntrustedRequestHints,
  warnOncePerProcess,
  withTimeout,
} from "./admission.js"
import {
  type EmailAccount,
  type EmailCodePurpose,
  type EmailConnectionConfig,
  codeMatches,
  hashEmailCode,
  hashPassword,
  newCodeSalt,
  newEmailAccountId,
  newEmailCode,
  normalizeEmailAddress,
  passwordProblem,
  verifyPassword,
} from "./email-auth.js"
import type { SessionMembership, SessionStore, StoredSession } from "./session-store.js"
import {
  createPkcePair,
  exchangeGoogleCode,
  exchangeXCode,
  googleAuthorizeUrl,
  OAuthExchangeError,
  randomUrlToken,
  xAuthorizeUrl,
  type OidcIdentity,
} from "./oauth-providers.js"
import {
  buildSamlClient,
  InMemorySamlReplayStore,
  samlLoginRedirectUrl,
  samlSpMetadata,
  validateSamlAcs,
  type SamlReplayStore,
  type SamlSpConfig,
} from "./saml.js"

/**
 * In-process Frontend API — the embedded counterpart to a deployed OpenAuthFederated server.
 *
 * `createAuthFrontend()` returns an Express/Node-compatible middleware that the host app mounts
 * (e.g. `app.use('/api/v1', createAuthFrontend(cfg))`). It implements exactly the endpoints the
 * `@auth/react` `RealAuthCore` calls, so a SPA gets a *real* Google, X or SAML sign-in with no
 * separate auth server process:
 *
 *   GET  /sign_in/sso                         → 302 to Google's OAuth 2.0 / OIDC authorize URL
 *   GET  /sign_in/sso?strategy=x              → 302 to X's OAuth 2.0 authorize URL (PKCE, no OIDC)
 *   GET  /oauth_callback/x                    → code→token exchange, then GET /2/users/me for the
 *                                               identity, then the same finishSignIn() tail
 *   GET  /oauth_callback                      → code→token exchange, id_token + hd verification,
 *                                               establishes the session cookie, 302 back to the SPA
 *   GET  /environment                         → instance configuration (hosted-IdP-style, secret-free)
 *   GET  /client                              → rehydrate the current session (signed-out = empty)
 *   POST /client/sessions/:id/tokens          → mint a short-lived access JWT for API calls
 *   POST /client/sessions/:id/tokens/:tmpl    → templated token mint (same path, tagged)
 *   POST /client/sessions/:id/touch           → set the session's active organization
 *   GET  /client/sessions/:id/reverify        → step-up: refresh the session's verified-at time
 *   POST /client/sessions/:id/remove          → sign out (clear the session cookie)
 *
 * Everything runs in the host's own process. The human is authenticated by the provider (for
 * Google: a real OIDC round-trip, a real id_token signature check against Google's JWKS, a real
 * `email_verified` check). WHO is admitted is the embedding app's stated policy (see admission.ts);
 * this file executes it. The app *session* and the short-lived access tokens are signed with a single
 * in-process HS256 secret (`sessionSecret`) — the same secret `verifyToken()` checks in embedded
 * mode — so there is no JWKS endpoint and no second service to run.
 */

// The Google and X protocols (authorize URLs, PKCE, code exchange, id_token verification, the X
// profile read) live in `oauth-providers.ts` and are exported from the package, so an app with its
// own session model runs the same code this middleware does. This file adds the state cookies, the
// session, and the EXECUTION of the admission policy the embedding app states (admission.ts).

/** @see oauth-providers.ts — re-exported here so existing `import { OidcIdentity } from "./frontend.js"` keeps working. */
export type { OidcIdentity }

/**
 * One organization membership. Aliased to {@link SessionMembership} (same shape) so the session
 * store and the session model share a single type and can never drift apart.
 */
export type OrgMembership = SessionMembership

/** RBAC + organization context resolved for a verified identity. */
export interface ResolvedGrants {
  roles: string[]
  permissions: string[]
  orgId: string | null
  memberships: OrgMembership[]
}

/** A Google OAuth (OIDC) sign-in connection. `strategy` mirrors Federated's `oauth_google`. */
export interface GoogleConnectionConfig {
  strategy: "oauth_google"
  /**
   * Google OAuth Web-client id. **Optional** (sign-in fails closed with a 503 if absent). The
   * embedding app owns where the value is sourced from (its own secrets file/config) and passes it
   * in here; the library reads no environment variable and no app-specific file. Never hardcode or commit it.
   */
  clientId?: string
  /**
   * Google OAuth Web-client secret. **Optional** — supplied the same way as {@link clientId}
   * (an explicit value here, sourced by the embedding app). Never hardcode the value or commit it.
   */
  clientSecret?: string
  /** Must exactly match an Authorized redirect URI in the Google Cloud OAuth client. */
  redirectUri: string
  /**
   * A fixed Google `hd` HINT sent on every authorize request (pre-selects that organization in
   * Google's account chooser). A hint only: admission is decided by {@link requireHostedDomain} /
   * {@link allowedHostedDomains} and the app's policy, never by this value.
   */
  hostedDomain?: string
  /** Refuse an identity without a verified hd. Never a default. */
  requireHostedDomain?: boolean
  /** When !== undefined: hd must be present and in this list ([] => nobody). Implies requireHostedDomain. */
  allowedHostedDomains?: string[]
  /**
   * Domains a client may pick as the hd hint via `?connection=conn_<slug>`. Legacy default: the
   * deprecated top-level `allowedDomains`. New-API default: `[]` (a client-chosen hint is ignored
   * and no hd is sent).
   */
  hostedDomainHints?: string[]
  /** Publish the hint domains in `/environment` `user_settings.connections`. Default false. */
  publishHintDomains?: boolean
  /** Button label. Default "Google". */
  label?: string
}

/**
 * An X (Twitter) OAuth 2.0 sign-in connection. `strategy` mirrors Federated's `oauth_x`.
 *
 * ⚠️ THE APPLICATION MUST BE REGISTERED AS A CONFIDENTIAL CLIENT ("Web App, Automated App or Bot"
 * in the X developer portal). A "Native App" is a PUBLIC client: X issues it no secret, and the
 * token exchange below authenticates the client with HTTP Basic.
 */
export interface XConnectionConfig {
  strategy: "oauth_x"
  /**
   * X OAuth 2.0 client id. **Optional** (sign-in fails closed with a 503 if absent). Sourced and
   * passed in by the embedding app, exactly as {@link GoogleConnectionConfig.clientId} is; the
   * library reads no environment variable and no app-specific file.
   */
  clientId?: string
  /** X OAuth 2.0 client secret. **Optional** — supplied the same way as {@link clientId}. */
  clientSecret?: string
  /** Must exactly match a Callback URI registered in the X app's *User authentication settings*. */
  redirectUri: string
  /** Button label. Default "X". An X identity always requires a confirmed email. */
  label?: string
}

/** A SAML 2.0 sign-in connection. `strategy` mirrors Federated's enterprise SSO vocabulary. */
export type SamlConnectionConfig = {
  strategy: "saml"
  /** Refuse an identity whose assertion carries no corroborated hosted-domain attribute. */
  requireHostedDomain?: boolean
  /** When !== undefined: the corroborated hd must be in this list ([] => nobody). Implies requireHostedDomain. */
  allowedHostedDomains?: string[]
  /** Button label. Default "SSO". */
  label?: string
} & SamlSpConfig

/**
 * One configured sign-in connection. Mirrors Federated's connection/strategy model
 * (`oauth_google`, SAML) so credentials are passed by API in a Federated-idiomatic shape rather than
 * via a provider-specific block.
 */
export type FederatedConnectionConfig =
  | GoogleConnectionConfig
  | SamlConnectionConfig
  | XConnectionConfig
  | EmailConnectionConfig

/** Shape of the legacy Google block (`google: { ... }`) accepted as deprecated shorthand. */
export interface LegacyGoogleConfig {
  clientId?: string
  clientSecret?: string
  redirectUri: string
  hostedDomain?: string
}

export interface FederatedFrontendConfig {
  /**
   * The sign-in connections this app offers. The Federated-idiomatic way to pass OAuth/SAML
   * credentials by API:
   *   `connections: [{ strategy: 'oauth_google', clientId, clientSecret, redirectUri }]`
   * At most one connection per strategy is used (the first of each wins).
   */
  connections?: FederatedConnectionConfig[]
  /**
   * @deprecated Use {@link connections} with `{ strategy: 'oauth_google', ... }`. Retained as a
   * shorthand so existing `createAuthFrontend({ google: { ... } })` call sites keep working.
   */
  google?: LegacyGoogleConfig
  /**
   * @deprecated Use {@link connections} with `{ strategy: 'saml', ... }`. Retained shorthand.
   * When present and `enabled`, the middleware serves the SAML SP routes (`/saml/metadata`,
   * `/saml/login`, `/saml/acs`) and `/sign_in/sso?strategy=saml`. A SAML sign-in establishes the
   * *same* session as the OIDC path. All SAML XML handling lives in `saml.ts`.
   */
  saml?: SamlSpConfig
  /**
   * @deprecated Use {@link signUpMode} + {@link restrictions} + {@link allowlistIdentifiers}
   * (`domains.map(d => "*@" + d)`) and, for the account-chooser hint, the Google connection's
   * `hostedDomainHints`.
   *
   * LEGACY GATE. When this key is PRESENT (it must then be an array of strings, or construction
   * throws {@link OafConfigError}), email/`hd` domains not on the list are refused — unless
   * {@link allowAnyDomain} is on. `[]` refuses everyone. Its presence also seeds the defaults for
   * `hostedDomainHints`, publishing `allowed_domains` in `/environment` and
   * `organization_settings.enabled`, unless those are set explicitly. Optional now (it used to be
   * required); omit it and state a policy with the new API instead.
   */
  allowedDomains?: string[]
  /**
   * @deprecated Omit the allowlist and use `signUpMode: "public"`.
   *
   * Admit a VERIFIED email on ANY domain, skipping the {@link allowedDomains} check. Defaults to
   * false — FAIL CLOSED.
   *
   * A public app's users arrive with every mailbox provider there is, and enumerating them is not
   * a control.
   *
   * WHAT IT DOES NOT LOOSEN. The provider must still assert a VERIFIED email — an identity without
   * one is refused exactly as before. {@link requireHostedDomain} still applies on its own terms,
   * so an operator who wants "any Workspace, any domain" can set both. And `allowedDomains` keeps
   * its other job: deciding which `hd` a connection may pre-select. Authorization (who is an admin,
   * what a user may do) is the host app's job and is untouched by this flag.
   */
  allowAnyDomain?: boolean
  /**
   * HS256 secret used to sign the session cookie + access tokens. The SAME value is used to verify
   * those tokens (this function calls configureEmbeddedVerification with it). Supplied by the caller.
   */
  sessionSecret: string
  /** `iss` stamped on minted access tokens (informational in embedded mode). */
  issuer?: string
  /**
   * Namespace for ALL cookies this middleware sets — the session cookie, the OAuth `state`
   * cookie, and the SAML relay cookie. Defaults to `"oaf"`, giving the historical names
   * `oaf_session` / `oaf_oauth_state` / `oaf_saml_relay`.
   *
   * Browsers do NOT isolate cookies by port, so two apps served from different ports on the
   * same host (e.g. two localhost dev servers) share one cookie jar. If both use the default
   * prefix, each app's `oaf_session` overwrites the other's and switching tabs logs you out of
   * the first. Give each app a DISTINCT prefix (e.g. `"oaf_app1"`, `"oaf_app2"`) so their
   * cookies coexist. `sessionCookieName`, if set, still wins for the session cookie specifically.
   */
  cookiePrefix?: string
  sessionCookieName?: string
  /**
   * Session **maximum lifetime** in seconds — the "maximum lifetime" knob. The absolute ceiling
   * after which the user must sign in again, regardless of activity. Defaults to 7 days. The
   * session is a sliding window (re-issued on each token mint), so active use rolls the cookie
   * forward up to this ceiling. (Name kept as `sessionTtlSeconds` for back-compat.)
   */
  sessionTtlSeconds?: number
  accessTokenTtlSeconds?: number
  /**
   * Session **inactivity timeout** in seconds — the "inactivity timeout" knob. If a session
   * goes this long without a token refresh / touch, it is treated as signed out. Defaults to 12
   * hours; `0` disables it (a user then stays signed in as long as they return within the maximum
   * lifetime). Only enforced when a {@link sessionStore} is set
   * (the store is where `lastActiveAt` is durably tracked).
   */
  inactivityTimeoutSeconds?: number
  /**
   * One-time migration opt-in: when true, a valid session cookie whose durable record is missing
   * re-creates that record from the cookie (instead of failing closed). Off by default. Supplied by
   * the API caller — never read from the environment.
   */
  sessionStoreMigrate?: boolean
  /**
   * Durable server-side session store (the stateful half of the session model). When provided, each
   * sign-in writes a {@link StoredSession}; reads validate it (revocation, max-lifetime, inactivity)
   * and the record survives app restarts. When omitted, the library is purely stateless (the signed
   * cookie is the whole session) — backward compatible. See `session-store.ts` / {@link FileSessionStore}.
   */
  sessionStore?: SessionStore
  /**
   * What a session-store READ error does (stateful mode). The store enforces revocation,
   * max-lifetime, and inactivity; if `store.get()` throws we must decide whether to trust the signed
   * cookie or treat the request as signed out.
   *   - `"closed"` (DEFAULT): fail closed — a store error returns null (signed out). Revocation is
   *     never silently bypassed, including under an attacker-induced store fault.
   *   - `"cookie-grace"`: fall back to the signed cookie on a store error (availability over the
   *     store-side checks). Use only for availability-sensitive apps that accept the documented risk
   *     that a revoked/aged-out session can slip through during a store outage.
   */
  sessionStoreFailMode?: "closed" | "cookie-grace"
  /**
   * Upper bound (seconds) on how old a session cookie may be for {@link sessionStoreMigrate} to
   * re-create a missing durable record from it. Migration trusts the cookie, so a lost tombstone
   * could otherwise resurrect a revoked session from an old-but-valid cookie. Only cookies issued
   * within this window are migrated; older ones fail closed. Defaults to 600 (10 minutes).
   */
  sessionStoreMigrateMaxAgeSeconds?: number
  /**
   * Bound deprovision latency: re-resolve grants on token mint when the session's grants are older
   * than this many seconds. Grants are otherwise baked in at sign-in and reused until the session
   * ends, so an upstream demotion/offboard only takes effect at session end. When set (> 0), each
   * mint whose grants exceed this age re-runs {@link revalidateGrants} (or {@link resolveGrants})
   * from the session's identity; if the user no longer qualifies (a null result) the session is
   * treated as signed out. Additive and **off by default** (0/undefined = never re-resolve).
   */
  reresolveGrantsEverySeconds?: number
  /**
   * Optional lighter-weight re-resolution used by {@link reresolveGrantsEverySeconds}. Given the
   * identity reconstructed from the current session, return fresh grants, or `null` to force
   * sign-out (e.g. the user was removed from the mapped upstream group). Defaults to
   * {@link resolveGrants} when omitted.
   */
  revalidateGrants?: (
    identity: OidcIdentity,
  ) => ResolvedGrants | null | Promise<ResolvedGrants | null>
  /**
   * Carry the Secure attribute on all cookies. Defaults to **true** (production-safe). Set false
   * ONLY for local http development; never ship a non-Secure session cookie to production.
   */
  cookieSecure?: boolean
  /**
   * SameSite for the session cookie. Defaults to `Lax` (the session is not a cross-site POST).
   * The SAML relay cookie always uses `None` (the cross-site ACS POST needs it) and therefore
   * requires `cookieSecure: true`.
   */
  sessionCookieSameSite?: "Lax" | "Strict"
  /**
   * Per-app audience (`aud`) stamped on minted session/access tokens AND enforced on verify. This
   * function bridges the value into `configureEmbeddedVerification`, so `verifyToken()` requires the
   * same `aud` by default (not only when each verify call passes it) — a token minted for another
   * app (different `aud`) is rejected here.
   *
   * IMPORTANT: `audience` is defense-in-depth, NOT the primary isolation control. The primary
   * control is a DISTINCT per-app `sessionSecret`: two apps that share a secret can forge each
   * other's tokens regardless of `aud`. Give every app its own strong `sessionSecret` (and, when
   * setting `audience`, also a distinct {@link issuer} — two apps that both omit `issuer` share the
   * default `"openauthfederated"`). A construction-time warning fires if `audience` is set without a
   * distinct `issuer`.
   */
  audience?: string
  /**
   * @deprecated Use the per-connection `requireHostedDomain` / `allowedHostedDomains` on the
   * Google and SAML connections.
   *
   * LEGACY GATE. Require a present, allowlisted hosted-domain (`hd`) claim. When true, an identity
   * lacking `hd` (e.g. a consumer mailbox account) is rejected even if its email domain is on
   * {@link allowedDomains} — the email domain is no longer accepted as a substitute for
   * organization membership. Defaults to false (back-compat).
   */
  requireHostedDomain?: boolean
  /**
   * Allowlist of origins (e.g. `https://app.example.com`) a post-sign-in redirect may target.
   * Absolute redirect URLs not on this list are rejected and rewritten to a same-origin relative
   * path. When omitted, ALL absolute redirect targets are refused (same-origin relative only).
   */
  allowedRedirectOrigins?: string[]
  /**
   * @deprecated HAS NO EFFECT (it never did). Set `trustAssertedEmailVerified` on the SAML
   * connection instead. A WARN is logged once per process when this key is present.
   */
  samlTrustAssertedEmailVerified?: boolean
  /**
   * @deprecated Not needed with the new admission API (the legacy hosted-domain gate is the only
   * thing it exempts X from).
   *
   * Admit an X sign-in on the strength of its `confirmed_email` alone, when
   * {@link requireHostedDomain} is on. Defaults to false — FAIL CLOSED.
   *
   * WHY THIS FLAG HAS TO EXIST. `requireHostedDomain` asks for a Google Workspace `hd` claim, and
   * its whole point is that membership of a Workspace is a stronger fact than an address that
   * merely ends in the right domain. X has no equivalent: `confirmed_email` says X delivered mail
   * to that address and nothing more. So an X sign-in CANNOT satisfy a hosted-domain requirement,
   * and silently exempting it would quietly downgrade the control the deployment asked for on
   * every account it protects. The operator says "I know, and the email is enough for X" here, in
   * one place, or X sign-in is refused with that reason. Mirrors
   * {@link samlTrustAssertedEmailVerified}, which exists for the same kind of reason.
   *
   * The {@link allowedDomains} allowlist still applies either way; this flag never bypasses it.
   */
  xTrustConfirmedEmail?: boolean
  /**
   * Replay store for consumed SAML assertion ids (one-time-use enforcement). Defaults to an
   * in-process {@link InMemorySamlReplayStore}; supply a shared store for multi-process SAML.
   */
  samlReplayStore?: SamlReplayStore
  /**
   * Add security response headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy,
   * X-Frame-Options) to every response. Defaults to true.
   */
  securityHeaders?: boolean
  /** CORS allowlist for the auth endpoints. When set, matching Origins get credentialed CORS. */
  allowedCorsOrigins?: string[]
  /**
   * Map a verified, ADMITTED identity to roles/permissions/orgs. Defaults to a least-privilege grant.
   * May be async (it is awaited). It runs after admission and cannot refuse; refuse with
   * {@link actions} instead.
   */
  resolveGrants?: (identity: OidcIdentity) => ResolvedGrants | Promise<ResolvedGrants>
  logger?: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void
  /**
   * @deprecated Not needed with the new admission API (the legacy hosted-domain gate is the only
   * thing it exempts SAML from).
   *
   * Admit a SAML sign-in under {@link requireHostedDomain} when the IdP asserts no hosted-domain
   * attribute. Defaults to false — FAIL CLOSED.
   *
   * `requireHostedDomain` asks for a Google Workspace `hd` claim, which is a Google concept. A SAML
   * IdP may assert an equivalent attribute (`hd` / `hostedDomain` / `domain`), and when it does the
   * assertion satisfies the requirement on its own — this flag is not needed. Many IdPs assert
   * nothing of the kind while nonetheless being scoped to exactly one verified company directory;
   * an operator says so HERE, in one place, rather than the library quietly exempting every SAML
   * sign-in from a control the deployment explicitly asked for. Mirrors {@link xTrustConfirmedEmail}.
   *
   * {@link allowedDomains} still applies either way; this flag never bypasses it.
   */
  samlSatisfiesHostedDomain?: boolean
  // --- admission (see admission.ts; "the platform executes, the app decides") ------------------
  /**
   * Who may CREATE an account. `public`: any verified identity that passes the lists.
   * `restricted`: a new identity needs an allowlist match (a standing invitation) or
   * `users.lookup(...).invited`. `waitlist`: no new identity is admitted (requires {@link users}).
   * When no policy is stated at all the library defaults to `public` and WARNs once per process
   * (or throws, with {@link requirePolicy}).
   */
  signUpMode?: Live<SignUpMode>
  /** Which lists are engaged. See {@link Restrictions}. */
  restrictions?: Live<Restrictions>
  /** Allowlist identifiers (`ann@example.com`, `*@example.com`, `*@*.example.com`). Never published. */
  allowlistIdentifiers?: Live<readonly Identifier[]>
  /** Blocklist identifiers, same grammar. The more specific match wins over the allowlist. Never published. */
  blocklistIdentifiers?: Live<readonly Identifier[]>
  /** App callbacks that may Allow or Deny each attempt. A Deny mints nothing. */
  actions?: AdmissionActions
  /** Optional app-owned user directory, so returning users can be told apart from new ones. */
  users?: AdmissionUsers
  /** Override the default (neutral) copy for any refusal code. */
  messages?: Partial<Record<AdmissionErrorCode, AdmissionMessage>>
  /** Throw at construction unless signUpMode, restrictions or a legacy key is present. Default false (WARN once). */
  requirePolicy?: boolean
  /** What the unauthenticated `/environment` endpoint publishes. */
  environment?: {
    /** display_config.allowed_domains. New-API default false; legacy default true. An explicit value wins in mixed mode. */
    publishAllowedDomains?: boolean
    /** organization_settings.enabled. New-API default false; legacy default true. An explicit value wins. */
    organizationsEnabled?: boolean
  }
  /**
   * Scope the minted user id to the strategy that authenticated it — `user_google_<sub>`,
   * `user_saml_<nameID>`, `user_x_<id>` — instead of the flat `user_<sub>`. Defaults to **false**
   * for back-compat.
   *
   * WHY IT MATTERS: without it, three strategies write into one identifier namespace. Google `sub`
   * and X account id are both numeric strings, and a SAML `persistent` NameID is an
   * operator-chosen opaque string, so nothing structurally prevents two different humans at two
   * different IdPs from resolving to the same `user_…`. It also means one human who signs in via
   * SAML on Monday and Google on Tuesday is silently two users with two grant sets.
   *
   * TURNING THIS ON IS A MIGRATION: every existing user id changes, so anything the host app
   * persisted against the old id must be migrated with it. New deployments should set it true.
   */
  namespaceUserIds?: boolean
  /**
   * What a THROWN {@link revalidateGrants} does (only when `reresolveGrantsEverySeconds` is set).
   *   - `"keep"` (DEFAULT): keep the existing grants for this mint and retry next window —
   *     availability first, matching the historical behaviour.
   *   - `"closed"`: treat the failure as a loss of authorization and sign the session out.
   *
   * The default is the riskier one on purpose (it is the pre-existing behaviour), but note what it
   * means: if the resolver fails BECAUSE the upstream directory is unreachable — exactly when
   * someone may have just been offboarded — deprovision latency silently reverts to the full
   * session lifetime. Deployments that would rather sign a user out than carry stale grants through
   * a directory outage set `"closed"`.
   */
  revalidateFailMode?: "keep" | "closed"
  /**
   * Timeout, in milliseconds, for every outbound call this middleware makes to an upstream IdP
   * (Google's token endpoint, X's token and user endpoints). Defaults to 20000. A hung upstream
   * otherwise holds the request, its socket and its closure open with the human watching a spinner.
   */
  upstreamTimeoutMs?: number
  /**
   * Per-request gate, consulted BEFORE any handler runs. Return false (or a rejected/false promise)
   * to answer `429` and stop.
   *
   * The library cannot own a rate limiter — it is mounted middleware with no store and no view of
   * the deployment — but it must expose the seam, because the routes that most need one are the
   * ones it owns: `/saml/acs` does XML signature work before it can cheaply refuse anything, and
   * `/oauth_callback/x` makes two outbound calls to X per unauthenticated request, which makes this
   * library an amplifier against a third party's limits. Every refusal also writes a log line, so an
   * unauthenticated flood is a log-volume DoS.
   *
   * A hook that THROWS is treated as a refusal (429): a limiter outage is not a reason to drop the
   * limit on the auth endpoints.
   */
  rateLimit?: (ctx: RateLimitContext) => boolean | Promise<boolean>
}

/** What {@link FederatedFrontendConfig.rateLimit} is told about the request it is gating. */
export interface RateLimitContext {
  /** Upper-cased HTTP method. */
  method: string
  /** Path within the mount point, e.g. `/client/sessions/sess_1/tokens`. */
  path: string
  /** The raw request, for a limiter that keys on a header or the socket address. */
  req: IncomingMessage
}

/**
 * @deprecated Use {@link FederatedFrontendConfig}. Alias retained so older imports resolve unchanged.
 */
export type AuthFrontendConfig = FederatedFrontendConfig

const STATE_TTL_SECONDS = 600

// --- small Node http helpers (no express dependency) ---------------------------------------

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function pathOf(req: IncomingMessage): string {
  const raw = req.url ?? "/"
  try {
    return new URL(raw, "http://internal").pathname
  } catch {
    return raw.split("?")[0] ?? raw
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  const raw = req.url ?? "/"
  try {
    return new URL(raw, "http://internal").searchParams
  } catch {
    return new URLSearchParams()
  }
}

function parseCookies(req: IncomingMessage): Record<string, string> {
  // Guard against request objects that arrive without `headers` (e.g. a minimal/malformed
  // request, or a non-Node caller constructing the object itself). Without this, the bare
  // `req.headers.cookie` deref throws "Cannot read properties of undefined (reading 'cookie')"
  // — the crash seen as "auth-frontend handler threw" in AuthFrontend logs.
  const header = req?.headers?.cookie
  if (!header) return {}
  const out: Record<string, string> = {}
  for (const part of header.split(";")) {
    const eq = part.indexOf("=")
    if (eq < 0) continue
    const k = part.slice(0, eq).trim()
    const v = part.slice(eq + 1).trim()
    if (k) out[k] = decodeURIComponent(v)
  }
  return out
}

function appendSetCookie(res: ServerResponse, cookie: string): void {
  const prev = res.getHeader("Set-Cookie")
  if (!prev) res.setHeader("Set-Cookie", [cookie])
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie])
  else res.setHeader("Set-Cookie", [String(prev), cookie])
}

function setCookie(
  res: ServerResponse,
  name: string,
  value: string,
  opts: { maxAgeSeconds?: number; secure?: boolean; sameSite?: "Lax" | "Strict" | "None" } = {},
): void {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    `SameSite=${opts.sameSite ?? "Lax"}`,
  ]
  if (opts.maxAgeSeconds != null) parts.push(`Max-Age=${opts.maxAgeSeconds}`)
  if (opts.secure) parts.push("Secure")
  appendSetCookie(res, parts.join("; "))
}

function clearCookie(
  res: ServerResponse,
  name: string,
  secure?: boolean,
  sameSite: "Lax" | "Strict" | "None" = "Lax",
): void {
  appendSetCookie(
    res,
    `${name}=; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=0${secure ? "; Secure" : ""}`,
  )
}

/** Security response headers applied to every auth-endpoint response (defense-in-depth). */
function setSecurityHeaders(res: ServerResponse): void {
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("Referrer-Policy", "no-referrer")
  res.setHeader("X-Frame-Options", "DENY")
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}

/**
 * Hash an email to a short, non-reversible token so logs carry no raw PII. When a per-deployment
 * `hmacKey` is supplied (derived from this app's sessionSecret), the digest is an HMAC — it is NOT
 * offline-guessable: an attacker who leaks the logs cannot confirm a guessed email by hashing it,
 * because they lack the key. The domain is dropped so the identifier is fully opaque (no company
 * domain enumeration from leaked logs). Without a key it falls back to a plain (keyed-less) SHA-256,
 * still domain-free.
 */
function redactEmail(email: string, hmacKey?: Uint8Array): string {
  if (!email) return "<none>"
  const normalized = email.toLowerCase()
  const digest = hmacKey
    ? createHmac("sha256", hmacKey).update(normalized).digest("hex").slice(0, 12)
    : createHash("sha256").update(normalized).digest("hex").slice(0, 12)
  return `user_${digest}`
}

/**
 * Strip anything from a log message that could forge a second log line.
 *
 * Several messages interpolate values an attacker influences — the presented email domain, the
 * scope string X returned, X's own error text. Under any line-oriented log sink a CR/LF in one of
 * those is an extra, attacker-authored audit entry. Applied centrally (see `normalizeConfig`) so it
 * covers every call site, including ones added later: a per-call-site fix is a fix that the next
 * `cfg.log(...)` forgets.
 */
const LOG_MESSAGE_MAX = 2000
function sanitizeLogMessage(message: string): string {
  // C0 controls (CR, LF, tab, NUL ...) and DEL collapse to a space, so the text stays readable
  // while a newline can no longer start a line of its own.
  return message.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, LOG_MESSAGE_MAX)
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body)
  res.statusCode = status
  res.setHeader("Content-Type", "application/json; charset=utf-8")
  res.setHeader("Cache-Control", "no-store")
  res.end(payload)
}

function redirect(res: ServerResponse, location: string): void {
  res.statusCode = 302
  res.setHeader("Location", location)
  res.setHeader("Cache-Control", "no-store")
  res.end()
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  // The host (NestJS) may have already parsed the body; prefer it to avoid a consumed stream.
  const pre = (req as IncomingMessage & { body?: unknown }).body
  if (pre && typeof pre === "object") return pre as Record<string, unknown>
  return await new Promise((resolve) => {
    let data = ""
    let done = false
    const finish = (v: Record<string, unknown>) => {
      if (!done) {
        done = true
        resolve(v)
      }
    }
    req.on("data", (c) => {
      data += c
      if (data.length > 1_000_000) {
        // Oversized body: resolve early AND stop buffering. Without destroying the stream, `data`
        // keeps growing on this closure until the client finishes — a slow, large upload is a memory
        // DoS even after the promise settled. Drop the reference and tear down the request.
        data = ""
        finish({})
        req.destroy()
      }
    })
    req.on("end", () => {
      try {
        finish(data ? (JSON.parse(data) as Record<string, unknown>) : {})
      } catch {
        finish({})
      }
    })
    req.on("error", () => finish({}))
  })
}

/**
 * Read an `application/x-www-form-urlencoded` body (the SAML ACS POST: `SAMLResponse`,
 * `RelayState`). Prefers a body the host (NestJS' express.urlencoded) already parsed, else reads
 * and parses the raw stream. Mirrors {@link readJsonBody}.
 */
async function readFormBody(req: IncomingMessage): Promise<Record<string, string>> {
  const pre = (req as IncomingMessage & { body?: unknown }).body
  if (pre && typeof pre === "object" && Object.keys(pre as object).length > 0) {
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(pre as Record<string, unknown>)) {
      out[k] = Array.isArray(v) ? String(v[0] ?? "") : String(v ?? "")
    }
    return out
  }
  return await new Promise((resolve) => {
    let data = ""
    let done = false
    const finish = (v: Record<string, string>) => {
      if (!done) {
        done = true
        resolve(v)
      }
    }
    req.on("data", (c) => {
      data += c
      if (data.length > 5_000_000) {
        // SAML responses are larger than JSON, but still cap. As in readJsonBody, resolve early AND
        // destroy the stream so an oversized/slow upload cannot keep buffering into memory after the
        // promise settled. (5MB cap.)
        data = ""
        finish({})
        req.destroy()
      }
    })
    req.on("end", () => {
      const out: Record<string, string> = {}
      try {
        for (const [k, v] of new URLSearchParams(data)) out[k] = v
      } catch {
        // malformed body → empty; the ACS handler will reject the (missing) SAMLResponse
      }
      finish(out)
    })
    req.on("error", () => finish({}))
  })
}

/**
 * Recover the upstream subject from a minted user id, for sessions predating {@link
 * SessionRecord.providerSub}. Strips the provider segment too, so a `namespaceUserIds` id does not
 * yield a subject with `saml_`/`google_`/`x_` still glued to the front.
 */
function stripUserIdPrefix(userId: string): string {
  return userId.replace(/^user_(?:google|saml|x)_/, "").replace(/^user_/, "")
}

function emailDomain(email: string): string {
  const at = email.lastIndexOf("@")
  return at < 0 ? "" : email.slice(at + 1).trim().toLowerCase()
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

// --- default RBAC mapping ------------------------------------------------------------------

/**
 * Default grant: a least-privilege authenticated member — NO write, NO membership-management, NO
 * admin role, one neutral default organization. Any elevated authority (`*:write`, `org:admin`,
 * `org:sys_memberships:manage`) MUST be granted explicitly by the embedding app via
 * `config.resolveGrants`. This fails closed: forgetting to wire `resolveGrants` yields a read-only
 * member, not an org admin.
 */
function defaultResolveGrants(_identity: OidcIdentity): ResolvedGrants {
  const membership: OrgMembership = {
    id: "orgmem_default",
    organization: { id: "org_default", name: "Default", slug: "default" },
    role: "member",
    permissions: [],
  }
  return {
    roles: ["member"],
    permissions: [],
    orgId: "org_default",
    memberships: [membership],
  }
}

// --- session model -------------------------------------------------------------------------

interface SessionRecord {
  sid: string
  userId: string
  email: string
  name?: string
  firstName?: string
  lastName?: string
  hd?: string
  roles: string[]
  permissions: string[]
  orgId: string | null
  memberships: OrgMembership[]
  lastVerifiedAt: number // epoch seconds
  /** When the grants (roles/permissions/memberships) were last resolved (epoch seconds). Drives the
   *  optional on-mint re-resolution that bounds deprovision latency (reresolveGrantsEverySeconds). */
  grantsResolvedAt: number
  /**
   * The upstream subject EXACTLY as the IdP asserted it, and which strategy asserted it.
   *
   * Kept verbatim rather than recovered from {@link userId} by stripping a prefix. `userId` is a
   * value WE mint, and its shape is configurable (`namespaceUserIds`), so parsing it back is a
   * decoding step that silently desynchronises the moment the minting rule changes — and the thing
   * it feeds is grant re-resolution, i.e. the authoritative "is this person still allowed?" call.
   * Optional so a session cookie issued before this field existed still reads.
   */
  providerSub?: string
  provider?: "google" | "saml" | "x" | "email"
  /** True on every session established after the admission redesign (a verified email was required). */
  emailVerified?: boolean
}

/**
 * Who is signed in on a request — the PUBLIC, read-only view of a session.
 *
 * This is the shape {@link FederatedFrontend.readBrowserSession} hands back to a host app. It is
 * deliberately a subset of the library-internal `SessionRecord`: the bookkeeping field
 * `grantsResolvedAt` exists only to schedule grant re-resolution inside the middleware, so it is not
 * part of the contract a host app may depend on.
 *
 * A host app that server-renders a page (a consent screen, an admin view) must be able to answer
 * "who is this?" from the SAME code path the Frontend API's `GET /client` uses. Reading and
 * verifying the session cookie by hand in the host app is how the two halves drift apart — and a
 * hand-rolled read is exactly the place where revocation, expiry and inactivity checks get skipped.
 *
 * That answer is also DELIBERATELY not derivable outside this module. The session cookie is signed
 * with an HKDF subkey (`oaf:session`), not the master `sessionSecret`, precisely so that a leak of
 * the secret used for access tokens cannot forge a session cookie — which also means
 * `verifyToken()` cannot verify one, and a host that tried would have to re-derive the subkey and
 * keep that derivation in step with this file forever. One implementation, exposed once, is the
 * alternative to that drift.
 */
export interface BrowserSession {
  /** Session id (the `sid` claim); the handle the /client/sessions/:id routes address. */
  sid: string
  /** Stable user id (`user_<hash>`). */
  userId: string
  /** Verified email address of the signed-in human. */
  email: string
  name?: string
  firstName?: string
  lastName?: string
  /** Google Workspace hosted domain, when the upstream identity carried one. */
  hd?: string
  roles: string[]
  permissions: string[]
  /** Active organization, or null when the session has not selected one. */
  orgId: string | null
  memberships: OrgMembership[]
  /** When the human last proved their identity upstream (epoch seconds). */
  lastVerifiedAt: number
  /** Which strategy authenticated this session. Absent on very old sessions. */
  provider?: IdentityProvider
  /** The upstream subject exactly as the provider asserted it. Absent on very old sessions. */
  providerSub?: string
}

/**
 * What {@link createFederatedFrontend} returns: the mountable Node/Express middleware, plus the
 * session reader the host app needs for its own server-rendered routes.
 *
 * It stays CALLABLE with the exact signature it always had — `app.use("/api/v1", frontend)` is
 * unchanged — so adding the method is not a breaking change for any existing embedder. The method
 * hangs off the function rather than the function becoming an object because every current call
 * site passes the return value straight to `app.use`.
 */
export interface FederatedFrontend {
  (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void): void
  /**
   * Resolve the session on a request, or `null` when signed out.
   *
   * Runs the identical path `GET /client` runs — cookie signature verification, then, when a
   * `sessionStore` is configured, the durable record's revoked / expired / inactive checks and the
   * configured fail mode. So a session that was signed out, offboarded or timed out reads as
   * signed-OUT here too, and a server-rendered page cannot disagree with the SPA about who is
   * signed in.
   *
   * Read-only: it never mints, refreshes, touches or clears anything, and writes nothing to the
   * response — safe to call from any route, including a GET that must stay side-effect free.
   */
  readBrowserSession(req: IncomingMessage): Promise<BrowserSession | null>
  /**
   * Verify an access token THIS frontend minted, using THIS frontend's secret, issuer and audience.
   *
   * Prefer it over the module-level `verifyToken()` in any process that mounts more than one
   * frontend. `configureEmbeddedVerification()` writes one process-global variable, so a second
   * `createFederatedFrontend()` would otherwise repoint the global at the second app — quietly
   * verifying app A's requests against app B's secret and destroying the per-app `aud` isolation
   * the config promises. This method reads no global state, so two apps in one process each keep
   * their own verifier.
   */
  verifyToken(token: string, opts?: VerifyTokenOptions): Promise<TokenClaims>
  /**
   * Run the full admission pipeline on a synthetic identity WITHOUT minting anything (no session,
   * no cookie, no store write, no `resolveGrants` call). For an app's boot self-test and for
   * tests. `isSignUp` (when given, including `null`) replaces `users.lookup`; `phase: "reverify"`
   * runs the reverify subset (no sign-up steps).
   */
  evaluateAdmission(
    identity: ActionIdentity,
    opts?: { isSignUp?: boolean | null; phase?: AdmissionPhase },
  ): Promise<AdmissionResult>
  /**
   * Revoke every session of one user (by email) in the configured `sessionStore`. Throws when no
   * store is configured or the store has no `revokeAllForUser`. Returns the count revoked.
   * Cookie-only (store-less) sessions cannot be revoked server-side.
   */
  revokeUserSessions(email: string): Promise<number>
}

/**
 * Alias for {@link FederatedFrontend}, kept because the callable-plus-method shape reads as a
 * "middleware" at the call sites that mount it. Both names describe the same value.
 */
export type FederatedFrontendMiddleware = FederatedFrontend

/** Google config after credential resolution: id/secret are filled (possibly empty) strings. */
interface ResolvedGoogleConfig {
  clientId: string
  clientSecret: string
  redirectUri: string
  hostedDomain?: string
}

/** A connection's own admission requirements (step 3), normalized. */
interface ConnectionRequirements {
  requireHostedDomain: boolean
  /** undefined = not set; [] = nobody. */
  allowedHostedDomains?: string[]
}

/** The admission policy after construction-time validation. Live values stay functions. */
interface AdmissionConfig {
  /** A legacy key (allowedDomains, allowAnyDomain, ...) is present. */
  legacy: boolean
  /** Legacy keys only: steps 0 and 4-8 are no-ops (byte-compatible with the old gate). */
  legacyOnly: boolean
  /** The deprecated keys actually present, for the once-per-process WARN. */
  deprecatedKeys: string[]
  signUpMode?: Live<SignUpMode>
  restrictions?: Live<Restrictions>
  allowlist?: Live<readonly Identifier[]>
  blocklist?: Live<readonly Identifier[]>
  actions?: AdmissionActions
  users?: AdmissionUsers
  messages: Partial<Record<AdmissionErrorCode, AdmissionMessage>>
  timeoutMs: number
  onError: { authentication: "deny" | "allow"; userRegistration: "deny" | "allow" }
  publishAllowedDomains: boolean
  organizationsEnabled: boolean
  google: ConnectionRequirements & { hostedDomainHints: string[]; publishHintDomains: boolean; label: string }
  saml: ConnectionRequirements & { label: string }
  xLabel: string
}

/** X config after resolution: id/secret are filled (possibly empty) strings. */
interface ResolvedXConfig {
  clientId: string
  clientSecret: string
  redirectUri: string
}

interface InternalConfig {
  google: ResolvedGoogleConfig
  x: ResolvedXConfig
  saml?: SamlSpConfig
  allowedDomains: string[]
  sessionSecret: string
  sessionCookieName: string
  /** `${cookiePrefix}_oauth_state` — the short-lived OAuth CSRF/PKCE state cookie. */
  stateCookieName: string
  /** `${cookiePrefix}_saml_relay` — the short-lived SAML RelayState/CSRF cookie. */
  samlRelayCookieName: string
  sessionTtlSeconds: number
  accessTokenTtlSeconds: number
  inactivityTimeoutSeconds: number
  sessionStoreMigrate: boolean
  sessionStoreMigrateMaxAgeSeconds: number
  sessionStoreFailMode: "closed" | "cookie-grace"
  reresolveGrantsEverySeconds: number
  revalidateGrants?: (
    identity: OidcIdentity,
  ) => ResolvedGrants | null | Promise<ResolvedGrants | null>
  sessionStore?: SessionStore
  cookieSecure: boolean
  sessionCookieSameSite: "Lax" | "Strict"
  audience?: string
  requireHostedDomain: boolean
  allowedRedirectOrigins: string[]
  samlTrustAssertedEmailVerified: boolean
  samlReplayStore: SamlReplayStore
  securityHeaders: boolean
  allowedCorsOrigins: string[]
  issuer?: string
  samlSatisfiesHostedDomain: boolean
  /** See {@link FederatedFrontendConfig.allowAnyDomain}. */
  allowAnyDomain: boolean
  namespaceUserIds: boolean
  revalidateFailMode: "keep" | "closed"
  upstreamTimeoutMs: number
  rateLimit?: (ctx: RateLimitContext) => boolean | Promise<boolean>
  resolveGrants: (identity: OidcIdentity) => ResolvedGrants | Promise<ResolvedGrants>
  log: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void
  /** True only when the X client id, secret AND redirect URI all resolved to non-empty values. */
  xConfigured: boolean
  /** See {@link FederatedFrontendConfig.xTrustConfirmedEmail}. */
  xTrustConfirmedEmail: boolean
  /** True only when both Google client id and secret resolved to non-empty values. */
  googleConfigured: boolean
  /** Secret-free, operator-actionable remediation text used when Google is unconfigured. */
  googleRemediation: string
  /** The app's stated admission policy (or the legacy gate). */
  admission: AdmissionConfig
  /** The `email` connection, resolved with its defaults (email-auth.ts). Absent = not offered. */
  email?: ResolvedEmailConfig
}

/** {@link EmailConnectionConfig} with every default filled in. */
interface ResolvedEmailConfig {
  sendCode: EmailConnectionConfig["sendCode"]
  store: EmailConnectionConfig["store"]
  password: boolean
  codeTtlSeconds: number
  maxCodeAttempts: number
  resendCooldownSeconds: number
  maxCodesPerHour: number
  minPasswordLength: number
  maxPasswordFailures: number
  passwordLockSeconds: number
  label: string
}

function resolveEmailConfig(c: EmailConnectionConfig | undefined): ResolvedEmailConfig | undefined {
  if (!c) return undefined
  if (typeof c.sendCode !== "function") {
    throw new OafConfigError("connections[strategy=email] needs sendCode(message) — the app owns the mail transport")
  }
  const s = c.store as Partial<EmailConnectionConfig["store"]> | undefined
  if (!s || ["getAccount", "putAccount", "getPending", "putPending", "deletePending"].some((m) => typeof (s as Record<string, unknown>)[m] !== "function")) {
    throw new OafConfigError("connections[strategy=email] needs a store (FileEmailAccountStore, InMemoryEmailAccountStore or your own)")
  }
  const pos = (v: number | undefined, d: number) => (typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : d)
  return {
    sendCode: c.sendCode,
    store: c.store,
    password: c.password !== false,
    codeTtlSeconds: pos(c.codeTtlSeconds, 600),
    maxCodeAttempts: pos(c.maxCodeAttempts, 5),
    resendCooldownSeconds: pos(c.resendCooldownSeconds, 30),
    maxCodesPerHour: pos(c.maxCodesPerHour, 10),
    minPasswordLength: Math.max(8, pos(c.minPasswordLength, 8)),
    maxPasswordFailures: pos(c.maxPasswordFailures, 10),
    passwordLockSeconds: pos(c.passwordLockSeconds, 900),
    label: c.label || "Email",
  }
}

/**
 * Collapse the Federated-idiomatic `connections[]` (and the deprecated `google`/`saml` shorthands)
 * into the `{ google, saml }` pair the request handlers consume. The first connection of each
 * strategy wins; an explicit `connections` entry takes precedence over the legacy shorthand.
 */
function normalizeConnections(config: FederatedFrontendConfig): {
  google?: LegacyGoogleConfig
  saml?: SamlSpConfig
  x?: XConnectionConfig
  googleConn?: GoogleConnectionConfig
  samlConn?: SamlConnectionConfig
  emailConn?: EmailConnectionConfig
} {
  const connections = config.connections ?? []
  const googleConn = connections.find(
    (c): c is GoogleConnectionConfig => c.strategy === "oauth_google",
  )
  const samlConn = connections.find((c): c is SamlConnectionConfig => c.strategy === "saml")
  // There is no legacy shorthand for X — it was added after `connections[]` became the idiom, so
  // this is the only way to configure it and there is no second spelling to keep working.
  const xConn = connections.find((c): c is XConnectionConfig => c.strategy === "oauth_x")

  const google: LegacyGoogleConfig | undefined = googleConn
    ? {
        clientId: googleConn.clientId,
        clientSecret: googleConn.clientSecret,
        redirectUri: googleConn.redirectUri,
        hostedDomain: googleConn.hostedDomain,
      }
    : config.google

  let saml: SamlSpConfig | undefined
  if (samlConn) {
    const { strategy: _strategy, ...rest } = samlConn
    saml = rest
  } else {
    saml = config.saml
  }

  const emailConn = connections.find((c): c is EmailConnectionConfig => c.strategy === "email")

  return { google, saml, x: xConn, googleConn, samlConn, emailConn }
}

const LEGACY_KEYS = [
  "allowedDomains",
  "allowAnyDomain",
  "requireHostedDomain",
  "xTrustConfirmedEmail",
  "samlSatisfiesHostedDomain",
] as const

/** Normalize a domain list (trim + lowercase, drop empties). */
function normDomains(list: readonly string[]): string[] {
  return list.map((d) => String(d).trim().toLowerCase()).filter(Boolean)
}

/**
 * Construction-time validation of the admission policy. Everything static is checked HERE so a
 * broken policy fails at boot, loudly, instead of at the first sign-in. Live values are checked on
 * every resolution instead (a failure there is `action_failed`, never a fallback).
 */
function normalizeAdmission(
  config: FederatedFrontendConfig,
  googleConn: GoogleConnectionConfig | undefined,
  samlConn: SamlConnectionConfig | undefined,
  xConn: XConnectionConfig | undefined,
): AdmissionConfig {
  const has = (k: string) => Object.prototype.hasOwnProperty.call(config, k)
  const deprecatedKeys: string[] = LEGACY_KEYS.filter((k) => has(k))
  const legacy = deprecatedKeys.length > 0

  if (legacy) {
    // Key presence decides legacy mode, so `{ allowedDomains: undefined }` can never fail open: it
    // throws here, exactly as the old unguarded `.map` crashed at construction.
    if (!Array.isArray(config.allowedDomains) || config.allowedDomains.some((d) => typeof d !== "string")) {
      throw new OafConfigError(
        "createFederatedFrontend: a legacy admission key is present (" +
          deprecatedKeys.join(", ") +
          ") so `allowedDomains` must be an array of strings. State the policy with signUpMode / " +
          "restrictions / allowlistIdentifiers instead, or pass allowedDomains explicitly.",
      )
    }
    for (const k of ["allowAnyDomain", "requireHostedDomain", "xTrustConfirmedEmail", "samlSatisfiesHostedDomain"] as const) {
      const v = (config as unknown as Record<string, unknown>)[k]
      if (v !== undefined && typeof v !== "boolean") {
        throw new OafConfigError(`createFederatedFrontend: \`${k}\` must be a boolean (got ${JSON.stringify(v)})`)
      }
    }
  }
  if (has("samlTrustAssertedEmailVerified")) deprecatedKeys.push("samlTrustAssertedEmailVerified")

  const newApi =
    config.signUpMode !== undefined ||
    config.restrictions !== undefined ||
    config.allowlistIdentifiers !== undefined ||
    config.blocklistIdentifiers !== undefined ||
    config.actions !== undefined ||
    config.users !== undefined
  const policyStated = config.signUpMode !== undefined || config.restrictions !== undefined || legacy
  if (!policyStated && config.requirePolicy === true) {
    throw new OafConfigError(
      "createFederatedFrontend: requirePolicy is set but no admission policy is stated. Pass " +
        "signUpMode (and restrictions / allowlistIdentifiers as needed).",
    )
  }

  // Static values are validated now; Live (function) values on every resolution.
  if (config.signUpMode !== undefined && typeof config.signUpMode !== "function") {
    const err = invalidSignUpMode(config.signUpMode)
    if (err) throw new OafConfigError(`createFederatedFrontend: ${err}`)
  }
  if (config.restrictions !== undefined && typeof config.restrictions !== "function") {
    const err = invalidRestrictions(config.restrictions)
    if (err) throw new OafConfigError(`createFederatedFrontend: ${err}`)
  }
  for (const [name, v] of [
    ["allowlistIdentifiers", config.allowlistIdentifiers],
    ["blocklistIdentifiers", config.blocklistIdentifiers],
  ] as const) {
    if (v !== undefined && typeof v !== "function") {
      const err = invalidIdentifierList(v, name)
      if (err) throw new OafConfigError(`createFederatedFrontend: ${err}`)
    }
  }
  // A list without its switch is IGNORED by decideRestrictions, which fails OPEN for a blocklist (the
  // person it names still gets in) and for an allowlist on a public install (anyone gets in). An app
  // author who writes the list and forgets the flag believes the opposite, so a static list that
  // would be ignored is a construction error. A Live list or Live restrictions cannot be judged here;
  // resolvePolicy() warns once per process for those instead.
  if (typeof config.restrictions !== "function") {
    const r = (config.restrictions ?? {}) as Restrictions
    for (const [name, v, flag] of [
      ["blocklistIdentifiers", config.blocklistIdentifiers, "blocklist"],
      ["allowlistIdentifiers", config.allowlistIdentifiers, "allowlist"],
    ] as const) {
      if (Array.isArray(v) && v.length > 0 && r[flag] !== true) {
        throw new OafConfigError(
          `createFederatedFrontend: \`${name}\` has ${v.length} entr${v.length === 1 ? "y" : "ies"} but ` +
            `restrictions.${flag} is not true, so the list would be silently ignored. Set ` +
            `restrictions.${flag}: true to enforce it, or pass an empty list.`,
        )
      }
    }
  }
  if (config.users !== undefined && (typeof config.users !== "object" || typeof config.users?.lookup !== "function")) {
    throw new OafConfigError("createFederatedFrontend: users must be { lookup(identity) }")
  }
  if (config.signUpMode === "waitlist" && !config.users) {
    throw new OafConfigError(
      "createFederatedFrontend: signUpMode 'waitlist' needs `users` (a lookup), or it would refuse " +
        "every returning user too.",
    )
  }
  if (
    config.signUpMode === "restricted" &&
    config.restrictions !== undefined &&
    typeof config.restrictions !== "function" &&
    config.restrictions.applyToSignIn === false &&
    !config.users
  ) {
    throw new OafConfigError(
      "createFederatedFrontend: signUpMode 'restricted' with restrictions.applyToSignIn false needs " +
        "`users`: without a lookup every sign-in is treated as a sign-up.",
    )
  }
  const actions = config.actions
  if (actions !== undefined) {
    if (typeof actions !== "object" || actions === null) {
      throw new OafConfigError("createFederatedFrontend: actions must be an object")
    }
    for (const k of ["authentication", "userRegistration"] as const) {
      if (actions[k] !== undefined && typeof actions[k] !== "function") {
        throw new OafConfigError(`createFederatedFrontend: actions.${k} must be a function`)
      }
    }
    if (
      actions.timeoutMs !== undefined &&
      !(typeof actions.timeoutMs === "number" && Number.isInteger(actions.timeoutMs) && actions.timeoutMs > 0)
    ) {
      throw new OafConfigError("createFederatedFrontend: actions.timeoutMs must be a positive integer")
    }
    for (const k of ["authentication", "userRegistration"] as const) {
      const v = actions.onError?.[k]
      if (v !== undefined && v !== "deny" && v !== "allow") {
        throw new OafConfigError(`createFederatedFrontend: actions.onError.${k} must be 'deny' or 'allow'`)
      }
    }
  }

  const listOrUndefined = (v: unknown, name: string): string[] | undefined => {
    if (v === undefined) return undefined
    const err = invalidIdentifierList(v, name)
    if (err) throw new OafConfigError(`createFederatedFrontend: ${err}`)
    return normDomains(v as string[])
  }
  const legacyDomains = legacy ? normDomains(config.allowedDomains as string[]) : []
  const hints = listOrUndefined(googleConn?.hostedDomainHints, "hostedDomainHints")
  const env = config.environment ?? {}

  return {
    legacy,
    legacyOnly: legacy && !newApi,
    deprecatedKeys,
    signUpMode: config.signUpMode,
    restrictions: config.restrictions,
    allowlist: config.allowlistIdentifiers,
    blocklist: config.blocklistIdentifiers,
    actions,
    users: config.users,
    messages: config.messages ?? {},
    timeoutMs: actions?.timeoutMs ?? 5000,
    onError: {
      authentication: actions?.onError?.authentication ?? "deny",
      userRegistration: actions?.onError?.userRegistration ?? "deny",
    },
    publishAllowedDomains: typeof env.publishAllowedDomains === "boolean" ? env.publishAllowedDomains : legacy,
    organizationsEnabled: typeof env.organizationsEnabled === "boolean" ? env.organizationsEnabled : legacy,
    google: {
      requireHostedDomain: googleConn?.requireHostedDomain === true,
      allowedHostedDomains: listOrUndefined(googleConn?.allowedHostedDomains, "google allowedHostedDomains"),
      hostedDomainHints: hints ?? (legacy ? legacyDomains : []),
      publishHintDomains: googleConn?.publishHintDomains === true,
      label: googleConn?.label || "Google",
    },
    saml: {
      requireHostedDomain: samlConn?.requireHostedDomain === true,
      allowedHostedDomains: listOrUndefined(samlConn?.allowedHostedDomains, "saml allowedHostedDomains"),
      label: samlConn?.label || "SSO",
    },
    xLabel: xConn?.label || "X",
  }
}

function normalizeConfig(config: FederatedFrontendConfig): InternalConfig {
  const { google: googleCfg, saml: samlCfg, x: xCfg, googleConn, samlConn, emailConn } = normalizeConnections(config)
  const admission = normalizeAdmission(config, googleConn, samlConn, xCfg)

  // Resolve the Google OAuth credentials the library was given (explicit config only — the library
  // reads no environment variable and no app-specific file; the embedding app sources the value and
  // passes it in). We capture a secret-free remediation message rather than throwing,
  // so a missing credential surfaces as a clear 503 at request time (and the SAML path, which needs
  // no Google credential, still works).
  const resolved = loadGoogleCredentials({
    clientId: googleCfg?.clientId,
    clientSecret: googleCfg?.clientSecret,
  })
  const clientId = resolved.clientId
  const clientSecret = resolved.clientSecret
  const googleConfigured = resolved.ok
  const googleRemediation = resolved.ok ? "" : credentialsRemediation()

  // X is configured or it is not; there is no partial state worth serving. All three values are
  // required because the exchange cannot be attempted without any one of them, and a half-filled
  // block that reported itself "configured" would fail at X with a 401 instead of here with a
  // sentence naming the missing piece.
  const xClientId = (xCfg?.clientId ?? "").trim()
  const xClientSecret = (xCfg?.clientSecret ?? "").trim()
  const xRedirectUri = (xCfg?.redirectUri ?? "").trim()

  return {
    google: {
      clientId,
      clientSecret,
      redirectUri: googleCfg?.redirectUri ?? "",
      hostedDomain: googleCfg?.hostedDomain,
    },
    x: { clientId: xClientId, clientSecret: xClientSecret, redirectUri: xRedirectUri },
    xConfigured: Boolean(xClientId && xClientSecret && xRedirectUri),
    xTrustConfirmedEmail: config.xTrustConfirmedEmail ?? false,
    googleConfigured,
    googleRemediation,
    saml: samlCfg?.enabled ? samlCfg : undefined,
    email: resolveEmailConfig(emailConn),
    // Only the LEGACY gate reads this; the unguarded `.map` that used to sit here crashed on a
    // missing list, and normalizeAdmission now throws a named OafConfigError for that case instead.
    allowedDomains: admission.legacy ? normDomains(config.allowedDomains as string[]) : [],
    sessionSecret: config.sessionSecret,
    issuer: config.issuer,
    // All cookies share one prefix so two apps on the same host (cookies aren't port-scoped)
    // can be isolated by giving each a distinct cookiePrefix. Default "oaf" keeps the historical
    // names. An explicit sessionCookieName still overrides just the session cookie.
    sessionCookieName: config.sessionCookieName ?? `${(config.cookiePrefix ?? "oaf").trim() || "oaf"}_session`,
    stateCookieName: `${(config.cookiePrefix ?? "oaf").trim() || "oaf"}_oauth_state`,
    samlRelayCookieName: `${(config.cookiePrefix ?? "oaf").trim() || "oaf"}_saml_relay`,
    // Conservative default maximum lifetime: ~7 days. A captured session must not remain a valid
    // credential indefinitely. The session is a sliding window (re-issued on every token mint), so
    // active use rolls this forward; this is the absolute ceiling. Apps that genuinely want longer
    // sessions opt in explicitly via sessionTtlSeconds.
    sessionTtlSeconds: config.sessionTtlSeconds ?? 7 * 24 * 60 * 60,
    accessTokenTtlSeconds: config.accessTokenTtlSeconds ?? 60,
    // Idle timeout ON by default (~12h): an idle/stolen session ages out instead of living for the
    // full maximum lifetime. Only enforced when a sessionStore tracks lastActiveAt; 0 disables it.
    inactivityTimeoutSeconds: config.inactivityTimeoutSeconds ?? 12 * 60 * 60,
    sessionStoreMigrate: config.sessionStoreMigrate === true,
    sessionStoreMigrateMaxAgeSeconds: config.sessionStoreMigrateMaxAgeSeconds ?? 10 * 60,
    // Fail CLOSED on a store read error by default: revocation/expiry must not be bypassable under a
    // (possibly attacker-induced) store fault. Apps that prioritize availability opt into "cookie-grace".
    sessionStoreFailMode: config.sessionStoreFailMode === "cookie-grace" ? "cookie-grace" : "closed",
    reresolveGrantsEverySeconds:
      typeof config.reresolveGrantsEverySeconds === "number" && config.reresolveGrantsEverySeconds > 0
        ? config.reresolveGrantsEverySeconds
        : 0,
    revalidateGrants: config.revalidateGrants,
    sessionStore: config.sessionStore,
    // Secure by default — never ship a non-Secure session cookie to production.
    cookieSecure: config.cookieSecure ?? true,
    sessionCookieSameSite: config.sessionCookieSameSite ?? "Lax",
    audience: config.audience,
    requireHostedDomain: config.requireHostedDomain ?? false,
    allowedRedirectOrigins: (config.allowedRedirectOrigins ?? []).map((o) => o.trim()).filter(Boolean),
    samlTrustAssertedEmailVerified: config.samlTrustAssertedEmailVerified ?? false,
    samlReplayStore: config.samlReplayStore ?? new InMemorySamlReplayStore(),
    securityHeaders: config.securityHeaders ?? true,
    allowedCorsOrigins: (config.allowedCorsOrigins ?? []).map((o) => o.trim()).filter(Boolean),
    samlSatisfiesHostedDomain: config.samlSatisfiesHostedDomain ?? false,
    allowAnyDomain: config.allowAnyDomain ?? false,
    namespaceUserIds: config.namespaceUserIds ?? false,
    revalidateFailMode: config.revalidateFailMode === "closed" ? "closed" : "keep",
    upstreamTimeoutMs:
      typeof config.upstreamTimeoutMs === "number" && config.upstreamTimeoutMs > 0
        ? config.upstreamTimeoutMs
        : 20_000,
    rateLimit: config.rateLimit,
    resolveGrants: config.resolveGrants ?? defaultResolveGrants,
    admission,
    // Every message is scrubbed of control characters on the way out — see sanitizeLogMessage.
    // Wrapping the sink (rather than each call site) is what makes it hold for call sites added
    // later, and it applies to a host-supplied logger too, which is where the messages actually go.
    log: ((): InternalConfig["log"] => {
      const sink =
        config.logger ??
        ((level: "info" | "warn" | "error", message: string, meta?: unknown) => {
          // Default: quiet on info, surface problems.
          if (level !== "info") console[level](`[auth-frontend] ${message}`, meta ?? "")
        })
      return (level, message, meta) => sink(level, sanitizeLogMessage(String(message)), meta)
    })(),
  }
}

/**
 * Create the embedded Frontend API middleware. Mount it where the SDK's `frontendApi` + `/v1`
 * resolves to — e.g. `app.use('/api/v1', createFederatedFrontend(cfg))` with `frontendApi: '/api'`.
 *
 * Pass connections the Federated-idiomatic way, and state the admission policy:
 *   `createFederatedFrontend({ connections: [{ strategy: 'oauth_google', clientId, clientSecret,
 *     redirectUri }], signUpMode: 'public', requirePolicy: true, sessionSecret })`
 */
/**
 * The log line and the human's sentence for a failed provider exchange. The sentences are the ones
 * this middleware has always used: "complete" when the provider refused the code, "reach" when the
 * request itself failed, "verify" when the identity did not check out.
 */
function describeExchangeFailure(
  err: unknown,
  who: "Google" | "X",
): { log: string; meta?: unknown; message: string } {
  if (!(err instanceof OAuthExchangeError)) {
    return {
      log: `${who} sign-in threw`,
      meta: err instanceof Error ? err.message : err,
      message: `Could not reach ${who} to complete sign-in.`,
    }
  }
  if (err.stage === "identity") {
    return {
      log: who === "Google" ? "id_token verification failed" : "reading the signed-in X account failed",
      meta: err.message,
      message: `Could not verify your ${who} identity.`,
    }
  }
  if (err.kind === "unreachable") {
    return {
      log: `${who} token exchange threw`,
      meta: err.message,
      message: `Could not reach ${who} to complete sign-in.`,
    }
  }
  // Never the body: a token error response can quote the code, or the token itself.
  return {
    log: `${who} token exchange failed (${err.status ?? "?"})`,
    message: `Could not complete sign-in with ${who}.`,
  }
}

/**
 * The `hd` of a session read back from its cookie or the durable store, or `undefined` when it cannot
 * be trusted.
 *
 * WHY: before 2026-09-09 (commit 3c961ca) a session's `hd` fell back to the presented email domain
 * whenever the upstream asserted none, so an old session can carry `hd: "corp.example"` for an account
 * Google never called a Workspace member. That same commit started recording `provider` on every
 * session. So a record WITH `provider` carries only an upstream-asserted `hd`, and a record WITHOUT it
 * may not. Dropping the legacy value keeps the documented contract ("`hd` is Google's verified claim")
 * true everywhere a session's `hd` leaves the library: access-token claims, the `revalidateGrants`
 * identity, `/client`, `readBrowserSession()`. An app that gates on `hd` then signs that old session out
 * (fail closed) and the person's next sign-in records a verified one. Nothing else about the session
 * changes.
 */
export function trustedSessionHd(hd: unknown, provider: unknown): string | undefined {
  if (typeof hd !== "string" || hd === "") return undefined
  return typeof provider === "string" && provider !== "" ? hd : undefined
}

export function createFederatedFrontend(config: FederatedFrontendConfig): FederatedFrontend {
  const cfg = normalizeConfig(config)

  // Fail closed on a weak/placeholder/short secret (mirrors verify.ts, which throws). Signing real
  // sessions under a guessable secret is trivial token forgery, so refuse to construct.
  const PLACEHOLDER_SECRETS = new Set(["dev-shared-secret", "dev-only-change-me", "changeme", "secret"])
  if (
    !cfg.sessionSecret ||
    cfg.sessionSecret.length < 32 ||
    PLACEHOLDER_SECRETS.has(cfg.sessionSecret)
  ) {
    throw new Error(
      "createFederatedFrontend: sessionSecret must be a strong, non-default value of at least 32 " +
        "characters. Supply it via this API (e.g. from loadOrCreateSecret) — no default is provided.",
    )
  }

  // Configure embedded-mode verification from the SAME config used to mint below, so verifyToken()
  // validates with this app's secret/issuer/audience WITHOUT reading any environment variable. This
  // is the single bridge between minting (here) and verification (verify.ts) — one source of truth,
  // set by the API caller. Passing `audience` here is what makes per-app `aud` isolation hold by
  // default: the same value stamped on mint is required on verify. Same-process tokens this app
  // mints therefore still verify (identical secret + issuer + audience).
  configureEmbeddedVerification({
    sessionSecret: cfg.sessionSecret,
    issuer: cfg.issuer,
    audience: cfg.audience,
  })

  // Isolation guard: `audience` is defense-in-depth, not the primary control. If an app sets an
  // audience but leaves issuer at the shared default, two sibling apps that both did so would still
  // share an issuer — warn once so the operator gives each app a distinct issuer (and, above all, a
  // distinct sessionSecret).
  if (cfg.audience && !cfg.issuer) {
    cfg.log(
      "warn",
      "audience is set but issuer is not: minted tokens fall back to the shared default issuer " +
        '"openauthfederated". Audience is defense-in-depth only — give each app a DISTINCT ' +
        "sessionSecret (primary control) and a distinct issuer.",
    )
  }

  // Derive a distinct per-purpose subkey (HKDF-SHA256, distinct info labels) for each cookie-signing
  // context that stays INSIDE this module — the session cookie, the OAuth state cookie, and the SAML
  // relay cookie. A leak of the low-value state/relay flow then cannot forge a session. The access
  // token is the one credential consumed OUTSIDE this module (by verifyToken() in embedded mode,
  // which keys off the raw sessionSecret), so it is signed with the master secret to stay
  // verifiable — its short TTL and per-app audience bound it.
  const master = new TextEncoder().encode(cfg.sessionSecret)
  const subkey = (label: string): Uint8Array =>
    new Uint8Array(hkdfSync("sha256", master, new Uint8Array(0), `oaf:${label}`, 32))
  const sessionKey = subkey("session")
  const accessKey = master
  const stateKey = subkey("state")
  const relayKey = subkey("relay")
  // Per-deployment key for HMACing the email identifier in logs, so a log leak does not let an
  // attacker offline-guess which emails signed in. Derived from (not equal to) the session secret.
  const emailLogKey = subkey("email-log")

  // No durable store configured: sign-out is local-only and several security controls are inert.
  // We do NOT hard-require a store (the library cannot know an appropriate data dir), but we warn
  // loudly once at construction so this is a deliberate choice, not an invisible gap.
  if (!cfg.sessionStore) {
    cfg.log(
      "warn",
      "No sessionStore configured: sign-out clears only the local cookie (a copied/stolen cookie " +
        "stays valid until it expires), 'sign out everywhere' / revocation is unavailable, the " +
        "inactivity timeout is disabled, and the active-sessions list is always empty. Pass a " +
        "sessionStore (e.g. FileSessionStore) to createFederatedFrontend() to enable server-side " +
        "revocation and idle timeout.",
    )
  }

  if (!cfg.googleConfigured) {
    // Loud at construction, but non-fatal: SAML still works, and the OIDC routes fail closed with
    // a clear 503 (see guardGoogleConfigured) instead of redirecting to Google with an empty
    // client_id. The remediation text is source-agnostic (it names no host file path — that is the
    // embedding app's concern; see credentialsRemediation) and contains no secrets.
    // The multi-line remediation rides in `meta`, not in the message: log messages are scrubbed of
    // newlines (sanitizeLogMessage) so an attacker-influenced value cannot forge an audit line, and
    // folding this block into the message would flatten it for no benefit.
    cfg.log(
      "warn",
      "Google OAuth client is not configured; Google sign-in routes will return 503 until it is.",
      { remediation: cfg.googleRemediation },
    )
  }

  // --- admission engine ("the platform executes, the app decides"; see admission.ts) -----------
  //
  // The pipeline below is the ONE place a sign-in, a reverify and evaluateAdmission() are decided.
  // It stops at the first refusal. Legacy-only configs (allowedDomains & co., no new keys) run only
  // the email check and the legacy gate, which keeps them byte-compatible apart from the neutral
  // copy and two additive redirect parameters (error_reason, email_verified).

  const adm = cfg.admission

  if (adm.deprecatedKeys.length > 0) {
    warnOncePerProcess(`oaf-deprecated:${adm.deprecatedKeys.join(",")}`, () =>
      cfg.log(
        "warn",
        `deprecated admission option(s) in use: ${adm.deprecatedKeys.join(", ")}. They keep working; ` +
          "see docs/apis/frontend/admission.mdx for the replacements (signUpMode, restrictions, " +
          "allowlistIdentifiers, per-connection requireHostedDomain / allowedHostedDomains / hostedDomainHints).",
      ),
    )
  }
  if (adm.deprecatedKeys.includes("samlTrustAssertedEmailVerified")) {
    warnOncePerProcess("oaf-saml-trust-dead", () =>
      cfg.log(
        "warn",
        "samlTrustAssertedEmailVerified has no effect; set trustAssertedEmailVerified on the SAML connection instead.",
      ),
    )
  }
  if (!adm.legacy && adm.signUpMode === undefined && adm.restrictions === undefined) {
    warnOncePerProcess("oaf-no-policy", () =>
      cfg.log(
        "warn",
        "no admission policy stated; defaulting to signUpMode 'public' (any verified email). Pass " +
          "signUpMode (and requirePolicy: true) to make this explicit.",
      ),
    )
  }

  /** One-line, content-free description of the effective policy for the boot log. */
  function describePolicy(): string {
    const live = (v: unknown) => typeof v === "function"
    const mode = live(adm.signUpMode)
      ? "live"
      : (adm.signUpMode as SignUpMode | undefined) ?? (adm.legacyOnly ? "legacy-gate" : "public")
    const r = adm.restrictions
    const flag = (k: keyof Restrictions) => (live(r) ? "live" : (r as Restrictions | undefined)?.[k] === true ? "on" : "off")
    const size = (v: unknown) => (live(v) ? "live" : Array.isArray(v) ? String(v.length) : "0")
    const conn = (c: ConnectionRequirements) =>
      c.allowedHostedDomains !== undefined
        ? `hd in ${c.allowedHostedDomains.length} domain(s)`
        : c.requireHostedDomain
          ? "hd required"
          : "no hd requirement"
    return (
      `policy: mode=${mode}, legacy=${adm.legacy ? (adm.legacyOnly ? "only" : "mixed") : "no"}, ` +
      `allowlist=${flag("allowlist")} (${size(adm.allowlist)} identifiers), ` +
      `blocklist=${flag("blocklist")} (${size(adm.blocklist)} identifiers), ` +
      `actions=${adm.actions ? Object.keys(adm.actions).filter((k) => k === "authentication" || k === "userRegistration").join("+") || "none" : "none"}, ` +
      `users=${adm.users ? "lookup" : "none"}, google: ${conn(adm.google)}, saml: ${conn(adm.saml)}`
    )
  }
  cfg.log("info", describePolicy())

  interface Refusal {
    ok: false
    code: string
    message: string
    longMessage?: string
    step: AdmissionStep
    /** Extra redirect parameters (presented_domain, error_reason, email_verified). */
    params: Record<string, string>
  }
  type Decision = { ok: true; matchedAllowlistIdentifier: string | null } | Refusal

  function messageFor(code: string): AdmissionMessage {
    return (
      adm.messages[code as AdmissionErrorCode] ??
      DEFAULT_ADMISSION_MESSAGES[code as AdmissionErrorCode] ??
      DEFAULT_ADMISSION_MESSAGES.action_denied
    )
  }

  function refuse(
    code: string,
    step: AdmissionStep,
    o: { messageCode?: string; message?: string; longMessage?: string; params?: Record<string, string> } = {},
  ): Refusal {
    const copy = messageFor(o.messageCode ?? code)
    return {
      ok: false,
      code,
      step,
      message: o.message ?? copy.message,
      longMessage: o.longMessage ?? (o.message ? undefined : copy.longMessage),
      params: o.params ?? {},
    }
  }

  interface ResolvedPolicy {
    mode: SignUpMode
    restrictions: Restrictions
    allowlist: readonly string[]
    blocklist: readonly string[]
  }

  /** Step 0: resolve every Live value once, under the timeout, and validate it. Never a fallback. */
  async function resolvePolicy(): Promise<ResolvedPolicy | { error: string }> {
    try {
      const ms = adm.timeoutMs
      const [mode, restrictions, allowlist, blocklist] = await Promise.all([
        resolveLive("signUpMode", adm.signUpMode, ms),
        resolveLive("restrictions", adm.restrictions, ms),
        resolveLive("allowlistIdentifiers", adm.allowlist, ms),
        resolveLive("blocklistIdentifiers", adm.blocklist, ms),
      ])
      // A STATIC absent value takes its default; a LIVE resolver that returns undefined is invalid.
      const m = mode === undefined && typeof adm.signUpMode !== "function" ? "public" : mode
      const modeErr = invalidSignUpMode(m)
      if (modeErr) return { error: modeErr }
      const r = restrictions === undefined && typeof adm.restrictions !== "function" ? {} : restrictions
      const rErr = invalidRestrictions(r)
      if (rErr) return { error: rErr }
      const a = allowlist === undefined && typeof adm.allowlist !== "function" ? [] : allowlist
      const aErr = invalidIdentifierList(a, "allowlistIdentifiers")
      if (aErr) return { error: aErr }
      const b = blocklist === undefined && typeof adm.blocklist !== "function" ? [] : blocklist
      const bErr = invalidIdentifierList(b, "blocklistIdentifiers")
      if (bErr) return { error: bErr }
      const policy: ResolvedPolicy = {
        mode: m as SignUpMode,
        restrictions: r as Restrictions,
        allowlist: a as string[],
        blocklist: b as string[],
      }
      // A list without its switch is ignored by decideRestrictions (fail open for a blocklist). Static
      // values were refused at construction; a Live value can only be reported, once per process.
      for (const [name, list, flag] of [
        ["blocklistIdentifiers", policy.blocklist, "blocklist"],
        ["allowlistIdentifiers", policy.allowlist, "allowlist"],
      ] as const) {
        if (list.length > 0 && policy.restrictions[flag] !== true) {
          warnOncePerProcess(`oaf-list-without-flag:${flag}`, () =>
            cfg.log(
              "warn",
              `admission: ${name} resolved to ${list.length} entr${list.length === 1 ? "y" : "ies"} but ` +
                `restrictions.${flag} is not true, so the list is IGNORED. Set restrictions.${flag}: true ` +
                `to enforce it, or resolve the list to [] when it is not meant to apply.`,
            ),
          )
        }
      }
      if (policy.mode === "waitlist" && !adm.users) return { error: "signUpMode 'waitlist' needs `users`" }
      if (policy.mode === "restricted" && policy.restrictions.applyToSignIn === false && !adm.users) {
        return { error: "signUpMode 'restricted' with applyToSignIn false needs `users`" }
      }
      return policy
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) }
    }
  }

  const AUTH_METHOD: Record<IdentityProvider, AuthenticationMethod> = {
    google: "GoogleOAuth",
    x: "XOAuth",
    saml: "SSO",
    email: "MagicAuth",
  }

  /**
   * The LEGACY gate (the old G2 + G3), extracted verbatim apart from the neutral copy. Runs whenever
   * a legacy key is present; in mixed mode it runs before the new steps, so legacy keys can only
   * ever NARROW what the new policy admits.
   */
  function legacyDomainGate(identity: OidcIdentity): Refusal | null {
    // When the deployment is Workspace-gated (requireHostedDomain), the authoritative signal is the
    // `hd` (Workspace-membership) claim — NOT the email domain. An identity that merely ends in an
    // allowlisted domain but is not a Workspace member (no hd) is rejected. When not gated, fall
    // back to the email domain for back-compat.
    const provider = identity.provider ?? "google"
    const hd = identity.hd?.toLowerCase()
    // X HAS NO HOSTED-DOMAIN CLAIM AND NEVER WILL. `confirmed_email` says X delivered mail to that
    // address; it asserts nothing about membership of an organization, which is the whole of what
    // requireHostedDomain is for. So an X identity is admissible under that setting only when the
    // operator has explicitly said the confirmed email is enough (xTrustConfirmedEmail).
    const xExempt = provider === "x" && cfg.xTrustConfirmedEmail
    // SAML's counterpart to the X exemption. A SAML IdP that DOES assert a hosted-domain attribute
    // needs nothing here — `hd` is populated and the check passes on its own merits.
    const samlExempt = provider === "saml" && cfg.samlSatisfiesHostedDomain
    const hdExempt = xExempt || samlExempt
    if (cfg.requireHostedDomain && !hd && !hdExempt) {
      cfg.log("warn", `Rejecting ${provider} sign-in: hosted-domain (hd) claim required but absent`)
      return refuse("identity_domain_not_allowed", "legacy_gate", {
        messageCode: "identity_hosted_domain_required",
        params: { presented_domain: "", error_reason: "identity_hosted_domain_required" },
      })
    }
    // The allowlist still runs for every strategy — the exemptions above are from the `hd`
    // requirement only, never from allowedDomains.
    //
    // SAML IS EVALUATED ON ITS EMAIL DOMAIN, NEVER ON THE ASSERTED `hd`. A SAML `hd` is just an
    // attribute whose value the IdP chose; letting it stand in for the email domain here would
    // mean an assertion for `attacker@evil.example` carrying `hd: company.example` satisfies a
    // `company.example` allowlist.
    const presentedDomain =
      (provider === "saml"
        ? emailDomain(identity.email)
        : cfg.requireHostedDomain && !hdExempt
          ? hd
          : hd || emailDomain(identity.email)) ?? ""
    // allowAnyDomain: any VERIFIED email (checked before this gate). The domain only has to exist.
    const domainAdmitted = cfg.allowAnyDomain
      ? Boolean(presentedDomain)
      : Boolean(presentedDomain) && cfg.allowedDomains.includes(presentedDomain)
    if (!domainAdmitted) {
      cfg.log("warn", `Rejecting sign-in from non-allowed domain: ${presentedDomain || "unknown"}`)
      return refuse("identity_domain_not_allowed", "legacy_gate", {
        params: { presented_domain: presentedDomain },
      })
    }
    return null
  }

  interface AdmitOptions {
    phase: AdmissionPhase
    untrusted: UntrustedRequestHints
    traceId: string
    /** When given (including null), replaces users.lookup. */
    isSignUp?: boolean | null
    /** Reverify only: the presented identity must be the session's own. */
    binding?: (identity: OidcIdentity) => boolean
    /** Overrides the per-provider method (the email connection: `MagicAuth` or `Password`). */
    authenticationMethod?: AuthenticationMethod
  }

  async function runAction<C>(
    kind: "authentication" | "userRegistration",
    fn: (ctx: C) => unknown,
    ctx: C,
    step: AdmissionStep,
    traceId: string,
  ): Promise<Refusal | null> {
    let verdict: ReturnType<typeof normalizeVerdict>
    try {
      const raw = await withTimeout(`actions.${kind}`, adm.timeoutMs, () => fn(ctx))
      verdict = normalizeVerdict(raw)
      if (!verdict) throw new Error(`actions.${kind} returned no valid { verdict: 'Allow' | 'Deny' }`)
    } catch (err) {
      const mode = adm.onError[kind]
      cfg.log(
        "error",
        `actions.${kind} failed (trace ${traceId}); onError=${mode}`,
        err instanceof Error ? err.message : err,
      )
      return mode === "allow" ? null : refuse("action_failed", step)
    }
    if (verdict.allow) return null
    cfg.log("warn", `Sign-in denied by actions.${kind} (trace ${traceId}, code ${verdict.code})`)
    return refuse(verdict.code, step, { message: verdict.message, longMessage: verdict.longMessage })
  }

  async function admit(identity: OidcIdentity, o: AdmitOptions): Promise<Decision> {
    const provider: IdentityProvider = identity.provider ?? "google"
    const legacyOnly = adm.legacyOnly

    // 0. Resolve the app's Live policy once.
    let policy: ResolvedPolicy = { mode: "public", restrictions: {}, allowlist: [], blocklist: [] }
    if (!legacyOnly) {
      const p = await resolvePolicy()
      if ("error" in p) {
        cfg.log("error", `admission policy could not be resolved; refusing (trace ${o.traceId}): ${p.error}`)
        return refuse("action_failed", "resolve_policy")
      }
      policy = p
    }

    // 1. A present, VERIFIED email (Google email_verified, X confirmed_email, SAML trusted/asserted).
    if (!identity.email || !identity.emailVerified) {
      cfg.log(
        "warn",
        `Rejecting ${provider} sign-in: ` +
          (identity.email ? "the provider did not assert the email as verified" : "the provider returned no email address"),
      )
      if (legacyOnly) {
        return refuse("identity_domain_not_allowed", "email", {
          messageCode: "identity_email_unverified",
          params: { presented_domain: "", error_reason: "identity_email_unverified", email_verified: "false" },
        })
      }
      return refuse("identity_email_unverified", "email", { params: { email_verified: "false" } })
    }
    const parsed = parseEmail(identity.email)
    if (!parsed && !legacyOnly) {
      cfg.log("warn", `Rejecting ${provider} sign-in: the email address does not parse`)
      return refuse("identity_email_invalid", "email")
    }

    // Reverify: the presented identity must be the one the session belongs to.
    if (o.binding && !o.binding(identity)) return refuse("sign_in_not_completed", "reverify_binding")

    // 2. The legacy gate (only when a legacy key is present).
    if (adm.legacy) {
      const g = legacyDomainGate(identity)
      if (g) return g
    }

    // 3. Requirements of the connection that produced the identity. X never carries an hd.
    // Neither X nor the email connection can vouch for organization membership.
    const hd = provider === "x" || provider === "email" ? undefined : identity.hd?.trim().toLowerCase() || undefined
    const req = provider === "google" ? adm.google : provider === "saml" ? adm.saml : undefined
    if (req && (req.requireHostedDomain || req.allowedHostedDomains !== undefined)) {
      if (!hd || (req.allowedHostedDomains !== undefined && !req.allowedHostedDomains.includes(hd))) {
        cfg.log("warn", `Rejecting ${provider} sign-in: the connection requires a verified hosted domain${hd ? " on its list" : ""}`)
        return refuse("identity_hosted_domain_required", "connection")
      }
    }

    if (legacyOnly || !parsed) return { ok: true, matchedAllowlistIdentifier: null }

    const actionIdentity: ActionIdentity = Object.freeze({
      provider,
      sub: identity.sub,
      email: `${parsed.local}@${parsed.domain}`,
      emailVerified: true as const,
      ...(hd ? { hd } : {}),
      ...(identity.name ? { name: identity.name } : {}),
      ...(identity.username ? { username: identity.username } : {}),
    })
    const untrusted = Object.freeze({ ...o.untrusted })

    // 4. Returning or new? Only the app can say (OpenAuthFederated has no user store).
    let isSignUp: boolean | null = null
    let invited = false
    if (o.phase === "reverify") isSignUp = false
    else if (o.isSignUp !== undefined) isSignUp = o.isSignUp
    else if (adm.users) {
      try {
        const users = adm.users
        const found = await withTimeout("users.lookup", adm.timeoutMs, () => users.lookup(actionIdentity))
        if (!found || typeof found !== "object" || typeof found.exists !== "boolean") {
          throw new Error("users.lookup must resolve to { exists: boolean, invited?: boolean }")
        }
        isSignUp = !found.exists
        invited = found.invited === true
      } catch (err) {
        cfg.log(
          "error",
          `users.lookup failed; refusing (trace ${o.traceId})`,
          err instanceof Error ? err.message : err,
        )
        return refuse("action_failed", "users_lookup")
      }
    }

    // 5. Allowlist / blocklist (the more specific match wins; equal specificity goes to the allowlist).
    const outcome = decideRestrictions(actionIdentity.email, policy.restrictions, policy.allowlist, policy.blocklist, {
      warn: (m) => cfg.log("warn", m),
    })
    const applyToSignIn = policy.restrictions.applyToSignIn !== false
    if (isSignUp !== false || applyToSignIn) {
      if (outcome.outcome === "blocked") {
        cfg.log("warn", `Rejecting ${provider} sign-in: identity is on the blocklist (trace ${o.traceId})`)
        return refuse("identity_blocked", "restrictions")
      }
      if (outcome.outcome === "not_allowlisted") {
        cfg.log("warn", `Rejecting ${provider} sign-in: identity is not on the allowlist (trace ${o.traceId})`)
        return refuse("identity_not_allowlisted", "restrictions")
      }
    }
    const matched = outcome.outcome === "allow" ? (outcome.matched?.identifier ?? null) : null

    // 6. Sign-up mode, for a new identity or an unknown one (null fails closed).
    if (o.phase === "sign_in" && isSignUp !== false) {
      if (policy.mode === "waitlist") return refuse("sign_up_waitlisted", "sign_up_mode")
      if (policy.mode === "restricted" && !matched && !invited) return refuse("sign_up_restricted", "sign_up_mode")
    }

    const base = {
      id: o.traceId,
      identity: actionIdentity,
      authenticationMethod: o.authenticationMethod ?? AUTH_METHOD[provider],
      signUpMode: policy.mode,
      matchedAllowlistIdentifier: matched,
      untrusted,
    }

    // 7. The app's registration action, for a new identity only.
    if (o.phase === "sign_in" && isSignUp === true && adm.actions?.userRegistration) {
      const denied = await runAction(
        "userRegistration",
        adm.actions.userRegistration as (c: unknown) => unknown,
        Object.freeze({ ...base, object: "user_registration_action_context" as const, phase: "sign_in" as const, isSignUp: true as const, invited }),
        "user_registration_action",
        o.traceId,
      )
      if (denied) return denied
    }

    // 8. The app's authentication action, on every attempt.
    if (adm.actions?.authentication) {
      const denied = await runAction(
        "authentication",
        adm.actions.authentication as (c: unknown) => unknown,
        Object.freeze({ ...base, object: "authentication_action_context" as const, phase: o.phase, isSignUp }),
        "authentication_action",
        o.traceId,
      )
      if (denied) return denied
    }

    return { ok: true, matchedAllowlistIdentifier: matched }
  }

  /** Codes whose refusal may name the (legacy) allowed domains, when publishing them is in effect. */
  const DOMAIN_CODES = new Set(["identity_domain_not_allowed", "identity_not_allowlisted"])

  function refusalParams(d: Refusal, traceId: string, redirectUrlComplete: string): Record<string, string> {
    const params: Record<string, string> = { error: d.code, error_message: d.message }
    if (d.longMessage) params.error_long_message = d.longMessage
    Object.assign(params, d.params)
    if (adm.publishAllowedDomains && DOMAIN_CODES.has(d.code) && cfg.allowedDomains.length > 0) {
      params.allowed_domains = cfg.allowedDomains.join(",")
    }
    params.redirect_url_complete = redirectUrlComplete
    params.trace_id = traceId
    return params
  }

  function newTraceId(): string {
    return `trc_${base64url(randomBytes(12))}`
  }

  function untrustedFrom(
    req: IncomingMessage,
    saved: { mode?: string; connectionId?: string } | null | undefined,
  ): UntrustedRequestHints {
    const ua = req?.headers?.["user-agent"]
    return {
      ...(saved?.connectionId ? { connectionId: String(saved.connectionId).slice(0, 200) } : {}),
      requestedMode: saved?.mode === "sign_up" ? "sign_up" : "sign_in",
      ...(req?.socket?.remoteAddress ? { ipAddress: req.socket.remoteAddress } : {}),
      ...(typeof ua === "string" ? { userAgent: ua.slice(0, 512) } : {}),
    }
  }

  async function signSession(record: SessionRecord): Promise<string> {
    let jwt = new SignJWT({
      email: record.email,
      name: record.name,
      first_name: record.firstName,
      last_name: record.lastName,
      hd: record.hd,
      sid: record.sid,
      roles: record.roles,
      permissions: record.permissions,
      org_id: record.orgId,
      memberships: record.memberships,
      lvc: record.lastVerifiedAt,
      gra: record.grantsResolvedAt,
      psub: record.providerSub,
      prv: record.provider,
      ev: record.emailVerified,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(record.userId)
      .setIssuedAt()
      .setIssuer(cfg.issuer ?? "openauthfederated")
      .setExpirationTime(`${cfg.sessionTtlSeconds}s`)
    if (cfg.audience) jwt = jwt.setAudience(cfg.audience)
    return await jwt.sign(sessionKey)
  }

  /** Build the in-memory SessionRecord from a durable StoredSession. */
  function recordFromStored(s: StoredSession): SessionRecord {
    return {
      sid: s.sid,
      userId: s.userId,
      email: s.email,
      name: s.name,
      firstName: s.firstName,
      lastName: s.lastName,
      hd: trustedSessionHd(s.hd, s.provider),
      roles: s.roles ?? [],
      permissions: s.permissions ?? [],
      orgId: s.orgId ?? null,
      memberships: Array.isArray(s.memberships) ? s.memberships : [],
      lastVerifiedAt: s.lastVerifiedAt ?? Math.floor(Date.now() / 1000),
      grantsResolvedAt: s.grantsResolvedAt ?? s.lastVerifiedAt ?? Math.floor(Date.now() / 1000),
      providerSub: s.providerSub,
      provider: s.provider,
      emailVerified: s.emailVerified,
    }
  }

  async function readSession(req: IncomingMessage): Promise<SessionRecord | null> {
    const raw = parseCookies(req)[cfg.sessionCookieName]
    if (!raw) return null
    let payload: Record<string, unknown>
    try {
      ;({ payload } = (await jwtVerify(raw, sessionKey, {
        algorithms: ["HS256"],
        ...(cfg.audience ? { audience: cfg.audience } : {}),
      })) as { payload: Record<string, unknown> })
    } catch {
      return null
    }
    const m = (payload.memberships as OrgMembership[] | undefined) ?? []
    const cookieRec: SessionRecord = {
      sid: (payload.sid as string) ?? "",
      userId: (payload.sub as string) ?? "",
      email: (payload.email as string) ?? "",
      name: payload.name as string | undefined,
      firstName: payload.first_name as string | undefined,
      lastName: payload.last_name as string | undefined,
      hd: trustedSessionHd(payload.hd, payload.prv),
      roles: Array.isArray(payload.roles) ? (payload.roles as string[]) : [],
      permissions: Array.isArray(payload.permissions) ? (payload.permissions as string[]) : [],
      orgId: (payload.org_id as string | null) ?? null,
      memberships: Array.isArray(m) ? m : [],
      lastVerifiedAt: (payload.lvc as number) ?? Math.floor(Date.now() / 1000),
      grantsResolvedAt:
        (payload.gra as number) ?? (payload.lvc as number) ?? Math.floor(Date.now() / 1000),
      providerSub: payload.psub as string | undefined,
      provider: payload.prv as "google" | "saml" | "x" | "email" | undefined,
      emailVerified: payload.ev === true ? true : undefined,
    }

    // Stateless mode (no store): the signed cookie IS the whole session — return it as before.
    if (!cfg.sessionStore || !cookieRec.sid) return cookieRec

    // Stateful mode (the stateful half of the session model): the durable record is the source of
    // truth. This is what makes
    // sessions survive restarts and supports revocation + inactivity timeout.
    const now = Math.floor(Date.now() / 1000)
    try {
      const stored = await cfg.sessionStore.get(cookieRec.email, cookieRec.sid)
      if (stored) {
        if (stored.revoked) return null // signed out / revoked everywhere
        if (stored.expireAt && now > stored.expireAt) return null // past maximum lifetime
        if (
          cfg.inactivityTimeoutSeconds > 0 &&
          stored.lastActiveAt &&
          now - stored.lastActiveAt > cfg.inactivityTimeoutSeconds
        ) {
          return null // inactive too long
        }
        return recordFromStored(stored)
      }
      // No durable record for this sid. When a store is configured it is authoritative, so "no
      // record" means signed-out / revoked (a lost tombstone must NOT resurrect access). Fail
      // closed. A one-time migration that re-creates records from valid cookies is enabled by the
      // API caller via the `sessionStoreMigrate` config flag.
      if (cfg.sessionStoreMigrate) {
        const createdAt = typeof payload.iat === "number" ? (payload.iat as number) : now
        // Bound the resurrection risk: only migrate a cookie issued within a short window. A lost
        // tombstone plus an old-but-valid cookie must NOT rebuild a revoked session. An old cookie
        // (issued before the cutoff) fails closed here instead of being re-created as active.
        if (now - createdAt > cfg.sessionStoreMigrateMaxAgeSeconds) {
          cfg.log(
            "warn",
            "sessionStoreMigrate: refusing to migrate a cookie older than the migrate cutoff (possible resurrected/revoked session)",
          )
          return null
        }
        const expireAt =
          typeof payload.exp === "number" ? (payload.exp as number) : now + cfg.sessionTtlSeconds
        await cfg.sessionStore.create({
          ...cookieRec,
          createdAt,
          lastActiveAt: now,
          expireAt,
          revoked: false,
        })
        return cookieRec
      }
      return null
    } catch (err) {
      // A store read error must not silently defeat revocation/expiry. Default (fail "closed"):
      // treat the request as signed out. Only "cookie-grace" mode falls back to the signed cookie
      // (availability over the store-side checks), and only for apps that opted into that risk.
      if (cfg.sessionStoreFailMode === "cookie-grace") {
        cfg.log("warn", "session store read failed; cookie-grace mode falling back to signed cookie", err)
        return cookieRec
      }
      cfg.log("warn", "session store read failed; failing closed (signed out)", err)
      return null
    }
  }

  /** The Client snapshot shape RealAuthCore.applyClient() consumes. */
  function clientSnapshot(session: SessionRecord): unknown {
    return {
      object: "client",
      last_active_session_id: session.sid,
      org_id: session.orgId,
      organization_memberships: session.memberships.map((m) => ({
        id: m.id,
        organization: { id: m.organization.id, name: m.organization.name, slug: m.organization.slug },
        role: m.role,
        permissions: m.permissions,
      })),
      sessions: [
        {
          id: session.sid,
          status: "active",
          user_id: session.userId,
          last_verified_at: session.lastVerifiedAt * 1000, // applyClient divides by 1000
          user: {
            id: session.userId,
            first_name: session.firstName,
            last_name: session.lastName,
            primary_email_address: session.email,
            roles: session.roles,
            permissions: session.permissions,
            hd: session.hd,
          },
        },
      ],
    }
  }

  /** Grants for the requested active org (falls back to the session's base grants). */
  function grantsForOrg(session: SessionRecord, orgId: string | null): {
    roles: string[]
    permissions: string[]
    orgId: string | null
  } {
    const active = session.memberships.find((m) => m.organization.id === orgId)
    if (active) return { roles: [active.role], permissions: active.permissions, orgId }
    return { roles: session.roles, permissions: session.permissions, orgId: session.orgId }
  }

  async function mintAccessToken(session: SessionRecord, orgId: string | null): Promise<string> {
    const g = grantsForOrg(session, orgId)
    let jwt = new SignJWT({
      email: session.email,
      sid: session.sid,
      org_id: g.orgId,
      roles: g.roles,
      permissions: g.permissions,
      hd: session.hd,
      // Additive claims, carried only when the session recorded them (sessions minted before the
      // admission redesign lack `ev`, so their tokens lack email_verified — an app treats absent as
      // "legacy", never as "verified").
      ...(session.provider ? { provider: session.provider } : {}),
      ...(session.emailVerified === true ? { email_verified: true } : {}),
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(session.userId)
      .setIssuedAt()
      .setIssuer(cfg.issuer ?? "openauthfederated")
      .setExpirationTime(`${cfg.accessTokenTtlSeconds}s`)
    if (cfg.audience) jwt = jwt.setAudience(cfg.audience)
    return await jwt.sign(accessKey)
  }

  /** Reconstruct the minimal upstream identity from a live session, for grant re-resolution. */
  function identityFromSession(session: SessionRecord): OidcIdentity {
    return {
      // The stored upstream subject, when the session carries one. The fallback is only for a
      // session established before `providerSub` existed, and it strips ONLY the prefixes this
      // library can mint — including the `namespaceUserIds` form, which the old `user_`-only strip
      // left mangled (`user_saml_alice@corp.com` became `saml_alice@corp.com`, a subject that never
      // existed upstream, silently missing every host lookup keyed on `sub`).
      sub: session.providerSub ?? stripUserIdPrefix(session.userId),
      email: session.email,
      provider: session.provider,
      // The identity was authenticated at sign-in; re-resolution re-checks AUTHORIZATION (grants),
      // not authentication, so this is treated as verified.
      emailVerified: true,
      hd: session.hd,
      name: session.name,
      givenName: session.firstName,
      familyName: session.lastName,
    }
  }

  /**
   * Bound deprovision latency (finding #2). When `reresolveGrantsEverySeconds` is set and this
   * session's grants are older than that window, re-run grant resolution from the session's identity
   * and update the record in place. Returns `"signed_out"` (and sends the 401 + clears the cookie +
   * tombstones the store record) when the user no longer qualifies; otherwise `"ok"`. Additive and
   * off by default (window 0 = never re-resolve, preserving the historical behavior).
   */
  async function maybeReresolveGrants(
    session: SessionRecord,
    res: ServerResponse,
  ): Promise<"ok" | "signed_out"> {
    if (cfg.reresolveGrantsEverySeconds <= 0) return "ok"
    const now = Math.floor(Date.now() / 1000)
    if (now - session.grantsResolvedAt <= cfg.reresolveGrantsEverySeconds) return "ok"

    const resolver = cfg.revalidateGrants ?? cfg.resolveGrants
    let fresh: ResolvedGrants | null
    try {
      fresh = await resolver(identityFromSession(session))
    } catch (err) {
      // A transient resolver error is ambiguous, and the two readings pull opposite ways: it may be
      // a blip (locking the user out mid-session would be wrong), or it may be the directory being
      // unreachable at exactly the moment someone was offboarded (carrying stale grants would be
      // wrong). The operator chooses; the default keeps the historical behaviour.
      if (cfg.revalidateFailMode === "closed") {
        cfg.log("warn", "grant re-resolution threw; failing closed and signing the session out", err)
        fresh = null
      } else {
        cfg.log("warn", "grant re-resolution threw; keeping existing grants for this mint", err)
        return "ok"
      }
    }

    if (!fresh) {
      // User no longer qualifies (e.g. removed from the mapped upstream group) → sign out.
      if (cfg.sessionStore && session.sid) {
        try {
          await cfg.sessionStore.remove(session.email, session.sid)
        } catch (err) {
          cfg.log("warn", "session store remove failed during grant re-resolution sign-out", err)
        }
      }
      clearCookie(res, cfg.sessionCookieName, cfg.cookieSecure)
      cfg.log("info", `Access revoked on grant re-resolution for ${redactEmail(session.email, emailLogKey)}`)
      sendJson(res, 401, { error: "not_authenticated" })
      return "signed_out"
    }

    // Apply the fresh grants to the in-memory session (the re-signed cookie below carries them).
    session.roles = fresh.roles
    session.permissions = fresh.permissions
    session.memberships = fresh.memberships
    // Keep the active org if the user is still a member; otherwise fall back to the fresh default.
    if (!session.orgId || !fresh.memberships.some((m) => m.organization.id === session.orgId)) {
      session.orgId = fresh.orgId
    }
    session.grantsResolvedAt = now
    if (cfg.sessionStore && session.sid) {
      try {
        await cfg.sessionStore.touch(session.email, session.sid, {
          roles: session.roles,
          permissions: session.permissions,
          memberships: session.memberships,
          orgId: session.orgId,
          grantsResolvedAt: now,
        })
      } catch (err) {
        cfg.log("warn", "session store touch failed after grant re-resolution", err)
      }
    }
    return "ok"
  }

  // --- OAuth state (CSRF + PKCE + return targets) carried in a short-lived signed cookie ----

  async function signState(state: {
    state: string
    nonce: string
    codeVerifier: string
    redirectUrl: string
    redirectUrlComplete: string
    domain?: string
    /** True when this round-trip is a step-up reverify (don't re-establish, just re-stamp). */
    reverify?: boolean
    /** Which strategy opened this round trip. Absent means Google (every pre-X state cookie). */
    provider?: "google" | "x"
    /** UNTRUSTED: the client's ?mode= (sign_in / sign_up). Never a security input. */
    mode?: "sign_in" | "sign_up"
    /** UNTRUSTED: the client's ?connection=. Never a security input. */
    connectionId?: string
  }): Promise<string> {
    return await new SignJWT(state as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(`${STATE_TTL_SECONDS}s`)
      .sign(stateKey)
  }

  async function readState(req: IncomingMessage): Promise<{
    state: string
    nonce: string
    codeVerifier: string
    redirectUrl: string
    redirectUrlComplete: string
    domain?: string
    reverify?: boolean
    provider?: "google" | "x"
    mode?: "sign_in" | "sign_up"
    connectionId?: string
  } | null> {
    const raw = parseCookies(req)[cfg.stateCookieName]
    if (!raw) return null
    try {
      const { payload } = await jwtVerify(raw, stateKey, { algorithms: ["HS256"] })
      return payload as unknown as {
        state: string
        nonce: string
        codeVerifier: string
        redirectUrl: string
        redirectUrlComplete: string
        domain?: string
        reverify?: boolean
        provider?: "google" | "x"
        mode?: "sign_in" | "sign_up"
        connectionId?: string
      }
    } catch {
      return null
    }
  }

  /** The client's ?mode= — UNTRUSTED, carried to the callback only as a hint for app actions. */
  function requestedModeOf(q: URLSearchParams): "sign_in" | "sign_up" {
    return q.get("mode") === "sign_up" ? "sign_up" : "sign_in"
  }

  // --- endpoint handlers ---------------------------------------------------------------------

  /**
   * Fail-closed guard for the Google OIDC routes. When the OAuth client id/secret are missing, do
   * NOT redirect the browser to Google with an empty `client_id` (which yields a confusing Google
   * "Error 400: invalid_request — Missing required parameter: client_id" page). Instead return a
   * clear app-side 503 whose body carries the machine code `oauth_not_configured` and the
   * secret-free, source-agnostic remediation (no host file path — that is the embedding app's
   * concern). Returns true when it handled the request (caller should stop). The SAML path does not
   * call this — it needs no Google credential.
   */
  function guardGoogleConfigured(res: ServerResponse): boolean {
    if (cfg.googleConfigured) return false
    cfg.log(
      "error",
      "Refusing to start Google sign-in: OAuth client credentials are not configured.",
      { remediation: cfg.googleRemediation },
    )
    sendJson(res, 503, {
      error: "oauth_not_configured",
      error_message:
        "Google sign-in is not configured on the server. An administrator must supply the Google " +
        "OAuth client id and secret to the embedding app, which passes them into " +
        "createFederatedFrontend(). See `remediation` for details.",
      // `remediation` is deliberately secret-free — safe to surface to the operator.
      remediation: cfg.googleRemediation,
    })
    return true
  }

  /**
   * The X counterpart of {@link guardGoogleConfigured}. Returns true (and has answered) when X
   * sign-in cannot be started, so the caller does nothing further.
   */
  function guardXConfigured(res: ServerResponse): boolean {
    if (cfg.xConfigured) return false
    cfg.log("error", "Refusing to start X sign-in: OAuth client credentials are not configured.")
    sendJson(res, 503, {
      error: "oauth_not_configured",
      error_message:
        "X sign-in is not configured on the server. An administrator must supply the X OAuth " +
        "client id, client secret and callback URI to the embedding app, which passes them into " +
        "createFederatedFrontend() as a connection with strategy 'oauth_x'. The application must " +
        "be registered as a CONFIDENTIAL client (\"Web App, Automated App or Bot\") in the X " +
        "developer portal — a Native App is issued no client secret.",
    })
    return true
  }

  /**
   * GET /sign_in/sso?strategy=x — hand the browser X's own authorization screen.
   *
   * The same shape as the Google start below (state + PKCE in one short-lived signed cookie), with
   * two differences that are X's, not ours: PKCE is MANDATORY even for a confidential client, and
   * there is no `nonce` because there is no id_token to bind one to.
   */
  async function handleXSsoStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const q = queryOf(req)
    const redirectUrl = q.get("redirect_url") || "/sso-callback"
    const redirectUrlComplete = q.get("redirect_url_complete") || "/"

    const state = randomUrlToken()
    const { codeVerifier, codeChallenge } = createPkcePair()

    const stateJwt = await signState({
      state,
      nonce: "",
      codeVerifier,
      redirectUrl,
      redirectUrlComplete,
      provider: "x",
      mode: requestedModeOf(q),
      ...(q.get("connection") ? { connectionId: String(q.get("connection")).slice(0, 200) } : {}),
    })
    setCookie(res, cfg.stateCookieName, stateJwt, {
      maxAgeSeconds: STATE_TTL_SECONDS,
      secure: cfg.cookieSecure,
    })

    redirect(
      res,
      xAuthorizeUrl({ clientId: cfg.x.clientId, redirectUri: cfg.x.redirectUri, state, codeChallenge }),
    )
  }

  /**
   * GET /oauth_callback/x — exchange the code, read who signed in, then join the shared tail.
   *
   * Deliberately a SEPARATE PATH from `/oauth_callback` rather than a branch inside it. X's callback
   * URI has to be registered in X's portal as an exact string, Google's in Google's console as an
   * exact string, and one path serving both means either console can be edited into breaking the
   * other provider's sign-in with nothing on either screen to say so.
   */
  async function handleXCallback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const q = queryOf(req)
    const saved = await readState(req)
    const redirectUrlComplete = saved?.redirectUrlComplete ?? q.get("redirect_url_complete") ?? "/"
    const fallbackRedirect = safeRedirectTarget(saved?.redirectUrl ?? "/sso-callback")
    clearCookie(res, cfg.stateCookieName, cfg.cookieSecure)

    const code = q.get("code") ?? ""
    const returnedState = q.get("state") ?? ""
    // X reports a refusal on the query string; it is the ordinary "not now" and is not an error.
    if (q.get("error")) {
      cfg.log("info", `X sign-in was not completed: ${String(q.get("error")).slice(0, 64)}`)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Sign-in with X was cancelled.",
        redirect_url_complete: redirectUrlComplete,
      })
    }
    // `state` is the CSRF token: a callback carrying one this install never issued is not a
    // callback. The provider check closes the matching hole — a Google state cookie must not be
    // spendable at the X callback, or the two round trips become interchangeable.
    if (
      !code ||
      !saved ||
      saved.provider !== "x" ||
      !constantTimeEqual(returnedState, saved.state)
    ) {
      cfg.log("warn", "X callback rejected: the saved SSO state is missing, expired or mismatched")
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Sign-in could not be verified. Please try again.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    let identity: OidcIdentity
    try {
      ;({ identity } = await exchangeXCode({
        clientId: cfg.x.clientId,
        clientSecret: cfg.x.clientSecret,
        redirectUri: cfg.x.redirectUri,
        code,
        codeVerifier: saved.codeVerifier,
        timeoutMs: cfg.upstreamTimeoutMs,
        log: cfg.log,
      }))
    } catch (err) {
      const failure = describeExchangeFailure(err, "X")
      cfg.log("error", failure.log, failure.meta)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: failure.message,
        redirect_url_complete: redirectUrlComplete,
      })
    }

    return finishSignIn(req, res, identity, fallbackRedirect, redirectUrlComplete, untrustedFrom(req, saved))
  }

  async function handleSsoStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const q = queryOf(req)
    const redirectUrl = q.get("redirect_url") || "/sso-callback"
    const redirectUrlComplete = q.get("redirect_url_complete") || "/"
    // Step-up reverify: the user already has a session but must prove fresh presence at the IdP.
    const reverify = q.get("reverify") === "1"
    // The SDK may pass connection=conn_<domain_slug>. The client only PICKS among the hint domains
    // the app configured (hostedDomainHints; legacy default: allowedDomains) — an unknown or empty
    // connection sends no `hd`. The explicit, fixed hostedDomain config wins over any pick.
    const connection = (q.get("connection") ?? "").toLowerCase()
    const legacySlugDomain = connection.startsWith("conn_")
      ? connection.slice("conn_".length).replace(/_/g, ".")
      : undefined
    const hintDomain = connection
      ? cfg.admission.google.hostedDomainHints.find(
          (d) => connectionIdForDomain(d) === connection || d === legacySlugDomain,
        )
      : undefined
    const hostedDomain = cfg.google.hostedDomain ?? hintDomain

    const state = randomUrlToken()
    const nonce = randomUrlToken()
    const { codeVerifier, codeChallenge } = createPkcePair()

    const stateJwt = await signState({
      state,
      nonce,
      codeVerifier,
      redirectUrl,
      redirectUrlComplete,
      domain: hostedDomain,
      reverify,
      provider: "google",
      mode: requestedModeOf(q),
      ...(connection ? { connectionId: connection.slice(0, 200) } : {}),
    })
    setCookie(res, cfg.stateCookieName, stateJwt, {
      maxAgeSeconds: STATE_TTL_SECONDS,
      secure: cfg.cookieSecure,
    })

    redirect(
      res,
      googleAuthorizeUrl({
        clientId: cfg.google.clientId,
        redirectUri: cfg.google.redirectUri,
        state,
        nonce,
        codeChallenge,
        // Step-up: force a fresh IdP authentication (prompt=login + max_age=0) so reverify is real
        // re-authentication, not a silent re-assertion. Normal sign-in just lets the user pick account.
        prompt: reverify ? "login" : "select_account",
        maxAge: reverify ? 0 : undefined,
        hostedDomain,
      }),
    )
  }

  /**
   * Normalize a caller-supplied redirect target to a SAFE value (open-redirect defense). An
   * absolute http(s) URL is allowed only when its origin is on `allowedRedirectOrigins`; otherwise
   * it is rewritten to a same-origin relative path (path + query only, dropping the foreign
   * origin). A relative target passes through unchanged. Defaults to `/` when unusable.
   */
  function safeRedirectTarget(redirectUrl: string): string {
    if (!redirectUrl) return "/"
    const isAbsolute = /^https?:\/\//i.test(redirectUrl)
    if (!isAbsolute) {
      // Reject protocol-relative (`//evil.com`) and other schemes; force a leading slash.
      if (redirectUrl.startsWith("//")) return "/"
      return redirectUrl.startsWith("/") ? redirectUrl : `/${redirectUrl}`
    }
    try {
      const u = new URL(redirectUrl)
      if (cfg.allowedRedirectOrigins.includes(u.origin)) return redirectUrl
      cfg.log("warn", `Rejected non-allowlisted redirect target origin: ${u.origin}`)
      return `${u.pathname}${u.search}` || "/"
    } catch {
      return "/"
    }
  }

  /** Bounce back to the SPA callback page, carrying either success or a rejection. */
  function backToApp(
    res: ServerResponse,
    redirectUrl: string,
    params: Record<string, string>,
  ): void {
    const safe = safeRedirectTarget(redirectUrl)
    let url: URL
    const isAbsolute = /^https?:\/\//i.test(safe)
    try {
      url = new URL(safe)
    } catch {
      url = new URL(safe, "http://localhost")
    }
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)
    redirect(res, isAbsolute ? url.toString() : `${url.pathname}${url.search}`)
  }

  async function handleCallback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const q = queryOf(req)
    const saved = await readState(req)
    clearCookie(res, cfg.stateCookieName, cfg.cookieSecure)

    const fallbackRedirect = saved?.redirectUrl ?? "/sso-callback"
    const redirectUrlComplete = saved?.redirectUrlComplete ?? "/"

    // Google-reported error (e.g. user cancelled consent).
    const googleError = q.get("error")
    if (googleError) {
      cfg.log("warn", `OAuth callback returned error: ${googleError}`)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Sign-in was not completed.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    const code = q.get("code")
    const returnedState = q.get("state")
    if (!saved || !code || !returnedState || !constantTimeEqual(returnedState, saved.state)) {
      cfg.log("warn", "OAuth callback failed state/PKCE validation")
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Sign-in could not be verified. Please try again.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    // A state cookie minted for the X round trip must not be spendable here (and vice versa in
    // handleXCallback). Absent means Google: every state cookie issued before X existed.
    if (saved.provider === "x") {
      cfg.log("warn", "Google callback rejected: the saved SSO state belongs to the X round trip")
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Sign-in could not be verified. Please try again.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    // Exchange the authorization code (PKCE), then verify the id_token signature against Google's
    // JWKS and check the standard claims and the nonce (oauth-providers.ts).
    let identity: OidcIdentity
    try {
      identity = await exchangeGoogleCode({
        clientId: cfg.google.clientId,
        clientSecret: cfg.google.clientSecret,
        redirectUri: cfg.google.redirectUri,
        code,
        codeVerifier: saved.codeVerifier,
        nonce: saved.nonce || undefined,
        timeoutMs: cfg.upstreamTimeoutMs,
      })
    } catch (err) {
      const failure = describeExchangeFailure(err, "Google")
      cfg.log("error", failure.log, failure.meta)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: failure.message,
        redirect_url_complete: redirectUrlComplete,
      })
    }

    // Step-up reverify: the user proved fresh presence at the IdP. Re-stamp the EXISTING session's
    // lastVerifiedAt only — do not mint a new session — after checking that the identity is the
    // session's own and that it is still admitted.
    if (saved.reverify) {
      return finishReverify(req, res, identity, fallbackRedirect, redirectUrlComplete, untrustedFrom(req, saved))
    }

    return finishSignIn(req, res, identity, fallbackRedirect, redirectUrlComplete, untrustedFrom(req, saved))
  }

  /** Reverify binding: the identity that just re-authenticated must be the session's own. */
  function bindingMatches(session: SessionRecord, identity: OidcIdentity): boolean {
    const provider = identity.provider ?? "google"
    const email = (identity.email ?? "").trim().toLowerCase()
    if (!email || email !== (session.email ?? "").trim().toLowerCase()) return false
    // A session created before provider/providerSub existed can only be matched on its email.
    if (!session.provider) return true
    if (session.provider !== provider) return false
    if (session.providerSub === undefined) return true
    return session.providerSub === identity.sub
  }

  /**
   * Shared tail of both step-up reverify paths (Google and SAML). Replaces the bare
   * `lastVerifiedAt` stamp, which re-stamped ANY session for ANY freshly-authenticated account.
   *   1. resolve policy + verified email; 2. binding check (mismatch: no stamp, session KEPT);
   *   3. legacy gate, connection requirements, lists (as a returning user) and the authentication
   *      action with phase 'reverify' (refusal: session REMOVED, cookie cleared); 4. stamp.
   */
  async function finishReverify(
    req: IncomingMessage,
    res: ServerResponse,
    identity: OidcIdentity,
    fallbackRedirect: string,
    redirectUrlComplete: string,
    untrusted: UntrustedRequestHints,
  ): Promise<void> {
    const session = await readSession(req)
    if (!session?.sid) return backToApp(res, redirectUrlComplete, {})
    const traceId = newTraceId()
    const d = await admit(identity, {
      phase: "reverify",
      untrusted,
      traceId,
      binding: (id) => bindingMatches(session, id),
    })
    if (!d.ok) {
      if (d.step === "reverify_binding") {
        cfg.log(
          "warn",
          `reverify identity mismatch (trace ${traceId}): session provider ${session.provider ?? "unknown"}, ` +
            `presented provider ${identity.provider ?? "google"}; not stamped, session kept`,
        )
      }
      if (d.step !== "reverify_binding" && d.step !== "resolve_policy" && d.step !== "email") {
        // The identity is the session's own but no longer admitted: end the session.
        if (cfg.sessionStore) {
          try {
            await cfg.sessionStore.remove(session.email, session.sid)
          } catch (err) {
            cfg.log("warn", "session store remove failed after a refused reverify", err)
          }
        }
        clearCookie(res, cfg.sessionCookieName, cfg.cookieSecure)
        cfg.log("info", `Session ended on reverify for ${redactEmail(session.email, emailLogKey)} (${d.code}, trace ${traceId})`)
      }
      return backToApp(res, fallbackRedirect, refusalParams(d, traceId, redirectUrlComplete))
    }
    session.lastVerifiedAt = Math.floor(Date.now() / 1000)
    const sessionJwt = await signSession(session)
    setCookie(res, cfg.sessionCookieName, sessionJwt, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      secure: cfg.cookieSecure,
      sameSite: cfg.sessionCookieSameSite,
    })
    if (cfg.sessionStore) {
      try {
        await cfg.sessionStore.touch(session.email, session.sid, {
          lastVerifiedAt: session.lastVerifiedAt,
          lastActiveAt: session.lastVerifiedAt,
        })
      } catch (err) {
        cfg.log("warn", "session store touch failed on reverify callback", err)
      }
    }
    return backToApp(res, redirectUrlComplete, {})
  }

  /**
   * Shared tail of every sign-in path (Google and X callbacks, SAML ACS): run the admission
   * pipeline on the verified identity, resolve grants, mint the session cookie, and bounce back to
   * the SPA. Keeping this in one place guarantees every strategy produces an identical session —
   * and that a refused identity never gets one.
   */
  async function finishSignIn(
    _req: IncomingMessage,
    res: ServerResponse,
    identity: OidcIdentity,
    fallbackRedirect: string,
    redirectUrlComplete: string,
    untrusted: UntrustedRequestHints,
  ): Promise<void> {
    const traceId = newTraceId()
    const decision = await admit(identity, { phase: "sign_in", untrusted, traceId })
    if (!decision.ok) {
      return backToApp(res, fallbackRedirect, refusalParams(decision, traceId, redirectUrlComplete))
    }
    await establishSession(res, identity)
    backToApp(res, fallbackRedirect, { redirect_url_complete: redirectUrlComplete })
  }

  /**
   * Mint the session for an identity admission ALREADY admitted: the signed cookie plus the durable
   * store record. Shared by the redirect connections (finishSignIn) and the email connection's JSON
   * routes, so every connection produces the identical session.
   */
  async function establishSession(res: ServerResponse, identity: OidcIdentity): Promise<void> {
    const provider = identity.provider ?? "google"
    // Establish the session. resolveGrants may be async; it is awaited.
    const grants = await cfg.resolveGrants(identity)
    const now = Math.floor(Date.now() / 1000)
    const session: SessionRecord = {
      sid: `sess_${base64url(randomBytes(12))}`,
      // Optionally scoped to the issuing strategy so Google, SAML and X do not share one flat
      // identifier namespace. Off by default because turning it on rewrites every user id.
      userId: cfg.namespaceUserIds ? `user_${provider}_${identity.sub}` : `user_${identity.sub}`,
      email: identity.email,
      name: identity.name,
      firstName: identity.givenName,
      lastName: identity.familyName,
      // `hd` ONLY when the upstream actually asserted one. It used to fall back to
      // `presentedDomain`, which outside the requireHostedDomain path is just the email suffix — so
      // a downstream service reading `claims.hd` as "Google Workspace membership" (which is what the
      // name means everywhere else here) was reading an unverified string. The email domain is
      // available from `email`; it does not need to masquerade as a hosted-domain claim.
      hd: identity.hd,
      roles: grants.roles,
      permissions: grants.permissions,
      orgId: grants.orgId,
      memberships: grants.memberships,
      lastVerifiedAt: now,
      grantsResolvedAt: now,
      // Kept verbatim so grant re-resolution asks about the subject the IdP actually named.
      providerSub: identity.sub,
      provider,
      // Admission refused every identity without a verified email, so this session's is verified.
      emailVerified: true,
    }
    const sessionJwt = await signSession(session)
    setCookie(res, cfg.sessionCookieName, sessionJwt, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      secure: cfg.cookieSecure,
      sameSite: cfg.sessionCookieSameSite,
    })
    // Persist the durable server-side record (the stateful half of the session model) so the session survives app
    // restarts, can be listed, and can be revoked. Best-effort: a store failure must not block a
    // successful sign-in (the signed cookie still works on its own).
    if (cfg.sessionStore) {
      try {
        await cfg.sessionStore.create({
          ...session,
          createdAt: now,
          lastActiveAt: now,
          expireAt: now + cfg.sessionTtlSeconds,
          revoked: false,
        })
      } catch (err) {
        cfg.log("warn", "session store create failed at sign-in", err)
      }
    }
    // Redact PII: log a hashed identifier, not the raw email, on the routine per-sign-in line.
    cfg.log("info", `Sign-in established for ${redactEmail(identity.email, emailLogKey)}`)
  }

  // ---------------------------------------------------------------------------------------------
  // THE EMAIL CONNECTION (email-auth.ts). Three JSON routes, mirroring Clerk's email_code and
  // password strategies. The proof of the mailbox is the code; the identity it yields goes through
  // admit() and establishSession() exactly like a Google, X or SAML identity.
  //
  //   POST /email/code      { email, purpose }                         → a code is emailed
  //   POST /email/verify    { email, code, password?, redirect_url_complete? } → signed in
  //   POST /email/password  { email, password, redirect_url_complete? } → signed in
  //
  // Every route requires `Content-Type: application/json`: a cross-site HTML form cannot send that
  // without a CORS preflight, which this middleware never grants to an unlisted origin — so a page
  // elsewhere cannot sign a visitor into an attacker's account (login CSRF).
  // ---------------------------------------------------------------------------------------------

  function emailError(
    res: ServerResponse,
    status: number,
    error: string,
    message: string,
    extra: Record<string, unknown> = {},
  ): void {
    sendJson(res, status, { error, error_message: message, ...extra })
  }

  function isJsonRequest(req: IncomingMessage): boolean {
    const ct = req.headers?.["content-type"]
    return typeof ct === "string" && /^application\/json\b/i.test(ct.trim())
  }

  function emailUntrusted(req: IncomingMessage, purpose: EmailCodePurpose): UntrustedRequestHints {
    return untrustedFrom(req, { mode: purpose === "sign_up" ? "sign_up" : "sign_in", connectionId: "conn_email" })
  }

  /** Admit, mint the session, answer JSON. The account is written only after admission said yes. */
  async function completeEmailSignIn(
    req: IncomingMessage,
    res: ServerResponse,
    account: EmailAccount,
    persist: boolean,
    method: AuthenticationMethod,
    purpose: EmailCodePurpose,
    redirectUrlComplete: string,
  ): Promise<void> {
    const email = cfg.email!
    const identity: OidcIdentity = { sub: account.id, email: account.email, emailVerified: true, provider: "email" }
    const traceId = newTraceId()
    const decision = await admit(identity, {
      phase: "sign_in",
      untrusted: emailUntrusted(req, purpose),
      traceId,
      authenticationMethod: method,
    })
    if (!decision.ok) {
      return emailError(res, 403, decision.code, decision.message, {
        ...(decision.longMessage ? { error_long_message: decision.longMessage } : {}),
        trace_id: traceId,
      })
    }
    if (persist) await email.store.putAccount(account)
    await establishSession(res, identity)
    sendJson(res, 200, { object: "sign_in", status: "complete", redirect_url_complete: redirectUrlComplete })
  }

  async function handleEmailCode(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const email = cfg.email!
    if (!isJsonRequest(req)) return emailError(res, 415, "unsupported_media_type", "Send this request as JSON.")
    const body = await readJsonBody(req)
    const address = normalizeEmailAddress(body.email)
    const purpose: EmailCodePurpose =
      body.purpose === "sign_up" || body.purpose === "reset_password" ? body.purpose : "sign_in"
    if (!address || !parseEmail(address)) {
      return emailError(res, 422, "form_identifier_invalid", "Enter a valid email address.")
    }
    if (purpose === "reset_password" && !email.password) {
      return emailError(res, 404, "password_disabled", "This app does not use passwords. Sign in with a code instead.")
    }
    const now = Math.floor(Date.now() / 1000)
    const prior = await email.store.getPending(address)
    const recent = (prior?.sentAt ?? []).filter((t) => now - t < 3600)
    const last = recent.length ? Math.max(...recent) : 0
    if (last && now - last < email.resendCooldownSeconds) {
      const wait = email.resendCooldownSeconds - (now - last)
      return emailError(res, 429, "too_many_requests", `Wait ${wait} seconds before asking for another code.`, {
        retry_after_seconds: wait,
      })
    }
    if (recent.length >= email.maxCodesPerHour) {
      const wait = 3600 - (now - Math.min(...recent))
      return emailError(res, 429, "too_many_requests", "Too many codes were sent to this address. Try again later.", {
        retry_after_seconds: wait,
      })
    }
    const account = await email.store.getAccount(address)
    const code = newEmailCode()
    const salt = newCodeSalt()
    await email.store.putPending({
      email: address,
      purpose,
      salt,
      codeHash: hashEmailCode(salt, address, purpose, code),
      expiresAt: now + email.codeTtlSeconds,
      attempts: 0,
      sentAt: [...recent, now],
    })
    let delivery: { delivered: boolean; problem?: string | null }
    try {
      delivery = await email.sendCode({
        to: address,
        code,
        purpose,
        expiresInMinutes: Math.max(1, Math.round(email.codeTtlSeconds / 60)),
        accountExists: Boolean(account),
      })
    } catch (err) {
      delivery = { delivered: false, problem: err instanceof Error ? err.message : String(err) }
    }
    if (!delivery || delivery.delivered !== true) {
      // A code that never left must not be spendable, and the throttle must not count it.
      await email.store.putPending({ ...(prior ?? { email: address, purpose, salt: "", codeHash: "", expiresAt: 0, attempts: 0 }), sentAt: recent })
      cfg.log("error", `email sign-in code was not delivered to ${redactEmail(address, emailLogKey)}: ${sanitizeLogMessage(String(delivery?.problem ?? "sendCode returned no delivery"))}`)
      return emailError(res, 503, "email_not_delivered", "We could not send the email just now. Please try again in a few minutes.")
    }
    cfg.log("info", `email sign-in code sent to ${redactEmail(address, emailLogKey)} (${purpose})`)
    // The same answer whether or not an account exists (no account enumeration).
    sendJson(res, 200, {
      object: "email_code",
      status: "code_sent",
      email: address,
      purpose,
      expires_in_seconds: email.codeTtlSeconds,
      password_enabled: email.password,
    })
  }

  async function handleEmailVerify(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const email = cfg.email!
    if (!isJsonRequest(req)) return emailError(res, 415, "unsupported_media_type", "Send this request as JSON.")
    const body = await readJsonBody(req)
    const address = normalizeEmailAddress(body.email)
    const redirectUrlComplete = safeRedirectTarget(typeof body.redirect_url_complete === "string" ? body.redirect_url_complete : "/")
    if (!address || !parseEmail(address)) {
      return emailError(res, 422, "form_identifier_invalid", "Enter a valid email address.")
    }
    const pending = await email.store.getPending(address)
    const now = Math.floor(Date.now() / 1000)
    if (!pending || !pending.codeHash || pending.expiresAt <= now) {
      return emailError(res, 410, "verification_expired", "That code has expired. Ask for a new one.")
    }
    // A password given with the code is validated BEFORE the code is spent, so a short password does
    // not burn a correct code. A reset requires one.
    const wantsPassword = typeof body.password === "string" && body.password !== ""
    if (pending.purpose === "reset_password" && !wantsPassword) {
      return emailError(res, 422, "form_password_invalid", "Choose a new password.")
    }
    if (wantsPassword) {
      if (!email.password) return emailError(res, 404, "password_disabled", "This app does not use passwords.")
      const problem = passwordProblem(body.password, email.minPasswordLength)
      if (problem) return emailError(res, 422, "form_password_invalid", problem)
    }
    if (!codeMatches(pending, address, String(body.code ?? ""))) {
      const attempts = pending.attempts + 1
      if (attempts >= email.maxCodeAttempts) {
        await email.store.putPending({ ...pending, codeHash: "", attempts })
        cfg.log("warn", `email sign-in code burned after ${attempts} wrong attempts for ${redactEmail(address, emailLogKey)}`)
        return emailError(res, 429, "verification_failed", "Too many wrong codes. Ask for a new one.")
      }
      await email.store.putPending({ ...pending, attempts })
      return emailError(res, 422, "form_code_incorrect", "That code is not right. Check the email and try again.", {
        attempts_remaining: email.maxCodeAttempts - attempts,
      })
    }
    // Single use: spent before anything else can fail. The throttle history is kept.
    await email.store.putPending({ ...pending, codeHash: "", attempts: 0, expiresAt: 0 })

    const existing = await email.store.getAccount(address)
    const account: EmailAccount = existing
      ? { ...existing, failedPasswordAttempts: 0, passwordLockedUntil: null, updatedAt: now }
      : { id: newEmailAccountId(), email: address, passwordHash: null, verifiedAt: now, createdAt: now, updatedAt: now }
    // Rule 1 (email-auth.ts): the password is written only now, with the mailbox proven.
    if (wantsPassword) account.passwordHash = await hashPassword(String(body.password))
    return completeEmailSignIn(req, res, account, true, "MagicAuth", pending.purpose, redirectUrlComplete)
  }

  async function handleEmailPassword(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const email = cfg.email!
    if (!email.password) return emailError(res, 404, "password_disabled", "This app does not use passwords. Sign in with a code instead.")
    if (!isJsonRequest(req)) return emailError(res, 415, "unsupported_media_type", "Send this request as JSON.")
    const body = await readJsonBody(req)
    const address = normalizeEmailAddress(body.email)
    const redirectUrlComplete = safeRedirectTarget(typeof body.redirect_url_complete === "string" ? body.redirect_url_complete : "/")
    const password = typeof body.password === "string" ? body.password : ""
    if (!address || !parseEmail(address) || !password || password.length > 1024) {
      return emailError(res, 401, "form_password_incorrect", "That email and password do not match.")
    }
    const now = Math.floor(Date.now() / 1000)
    const account = await email.store.getAccount(address)
    if (account?.passwordLockedUntil && account.passwordLockedUntil > now) {
      const wait = account.passwordLockedUntil - now
      return emailError(res, 429, "user_locked", "Too many wrong passwords. Sign in with an emailed code, or try again later.", {
        retry_after_seconds: wait,
      })
    }
    // verifyPassword spends the same time on a missing account or a code-only account.
    const ok = await verifyPassword(password, account?.passwordHash)
    if (!ok || !account) {
      if (account) {
        const failures = (account.failedPasswordAttempts ?? 0) + 1
        const locked = failures >= email.maxPasswordFailures
        await email.store.putAccount({
          ...account,
          failedPasswordAttempts: locked ? 0 : failures,
          passwordLockedUntil: locked ? now + email.passwordLockSeconds : null,
          updatedAt: now,
        })
        if (locked) cfg.log("warn", `password sign-in locked for ${redactEmail(address, emailLogKey)} after ${failures} failures`)
      }
      return emailError(res, 401, "form_password_incorrect", "That email and password do not match.")
    }
    const clean = (account.failedPasswordAttempts ?? 0) === 0 && !account.passwordLockedUntil
    return completeEmailSignIn(
      req,
      res,
      clean ? account : { ...account, failedPasswordAttempts: 0, passwordLockedUntil: null, updatedAt: now },
      !clean,
      "Password",
      "sign_in",
      redirectUrlComplete,
    )
  }

  /**
   * GET /environment — instance configuration, mirroring the hosted-identity-provider Frontend-API
   * `/v1/environment`. Hosted-IdP-style clients fetch this on load to learn which sign-in strategies exist before any
   * session is established, so it is UNAUTHENTICATED by design and must stay secret-free: it
   * exposes only which strategies are enabled and the non-secret session policy — never client
   * ids/secrets, cookie names, or the signing secret.
   */
  async function handleEnvironment(res: ServerResponse): Promise<void> {
    // Sign-up mode as the app states it. A Live value that fails to resolve is reported as
    // "restricted" (never a more open mode) and logged. Identifier lists are NEVER published.
    let mode: SignUpMode
    let allowlistOnly: boolean
    if (adm.legacyOnly) {
      mode = cfg.allowAnyDomain ? "public" : "restricted"
      allowlistOnly = !cfg.allowAnyDomain
    } else {
      const p = await resolvePolicy()
      if ("error" in p) {
        cfg.log("error", `admission policy could not be resolved for /environment; reporting restricted: ${p.error}`)
        mode = "restricted"
        allowlistOnly = false
      } else {
        mode = p.mode
        allowlistOnly = p.restrictions.allowlist === true
      }
    }
    const connections: Array<{ id: string; strategy: string; label: string; domain?: string }> = []
    if (cfg.googleConfigured) {
      connections.push({ id: "conn_google", strategy: "oauth_google", label: adm.google.label })
      if (adm.google.publishHintDomains) {
        for (const d of adm.google.hostedDomainHints) {
          connections.push({ id: connectionIdForDomain(d), strategy: "oauth_google", label: d, domain: d })
        }
      }
    }
    if (cfg.xConfigured) connections.push({ id: "conn_x", strategy: "oauth_x", label: adm.xLabel })
    if (cfg.saml) connections.push({ id: "conn_saml", strategy: "saml", label: adm.saml.label })
    if (cfg.email) connections.push({ id: "conn_email", strategy: "email_code", label: cfg.email.label })

    sendJson(res, 200, {
      object: "environment",
      auth_config: {
        object: "auth_config",
        single_session_mode: true,
        session_maximum_lifetime_seconds: cfg.sessionTtlSeconds,
        session_inactivity_timeout_seconds: cfg.inactivityTimeoutSeconds,
      },
      display_config: {
        object: "display_config",
        // Published only when the app opted in (the legacy default, because legacy always did).
        ...(adm.publishAllowedDomains ? { allowed_domains: cfg.allowedDomains } : {}),
      },
      user_settings: {
        sign_up: { mode, allowlist_only: allowlistOnly },
        social: {
          oauth_google: { enabled: cfg.googleConfigured, strategy: "oauth_google", name: adm.google.label },
          oauth_x: { enabled: cfg.xConfigured, strategy: "oauth_x", name: adm.xLabel },
        },
        saml: { enabled: Boolean(cfg.saml) },
        // Clerk's user_settings.attributes.email_address / password, flattened.
        email: {
          enabled: Boolean(cfg.email),
          strategies: cfg.email ? (cfg.email.password ? ["email_code", "password"] : ["email_code"]) : [],
          password_enabled: Boolean(cfg.email?.password),
          min_password_length: cfg.email?.minPasswordLength ?? null,
          name: cfg.email?.label ?? null,
        },
        connections,
      },
      organization_settings: { enabled: adm.organizationsEnabled },
    })
  }

  async function handleClient(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const session = await readSession(req)
    if (!session || !session.sid) {
      // Signed out — RealAuthCore treats an empty client as EMPTY_SNAPSHOT.
      return sendJson(res, 200, {
        object: "client",
        last_active_session_id: null,
        sessions: [],
      })
    }
    sendJson(res, 200, clientSnapshot(session))
  }

  async function handleMintToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const session = await readSession(req)
    if (!session) return sendJson(res, 401, { error: "not_authenticated" })
    // Optionally re-resolve grants before minting so a deprovision/role change upstream takes effect
    // within reresolveGrantsEverySeconds instead of only at session end. No-op when disabled.
    if ((await maybeReresolveGrants(session, res)) === "signed_out") return
    const body = await readJsonBody(req)
    let orgId = (body.org_id as string | undefined) ?? session.orgId
    // After a re-resolution the requested org may no longer be a membership; fall back to the base.
    if (orgId && !session.memberships.some((m) => m.organization.id === orgId)) orgId = session.orgId
    const jwt = await mintAccessToken(session, orgId)
    // Sliding session: re-issue the session cookie on each mint so an actively-used session rolls
    // forward instead of hard-expiring at the absolute sessionTtl. Re-signed (not just a Max-Age
    // bump) so the JWT `exp` advances in lockstep with the cookie. The client caches the access
    // token (~60s TTL), so during active use this rolls roughly once a minute, not per request.
    const sessionJwt = await signSession(session)
    setCookie(res, cfg.sessionCookieName, sessionJwt, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      secure: cfg.cookieSecure,
      sameSite: cfg.sessionCookieSameSite,
    })
    // Record activity so the inactivity-timeout clock (when enabled) tracks real use, and so the
    // durable record's lastActiveAt stays current across restarts.
    if (cfg.sessionStore) {
      try {
        await cfg.sessionStore.touch(session.email, session.sid, {
          lastActiveAt: Math.floor(Date.now() / 1000),
        })
      } catch (err) {
        cfg.log("warn", "session store touch failed on token mint", err)
      }
    }
    // Audit trail: token refresh is logged alongside sign-in/sign-out (consumer specs require it).
    // The client caches the access token, so this fires roughly once a minute during active use.
    cfg.log("info", `Access token refreshed for ${redactEmail(session.email, emailLogKey)}`)
    sendJson(res, 200, { jwt, object: "token" })
  }

  async function handleTouch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const session = await readSession(req)
    if (!session) return sendJson(res, 401, { error: "not_authenticated" })
    const body = await readJsonBody(req)
    const next = (body.active_organization_id as string | null | undefined) ?? null
    if (next && !session.memberships.some((m) => m.organization.id === next)) {
      return sendJson(res, 400, { error: "not_a_member" })
    }
    session.orgId = next
    const sessionJwt = await signSession(session)
    setCookie(res, cfg.sessionCookieName, sessionJwt, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      secure: cfg.cookieSecure,
      sameSite: cfg.sessionCookieSameSite,
    })
    if (cfg.sessionStore) {
      try {
        await cfg.sessionStore.touch(session.email, session.sid, {
          orgId: session.orgId,
          lastActiveAt: Math.floor(Date.now() / 1000),
        })
      } catch (err) {
        cfg.log("warn", "session store touch failed on org switch", err)
      }
    }
    sendJson(res, 200, { object: "session", id: session.sid, org_id: session.orgId })
  }

  async function handleReverify(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const session = await readSession(req)
    const q = queryOf(req)
    const back = safeRedirectTarget(q.get("redirect_url") || "/")
    if (!session) return redirect(res, back)
    // An email session has no IdP to bounce through, and routing it to Google would fail the
    // binding check anyway. Say so instead of sending the person on a round trip that cannot work.
    if (session.provider === "email") {
      return backToApp(res, back, { error: "reverify_unsupported", error_message: "Sign in again with your email to continue." })
    }
    // REAL step-up: route through the IdP with a forced fresh authentication. lastVerifiedAt is
    // stamped ONLY after the IdP returns a fresh assertion (see the reverify branch in
    // handleCallback / handleSamlAcs), never by this endpoint alone. This closes the no-op-stamp
    // gap where a live (or stolen-but-valid) session could "reverify" with no proof of presence.
    if (cfg.saml) {
      // SAML step-up uses ForceAuthn; build a one-off client with forceAuthn set.
      const stepUpClient = buildSamlClient({ ...(cfg.saml as SamlSpConfig), forceAuthn: true })
      const relayState = base64url(randomBytes(24))
      const url = await samlLoginRedirectUrl(stepUpClient, relayState)
      const relayJwt = await signSamlRelay({
        relayState,
        redirectUrl: back,
        redirectUrlComplete: back,
        reverify: true,
      })
      setCookie(res, cfg.samlRelayCookieName, relayJwt, {
        maxAgeSeconds: STATE_TTL_SECONDS,
        secure: true,
        sameSite: "None",
      })
      return redirect(res, url)
    }
    // OIDC step-up: bounce through /sign_in/sso with reverify=1 (prompt=login + max_age=0).
    if (!guardGoogleConfigured(res)) {
      const start = new URL("http://internal/sign_in/sso")
      start.searchParams.set("reverify", "1")
      start.searchParams.set("redirect_url_complete", back)
      ;(req as IncomingMessage & { url?: string }).url = `${start.pathname}${start.search}`
      await handleSsoStart(req, res)
    }
  }

  async function handleRemove(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Revoke the durable record (tombstone) so the session can't be reused, then clear the cookie.
    let session: SessionRecord | null = null
    try {
      session = await readSession(req)
    } catch {
      session = null
    }
    if (cfg.sessionStore && session?.sid) {
      try {
        await cfg.sessionStore.remove(session.email, session.sid)
      } catch (err) {
        cfg.log("warn", "session store remove failed at sign-out", err)
      }
    }
    clearCookie(res, cfg.sessionCookieName, cfg.cookieSecure)
    // Audit trail: sign-out is logged like sign-in and token refresh (consumer specs require it).
    if (session) cfg.log("info", `Sign-out completed for ${redactEmail(session.email, emailLogKey)}`)
    sendJson(res, 200, { object: "session", deleted: true })
  }

  /**
   * GET /client/sessions/active — list the signed-in user's active (non-revoked, unexpired)
   * sessions. Mirrors the hosted-identity-provider session-listing surface so an app can build a "sign out other
   * devices" view. Returns an empty list when signed out or when no store is configured.
   */
  async function handleListSessions(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const session = await readSession(req)
    if (!session || !session.sid || !cfg.sessionStore) {
      return sendJson(res, 200, { object: "list", data: [] })
    }
    try {
      const now = Math.floor(Date.now() / 1000)
      const all = await cfg.sessionStore.list(session.email)
      const active = all.filter((s) => !s.revoked && (!s.expireAt || s.expireAt > now))
      return sendJson(res, 200, {
        object: "list",
        data: active.map((s) => ({
          id: s.sid,
          status: "active",
          user_id: s.userId,
          created_at: s.createdAt * 1000,
          last_active_at: s.lastActiveAt * 1000,
          expire_at: s.expireAt * 1000,
          is_current: s.sid === session.sid,
        })),
      })
    } catch (err) {
      cfg.log("warn", "session store list failed", err)
      return sendJson(res, 200, { object: "list", data: [] })
    }
  }

  // --- SAML 2.0 SP path ----------------------------------------------------------------------
  // All SAML XML/crypto lives in saml.ts; here we only carry the redirect targets + CSRF token
  // (in a signed cookie, mirroring the OIDC `state` cookie) and funnel the verified identity into
  // the shared finishSignIn() so a SAML sign-in yields the exact same session as the OIDC path.

  // The node-saml SAML client is built once (it parses the IdP cert). Null when SAML is disabled.
  let samlClient: ReturnType<typeof buildSamlClient> | null = null
  function getSamlClient(): ReturnType<typeof buildSamlClient> | null {
    if (!cfg.saml) return null
    if (!samlClient) samlClient = buildSamlClient(cfg.saml)
    return samlClient
  }

  async function signSamlRelay(state: {
    relayState: string
    redirectUrl: string
    redirectUrlComplete: string
    /** True when this is a SAML step-up reverify (re-stamp lastVerifiedAt only). */
    reverify?: boolean
    /** UNTRUSTED client hints, see signState. */
    mode?: "sign_in" | "sign_up"
    connectionId?: string
  }): Promise<string> {
    return await new SignJWT(state as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(`${STATE_TTL_SECONDS}s`)
      .sign(relayKey)
  }

  async function readSamlRelay(req: IncomingMessage): Promise<{
    relayState: string
    redirectUrl: string
    redirectUrlComplete: string
    reverify?: boolean
    mode?: "sign_in" | "sign_up"
    connectionId?: string
  } | null> {
    const raw = parseCookies(req)[cfg.samlRelayCookieName]
    if (!raw) return null
    try {
      const { payload } = await jwtVerify(raw, relayKey, { algorithms: ["HS256"] })
      return payload as unknown as {
        relayState: string
        redirectUrl: string
        redirectUrlComplete: string
        reverify?: boolean
        mode?: "sign_in" | "sign_up"
        connectionId?: string
      }
    } catch {
      return null
    }
  }

  /** SP metadata XML — hand this to the IdP operator to register the ACS URL + Entity ID. */
  function handleSamlMetadata(_req: IncomingMessage, res: ServerResponse): void {
    if (!cfg.saml) return sendJson(res, 404, { error: "saml_not_configured" })
    const xml = samlSpMetadata(cfg.saml)
    res.statusCode = 200
    res.setHeader("Content-Type", "application/xml; charset=utf-8")
    res.setHeader("Cache-Control", "no-store")
    res.end(xml)
  }

  /** SP-initiated SAML login: stash CSRF token + redirect targets, then 302 to the IdP. */
  async function handleSamlLogin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const saml = getSamlClient()
    if (!saml) return sendJson(res, 404, { error: "saml_not_configured" })
    const q = queryOf(req)
    const redirectUrl = q.get("redirect_url") || "/sso-callback"
    const redirectUrlComplete = q.get("redirect_url_complete") || "/"
    const relayState = base64url(randomBytes(24))

    const url = await samlLoginRedirectUrl(saml, relayState)
    // node-saml caches the AuthnRequest ID it generated (its default cacheProvider) and enforces
    // InResponseTo at the ACS via validateInResponseTo: ifPresent, binding the Response to the
    // request in-process. We additionally carry our signed RelayState cookie as defense-in-depth.
    const relayJwt = await signSamlRelay({
      relayState,
      redirectUrl,
      redirectUrlComplete,
      mode: requestedModeOf(q),
      ...(q.get("connection") ? { connectionId: String(q.get("connection")).slice(0, 200) } : {}),
    })
    // The ACS is a cross-site top-level POST from the IdP, so the relay cookie MUST be
    // SameSite=None to be sent — which requires Secure. Lax/Strict would drop it and break SAML.
    setCookie(res, cfg.samlRelayCookieName, relayJwt, {
      maxAgeSeconds: STATE_TTL_SECONDS,
      secure: true,
      sameSite: "None",
    })
    redirect(res, url)
  }

  /** ACS: validate the signed SAML Response, enforce domain, establish the shared session. */
  async function handleSamlAcs(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const saml = getSamlClient()
    if (!saml) return sendJson(res, 404, { error: "saml_not_configured" })
    const saved = await readSamlRelay(req)
    clearCookie(res, cfg.samlRelayCookieName, true, "None")
    const fallbackRedirect = saved?.redirectUrl ?? "/sso-callback"
    const redirectUrlComplete = saved?.redirectUrlComplete ?? "/"

    const body = await readFormBody(req)
    // CSRF: the IdP echoes RelayState unchanged; it must match the value we signed into the cookie.
    if (!saved || !body.RelayState || !constantTimeEqual(body.RelayState, saved.relayState)) {
      cfg.log("warn", "SAML ACS failed RelayState validation")
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Sign-in could not be verified. Please try again.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    let identity: OidcIdentity
    try {
      // node-saml enforces audience + InResponseTo (ifPresent) + signature internally; we add an
      // assertion-id replay cache (one-time use) and the emailVerified/audience defense-in-depth.
      const result = await validateSamlAcs(
        saml,
        { SAMLResponse: body.SAMLResponse, RelayState: body.RelayState },
        cfg.saml as SamlSpConfig,
        cfg.samlReplayStore,
      )
      identity = result.identity
    } catch (err) {
      cfg.log("error", "SAML assertion validation failed", err instanceof Error ? err.message : err)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Could not verify your SAML sign-in.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    // SAML step-up reverify: a fresh ForceAuthn assertion proved presence. Same tail as Google's:
    // binding check, admission re-check, then re-stamp lastVerifiedAt (never re-establish).
    if (saved.reverify) {
      return finishReverify(req, res, identity, fallbackRedirect, redirectUrlComplete, untrustedFrom(req, saved))
    }

    return finishSignIn(req, res, identity, fallbackRedirect, redirectUrlComplete, untrustedFrom(req, saved))
  }

  // --- router --------------------------------------------------------------------------------

  const handler = ((req, res, next) => {
    const path = pathOf(req)
    const method = (req.method ?? "GET").toUpperCase()

    // Security headers + CORS on every auth-endpoint response (defense-in-depth).
    if (cfg.securityHeaders) setSecurityHeaders(res)
    if (cfg.allowedCorsOrigins.length > 0) {
      const origin = ((): string | undefined => {
        const o = req.headers?.origin
        return Array.isArray(o) ? o[0] : o
      })()
      // Unconditional: once CORS is configured, the response content depends on Origin whether or
      // not this particular Origin matched, and a cache must be told so either way. Setting it only
      // on the matching branch lets a shared cache serve a no-CORS response to an allowlisted origin
      // (or the reverse) without ever knowing the two differ.
      res.setHeader("Vary", "Origin")
      if (origin && cfg.allowedCorsOrigins.includes(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin)
        res.setHeader("Access-Control-Allow-Credentials", "true")
        res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type")
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
      }
      if (method === "OPTIONS") {
        res.statusCode = 204
        res.end()
        return
      }
    }

    const route = async (): Promise<boolean> => {
      // Gate FIRST, so a refusal costs nothing: no XML parsing on /saml/acs, no outbound call to
      // Google or X, no log line per refused request. A hook that throws is a refusal — a limiter
      // outage must not silently remove the limit from the auth endpoints.
      if (cfg.rateLimit) {
        let allowed: boolean
        try {
          allowed = (await cfg.rateLimit({ method, path, req })) !== false
        } catch (err) {
          cfg.log("warn", "rateLimit hook threw; refusing the request (fail closed)", err)
          allowed = false
        }
        if (!allowed) {
          sendJson(res, 429, { error: "rate_limited" })
          return true
        }
      }
      if (method === "GET" && path === "/sign_in/sso") {
        // Unified sign-in entry point: strategy=saml routes to the SAML SP path (when
        // configured); strategy=x (or the connection-strategy spelling oauth_x) to X; everything
        // else (oauth_google, the legacy oauth_google_workspace alias, none) is the Google path.
        const strategy = queryOf(req).get("strategy") ?? ""
        if (strategy === "saml" && cfg.saml) await handleSamlLogin(req, res)
        else if (strategy === "x" || strategy === "oauth_x") {
          if (!guardXConfigured(res)) await handleXSsoStart(req, res)
        } else if (!guardGoogleConfigured(res)) await handleSsoStart(req, res)
        return true
      }
      if (method === "GET" && path === "/oauth_callback") {
        if (!guardGoogleConfigured(res)) await handleCallback(req, res)
        return true
      }
      if (cfg.email && method === "POST" && path === "/email/code") {
        await handleEmailCode(req, res)
        return true
      }
      if (cfg.email && method === "POST" && path === "/email/verify") {
        await handleEmailVerify(req, res)
        return true
      }
      if (cfg.email && method === "POST" && path === "/email/password") {
        await handleEmailPassword(req, res)
        return true
      }
      if (method === "GET" && path === "/oauth_callback/x") {
        if (!guardXConfigured(res)) await handleXCallback(req, res)
        return true
      }
      // SAML 2.0 SP routes (served only when a `saml` config block is present + enabled).
      if (method === "GET" && path === "/saml/metadata") {
        handleSamlMetadata(req, res)
        return true
      }
      if (method === "GET" && path === "/saml/login") {
        await handleSamlLogin(req, res)
        return true
      }
      if (method === "POST" && path === "/saml/acs") {
        await handleSamlAcs(req, res)
        return true
      }
      // Hosted-IdP-style instance-configuration endpoint. Some hosted-IdP-style clients fetch this on
      // load; without it the request falls through to the host app as a noisy 404.
      if (method === "GET" && path === "/environment") {
        await handleEnvironment(res)
        return true
      }
      if (method === "GET" && path === "/client") {
        await handleClient(req, res)
        return true
      }
      // List the user's active sessions (hosted-IdP-style). Declared before the :id pattern below.
      if (method === "GET" && path === "/client/sessions/active") {
        await handleListSessions(req, res)
        return true
      }
      // /client/sessions/:id/...
      const m = /^\/client\/sessions\/([^/]+)\/(tokens|touch|reverify|remove)(?:\/[^/]+)?$/.exec(path)
      if (m) {
        const action = m[2]
        if (action === "tokens" && method === "POST") {
          await handleMintToken(req, res)
          return true
        }
        if (action === "touch" && method === "POST") {
          await handleTouch(req, res)
          return true
        }
        if (action === "reverify" && method === "GET") {
          await handleReverify(req, res)
          return true
        }
        if (action === "remove" && method === "POST") {
          await handleRemove(req, res)
          return true
        }
      }
      return false
    }

    route()
      .then((handled) => {
        if (!handled) {
          if (next) next()
          else sendJson(res, 404, { error: "not_found" })
        }
      })
      .catch((err) => {
        cfg.log("error", "auth-frontend handler threw", err instanceof Error ? err.message : err)
        if (!res.headersSent) sendJson(res, 500, { error: "internal_error" })
      })
  }) as FederatedFrontend

  // The session reader, exposed on the middleware itself. It delegates to the SAME internal
  // `readSession` the routes above use — that shared implementation is the point. `publicSession`
  // strips the internal-only bookkeeping field so the contract stays the documented one.
  handler.readBrowserSession = async (req: IncomingMessage): Promise<BrowserSession | null> => {
    const session = await readSession(req)
    return session ? publicSession(session) : null
  }

  // This app's own verifier, closed over this app's config — never the process-global one.
  const ownVerifier = createEmbeddedVerifier({
    sessionSecret: cfg.sessionSecret,
    issuer: cfg.issuer,
    audience: cfg.audience,
  })
  handler.verifyToken = (token: string, opts: VerifyTokenOptions = {}) => ownVerifier(token, opts)

  // The same pipeline a real sign-in runs, minus every side effect (no mint, no cookie, no store
  // write, no resolveGrants). For an app's boot self-test: misconfiguration fails loudly at boot.
  handler.evaluateAdmission = async (
    identity: ActionIdentity,
    opts: { isSignUp?: boolean | null; phase?: AdmissionPhase } = {},
  ): Promise<AdmissionResult> => {
    const oidc: OidcIdentity = {
      sub: identity?.sub ?? "",
      email: identity?.email ?? "",
      emailVerified: identity?.emailVerified === true,
      hd: identity?.hd,
      name: identity?.name,
      provider: identity?.provider,
      username: identity?.username,
    }
    const d = await admit(oidc, {
      phase: opts.phase === "reverify" ? "reverify" : "sign_in",
      untrusted: { requestedMode: "sign_in" },
      traceId: newTraceId(),
      ...(opts.isSignUp !== undefined ? { isSignUp: opts.isSignUp } : {}),
    })
    return d.ok
      ? { allowed: true, matchedAllowlistIdentifier: d.matchedAllowlistIdentifier }
      : { allowed: false, code: d.code, message: d.message, step: d.step }
  }

  handler.revokeUserSessions = async (email: string): Promise<number> => {
    const store = cfg.sessionStore
    if (!store || typeof store.revokeAllForUser !== "function") {
      throw new Error(
        "revokeUserSessions needs a sessionStore that implements revokeAllForUser (FileSessionStore and " +
          "InMemorySessionStore do). Cookie-only sessions cannot be revoked server-side.",
      )
    }
    const count = await store.revokeAllForUser(email)
    cfg.log("info", `Revoked ${count} session(s) for ${redactEmail(email, emailLogKey)}`)
    return count
  }

  return handler
}

/** Project the library-internal session record onto the public {@link BrowserSession} contract. */
function publicSession(s: {
  sid: string
  userId: string
  email: string
  name?: string
  firstName?: string
  lastName?: string
  hd?: string
  roles: string[]
  permissions: string[]
  orgId: string | null
  memberships: OrgMembership[]
  lastVerifiedAt: number
  provider?: IdentityProvider
  providerSub?: string
}): BrowserSession {
  return {
    sid: s.sid,
    userId: s.userId,
    email: s.email,
    name: s.name,
    firstName: s.firstName,
    lastName: s.lastName,
    hd: s.hd,
    // Copy the arrays: a host app must not be able to mutate the live session record it was handed.
    roles: [...s.roles],
    permissions: [...s.permissions],
    orgId: s.orgId,
    memberships: [...s.memberships],
    lastVerifiedAt: s.lastVerifiedAt,
    ...(s.provider ? { provider: s.provider } : {}),
    ...(s.providerSub !== undefined ? { providerSub: s.providerSub } : {}),
  }
}

/**
 * @deprecated Use {@link createFederatedFrontend}. Alias retained so existing
 * `createAuthFrontend({ google: { ... } })` call sites keep working unchanged (the deprecated
 * `google`/`saml` shorthand is still accepted).
 */
export const createAuthFrontend = createFederatedFrontend
