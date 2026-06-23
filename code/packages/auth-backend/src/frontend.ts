import { createHash, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto"
import type { IncomingMessage, ServerResponse } from "node:http"

import { createRemoteJWKSet, jwtVerify, SignJWT } from "jose"

import { credentialsRemediation, loadGoogleCredentials } from "./credentials.js"
import { configureEmbeddedVerification } from "./verify.js"
import type { SessionMembership, SessionStore, StoredSession } from "./session-store.js"
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
 * `@auth/react` `RealAuthCore` calls, so a SPA gets a *real* Google Workspace sign-in with no
 * separate auth server process:
 *
 *   GET  /sign_in/sso                         → 302 to Google's OAuth 2.0 / OIDC authorize URL
 *   GET  /oauth_callback                      → code→token exchange, id_token + hd verification,
 *                                               establishes the session cookie, 302 back to the SPA
 *   GET  /client                              → rehydrate the current session (signed-out = empty)
 *   POST /client/sessions/:id/tokens          → mint a short-lived access JWT for API calls
 *   POST /client/sessions/:id/tokens/:tmpl    → templated token mint (same path, tagged)
 *   POST /client/sessions/:id/touch           → set the session's active organization
 *   GET  /client/sessions/:id/reverify        → step-up: refresh the session's verified-at time
 *   POST /client/sessions/:id/remove          → sign out (clear the session cookie)
 *
 * Everything runs in the host's own process. The human is authenticated by Google (real OIDC
 * round-trip, real id_token signature check against Google's JWKS, real `hd`/`email_verified`
 * enforcement). The app *session* and the short-lived access tokens are signed with a single
 * in-process HS256 secret (`sessionSecret`) — the same secret `verifyToken()` checks in embedded
 * mode — so there is no JWKS endpoint and no second service to run.
 */

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"]

// `jose` v5 is a dual ESM/CJS package (its package.json `exports` has a `require` entry), so the
// static import above is safe from a CommonJS host (NestJS): NodeNext compiles it to
// `require("jose")`, resolving to jose's CJS build. We deliberately do NOT use a dynamic
// `import("jose")` — under any vm-based module loader without `importModuleDynamically` (notably
// jest/ts-jest's CJS sandbox), a runtime `import()` throws
// ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG. Mirrors verify.ts.
let googleJwks: ReturnType<typeof createRemoteJWKSet> | null = null
function googleKeySet(): ReturnType<typeof createRemoteJWKSet> {
  if (!googleJwks) {
    googleJwks = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"))
  }
  return googleJwks
}

/** The verified upstream identity returned by Google's OIDC id_token. */
export interface OidcIdentity {
  /** Google's stable subject identifier. */
  sub: string
  email: string
  emailVerified: boolean
  /** Hosted-domain claim (Google Workspace). Absent for consumer gmail.com accounts. */
  hd?: string
  name?: string
  givenName?: string
  familyName?: string
  picture?: string
}

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
  /** Google Workspace hosted domain to hint + enforce (`hd`). Optional. */
  hostedDomain?: string
}

/** A SAML 2.0 sign-in connection. `strategy` mirrors Federated's enterprise SSO vocabulary. */
export type SamlConnectionConfig = { strategy: "saml" } & SamlSpConfig

/**
 * One configured sign-in connection. Mirrors Federated's connection/strategy model
 * (`oauth_google`, SAML) so credentials are passed by API in a Federated-idiomatic shape rather than
 * via a provider-specific block.
 */
export type FederatedConnectionConfig = GoogleConnectionConfig | SamlConnectionConfig

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
  /** Email/`hd` domains permitted to complete sign-in. Anything else is rejected. */
  allowedDomains: string[]
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
   * Session **maximum lifetime** in seconds — Clerk's "Maximum lifetime" knob. The absolute ceiling
   * after which the user must sign in again, regardless of activity. Defaults to ~4 months. The
   * session is a sliding window (re-issued on each token mint), so active use rolls the cookie
   * forward up to this ceiling. (Name kept as `sessionTtlSeconds` for back-compat.)
   */
  sessionTtlSeconds?: number
  accessTokenTtlSeconds?: number
  /**
   * Session **inactivity timeout** in seconds — Clerk's "Inactivity timeout" knob. If a session
   * goes this long without a token refresh / touch, it is treated as signed out. `0` (the default)
   * disables it: combined with the long maximum lifetime, a user stays signed in "forever" as long
   * as they return within the maximum lifetime. Only enforced when a {@link sessionStore} is set
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
   * Durable server-side session store (the stateful half of the Clerk model). When provided, each
   * sign-in writes a {@link StoredSession}; reads validate it (revocation, max-lifetime, inactivity)
   * and the record survives app restarts. When omitted, the library is purely stateless (the signed
   * cookie is the whole session) — backward compatible. See `session-store.ts` / {@link FileSessionStore}.
   */
  sessionStore?: SessionStore
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
   * Per-app audience (`aud`) stamped on minted session/access tokens and required on verify. Binds
   * a token to this app so two apps sharing a secret/prefix cannot accept each other's tokens.
   */
  audience?: string
  /**
   * Require a present, allowlisted Google Workspace hosted-domain (`hd`) claim. When true, an
   * identity lacking `hd` (e.g. a consumer gmail.com account) is rejected even if its email domain
   * is on {@link allowedDomains} — the email domain is no longer accepted as a substitute for
   * Workspace membership. Defaults to false (back-compat).
   */
  requireHostedDomain?: boolean
  /**
   * Allowlist of origins (e.g. `https://app.example.com`) a post-sign-in redirect may target.
   * Absolute redirect URLs not on this list are rejected and rewritten to a same-origin relative
   * path. When omitted, ALL absolute redirect targets are refused (same-origin relative only).
   */
  allowedRedirectOrigins?: string[]
  /**
   * Trust the IdP-asserted SAML email as verified when no explicit attribute is present. Forwarded
   * to {@link validateSamlAcs}; defaults to false (fail closed).
   */
  samlTrustAssertedEmailVerified?: boolean
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
  /** Map a verified identity to roles/permissions/orgs. Defaults to a least-privilege grant. */
  resolveGrants?: (identity: OidcIdentity) => ResolvedGrants
  logger?: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void
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

/** Hash an email to a short, non-reversible token so logs carry no raw PII. */
function redactEmail(email: string): string {
  if (!email) return "<none>"
  const at = email.lastIndexOf("@")
  const domain = at >= 0 ? email.slice(at + 1) : ""
  const digest = createHash("sha256").update(email.toLowerCase()).digest("hex").slice(0, 12)
  return `user_${digest}${domain ? `@${domain}` : ""}`
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
      if (data.length > 1_000_000) finish({}) // guard against oversized bodies
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
      if (data.length > 5_000_000) finish({}) // SAML responses are larger than JSON; cap generously
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
 * Default grant: a least-privilege authenticated employee — NO write, NO membership-management, NO
 * admin role. Any elevated authority (`*:write`, `org:admin`, `org:sys_memberships:manage`) MUST be
 * granted explicitly by the embedding app via `config.resolveGrants`, mapping Google Workspace
 * groups to roles. This fails closed: forgetting to wire `resolveGrants` yields a read-only user,
 * not an org admin.
 */
function defaultResolveGrants(identity: OidcIdentity): ResolvedGrants {
  const domain = identity.hd || emailDomain(identity.email) || "company"
  const membership: OrgMembership = {
    id: "orgmem_internal",
    organization: { id: "org_internal", name: `${domain} (Internal)`, slug: "internal" },
    role: "employee",
    permissions: [],
  }
  return {
    roles: ["employee"],
    permissions: [],
    orgId: "org_internal",
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
}

/** Google config after credential resolution: id/secret are filled (possibly empty) strings. */
interface ResolvedGoogleConfig {
  clientId: string
  clientSecret: string
  redirectUri: string
  hostedDomain?: string
}

interface InternalConfig {
  google: ResolvedGoogleConfig
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
  resolveGrants: (identity: OidcIdentity) => ResolvedGrants
  log: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void
  /** True only when both Google client id and secret resolved to non-empty values. */
  googleConfigured: boolean
  /** Secret-free, operator-actionable remediation text used when Google is unconfigured. */
  googleRemediation: string
}

/**
 * Collapse the Federated-idiomatic `connections[]` (and the deprecated `google`/`saml` shorthands)
 * into the `{ google, saml }` pair the request handlers consume. The first connection of each
 * strategy wins; an explicit `connections` entry takes precedence over the legacy shorthand.
 */
function normalizeConnections(config: FederatedFrontendConfig): {
  google?: LegacyGoogleConfig
  saml?: SamlSpConfig
} {
  const connections = config.connections ?? []
  const googleConn = connections.find(
    (c): c is GoogleConnectionConfig => c.strategy === "oauth_google",
  )
  const samlConn = connections.find((c): c is SamlConnectionConfig => c.strategy === "saml")

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

  return { google, saml }
}

function normalizeConfig(config: FederatedFrontendConfig): InternalConfig {
  const { google: googleCfg, saml: samlCfg } = normalizeConnections(config)

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

  return {
    google: {
      clientId,
      clientSecret,
      redirectUri: googleCfg?.redirectUri ?? "",
      hostedDomain: googleCfg?.hostedDomain,
    },
    googleConfigured,
    googleRemediation,
    saml: samlCfg?.enabled ? samlCfg : undefined,
    allowedDomains: config.allowedDomains.map((d) => d.trim().toLowerCase()).filter(Boolean),
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
    resolveGrants: config.resolveGrants ?? defaultResolveGrants,
    log:
      config.logger ??
      ((level, message, meta) => {
        // Default: quiet on info, surface problems.
        if (level !== "info") console[level](`[auth-frontend] ${message}`, meta ?? "")
      }),
  }
}

/**
 * Create the embedded Frontend API middleware. Mount it where the SDK's `frontendApi` + `/v1`
 * resolves to — e.g. `app.use('/api/v1', createFederatedFrontend(cfg))` with `frontendApi: '/api'`.
 *
 * Pass connections the Federated-idiomatic way:
 *   `createFederatedFrontend({ connections: [{ strategy: 'oauth_google', clientId, clientSecret,
 *     redirectUri }], allowedDomains, sessionSecret })`
 */
export function createFederatedFrontend(
  config: FederatedFrontendConfig,
): (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void) => void {
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
  // validates with this app's secret/issuer WITHOUT reading any environment variable. This is the
  // single bridge between minting (here) and verification (verify.ts) — one source of truth, set by
  // the API caller.
  configureEmbeddedVerification({ sessionSecret: cfg.sessionSecret, issuer: cfg.issuer })

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

  if (!cfg.googleConfigured) {
    // Loud at construction, but non-fatal: SAML still works, and the OIDC routes fail closed with
    // a clear 503 (see guardGoogleConfigured) instead of redirecting to Google with an empty
    // client_id. The remediation text is source-agnostic (it names no host file path — that is the
    // embedding app's concern; see credentialsRemediation) and contains no secrets.
    cfg.log(
      "warn",
      "Google OAuth client is not configured; Google sign-in routes will return 503 until it is.\n" +
        cfg.googleRemediation,
    )
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
      hd: s.hd,
      roles: s.roles ?? [],
      permissions: s.permissions ?? [],
      orgId: s.orgId ?? null,
      memberships: Array.isArray(s.memberships) ? s.memberships : [],
      lastVerifiedAt: s.lastVerifiedAt ?? Math.floor(Date.now() / 1000),
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
      hd: payload.hd as string | undefined,
      roles: Array.isArray(payload.roles) ? (payload.roles as string[]) : [],
      permissions: Array.isArray(payload.permissions) ? (payload.permissions as string[]) : [],
      orgId: (payload.org_id as string | null) ?? null,
      memberships: Array.isArray(m) ? m : [],
      lastVerifiedAt: (payload.lvc as number) ?? Math.floor(Date.now() / 1000),
    }

    // Stateless mode (no store): the signed cookie IS the whole session — return it as before.
    if (!cfg.sessionStore || !cookieRec.sid) return cookieRec

    // Stateful (Clerk-style) mode: the durable record is the source of truth. This is what makes
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
      // A transient filesystem error must not lock the user out: fall back to the signed cookie.
      cfg.log("warn", "session store read failed; falling back to signed cookie", err)
      return cookieRec
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
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(session.userId)
      .setIssuedAt()
      .setIssuer(cfg.issuer ?? "openauthfederated")
      .setExpirationTime(`${cfg.accessTokenTtlSeconds}s`)
    if (cfg.audience) jwt = jwt.setAudience(cfg.audience)
    return await jwt.sign(accessKey)
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
      }
    } catch {
      return null
    }
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
      "Refusing to start Google sign-in: OAuth client credentials are not configured.\n" +
        cfg.googleRemediation,
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

  async function handleSsoStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const q = queryOf(req)
    const redirectUrl = q.get("redirect_url") || "/sso-callback"
    const redirectUrlComplete = q.get("redirect_url_complete") || "/"
    // Step-up reverify: the user already has a session but must prove fresh presence at the IdP.
    const reverify = q.get("reverify") === "1"
    // The SDK passes connection=conn_<domain_slug>; the explicit hostedDomain config wins.
    const connection = q.get("connection") ?? ""
    const domainFromConn = connection.startsWith("conn_")
      ? connection.slice("conn_".length).replace(/_/g, ".")
      : undefined
    const hostedDomain =
      cfg.google.hostedDomain ??
      (domainFromConn && cfg.allowedDomains.includes(domainFromConn) ? domainFromConn : undefined)

    const state = base64url(randomBytes(24))
    const nonce = base64url(randomBytes(24))
    const codeVerifier = base64url(randomBytes(32))
    const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest())

    const stateJwt = await signState({
      state,
      nonce,
      codeVerifier,
      redirectUrl,
      redirectUrlComplete,
      domain: hostedDomain,
      reverify,
    })
    setCookie(res, cfg.stateCookieName, stateJwt, {
      maxAgeSeconds: STATE_TTL_SECONDS,
      secure: cfg.cookieSecure,
    })

    const authUrl = new URL(GOOGLE_AUTH_URL)
    authUrl.searchParams.set("client_id", cfg.google.clientId)
    authUrl.searchParams.set("redirect_uri", cfg.google.redirectUri)
    authUrl.searchParams.set("response_type", "code")
    authUrl.searchParams.set("scope", "openid email profile")
    authUrl.searchParams.set("state", state)
    authUrl.searchParams.set("nonce", nonce)
    authUrl.searchParams.set("code_challenge", codeChallenge)
    authUrl.searchParams.set("code_challenge_method", "S256")
    // Step-up: force a fresh IdP authentication (prompt=login + max_age=0) so reverify is real
    // re-authentication, not a silent re-assertion. Normal sign-in just lets the user pick account.
    if (reverify) {
      authUrl.searchParams.set("prompt", "login")
      authUrl.searchParams.set("max_age", "0")
    } else {
      authUrl.searchParams.set("prompt", "select_account")
    }
    authUrl.searchParams.set("access_type", "online")
    if (hostedDomain) authUrl.searchParams.set("hd", hostedDomain)

    redirect(res, authUrl.toString())
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

    // Exchange the authorization code for tokens (PKCE).
    let idToken: string
    try {
      const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: cfg.google.clientId,
          client_secret: cfg.google.clientSecret,
          redirect_uri: cfg.google.redirectUri,
          code_verifier: saved.codeVerifier,
        }),
      })
      if (!tokenRes.ok) {
        // Do NOT log the raw provider error body — it can carry sensitive request detail. The
        // status code alone is enough to diagnose.
        cfg.log("error", `Google token exchange failed (${tokenRes.status})`)
        return backToApp(res, fallbackRedirect, {
          error: "sign_in_not_completed",
          error_message: "Could not complete sign-in with Google.",
          redirect_url_complete: redirectUrlComplete,
        })
      }
      const tokenJson = (await tokenRes.json()) as { id_token?: string }
      if (!tokenJson.id_token) throw new Error("no id_token in token response")
      idToken = tokenJson.id_token
    } catch (err) {
      cfg.log("error", "Google token exchange threw", err instanceof Error ? err.message : err)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Could not reach Google to complete sign-in.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    // Verify the id_token signature against Google's JWKS and check the standard claims.
    let identity: OidcIdentity
    try {
      const jwks = googleKeySet()
      const { payload } = await jwtVerify(idToken, jwks, {
        issuer: GOOGLE_ISSUERS,
        audience: cfg.google.clientId,
      })
      if (saved.nonce && payload.nonce !== saved.nonce) {
        throw new Error("nonce mismatch")
      }
      identity = {
        sub: String(payload.sub ?? ""),
        email: String(payload.email ?? ""),
        emailVerified: payload.email_verified === true || payload.email_verified === "true",
        hd: typeof payload.hd === "string" ? payload.hd : undefined,
        name: typeof payload.name === "string" ? payload.name : undefined,
        givenName: typeof payload.given_name === "string" ? payload.given_name : undefined,
        familyName: typeof payload.family_name === "string" ? payload.family_name : undefined,
        picture: typeof payload.picture === "string" ? payload.picture : undefined,
      }
    } catch (err) {
      cfg.log("error", "id_token verification failed", err instanceof Error ? err.message : err)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Could not verify your Google identity.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    // Step-up reverify: the user proved fresh presence at the IdP. Re-stamp the EXISTING session's
    // lastVerifiedAt only — do not mint a new session — and bounce back to where they were.
    if (saved.reverify) {
      const session = await readSession(req)
      if (session?.sid) {
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
      }
      return backToApp(res, redirectUrlComplete, {})
    }

    return finishSignIn(res, identity, fallbackRedirect, redirectUrlComplete)
  }

  /**
   * Shared tail of every sign-in path (OIDC callback and SAML ACS): enforce the company-domain
   * allowlist on the verified identity, resolve grants, mint the session cookie, and bounce back
   * to the SPA. Keeping this in one place guarantees SAML and OIDC produce an identical session.
   */
  async function finishSignIn(
    res: ServerResponse,
    identity: OidcIdentity,
    fallbackRedirect: string,
    redirectUrlComplete: string,
  ): Promise<void> {
    // Domain enforcement (authentication.mdx §3): require a verified email on an allowed domain.
    if (!identity.email || !identity.emailVerified) {
      return backToApp(res, fallbackRedirect, {
        error: "identity_domain_not_allowed",
        error_message: "A verified company email is required.",
        presented_domain: "",
        redirect_url_complete: redirectUrlComplete,
      })
    }
    // When the deployment is Workspace-gated (requireHostedDomain), the authoritative signal is the
    // `hd` (Workspace-membership) claim — NOT the email domain. An identity that merely ends in an
    // allowlisted domain but is not a Workspace member (no hd) is rejected. When not gated, fall
    // back to the email domain for back-compat.
    const hd = identity.hd?.toLowerCase()
    if (cfg.requireHostedDomain && !hd) {
      cfg.log("warn", "Rejecting sign-in: hosted-domain (hd) claim required but absent")
      return backToApp(res, fallbackRedirect, {
        error: "identity_domain_not_allowed",
        error_message: "This app requires a Google Workspace account (hosted domain).",
        presented_domain: "",
        redirect_url_complete: redirectUrlComplete,
      })
    }
    const presentedDomain = (cfg.requireHostedDomain ? hd : hd || emailDomain(identity.email)) ?? ""
    if (!presentedDomain || !cfg.allowedDomains.includes(presentedDomain)) {
      cfg.log("warn", `Rejecting sign-in from non-allowed domain: ${presentedDomain || "unknown"}`)
      return backToApp(res, fallbackRedirect, {
        error: "identity_domain_not_allowed",
        error_message:
          "This app is restricted to company accounts. Your domain is not on the allowlist.",
        presented_domain: presentedDomain,
        redirect_url_complete: redirectUrlComplete,
      })
    }

    // Establish the session.
    const grants = cfg.resolveGrants(identity)
    const now = Math.floor(Date.now() / 1000)
    const session: SessionRecord = {
      sid: `sess_${base64url(randomBytes(12))}`,
      userId: `user_${identity.sub}`,
      email: identity.email,
      name: identity.name,
      firstName: identity.givenName,
      lastName: identity.familyName,
      hd: identity.hd ?? presentedDomain,
      roles: grants.roles,
      permissions: grants.permissions,
      orgId: grants.orgId,
      memberships: grants.memberships,
      lastVerifiedAt: now,
    }
    const sessionJwt = await signSession(session)
    setCookie(res, cfg.sessionCookieName, sessionJwt, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      secure: cfg.cookieSecure,
      sameSite: cfg.sessionCookieSameSite,
    })
    // Persist the durable server-side record (Clerk's stateful half) so the session survives app
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
    cfg.log("info", `Sign-in established for ${redactEmail(identity.email)}`)

    backToApp(res, fallbackRedirect, { redirect_url_complete: redirectUrlComplete })
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
    const body = await readJsonBody(req)
    const orgId = (body.org_id as string | undefined) ?? session.orgId
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
    if (cfg.sessionStore) {
      try {
        const session = await readSession(req)
        if (session?.sid) await cfg.sessionStore.remove(session.email, session.sid)
      } catch (err) {
        cfg.log("warn", "session store remove failed at sign-out", err)
      }
    }
    clearCookie(res, cfg.sessionCookieName, cfg.cookieSecure)
    sendJson(res, 200, { object: "session", deleted: true })
  }

  /**
   * GET /client/sessions/active — list the signed-in user's active (non-revoked, unexpired)
   * sessions. Mirrors Clerk's session-listing surface so an app can build a "sign out other
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
    const relayJwt = await signSamlRelay({ relayState, redirectUrl, redirectUrlComplete })
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

    // SAML step-up reverify: fresh ForceAuthn assertion proved presence — re-stamp the existing
    // session's lastVerifiedAt only, do not re-establish.
    if (saved.reverify) {
      const session = await readSession(req)
      if (session?.sid) {
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
            cfg.log("warn", "session store touch failed on SAML reverify", err)
          }
        }
      }
      return backToApp(res, redirectUrlComplete, {})
    }

    return finishSignIn(res, identity, fallbackRedirect, redirectUrlComplete)
  }

  // --- router --------------------------------------------------------------------------------

  return (req, res, next) => {
    const path = pathOf(req)
    const method = (req.method ?? "GET").toUpperCase()

    // Security headers + CORS on every auth-endpoint response (defense-in-depth).
    if (cfg.securityHeaders) setSecurityHeaders(res)
    if (cfg.allowedCorsOrigins.length > 0) {
      const origin = ((): string | undefined => {
        const o = req.headers?.origin
        return Array.isArray(o) ? o[0] : o
      })()
      if (origin && cfg.allowedCorsOrigins.includes(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin)
        res.setHeader("Access-Control-Allow-Credentials", "true")
        res.setHeader("Vary", "Origin")
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
      if (method === "GET" && path === "/sign_in/sso") {
        // Unified sign-in entry point: strategy=saml routes to the SAML SP path (when
        // configured); everything else is the Google OIDC path.
        const strategy = queryOf(req).get("strategy") ?? ""
        if (strategy === "saml" && cfg.saml) await handleSamlLogin(req, res)
        else if (!guardGoogleConfigured(res)) await handleSsoStart(req, res)
        return true
      }
      if (method === "GET" && path === "/oauth_callback") {
        if (!guardGoogleConfigured(res)) await handleCallback(req, res)
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
      if (method === "GET" && path === "/client") {
        await handleClient(req, res)
        return true
      }
      // List the user's active sessions (Clerk-style). Declared before the :id pattern below.
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
  }
}

/**
 * @deprecated Use {@link createFederatedFrontend}. Alias retained so existing
 * `createAuthFrontend({ google: { ... } })` call sites keep working unchanged (the deprecated
 * `google`/`saml` shorthand is still accepted).
 */
export const createAuthFrontend = createFederatedFrontend
