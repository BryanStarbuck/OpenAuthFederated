import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import type { IncomingMessage, ServerResponse } from "node:http"

import { credentialsRemediation, loadGoogleCredentials } from "./credentials.js"
import {
  buildSamlClient,
  samlLoginRedirectUrl,
  samlSpMetadata,
  validateSamlAcs,
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

// `jose` is ESM-only; load it through a real dynamic import() so this package stays consumable
// from a CommonJS host (NestJS). Mirrors verify.ts.
type Jose = typeof import("jose")
let josePromise: Promise<Jose> | null = null
function jose(): Promise<Jose> {
  if (!josePromise) josePromise = import("jose")
  return josePromise
}

let googleJwks: ReturnType<Jose["createRemoteJWKSet"]> | null = null
async function googleKeySet(): Promise<ReturnType<Jose["createRemoteJWKSet"]>> {
  if (!googleJwks) {
    const { createRemoteJWKSet } = await jose()
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

export interface OrgMembership {
  id: string
  organization: { id: string; name: string; slug?: string }
  role: string
  permissions: string[]
}

/** RBAC + organization context resolved for a verified identity. */
export interface ResolvedGrants {
  roles: string[]
  permissions: string[]
  orgId: string | null
  memberships: OrgMembership[]
}

export interface AuthFrontendConfig {
  google: {
    /**
     * Google OAuth Web-client id. **Optional.** When omitted/empty, the library falls back to the
     * generic `GOOGLE_CLIENT_ID` environment variable (see `credentials.ts`). The embedding app
     * owns where the value is sourced from (its own secrets file/env) and passes it in here; the
     * library never reads an app-specific credentials file. Never hardcode the value or commit it.
     */
    clientId?: string
    /**
     * Google OAuth Web-client secret. **Optional** — resolved the same way as {@link clientId}
     * (explicit value here, then the generic `GOOGLE_CLIENT_SECRET` env var). Never hardcode the
     * value or commit it.
     */
    clientSecret?: string
    /** Must exactly match an Authorized redirect URI in the Google Cloud OAuth client. */
    redirectUri: string
    /** Google Workspace hosted domain to hint + enforce (`hd`). Optional. */
    hostedDomain?: string
  }
  /**
   * Optional SAML 2.0 Service Provider configuration. When present and `enabled`, the same
   * middleware also serves the SAML SP routes (`/saml/metadata`, `/saml/login`, `/saml/acs`)
   * and `/sign_in/sso?strategy=saml`. A SAML sign-in establishes the *same* session as the OIDC
   * path. All SAML XML handling lives in `saml.ts`; the host app only supplies this config.
   */
  saml?: SamlSpConfig
  /** Email/`hd` domains permitted to complete sign-in. Anything else is rejected. */
  allowedDomains: string[]
  /** HS256 secret used to sign the session cookie + access tokens. MUST match AUTH_SESSION_SECRET. */
  sessionSecret: string
  /** `iss` stamped on minted access tokens (informational in embedded mode). */
  issuer?: string
  sessionCookieName?: string
  sessionTtlSeconds?: number
  accessTokenTtlSeconds?: number
  /** Set true behind HTTPS so cookies carry the Secure attribute. */
  cookieSecure?: boolean
  /** Map a verified identity to roles/permissions/orgs. Defaults to an internal-employee grant. */
  resolveGrants?: (identity: OidcIdentity) => ResolvedGrants
  logger?: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void
}

const STATE_COOKIE = "oaf_oauth_state"
const SAML_RELAY_COOKIE = "oaf_saml_relay"
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
  const header = req.headers.cookie
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

function clearCookie(res: ServerResponse, name: string, secure?: boolean): void {
  appendSetCookie(
    res,
    `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`,
  )
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
 * Default grant: an internal employee who is an admin of the single "internal" org. Read
 * everything, write everything within the org — mirrors the prior dev-mock behavior so the
 * app's `<Protect …:write>` controls keep working. Replace via `config.resolveGrants` to map
 * Google Workspace groups to finer-grained roles.
 */
function defaultResolveGrants(identity: OidcIdentity): ResolvedGrants {
  const domain = identity.hd || emailDomain(identity.email) || "company"
  const membership: OrgMembership = {
    id: "orgmem_internal",
    organization: { id: "org_internal", name: `${domain} (Internal)`, slug: "internal" },
    role: "org:admin",
    permissions: ["*:read", "*:write", "org:sys_memberships:manage"],
  }
  return {
    roles: ["employee"],
    permissions: ["*:read"],
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

interface InternalConfig
  extends Required<Omit<AuthFrontendConfig, "issuer" | "logger" | "google" | "resolveGrants" | "saml">> {
  google: ResolvedGoogleConfig
  saml?: SamlSpConfig
  issuer?: string
  resolveGrants: (identity: OidcIdentity) => ResolvedGrants
  log: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void
  /** True only when both Google client id and secret resolved to non-empty values. */
  googleConfigured: boolean
  /** Secret-free, operator-actionable remediation text used when Google is unconfigured. */
  googleRemediation: string
}

function normalizeConfig(config: AuthFrontendConfig): InternalConfig {
  // Resolve the Google OAuth credentials the library was given: explicit config → generic
  // GOOGLE_CLIENT_ID/SECRET env. The library reads no app-specific file — the embedding app sources
  // the value and passes it in. We capture a secret-free remediation message rather than throwing,
  // so a missing credential surfaces as a clear 503 at request time (and the SAML path, which needs
  // no Google credential, still works).
  const resolved = loadGoogleCredentials({
    clientId: config.google.clientId,
    clientSecret: config.google.clientSecret,
  })
  const clientId = resolved.clientId
  const clientSecret = resolved.clientSecret
  const googleConfigured = resolved.ok
  const googleRemediation = resolved.ok ? "" : credentialsRemediation()

  return {
    google: {
      clientId,
      clientSecret,
      redirectUri: config.google.redirectUri,
      hostedDomain: config.google.hostedDomain,
    },
    googleConfigured,
    googleRemediation,
    saml: config.saml?.enabled ? config.saml : undefined,
    allowedDomains: config.allowedDomains.map((d) => d.trim().toLowerCase()).filter(Boolean),
    sessionSecret: config.sessionSecret,
    issuer: config.issuer,
    sessionCookieName: config.sessionCookieName ?? "oaf_session",
    sessionTtlSeconds: config.sessionTtlSeconds ?? 8 * 60 * 60,
    accessTokenTtlSeconds: config.accessTokenTtlSeconds ?? 60,
    cookieSecure: config.cookieSecure ?? false,
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
 * resolves to — e.g. `app.use('/api/v1', createAuthFrontend(cfg))` with `frontendApi: '/api'`.
 */
export function createAuthFrontend(
  config: AuthFrontendConfig,
): (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void) => void {
  const cfg = normalizeConfig(config)
  const secretKey = new TextEncoder().encode(cfg.sessionSecret)

  if (!cfg.googleConfigured) {
    // Loud at construction, but non-fatal: SAML still works, and the OIDC routes fail closed with
    // a clear 503 (see guardGoogleConfigured) instead of redirecting to Google with an empty
    // client_id. The remediation text names the file path + JSON shape and contains no secrets.
    cfg.log(
      "warn",
      "Google OAuth client is not configured; Google sign-in routes will return 503 until it is.\n" +
        cfg.googleRemediation,
    )
  }
  if (!cfg.sessionSecret || cfg.sessionSecret === "dev-shared-secret") {
    cfg.log("warn", "AUTH_SESSION_SECRET is unset or default — set a strong secret before production.")
  }

  async function signSession(record: SessionRecord): Promise<string> {
    const { SignJWT } = await jose()
    return await new SignJWT({
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
      .sign(secretKey)
  }

  async function readSession(req: IncomingMessage): Promise<SessionRecord | null> {
    const raw = parseCookies(req)[cfg.sessionCookieName]
    if (!raw) return null
    try {
      const { jwtVerify } = await jose()
      const { payload } = await jwtVerify(raw, secretKey)
      const m = (payload.memberships as OrgMembership[] | undefined) ?? []
      return {
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
    } catch {
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
    const { SignJWT } = await jose()
    const g = grantsForOrg(session, orgId)
    return await new SignJWT({
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
      .sign(secretKey)
  }

  // --- OAuth state (CSRF + PKCE + return targets) carried in a short-lived signed cookie ----

  async function signState(state: {
    state: string
    nonce: string
    codeVerifier: string
    redirectUrl: string
    redirectUrlComplete: string
    domain?: string
  }): Promise<string> {
    const { SignJWT } = await jose()
    return await new SignJWT(state as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(`${STATE_TTL_SECONDS}s`)
      .sign(secretKey)
  }

  async function readState(req: IncomingMessage): Promise<{
    state: string
    nonce: string
    codeVerifier: string
    redirectUrl: string
    redirectUrlComplete: string
    domain?: string
  } | null> {
    const raw = parseCookies(req)[STATE_COOKIE]
    if (!raw) return null
    try {
      const { jwtVerify } = await jose()
      const { payload } = await jwtVerify(raw, secretKey)
      return payload as unknown as {
        state: string
        nonce: string
        codeVerifier: string
        redirectUrl: string
        redirectUrlComplete: string
        domain?: string
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
   * secret-free remediation (file path + required JSON shape). Returns true when it handled the
   * request (caller should stop). The SAML path does not call this — it needs no Google credential.
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
        "OAuth client id and secret (via GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET or the out-of-repo " +
        "credentials file). See `remediation` for the exact path and JSON shape.",
      // `remediation` is deliberately secret-free — safe to surface to the operator.
      remediation: cfg.googleRemediation,
    })
    return true
  }

  async function handleSsoStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const q = queryOf(req)
    const redirectUrl = q.get("redirect_url") || "/sso-callback"
    const redirectUrlComplete = q.get("redirect_url_complete") || "/"
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
    })
    setCookie(res, STATE_COOKIE, stateJwt, {
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
    authUrl.searchParams.set("prompt", "select_account")
    authUrl.searchParams.set("access_type", "online")
    if (hostedDomain) authUrl.searchParams.set("hd", hostedDomain)

    redirect(res, authUrl.toString())
  }

  /** Bounce back to the SPA callback page, carrying either success or a rejection. */
  function backToApp(
    res: ServerResponse,
    redirectUrl: string,
    params: Record<string, string>,
  ): void {
    let url: URL
    try {
      url = new URL(redirectUrl)
    } catch {
      url = new URL(redirectUrl, "http://localhost")
    }
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)
    // Preserve a relative target if the SDK passed one.
    const isAbsolute = /^https?:\/\//i.test(redirectUrl)
    redirect(res, isAbsolute ? url.toString() : `${url.pathname}${url.search}`)
  }

  async function handleCallback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const q = queryOf(req)
    const saved = await readState(req)
    clearCookie(res, STATE_COOKIE, cfg.cookieSecure)

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
        const detail = await tokenRes.text()
        cfg.log("error", `Google token exchange failed (${tokenRes.status})`, detail.slice(0, 500))
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
      const { jwtVerify } = await jose()
      const jwks = await googleKeySet()
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
    const presentedDomain = (identity.hd || emailDomain(identity.email)).toLowerCase()
    if (!identity.email || !identity.emailVerified) {
      return backToApp(res, fallbackRedirect, {
        error: "identity_domain_not_allowed",
        error_message: "A verified company email is required.",
        presented_domain: presentedDomain,
        redirect_url_complete: redirectUrlComplete,
      })
    }
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
    })
    cfg.log("info", `Sign-in established for ${identity.email}`)

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
    })
    sendJson(res, 200, { object: "session", id: session.sid, org_id: session.orgId })
  }

  async function handleReverify(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const session = await readSession(req)
    const q = queryOf(req)
    const back = q.get("redirect_url") || "/"
    if (!session) return redirect(res, back)
    // Step-up in embedded mode: refresh the verified-at stamp and return. (A full IdP
    // re-prompt would route back through /sign_in/sso with prompt=login.)
    session.lastVerifiedAt = Math.floor(Date.now() / 1000)
    const sessionJwt = await signSession(session)
    setCookie(res, cfg.sessionCookieName, sessionJwt, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      secure: cfg.cookieSecure,
    })
    redirect(res, back)
  }

  async function handleRemove(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    clearCookie(res, cfg.sessionCookieName, cfg.cookieSecure)
    sendJson(res, 200, { object: "session", deleted: true })
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
  }): Promise<string> {
    const { SignJWT } = await jose()
    return await new SignJWT(state as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(`${STATE_TTL_SECONDS}s`)
      .sign(secretKey)
  }

  async function readSamlRelay(req: IncomingMessage): Promise<{
    relayState: string
    redirectUrl: string
    redirectUrlComplete: string
  } | null> {
    const raw = parseCookies(req)[SAML_RELAY_COOKIE]
    if (!raw) return null
    try {
      const { jwtVerify } = await jose()
      const { payload } = await jwtVerify(raw, secretKey)
      return payload as unknown as {
        relayState: string
        redirectUrl: string
        redirectUrlComplete: string
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

    const relayJwt = await signSamlRelay({ relayState, redirectUrl, redirectUrlComplete })
    setCookie(res, SAML_RELAY_COOKIE, relayJwt, {
      maxAgeSeconds: STATE_TTL_SECONDS,
      secure: cfg.cookieSecure,
    })
    const url = await samlLoginRedirectUrl(saml, relayState)
    redirect(res, url)
  }

  /** ACS: validate the signed SAML Response, enforce domain, establish the shared session. */
  async function handleSamlAcs(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const saml = getSamlClient()
    if (!saml) return sendJson(res, 404, { error: "saml_not_configured" })
    const saved = await readSamlRelay(req)
    clearCookie(res, SAML_RELAY_COOKIE, cfg.cookieSecure)
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
      const result = await validateSamlAcs(saml, {
        SAMLResponse: body.SAMLResponse,
        RelayState: body.RelayState,
      })
      identity = result.identity
    } catch (err) {
      cfg.log("error", "SAML assertion validation failed", err instanceof Error ? err.message : err)
      return backToApp(res, fallbackRedirect, {
        error: "sign_in_not_completed",
        error_message: "Could not verify your SAML sign-in.",
        redirect_url_complete: redirectUrlComplete,
      })
    }

    return finishSignIn(res, identity, fallbackRedirect, redirectUrlComplete)
  }

  // --- router --------------------------------------------------------------------------------

  return (req, res, next) => {
    const path = pathOf(req)
    const method = (req.method ?? "GET").toUpperCase()

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
