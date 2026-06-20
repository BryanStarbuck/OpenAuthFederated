import { SignJWT } from "jose"
import {
  type AuthCore,
  type AuthenticateWithRedirectParams,
  type Connection,
  domainSlug,
  EMPTY_SNAPSHOT,
  hasPermission,
  type PermissionCheck,
  type SdkUser,
  type SessionSnapshot,
} from "./types.js"

const LS_SESSION = "openauthfed_dev_session_v1"
const LS_PENDING = "openauthfed_dev_pending_v1"

/** Shared subscribe/emit plumbing for the external store. */
abstract class BaseCore implements AuthCore {
  protected snapshot: SessionSnapshot = EMPTY_SNAPSHOT
  private readonly listeners = new Set<() => void>()

  getSnapshot(): SessionSnapshot {
    return this.snapshot
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  protected setSnapshot(next: SessionSnapshot): void {
    this.snapshot = next
    for (const listener of this.listeners) listener()
  }

  has(check: PermissionCheck = {}): boolean {
    const user = this.snapshot.user
    if (!user) return false
    if (check.role && !user.roles.includes(check.role)) return false
    if (check.permission && !hasPermission(user.permissions, check.permission)) return false
    return true
  }

  abstract load(): Promise<void>
  abstract connections(): Connection[]
  abstract getToken(opts?: { template?: string }): Promise<string | null>
  abstract authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>
  abstract completeRedirectCallback(): Promise<{ redirectTo: string }>
  abstract signOut(opts?: { redirectUrl?: string }): Promise<void>
}

/**
 * Local dev mock: no Google round-trip, no running server. Sign-in establishes a session
 * in localStorage and `getToken()` mints a short-lived HS256 JWT with the shared dev secret
 * that `@auth/backend` verifies in dev mode.
 */
export class DevAuthCore extends BaseCore {
  private token: string | null = null
  private tokenExp = 0

  constructor(
    private readonly allowedDomains: string[],
    private readonly devSharedSecret: string,
    private readonly issuer: string,
  ) {
    super()
  }

  connections(): Connection[] {
    return this.allowedDomains.map((domain) => ({
      id: `conn_${domainSlug(domain)}`,
      domain,
      label: domain,
    }))
  }

  async load(): Promise<void> {
    const raw = localStorage.getItem(LS_SESSION)
    if (!raw) return
    try {
      this.setSnapshot(JSON.parse(raw) as SessionSnapshot)
    } catch {
      localStorage.removeItem(LS_SESSION)
    }
  }

  async authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void> {
    const conn =
      this.connections().find((c) => c.id === params.connectionId) ?? this.connections()[0]
    localStorage.setItem(
      LS_PENDING,
      JSON.stringify({ domain: conn?.domain, redirectUrlComplete: params.redirectUrlComplete }),
    )
    window.location.assign(params.redirectUrl)
  }

  async completeRedirectCallback(): Promise<{ redirectTo: string }> {
    const raw = localStorage.getItem(LS_PENDING)
    localStorage.removeItem(LS_PENDING)
    const pending = raw ? (JSON.parse(raw) as { domain?: string; redirectUrlComplete?: string }) : null
    const domain = pending?.domain ?? this.allowedDomains[0]
    const snapshot = this.buildSession(domain)
    localStorage.setItem(LS_SESSION, JSON.stringify(snapshot))
    this.token = null
    this.setSnapshot(snapshot)
    return { redirectTo: pending?.redirectUrlComplete ?? "/" }
  }

  private buildSession(domain: string): SessionSnapshot {
    const slug = domainSlug(domain)
    const user: SdkUser = {
      id: `user_dev_${slug}`,
      firstName: "Dev",
      lastName: "Employee",
      primaryEmailAddress: `dev@${domain}`,
      // Demo RBAC: read everything, write a subset — enough to exercise <Protect> both ways.
      roles: ["employee"],
      permissions: ["*:read", "film:write", "movies:write", "tools:write"],
      hd: domain,
    }
    return {
      isSignedIn: true,
      userId: user.id,
      sessionId: `sess_dev_${slug}`,
      orgId: "org_dev_internal",
      user,
    }
  }

  async getToken(): Promise<string | null> {
    const snap = this.snapshot
    if (!snap.isSignedIn || !snap.user) return null
    const now = Math.floor(Date.now() / 1000)
    if (this.token && this.tokenExp - now > 10) return this.token

    const key = new TextEncoder().encode(this.devSharedSecret)
    const jwt = await new SignJWT({
      email: snap.user.primaryEmailAddress,
      org_id: snap.orgId,
      roles: snap.user.roles,
      permissions: snap.user.permissions,
      hd: snap.user.hd,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(snap.userId ?? "")
      .setIssuedAt(now)
      .setIssuer(this.issuer)
      .setExpirationTime(now + 60)
      .sign(key)

    this.token = jwt
    this.tokenExp = now + 60
    return jwt
  }

  async signOut(opts: { redirectUrl?: string } = {}): Promise<void> {
    localStorage.removeItem(LS_SESSION)
    this.token = null
    this.setSnapshot(EMPTY_SNAPSHOT)
    if (opts.redirectUrl) window.location.assign(opts.redirectUrl)
  }
}

/**
 * Real client against the Frontend API: rehydrates the Client, mints short-lived JWTs, and
 * runs the SSO redirect handshake. Authorized with the publishable key + rotating session
 * cookie (`credentials: 'include'`). Requires a deployed OpenAuthFederated server.
 */
export class RealAuthCore extends BaseCore {
  private activeSessionId: string | null = null

  constructor(
    private readonly frontendApi: string,
    private readonly publishableKey: string,
    private readonly allowedDomains: string[],
  ) {
    super()
  }

  private base(): string {
    return `${this.frontendApi.replace(/\/+$/, "")}/v1`
  }

  private headers(): Record<string, string> {
    return { Authorization: `Bearer ${this.publishableKey}` }
  }

  connections(): Connection[] {
    return this.allowedDomains.map((domain) => ({
      id: `conn_${domainSlug(domain)}`,
      domain,
      label: domain,
    }))
  }

  async load(): Promise<void> {
    try {
      const res = await fetch(`${this.base()}/client`, {
        headers: this.headers(),
        credentials: "include",
      })
      if (!res.ok) return
      this.applyClient(await res.json())
    } catch {
      // Frontend API unreachable — stay signed out.
    }
  }

  private applyClient(client: {
    sessions?: Array<Record<string, unknown>>
    last_active_session_id?: string | null
    org_id?: string | null
  }): void {
    const activeId = client.last_active_session_id
    const session = (client.sessions ?? []).find(
      (s) => s.id === activeId && s.status === "active",
    )
    if (!session) {
      this.activeSessionId = null
      this.setSnapshot(EMPTY_SNAPSHOT)
      return
    }
    const user = (session.user ?? {}) as Record<string, unknown>
    this.activeSessionId = session.id as string
    this.setSnapshot({
      isSignedIn: true,
      userId: session.user_id as string,
      sessionId: session.id as string,
      orgId: (client.org_id as string | undefined) ?? null,
      user: {
        id: session.user_id as string,
        firstName: user.first_name as string | undefined,
        lastName: user.last_name as string | undefined,
        primaryEmailAddress: user.primary_email_address as string | undefined,
        roles: (user.roles as string[] | undefined) ?? [],
        permissions: (user.permissions as string[] | undefined) ?? [],
        hd: user.hd as string | undefined,
      },
    })
  }

  async authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void> {
    const conn =
      this.connections().find((c) => c.id === params.connectionId) ?? this.connections()[0]
    const query = new URLSearchParams({
      strategy: params.strategy ?? "oauth_google_workspace",
      connection: conn?.id ?? "",
      redirect_url: new URL(params.redirectUrl, window.location.origin).toString(),
      redirect_url_complete: new URL(params.redirectUrlComplete, window.location.origin).toString(),
    })
    window.location.assign(`${this.base()}/sign_in/sso?${query.toString()}`)
  }

  async completeRedirectCallback(): Promise<{ redirectTo: string }> {
    await this.load()
    const params = new URLSearchParams(window.location.search)
    return { redirectTo: params.get("redirect_url_complete") ?? "/" }
  }

  async getToken(): Promise<string | null> {
    if (!this.activeSessionId) return null
    const res = await fetch(`${this.base()}/client/sessions/${this.activeSessionId}/tokens`, {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      credentials: "include",
      body: "{}",
    })
    if (!res.ok) return null
    const data = (await res.json()) as { jwt?: string }
    return data.jwt ?? null
  }

  async signOut(opts: { redirectUrl?: string } = {}): Promise<void> {
    try {
      if (this.activeSessionId) {
        await fetch(`${this.base()}/client/sessions/${this.activeSessionId}/remove`, {
          method: "POST",
          headers: this.headers(),
          credentials: "include",
        })
      }
    } catch {
      // best-effort; clear local state regardless
    }
    this.activeSessionId = null
    this.setSnapshot(EMPTY_SNAPSHOT)
    if (opts.redirectUrl) window.location.assign(opts.redirectUrl)
  }
}
