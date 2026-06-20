import type { CreateAuthClientOptions, TokenClaims } from "./types.js"
import { requirePermission } from "./permissions.js"
import { verifyToken } from "./verify.js"

export interface ListResponse<T> {
  data: T[]
  total_count: number
}

export interface AuthUser {
  object: "user"
  id: string
  primaryEmailAddress?: string
  publicMetadata?: Record<string, unknown>
  [k: string]: unknown
}

export interface AuthSession {
  object: "session"
  id: string
  status: string
  user_id: string
  [k: string]: unknown
}

export interface AuthOrganization {
  object: "organization"
  id: string
  name: string
  slug?: string
  [k: string]: unknown
}

/** `authClient.users` — read and deprovision users via the Backend API. */
class UsersResource {
  constructor(private readonly client: AuthClient) {}

  getUser(userId: string): Promise<AuthUser> {
    return this.client.request(`/users/${userId}`)
  }

  getUserList(
    params: {
      emailAddress?: string[]
      limit?: number
      offset?: number
      orderBy?: string
    } = {},
  ): Promise<ListResponse<AuthUser>> {
    const q = new URLSearchParams()
    if (params.limit != null) q.set("limit", String(params.limit))
    if (params.offset != null) q.set("offset", String(params.offset))
    if (params.orderBy) q.set("order_by", params.orderBy)
    for (const email of params.emailAddress ?? []) q.append("email_address", email)
    const qs = q.toString()
    return this.client.request(`/users${qs ? `?${qs}` : ""}`)
  }

  updateUserMetadata(
    userId: string,
    body: { publicMetadata?: Record<string, unknown> },
  ): Promise<AuthUser> {
    return this.client.request(`/users/${userId}/metadata`, {
      method: "PATCH",
      body: JSON.stringify(body),
    })
  }

  deleteUser(userId: string): Promise<AuthUser> {
    return this.client.request(`/users/${userId}`, { method: "DELETE" })
  }
}

/** `authClient.sessions` — inspect, verify, and immediately revoke server-side sessions. */
class SessionsResource {
  constructor(private readonly client: AuthClient) {}

  getSessionList(
    params: { userId?: string; status?: string } = {},
  ): Promise<ListResponse<AuthSession>> {
    const q = new URLSearchParams()
    if (params.userId) q.set("user_id", params.userId)
    if (params.status) q.set("status", params.status)
    const qs = q.toString()
    return this.client.request(`/sessions${qs ? `?${qs}` : ""}`)
  }

  revokeSession(sessionId: string): Promise<AuthSession> {
    return this.client.request(`/sessions/${sessionId}/revoke`, { method: "POST" })
  }

  /** Stateful re-check for sensitive actions — a just-offboarded user fails here. */
  verifySession(sessionId: string): Promise<AuthSession> {
    return this.client.request(`/sessions/${sessionId}/verify`, { method: "POST" })
  }
}

/** `authClient.organizations` — orgs/tenants and their memberships. */
class OrganizationsResource {
  constructor(private readonly client: AuthClient) {}

  getOrganization(params: { organizationId: string }): Promise<AuthOrganization> {
    return this.client.request(`/organizations/${params.organizationId}`)
  }

  getOrganizationMembershipList(params: {
    organizationId: string
  }): Promise<ListResponse<Record<string, unknown>>> {
    return this.client.request(`/organizations/${params.organizationId}/memberships`)
  }

  createOrganization(body: { name: string; slug?: string }): Promise<AuthOrganization> {
    return this.client.request(`/organizations`, {
      method: "POST",
      body: JSON.stringify(body),
    })
  }
}

/**
 * Typed wrapper over the Backend REST API, authorized with the secret key. Use it from
 * trusted server code only (NestJS services, jobs, webhook/SCIM handlers).
 */
export class AuthClient {
  readonly users: UsersResource = new UsersResource(this)
  readonly sessions: SessionsResource = new SessionsResource(this)
  readonly organizations: OrganizationsResource = new OrganizationsResource(this)

  private readonly secretKey: string
  private readonly apiUrl: string
  private readonly issuer?: string

  constructor(opts: CreateAuthClientOptions = {}) {
    this.secretKey = opts.secretKey ?? process.env.AUTH_SECRET_KEY ?? ""
    this.apiUrl = opts.apiUrl ?? process.env.AUTH_BACKEND_API ?? "https://api.localhost/v1"
    this.issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER
  }

  get isDevMode(): boolean {
    return process.env.AUTH_DEV_MODE === "true"
  }

  /** Networkless JWT verification (JWKS in prod, HS256 dev secret in dev mode). */
  verifyToken(token: string): Promise<TokenClaims> {
    return verifyToken(token, { issuer: this.issuer })
  }

  /** Verify a token and assert a `<feature>:<action>` permission; throws `Forbidden`. */
  requirePermission(token: string, permission: string): Promise<TokenClaims> {
    return requirePermission(token, permission)
  }

  /** Low-level authorized request to the Backend API. */
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    if (this.isDevMode) {
      throw new Error(
        `@auth/backend: ${init.method ?? "GET"} ${path} is unavailable in dev mode ` +
          `(no live OpenAuthFederated server). Only verifyToken() is supported in dev.`,
      )
    }
    const res = await fetch(`${this.apiUrl.replace(/\/+$/, "")}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/json",
        ...(init.headers ?? {}),
      },
    })
    if (!res.ok) {
      throw new Error(`@auth/backend: ${init.method ?? "GET"} ${path} → ${res.status}`)
    }
    return (await res.json()) as T
  }
}
