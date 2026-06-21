import type { CreateAuthClientOptions, MachineClaims, TokenClaims } from "./types.js"
import { requirePermission, requireRole } from "./permissions.js"
import { verifyMachineToken, verifyToken } from "./verify.js"

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
  max_allowed_memberships?: number
  [k: string]: unknown
}

export interface AuthMembership {
  object: "organization_membership"
  id: string
  organization_id: string
  user_id: string
  /** The mapped role, e.g. `org:admin` (resolved from upstream groups via SCIM). */
  role: string
  /** Permissions the role resolves to (`<feature>:<action>`). */
  permissions?: string[]
  [k: string]: unknown
}

export interface AuthInvitation {
  object: "invitation"
  id: string
  email_address: string
  status: "pending" | "accepted" | "revoked"
  organization_id?: string | null
  role?: string | null
  url?: string
  [k: string]: unknown
}

export interface AuthJwtTemplate {
  object: "jwt_template"
  id: string
  name: string
  claims: Record<string, unknown>
  lifetime?: number
  allowed_clock_skew?: number
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
  }): Promise<ListResponse<AuthMembership>> {
    return this.client.request(`/organizations/${params.organizationId}/memberships`)
  }

  createOrganization(body: {
    name: string
    slug?: string
    max_allowed_memberships?: number
  }): Promise<AuthOrganization> {
    return this.client.request(`/organizations`, {
      method: "POST",
      body: JSON.stringify(body),
    })
  }

  updateOrganization(
    organizationId: string,
    body: { name?: string; slug?: string; max_allowed_memberships?: number },
  ): Promise<AuthOrganization> {
    return this.client.request(`/organizations/${organizationId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    })
  }

  deleteOrganization(organizationId: string): Promise<AuthOrganization> {
    return this.client.request(`/organizations/${organizationId}`, { method: "DELETE" })
  }

  /** Add a member with a role — the RBAC join used by JIT/SCIM provisioning. */
  createOrganizationMembership(params: {
    organizationId: string
    userId: string
    role: string
  }): Promise<AuthMembership> {
    return this.client.request(`/organizations/${params.organizationId}/memberships`, {
      method: "POST",
      body: JSON.stringify({ user_id: params.userId, role: params.role }),
    })
  }

  /** Update a member's role — e.g. when their upstream group membership changes. */
  updateOrganizationMembership(params: {
    organizationId: string
    userId: string
    role: string
  }): Promise<AuthMembership> {
    return this.client.request(
      `/organizations/${params.organizationId}/memberships/${params.userId}`,
      { method: "PATCH", body: JSON.stringify({ role: params.role }) },
    )
  }

  /** Remove a member — e.g. SCIM deprovisioning or losing the gating group. */
  deleteOrganizationMembership(params: {
    organizationId: string
    userId: string
  }): Promise<AuthMembership> {
    return this.client.request(
      `/organizations/${params.organizationId}/memberships/${params.userId}`,
      { method: "DELETE" },
    )
  }
}

/** `authClient.invitations` — proactively grant access before first sign-in (spec §8/§12). */
class InvitationsResource {
  constructor(private readonly client: AuthClient) {}

  getInvitationList(
    params: { status?: "pending" | "accepted" | "revoked"; limit?: number; offset?: number } = {},
  ): Promise<ListResponse<AuthInvitation>> {
    const q = new URLSearchParams()
    if (params.status) q.set("status", params.status)
    if (params.limit != null) q.set("limit", String(params.limit))
    if (params.offset != null) q.set("offset", String(params.offset))
    const qs = q.toString()
    return this.client.request(`/invitations${qs ? `?${qs}` : ""}`)
  }

  createInvitation(body: {
    emailAddress: string
    organizationId?: string
    role?: string
    publicMetadata?: Record<string, unknown>
  }): Promise<AuthInvitation> {
    return this.client.request(`/invitations`, {
      method: "POST",
      body: JSON.stringify({
        email_address: body.emailAddress,
        organization_id: body.organizationId,
        role: body.role,
        public_metadata: body.publicMetadata,
      }),
    })
  }

  revokeInvitation(invitationId: string): Promise<AuthInvitation> {
    return this.client.request(`/invitations/${invitationId}/revoke`, { method: "POST" })
  }
}

/** `authClient.jwtTemplates` — named custom-claim templates for downstream tokens (spec §15). */
class JwtTemplatesResource {
  constructor(private readonly client: AuthClient) {}

  getJwtTemplateList(): Promise<ListResponse<AuthJwtTemplate>> {
    return this.client.request(`/jwt_templates`)
  }

  createJwtTemplate(body: {
    name: string
    claims: Record<string, unknown>
    lifetime?: number
    allowed_clock_skew?: number
  }): Promise<AuthJwtTemplate> {
    return this.client.request(`/jwt_templates`, {
      method: "POST",
      body: JSON.stringify(body),
    })
  }

  updateJwtTemplate(
    templateId: string,
    body: Partial<{
      name: string
      claims: Record<string, unknown>
      lifetime: number
      allowed_clock_skew: number
    }>,
  ): Promise<AuthJwtTemplate> {
    return this.client.request(`/jwt_templates/${templateId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    })
  }

  deleteJwtTemplate(templateId: string): Promise<{ id: string; deleted: boolean }> {
    return this.client.request(`/jwt_templates/${templateId}`, { method: "DELETE" })
  }

  /** Mint a session token shaped by a template, server-side (spec §15 / jwt-templates.mdx). */
  mintToken(params: { sessionId: string; template: string }): Promise<{ jwt: string }> {
    return this.client.request(`/tokens`, {
      method: "POST",
      body: JSON.stringify({ session_id: params.sessionId, template: params.template }),
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
  readonly invitations: InvitationsResource = new InvitationsResource(this)
  readonly jwtTemplates: JwtTemplatesResource = new JwtTemplatesResource(this)

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

  /** Verify a token and assert a role (e.g. `org:admin`); throws `Forbidden`. */
  requireRole(token: string, role: string): Promise<TokenClaims> {
    return requireRole(token, role)
  }

  /** Verify a machine (M2M / API-key) token for server-to-server calls (spec §15). */
  verifyMachineToken(token: string): Promise<MachineClaims> {
    return verifyMachineToken(token, { issuer: this.issuer })
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
