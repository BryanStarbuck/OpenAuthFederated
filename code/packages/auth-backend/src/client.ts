import type { CreateFederatedClientOptions, MachineClaims, TokenClaims } from "./types.js"
import { requirePermission, requireRole } from "./permissions.js"
import { verifyMachineToken, verifyToken } from "./verify.js"

/**
 * Paginated list envelope `PaginatedResourceResponse<T>`. The generic
 * `T` is the *array* type — list methods are typed `PaginatedResourceResponse<User[]>` — and the
 * count field is camelCase `totalCount`.
 */
export interface PaginatedResourceResponse<T> {
  data: T
  totalCount: number
}

/**
 * @deprecated Use {@link PaginatedResourceResponse}. Kept as an alias for existing call sites.
 * Note the field rename: list methods now return `totalCount` (Federated parity), not `total_count`.
 */
export interface ListResponse<T> {
  data: T[]
  totalCount: number
}

export interface User {
  object: "user"
  id: string
  primaryEmailAddress?: string
  publicMetadata?: Record<string, unknown>
  [k: string]: unknown
}

export interface Session {
  object: "session"
  id: string
  status: string
  user_id: string
  [k: string]: unknown
}

export interface Organization {
  object: "organization"
  id: string
  name: string
  slug?: string
  max_allowed_memberships?: number
  [k: string]: unknown
}

export interface OrganizationMembership {
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

export interface Invitation {
  object: "invitation"
  id: string
  email_address: string
  status: "pending" | "accepted" | "revoked"
  organization_id?: string | null
  role?: string | null
  url?: string
  [k: string]: unknown
}

export interface JwtTemplate {
  object: "jwt_template"
  id: string
  name: string
  claims: Record<string, unknown>
  lifetime?: number
  allowed_clock_skew?: number
  [k: string]: unknown
}

/* ----------------------------------------------------------------------------------------------
 * Deprecated type aliases — the resource types were renamed to Federated's names (User, Session,
 * Organization, OrganizationMembership, Invitation, JwtTemplate). The `Auth*` names remain as
 * aliases so existing imports keep compiling.
 * -------------------------------------------------------------------------------------------- */
/** @deprecated Use {@link User}. */
export type AuthUser = User
/** @deprecated Use {@link Session}. */
export type AuthSession = Session
/** @deprecated Use {@link Organization}. */
export type AuthOrganization = Organization
/** @deprecated Use {@link OrganizationMembership}. */
export type AuthMembership = OrganizationMembership
/** @deprecated Use {@link Invitation}. */
export type AuthInvitation = Invitation
/** @deprecated Use {@link JwtTemplate}. */
export type AuthJwtTemplate = JwtTemplate

/** `federatedClient.users` — read and deprovision users via the Backend API. */
class UsersResource {
  constructor(private readonly client: AuthClient) {}

  getUser(userId: string): Promise<User> {
    return this.client.request(`/users/${userId}`)
  }

  getUserList(
    params: {
      emailAddress?: string[]
      userId?: string[]
      query?: string
      limit?: number
      offset?: number
      orderBy?: string
    } = {},
  ): Promise<PaginatedResourceResponse<User[]>> {
    const q = new URLSearchParams()
    if (params.limit != null) q.set("limit", String(params.limit))
    if (params.offset != null) q.set("offset", String(params.offset))
    if (params.orderBy) q.set("order_by", params.orderBy)
    if (params.query) q.set("query", params.query)
    for (const email of params.emailAddress ?? []) q.append("email_address", email)
    for (const id of params.userId ?? []) q.append("user_id", id)
    const qs = q.toString()
    return this.client.requestList<User>(`/users${qs ? `?${qs}` : ""}`)
  }

  updateUserMetadata(
    userId: string,
    body: {
      publicMetadata?: Record<string, unknown>
      privateMetadata?: Record<string, unknown>
      unsafeMetadata?: Record<string, unknown>
    },
  ): Promise<User> {
    return this.client.request(`/users/${userId}/metadata`, {
      method: "PATCH",
      body: JSON.stringify({
        public_metadata: body.publicMetadata,
        private_metadata: body.privateMetadata,
        unsafe_metadata: body.unsafeMetadata,
      }),
    })
  }

  deleteUser(userId: string): Promise<User> {
    return this.client.request(`/users/${userId}`, { method: "DELETE" })
  }
}

/** `federatedClient.sessions` — inspect, verify, and immediately revoke server-side sessions. */
class SessionsResource {
  constructor(private readonly client: AuthClient) {}

  getSession(sessionId: string): Promise<Session> {
    return this.client.request(`/sessions/${sessionId}`)
  }

  getSessionList(
    params: { clientId?: string; userId?: string; status?: string; limit?: number; offset?: number } = {},
  ): Promise<PaginatedResourceResponse<Session[]>> {
    const q = new URLSearchParams()
    if (params.clientId) q.set("client_id", params.clientId)
    if (params.userId) q.set("user_id", params.userId)
    if (params.status) q.set("status", params.status)
    if (params.limit != null) q.set("limit", String(params.limit))
    if (params.offset != null) q.set("offset", String(params.offset))
    const qs = q.toString()
    return this.client.requestList<Session>(`/sessions${qs ? `?${qs}` : ""}`)
  }

  revokeSession(sessionId: string): Promise<Session> {
    return this.client.request(`/sessions/${sessionId}/revoke`, { method: "POST" })
  }

  /**
   * Stateful re-check for sensitive actions — a just-offboarded user fails here.
   * Signature mirrors Federated's `sessions.verifySession(sessionId, token)`; the optional `token`
   * is forwarded to the server-side verify when provided.
   */
  verifySession(sessionId: string, token?: string): Promise<Session> {
    return this.client.request(`/sessions/${sessionId}/verify`, {
      method: "POST",
      body: token ? JSON.stringify({ token }) : undefined,
    })
  }
}

/** `federatedClient.organizations` — orgs/tenants and their memberships. */
class OrganizationsResource {
  constructor(private readonly client: AuthClient) {}

  getOrganization(params: { organizationId: string } | { slug: string }): Promise<Organization> {
    const id = "organizationId" in params ? params.organizationId : params.slug
    return this.client.request(`/organizations/${id}`)
  }

  getOrganizationList(
    params: { limit?: number; offset?: number; query?: string } = {},
  ): Promise<PaginatedResourceResponse<Organization[]>> {
    const q = new URLSearchParams()
    if (params.limit != null) q.set("limit", String(params.limit))
    if (params.offset != null) q.set("offset", String(params.offset))
    if (params.query) q.set("query", params.query)
    const qs = q.toString()
    return this.client.requestList<Organization>(`/organizations${qs ? `?${qs}` : ""}`)
  }

  getOrganizationMembershipList(params: {
    organizationId: string
    limit?: number
    offset?: number
  }): Promise<PaginatedResourceResponse<OrganizationMembership[]>> {
    const q = new URLSearchParams()
    if (params.limit != null) q.set("limit", String(params.limit))
    if (params.offset != null) q.set("offset", String(params.offset))
    const qs = q.toString()
    return this.client.requestList<OrganizationMembership>(
      `/organizations/${params.organizationId}/memberships${qs ? `?${qs}` : ""}`,
    )
  }

  createOrganization(body: {
    name: string
    createdBy?: string
    slug?: string
    publicMetadata?: Record<string, unknown>
    maxAllowedMemberships?: number
  }): Promise<Organization> {
    return this.client.request(`/organizations`, {
      method: "POST",
      body: JSON.stringify({
        name: body.name,
        created_by: body.createdBy,
        slug: body.slug,
        public_metadata: body.publicMetadata,
        max_allowed_memberships: body.maxAllowedMemberships,
      }),
    })
  }

  updateOrganization(
    organizationId: string,
    body: {
      name?: string
      slug?: string
      publicMetadata?: Record<string, unknown>
      maxAllowedMemberships?: number
    },
  ): Promise<Organization> {
    return this.client.request(`/organizations/${organizationId}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: body.name,
        slug: body.slug,
        public_metadata: body.publicMetadata,
        max_allowed_memberships: body.maxAllowedMemberships,
      }),
    })
  }

  deleteOrganization(organizationId: string): Promise<Organization> {
    return this.client.request(`/organizations/${organizationId}`, { method: "DELETE" })
  }

  /** Add a member with a role — the RBAC join used by JIT/SCIM provisioning. */
  createOrganizationMembership(params: {
    organizationId: string
    userId: string
    role: string
  }): Promise<OrganizationMembership> {
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
  }): Promise<OrganizationMembership> {
    return this.client.request(
      `/organizations/${params.organizationId}/memberships/${params.userId}`,
      { method: "PATCH", body: JSON.stringify({ role: params.role }) },
    )
  }

  /** Remove a member — e.g. SCIM deprovisioning or losing the gating group. */
  deleteOrganizationMembership(params: {
    organizationId: string
    userId: string
  }): Promise<OrganizationMembership> {
    return this.client.request(
      `/organizations/${params.organizationId}/memberships/${params.userId}`,
      { method: "DELETE" },
    )
  }
}

/** `federatedClient.invitations` — proactively grant access before first sign-in (spec §8/§12). */
class InvitationsResource {
  constructor(private readonly client: AuthClient) {}

  getInvitationList(
    params: { status?: "pending" | "accepted" | "revoked"; limit?: number; offset?: number } = {},
  ): Promise<PaginatedResourceResponse<Invitation[]>> {
    const q = new URLSearchParams()
    if (params.status) q.set("status", params.status)
    if (params.limit != null) q.set("limit", String(params.limit))
    if (params.offset != null) q.set("offset", String(params.offset))
    const qs = q.toString()
    return this.client.requestList<Invitation>(`/invitations${qs ? `?${qs}` : ""}`)
  }

  createInvitation(body: {
    emailAddress: string
    redirectUrl?: string
    organizationId?: string
    role?: string
    publicMetadata?: Record<string, unknown>
  }): Promise<Invitation> {
    return this.client.request(`/invitations`, {
      method: "POST",
      body: JSON.stringify({
        email_address: body.emailAddress,
        redirect_url: body.redirectUrl,
        organization_id: body.organizationId,
        role: body.role,
        public_metadata: body.publicMetadata,
      }),
    })
  }

  revokeInvitation(invitationId: string): Promise<Invitation> {
    return this.client.request(`/invitations/${invitationId}/revoke`, { method: "POST" })
  }
}

/** `federatedClient.jwtTemplates` — named custom-claim templates for downstream tokens (spec §15). */
class JwtTemplatesResource {
  constructor(private readonly client: AuthClient) {}

  getJwtTemplateList(): Promise<PaginatedResourceResponse<JwtTemplate[]>> {
    return this.client.requestList<JwtTemplate>(`/jwt_templates`)
  }

  createJwtTemplate(body: {
    name: string
    claims: Record<string, unknown>
    lifetime?: number
    allowed_clock_skew?: number
  }): Promise<JwtTemplate> {
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
  ): Promise<JwtTemplate> {
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
  private readonly jwtKey?: string
  private readonly audience?: string | string[]
  private readonly authorizedParties?: string[]

  constructor(opts: CreateFederatedClientOptions = {}) {
    this.secretKey = opts.secretKey ?? process.env.AUTH_SECRET_KEY ?? ""
    this.apiUrl = opts.apiUrl ?? process.env.AUTH_BACKEND_API ?? "https://api.localhost/v1"
    this.issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER
    this.jwtKey = opts.jwtKey
    this.audience = opts.audience
    this.authorizedParties = opts.authorizedParties
  }

  get isDevMode(): boolean {
    return process.env.AUTH_DEV_MODE === "true"
  }

  /** Networkless JWT verification (JWKS in prod, HS256 dev/embedded secret otherwise). */
  verifyToken(token: string): Promise<TokenClaims> {
    return verifyToken(token, {
      issuer: this.issuer,
      jwtKey: this.jwtKey,
      audience: this.audience,
      authorizedParties: this.authorizedParties,
    })
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

  /**
   * List request that normalizes the wire envelope to Federated's
   * {@link PaginatedResourceResponse}: `{ data, totalCount }`. The Backend API returns the count
   * as snake_case `total_count`; we map it to camelCase `totalCount` here so callers see the same
   * shape Federated's SDK returns.
   */
  async requestList<T>(path: string, init: RequestInit = {}): Promise<PaginatedResourceResponse<T[]>> {
    const raw = await this.request<{
      data?: T[]
      total_count?: number
      totalCount?: number
    }>(path, init)
    return {
      data: raw.data ?? [],
      totalCount: raw.totalCount ?? raw.total_count ?? (raw.data?.length ?? 0),
    }
  }
}
