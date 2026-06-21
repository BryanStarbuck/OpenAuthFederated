import type { CreateAuthClientOptions, MachineClaims, TokenClaims } from "./types.js";
export interface ListResponse<T> {
    data: T[];
    total_count: number;
}
export interface AuthUser {
    object: "user";
    id: string;
    primaryEmailAddress?: string;
    publicMetadata?: Record<string, unknown>;
    [k: string]: unknown;
}
export interface AuthSession {
    object: "session";
    id: string;
    status: string;
    user_id: string;
    [k: string]: unknown;
}
export interface AuthOrganization {
    object: "organization";
    id: string;
    name: string;
    slug?: string;
    max_allowed_memberships?: number;
    [k: string]: unknown;
}
export interface AuthMembership {
    object: "organization_membership";
    id: string;
    organization_id: string;
    user_id: string;
    /** The mapped role, e.g. `org:admin` (resolved from upstream groups via SCIM). */
    role: string;
    /** Permissions the role resolves to (`<feature>:<action>`). */
    permissions?: string[];
    [k: string]: unknown;
}
export interface AuthInvitation {
    object: "invitation";
    id: string;
    email_address: string;
    status: "pending" | "accepted" | "revoked";
    organization_id?: string | null;
    role?: string | null;
    url?: string;
    [k: string]: unknown;
}
export interface AuthJwtTemplate {
    object: "jwt_template";
    id: string;
    name: string;
    claims: Record<string, unknown>;
    lifetime?: number;
    allowed_clock_skew?: number;
    [k: string]: unknown;
}
/** `authClient.users` — read and deprovision users via the Backend API. */
declare class UsersResource {
    private readonly client;
    constructor(client: AuthClient);
    getUser(userId: string): Promise<AuthUser>;
    getUserList(params?: {
        emailAddress?: string[];
        limit?: number;
        offset?: number;
        orderBy?: string;
    }): Promise<ListResponse<AuthUser>>;
    updateUserMetadata(userId: string, body: {
        publicMetadata?: Record<string, unknown>;
    }): Promise<AuthUser>;
    deleteUser(userId: string): Promise<AuthUser>;
}
/** `authClient.sessions` — inspect, verify, and immediately revoke server-side sessions. */
declare class SessionsResource {
    private readonly client;
    constructor(client: AuthClient);
    getSessionList(params?: {
        userId?: string;
        status?: string;
    }): Promise<ListResponse<AuthSession>>;
    revokeSession(sessionId: string): Promise<AuthSession>;
    /** Stateful re-check for sensitive actions — a just-offboarded user fails here. */
    verifySession(sessionId: string): Promise<AuthSession>;
}
/** `authClient.organizations` — orgs/tenants and their memberships. */
declare class OrganizationsResource {
    private readonly client;
    constructor(client: AuthClient);
    getOrganization(params: {
        organizationId: string;
    }): Promise<AuthOrganization>;
    getOrganizationMembershipList(params: {
        organizationId: string;
    }): Promise<ListResponse<AuthMembership>>;
    createOrganization(body: {
        name: string;
        slug?: string;
        max_allowed_memberships?: number;
    }): Promise<AuthOrganization>;
    updateOrganization(organizationId: string, body: {
        name?: string;
        slug?: string;
        max_allowed_memberships?: number;
    }): Promise<AuthOrganization>;
    deleteOrganization(organizationId: string): Promise<AuthOrganization>;
    /** Add a member with a role — the RBAC join used by JIT/SCIM provisioning. */
    createOrganizationMembership(params: {
        organizationId: string;
        userId: string;
        role: string;
    }): Promise<AuthMembership>;
    /** Update a member's role — e.g. when their upstream group membership changes. */
    updateOrganizationMembership(params: {
        organizationId: string;
        userId: string;
        role: string;
    }): Promise<AuthMembership>;
    /** Remove a member — e.g. SCIM deprovisioning or losing the gating group. */
    deleteOrganizationMembership(params: {
        organizationId: string;
        userId: string;
    }): Promise<AuthMembership>;
}
/** `authClient.invitations` — proactively grant access before first sign-in (spec §8/§12). */
declare class InvitationsResource {
    private readonly client;
    constructor(client: AuthClient);
    getInvitationList(params?: {
        status?: "pending" | "accepted" | "revoked";
        limit?: number;
        offset?: number;
    }): Promise<ListResponse<AuthInvitation>>;
    createInvitation(body: {
        emailAddress: string;
        organizationId?: string;
        role?: string;
        publicMetadata?: Record<string, unknown>;
    }): Promise<AuthInvitation>;
    revokeInvitation(invitationId: string): Promise<AuthInvitation>;
}
/** `authClient.jwtTemplates` — named custom-claim templates for downstream tokens (spec §15). */
declare class JwtTemplatesResource {
    private readonly client;
    constructor(client: AuthClient);
    getJwtTemplateList(): Promise<ListResponse<AuthJwtTemplate>>;
    createJwtTemplate(body: {
        name: string;
        claims: Record<string, unknown>;
        lifetime?: number;
        allowed_clock_skew?: number;
    }): Promise<AuthJwtTemplate>;
    updateJwtTemplate(templateId: string, body: Partial<{
        name: string;
        claims: Record<string, unknown>;
        lifetime: number;
        allowed_clock_skew: number;
    }>): Promise<AuthJwtTemplate>;
    deleteJwtTemplate(templateId: string): Promise<{
        id: string;
        deleted: boolean;
    }>;
    /** Mint a session token shaped by a template, server-side (spec §15 / jwt-templates.mdx). */
    mintToken(params: {
        sessionId: string;
        template: string;
    }): Promise<{
        jwt: string;
    }>;
}
/**
 * Typed wrapper over the Backend REST API, authorized with the secret key. Use it from
 * trusted server code only (NestJS services, jobs, webhook/SCIM handlers).
 */
export declare class AuthClient {
    readonly users: UsersResource;
    readonly sessions: SessionsResource;
    readonly organizations: OrganizationsResource;
    readonly invitations: InvitationsResource;
    readonly jwtTemplates: JwtTemplatesResource;
    private readonly secretKey;
    private readonly apiUrl;
    private readonly issuer?;
    constructor(opts?: CreateAuthClientOptions);
    get isDevMode(): boolean;
    /** Networkless JWT verification (JWKS in prod, HS256 dev secret in dev mode). */
    verifyToken(token: string): Promise<TokenClaims>;
    /** Verify a token and assert a `<feature>:<action>` permission; throws `Forbidden`. */
    requirePermission(token: string, permission: string): Promise<TokenClaims>;
    /** Verify a token and assert a role (e.g. `org:admin`); throws `Forbidden`. */
    requireRole(token: string, role: string): Promise<TokenClaims>;
    /** Verify a machine (M2M / API-key) token for server-to-server calls (spec §15). */
    verifyMachineToken(token: string): Promise<MachineClaims>;
    /** Low-level authorized request to the Backend API. */
    request<T>(path: string, init?: RequestInit): Promise<T>;
}
export {};
