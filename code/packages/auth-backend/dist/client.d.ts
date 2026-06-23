import type { CreateFederatedClientOptions, MachineClaims, TokenClaims } from "./types.js";
/**
 * Verify an inbound webhook / SCIM event signature (HMAC-SHA256 over `${timestamp}.${rawBody}`).
 * Provisioning events (`user.created` / `user.deleted`, group/membership changes) drive RBAC, so
 * they must be authenticated before the host app trusts them.
 *
 * `rawBody` MUST be the exact bytes received (capture them with an express.json `verify` hook) — a
 * re-serialized JSON object will not match the producer's signed bytes.
 *
 * The signature header is compared in constant time; a timestamp outside `toleranceSeconds`
 * (default 300s) is rejected to bound replay.
 */
export declare function verifyWebhook(rawBody: string | Buffer, headers: Record<string, string | string[] | undefined>, secret: string, opts?: {
    toleranceSeconds?: number;
    signatureHeader?: string;
    timestampHeader?: string;
}): boolean;
/**
 * Paginated list envelope `PaginatedResourceResponse<T>`. The generic
 * `T` is the *array* type — list methods are typed `PaginatedResourceResponse<User[]>` — and the
 * count field is camelCase `totalCount`.
 */
export interface PaginatedResourceResponse<T> {
    data: T;
    totalCount: number;
}
/**
 * @deprecated Use {@link PaginatedResourceResponse}. Kept as an alias for existing call sites.
 * Note the field rename: list methods now return `totalCount` (Federated parity), not `total_count`.
 */
export interface ListResponse<T> {
    data: T[];
    totalCount: number;
}
export interface User {
    object: "user";
    id: string;
    primaryEmailAddress?: string;
    publicMetadata?: Record<string, unknown>;
    [k: string]: unknown;
}
export interface Session {
    object: "session";
    id: string;
    status: string;
    user_id: string;
    [k: string]: unknown;
}
export interface Organization {
    object: "organization";
    id: string;
    name: string;
    slug?: string;
    max_allowed_memberships?: number;
    [k: string]: unknown;
}
export interface OrganizationMembership {
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
export interface Invitation {
    object: "invitation";
    id: string;
    email_address: string;
    status: "pending" | "accepted" | "revoked";
    organization_id?: string | null;
    role?: string | null;
    url?: string;
    [k: string]: unknown;
}
export interface JwtTemplate {
    object: "jwt_template";
    id: string;
    name: string;
    claims: Record<string, unknown>;
    lifetime?: number;
    allowed_clock_skew?: number;
    [k: string]: unknown;
}
/** @deprecated Use {@link User}. */
export type AuthUser = User;
/** @deprecated Use {@link Session}. */
export type AuthSession = Session;
/** @deprecated Use {@link Organization}. */
export type AuthOrganization = Organization;
/** @deprecated Use {@link OrganizationMembership}. */
export type AuthMembership = OrganizationMembership;
/** @deprecated Use {@link Invitation}. */
export type AuthInvitation = Invitation;
/** @deprecated Use {@link JwtTemplate}. */
export type AuthJwtTemplate = JwtTemplate;
/** `federatedClient.users` — read and deprovision users via the Backend API. */
declare class UsersResource {
    private readonly client;
    constructor(client: AuthClient);
    getUser(userId: string): Promise<User>;
    getUserList(params?: {
        emailAddress?: string[];
        userId?: string[];
        query?: string;
        limit?: number;
        offset?: number;
        orderBy?: string;
    }): Promise<PaginatedResourceResponse<User[]>>;
    updateUserMetadata(userId: string, body: {
        publicMetadata?: Record<string, unknown>;
        privateMetadata?: Record<string, unknown>;
        unsafeMetadata?: Record<string, unknown>;
    }): Promise<User>;
    deleteUser(userId: string): Promise<User>;
}
/** `federatedClient.sessions` — inspect, verify, and immediately revoke server-side sessions. */
declare class SessionsResource {
    private readonly client;
    constructor(client: AuthClient);
    getSession(sessionId: string): Promise<Session>;
    getSessionList(params?: {
        clientId?: string;
        userId?: string;
        status?: string;
        limit?: number;
        offset?: number;
    }): Promise<PaginatedResourceResponse<Session[]>>;
    revokeSession(sessionId: string): Promise<Session>;
    /**
     * Stateful re-check for sensitive actions — a just-offboarded user fails here.
     * Signature mirrors Federated's `sessions.verifySession(sessionId, token)`; the optional `token`
     * is forwarded to the server-side verify when provided.
     */
    verifySession(sessionId: string, token?: string): Promise<Session>;
}
/** `federatedClient.organizations` — orgs/tenants and their memberships. */
declare class OrganizationsResource {
    private readonly client;
    constructor(client: AuthClient);
    getOrganization(params: {
        organizationId: string;
    } | {
        slug: string;
    }): Promise<Organization>;
    getOrganizationList(params?: {
        limit?: number;
        offset?: number;
        query?: string;
    }): Promise<PaginatedResourceResponse<Organization[]>>;
    getOrganizationMembershipList(params: {
        organizationId: string;
        limit?: number;
        offset?: number;
    }): Promise<PaginatedResourceResponse<OrganizationMembership[]>>;
    createOrganization(body: {
        name: string;
        createdBy?: string;
        slug?: string;
        publicMetadata?: Record<string, unknown>;
        maxAllowedMemberships?: number;
    }): Promise<Organization>;
    updateOrganization(organizationId: string, body: {
        name?: string;
        slug?: string;
        publicMetadata?: Record<string, unknown>;
        maxAllowedMemberships?: number;
    }): Promise<Organization>;
    deleteOrganization(organizationId: string): Promise<Organization>;
    /** Add a member with a role — the RBAC join used by JIT/SCIM provisioning. */
    createOrganizationMembership(params: {
        organizationId: string;
        userId: string;
        role: string;
    }): Promise<OrganizationMembership>;
    /** Update a member's role — e.g. when their upstream group membership changes. */
    updateOrganizationMembership(params: {
        organizationId: string;
        userId: string;
        role: string;
    }): Promise<OrganizationMembership>;
    /** Remove a member — e.g. SCIM deprovisioning or losing the gating group. */
    deleteOrganizationMembership(params: {
        organizationId: string;
        userId: string;
    }): Promise<OrganizationMembership>;
}
/** `federatedClient.invitations` — proactively grant access before first sign-in (spec §8/§12). */
declare class InvitationsResource {
    private readonly client;
    constructor(client: AuthClient);
    getInvitationList(params?: {
        status?: "pending" | "accepted" | "revoked";
        limit?: number;
        offset?: number;
    }): Promise<PaginatedResourceResponse<Invitation[]>>;
    createInvitation(body: {
        emailAddress: string;
        redirectUrl?: string;
        organizationId?: string;
        role?: string;
        publicMetadata?: Record<string, unknown>;
    }): Promise<Invitation>;
    revokeInvitation(invitationId: string): Promise<Invitation>;
}
/** `federatedClient.jwtTemplates` — named custom-claim templates for downstream tokens (spec §15). */
declare class JwtTemplatesResource {
    private readonly client;
    constructor(client: AuthClient);
    getJwtTemplateList(): Promise<PaginatedResourceResponse<JwtTemplate[]>>;
    createJwtTemplate(body: {
        name: string;
        claims: Record<string, unknown>;
        lifetime?: number;
        allowed_clock_skew?: number;
    }): Promise<JwtTemplate>;
    updateJwtTemplate(templateId: string, body: Partial<{
        name: string;
        claims: Record<string, unknown>;
        lifetime: number;
        allowed_clock_skew: number;
    }>): Promise<JwtTemplate>;
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
    private readonly jwtKey?;
    private readonly audience?;
    private readonly authorizedParties?;
    constructor(opts?: CreateFederatedClientOptions);
    /** Networkless JWT verification (JWKS in production, HS256 `AUTH_SESSION_SECRET` when embedded). */
    verifyToken(token: string): Promise<TokenClaims>;
    /** Verify a token and assert a `<feature>:<action>` permission; throws `Forbidden`. */
    requirePermission(token: string, permission: string): Promise<TokenClaims>;
    /** Verify a token and assert a role (e.g. `org:admin`); throws `Forbidden`. */
    requireRole(token: string, role: string): Promise<TokenClaims>;
    /** Verify a machine (M2M / API-key) token for server-to-server calls (spec §15). */
    verifyMachineToken(token: string): Promise<MachineClaims>;
    /** Low-level authorized request to the Backend API. */
    request<T>(path: string, init?: RequestInit): Promise<T>;
    /**
     * List request that normalizes the wire envelope to Federated's
     * {@link PaginatedResourceResponse}: `{ data, totalCount }`. The Backend API returns the count
     * as snake_case `total_count`; we map it to camelCase `totalCount` here so callers see the same
     * shape Federated's SDK returns.
     */
    requestList<T>(path: string, init?: RequestInit): Promise<PaginatedResourceResponse<T[]>>;
}
export {};
