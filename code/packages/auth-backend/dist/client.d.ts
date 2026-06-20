import type { CreateAuthClientOptions, TokenClaims } from "./types.js";
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
    }): Promise<ListResponse<Record<string, unknown>>>;
    createOrganization(body: {
        name: string;
        slug?: string;
    }): Promise<AuthOrganization>;
}
/**
 * Typed wrapper over the Backend REST API, authorized with the secret key. Use it from
 * trusted server code only (NestJS services, jobs, webhook/SCIM handlers).
 */
export declare class AuthClient {
    readonly users: UsersResource;
    readonly sessions: SessionsResource;
    readonly organizations: OrganizationsResource;
    private readonly secretKey;
    private readonly apiUrl;
    private readonly issuer?;
    constructor(opts?: CreateAuthClientOptions);
    get isDevMode(): boolean;
    /** Networkless JWT verification (JWKS in prod, HS256 dev secret in dev mode). */
    verifyToken(token: string): Promise<TokenClaims>;
    /** Verify a token and assert a `<feature>:<action>` permission; throws `Forbidden`. */
    requirePermission(token: string, permission: string): Promise<TokenClaims>;
    /** Low-level authorized request to the Backend API. */
    request<T>(path: string, init?: RequestInit): Promise<T>;
}
export {};
