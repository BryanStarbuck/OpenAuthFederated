/** Claims carried by an OpenAuthFederated short-lived JWT access token. */
export interface TokenClaims {
    /** Subject — the user id (`user_…`). */
    sub: string;
    email?: string;
    /** Active organization/tenant id (`org_…`). */
    org_id?: string;
    /** Mapped RBAC roles, derived from upstream Google Workspace groups. */
    roles?: string[];
    /** Mapped `<feature>:<action>` permissions, derived from groups. */
    permissions?: string[];
    /** Upstream hosted-domain claim (Google Workspace `hd`). */
    hd?: string;
    iss?: string;
    aud?: string | string[];
    exp?: number;
    iat?: number;
    [claim: string]: unknown;
}
export interface CreateAuthClientOptions {
    /** Defaults to process.env.AUTH_SECRET_KEY. */
    secretKey?: string;
    /** Backend API base, e.g. https://api.<domain>/v1. Defaults to AUTH_BACKEND_API. */
    apiUrl?: string;
    /** Expected token issuer for JWKS verification. Defaults to AUTH_JWT_ISSUER. */
    issuer?: string;
}
