import type { IncomingMessage, ServerResponse } from "node:http";
/** The verified upstream identity returned by Google's OIDC id_token. */
export interface OidcIdentity {
    /** Google's stable subject identifier. */
    sub: string;
    email: string;
    emailVerified: boolean;
    /** Hosted-domain claim (Google Workspace). Absent for consumer gmail.com accounts. */
    hd?: string;
    name?: string;
    givenName?: string;
    familyName?: string;
    picture?: string;
}
export interface OrgMembership {
    id: string;
    organization: {
        id: string;
        name: string;
        slug?: string;
    };
    role: string;
    permissions: string[];
}
/** RBAC + organization context resolved for a verified identity. */
export interface ResolvedGrants {
    roles: string[];
    permissions: string[];
    orgId: string | null;
    memberships: OrgMembership[];
}
export interface AuthFrontendConfig {
    google: {
        clientId: string;
        clientSecret: string;
        /** Must exactly match an Authorized redirect URI in the Google Cloud OAuth client. */
        redirectUri: string;
        /** Google Workspace hosted domain to hint + enforce (`hd`). Optional. */
        hostedDomain?: string;
    };
    /** Email/`hd` domains permitted to complete sign-in. Anything else is rejected. */
    allowedDomains: string[];
    /** HS256 secret used to sign the session cookie + access tokens. MUST match AUTH_SESSION_SECRET. */
    sessionSecret: string;
    /** `iss` stamped on minted access tokens (informational in embedded mode). */
    issuer?: string;
    sessionCookieName?: string;
    sessionTtlSeconds?: number;
    accessTokenTtlSeconds?: number;
    /** Set true behind HTTPS so cookies carry the Secure attribute. */
    cookieSecure?: boolean;
    /** Map a verified identity to roles/permissions/orgs. Defaults to an internal-employee grant. */
    resolveGrants?: (identity: OidcIdentity) => ResolvedGrants;
    logger?: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void;
}
/**
 * Create the embedded Frontend API middleware. Mount it where the SDK's `frontendApi` + `/v1`
 * resolves to — e.g. `app.use('/api/v1', createAuthFrontend(cfg))` with `frontendApi: '/api'`.
 */
export declare function createAuthFrontend(config: AuthFrontendConfig): (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void) => void;
