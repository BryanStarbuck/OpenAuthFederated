import type { IncomingMessage, ServerResponse } from "node:http";
import { type SamlSpConfig } from "./saml.js";
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
        /**
         * Google OAuth Web-client id. **Optional.** When omitted/empty, the library resolves it from
         * `GOOGLE_CLIENT_ID`, then from the out-of-repo credentials file
         * (`~/.credentials/app_internal_act3.json` → `act3_internal_app.google.clientId`). See
         * `credentials.ts`. Never hardcode the value or commit it.
         */
        clientId?: string;
        /**
         * Google OAuth Web-client secret. **Optional** — resolved the same way as {@link clientId}
         * (`GOOGLE_CLIENT_SECRET`, then `act3_internal_app.google.clientSecret` in the credentials
         * file). Never hardcode the value or commit it.
         */
        clientSecret?: string;
        /** Must exactly match an Authorized redirect URI in the Google Cloud OAuth client. */
        redirectUri: string;
        /** Google Workspace hosted domain to hint + enforce (`hd`). Optional. */
        hostedDomain?: string;
        /**
         * Override the out-of-repo credentials-file path used when `clientId`/`clientSecret` are not
         * supplied here or via env. Defaults to `APP_INTERNAL_ACT3_CREDENTIALS_FILE`, then
         * `~/.credentials/app_internal_act3.json`.
         */
        credentialsFile?: string;
    };
    /**
     * Optional SAML 2.0 Service Provider configuration. When present and `enabled`, the same
     * middleware also serves the SAML SP routes (`/saml/metadata`, `/saml/login`, `/saml/acs`)
     * and `/sign_in/sso?strategy=saml`. A SAML sign-in establishes the *same* session as the OIDC
     * path. All SAML XML handling lives in `saml.ts`; the host app only supplies this config.
     */
    saml?: SamlSpConfig;
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
