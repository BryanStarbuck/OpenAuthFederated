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
/** A Google OAuth (OIDC) sign-in connection. `strategy` mirrors Federated's `oauth_google`. */
export interface GoogleConnectionConfig {
    strategy: "oauth_google";
    /**
     * Google OAuth Web-client id. **Optional.** When omitted/empty, the library falls back to the
     * generic `GOOGLE_CLIENT_ID` environment variable (see `credentials.ts`). The embedding app
     * owns where the value is sourced from (its own secrets file/env) and passes it in here; the
     * library never reads an app-specific credentials file. Never hardcode the value or commit it.
     */
    clientId?: string;
    /**
     * Google OAuth Web-client secret. **Optional** — resolved the same way as {@link clientId}
     * (explicit value here, then the generic `GOOGLE_CLIENT_SECRET` env var). Never hardcode the
     * value or commit it.
     */
    clientSecret?: string;
    /** Must exactly match an Authorized redirect URI in the Google Cloud OAuth client. */
    redirectUri: string;
    /** Google Workspace hosted domain to hint + enforce (`hd`). Optional. */
    hostedDomain?: string;
}
/** A SAML 2.0 sign-in connection. `strategy` mirrors Federated's enterprise SSO vocabulary. */
export type SamlConnectionConfig = {
    strategy: "saml";
} & SamlSpConfig;
/**
 * One configured sign-in connection. Mirrors Federated's connection/strategy model
 * (`oauth_google`, SAML) so credentials are passed by API in a Federated-idiomatic shape rather than
 * via a provider-specific block.
 */
export type FederatedConnectionConfig = GoogleConnectionConfig | SamlConnectionConfig;
/** Shape of the legacy Google block (`google: { ... }`) accepted as deprecated shorthand. */
export interface LegacyGoogleConfig {
    clientId?: string;
    clientSecret?: string;
    redirectUri: string;
    hostedDomain?: string;
}
export interface FederatedFrontendConfig {
    /**
     * The sign-in connections this app offers. The Federated-idiomatic way to pass OAuth/SAML
     * credentials by API:
     *   `connections: [{ strategy: 'oauth_google', clientId, clientSecret, redirectUri }]`
     * At most one connection per strategy is used (the first of each wins).
     */
    connections?: FederatedConnectionConfig[];
    /**
     * @deprecated Use {@link connections} with `{ strategy: 'oauth_google', ... }`. Retained as a
     * shorthand so existing `createAuthFrontend({ google: { ... } })` call sites keep working.
     */
    google?: LegacyGoogleConfig;
    /**
     * @deprecated Use {@link connections} with `{ strategy: 'saml', ... }`. Retained shorthand.
     * When present and `enabled`, the middleware serves the SAML SP routes (`/saml/metadata`,
     * `/saml/login`, `/saml/acs`) and `/sign_in/sso?strategy=saml`. A SAML sign-in establishes the
     * *same* session as the OIDC path. All SAML XML handling lives in `saml.ts`.
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
 * @deprecated Use {@link FederatedFrontendConfig}. Alias retained so older imports resolve unchanged.
 */
export type AuthFrontendConfig = FederatedFrontendConfig;
/**
 * Create the embedded Frontend API middleware. Mount it where the SDK's `frontendApi` + `/v1`
 * resolves to — e.g. `app.use('/api/v1', createFederatedFrontend(cfg))` with `frontendApi: '/api'`.
 *
 * Pass connections the Federated-idiomatic way:
 *   `createFederatedFrontend({ connections: [{ strategy: 'oauth_google', clientId, clientSecret,
 *     redirectUri }], allowedDomains, sessionSecret })`
 */
export declare function createFederatedFrontend(config: FederatedFrontendConfig): (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void) => void;
/**
 * @deprecated Use {@link createFederatedFrontend}. Alias retained so existing
 * `createAuthFrontend({ google: { ... } })` call sites keep working unchanged (the deprecated
 * `google`/`saml` shorthand is still accepted).
 */
export declare const createAuthFrontend: typeof createFederatedFrontend;
