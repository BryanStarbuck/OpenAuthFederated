import type { IncomingMessage, ServerResponse } from "node:http";
import type { SessionMembership, SessionStore } from "./session-store.js";
import { type SamlReplayStore, type SamlSpConfig } from "./saml.js";
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
/**
 * One organization membership. Aliased to {@link SessionMembership} (same shape) so the session
 * store and the session model share a single type and can never drift apart.
 */
export type OrgMembership = SessionMembership;
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
    /**
     * Namespace for ALL cookies this middleware sets — the session cookie, the OAuth `state`
     * cookie, and the SAML relay cookie. Defaults to `"oaf"`, giving the historical names
     * `oaf_session` / `oaf_oauth_state` / `oaf_saml_relay`.
     *
     * Browsers do NOT isolate cookies by port, so two apps served from different ports on the
     * same host (e.g. two localhost dev servers) share one cookie jar. If both use the default
     * prefix, each app's `oaf_session` overwrites the other's and switching tabs logs you out of
     * the first. Give each app a DISTINCT prefix (e.g. `"oaf_app1"`, `"oaf_app2"`) so their
     * cookies coexist. `sessionCookieName`, if set, still wins for the session cookie specifically.
     */
    cookiePrefix?: string;
    sessionCookieName?: string;
    /**
     * Session **maximum lifetime** in seconds — Clerk's "Maximum lifetime" knob. The absolute ceiling
     * after which the user must sign in again, regardless of activity. Defaults to ~4 months. The
     * session is a sliding window (re-issued on each token mint), so active use rolls the cookie
     * forward up to this ceiling. (Name kept as `sessionTtlSeconds` for back-compat.)
     */
    sessionTtlSeconds?: number;
    accessTokenTtlSeconds?: number;
    /**
     * Session **inactivity timeout** in seconds — Clerk's "Inactivity timeout" knob. If a session
     * goes this long without a token refresh / touch, it is treated as signed out. `0` (the default)
     * disables it: combined with the long maximum lifetime, a user stays signed in "forever" as long
     * as they return within the maximum lifetime. Only enforced when a {@link sessionStore} is set
     * (the store is where `lastActiveAt` is durably tracked).
     */
    inactivityTimeoutSeconds?: number;
    /**
     * Durable server-side session store (the stateful half of the Clerk model). When provided, each
     * sign-in writes a {@link StoredSession}; reads validate it (revocation, max-lifetime, inactivity)
     * and the record survives app restarts. When omitted, the library is purely stateless (the signed
     * cookie is the whole session) — backward compatible. See `session-store.ts` / {@link FileSessionStore}.
     */
    sessionStore?: SessionStore;
    /**
     * Carry the Secure attribute on all cookies. Defaults to **true** (production-safe). Set false
     * ONLY for local http development; never ship a non-Secure session cookie to production.
     */
    cookieSecure?: boolean;
    /**
     * SameSite for the session cookie. Defaults to `Lax` (the session is not a cross-site POST).
     * The SAML relay cookie always uses `None` (the cross-site ACS POST needs it) and therefore
     * requires `cookieSecure: true`.
     */
    sessionCookieSameSite?: "Lax" | "Strict";
    /**
     * Per-app audience (`aud`) stamped on minted session/access tokens and required on verify. Binds
     * a token to this app so two apps sharing a secret/prefix cannot accept each other's tokens.
     */
    audience?: string;
    /**
     * Require a present, allowlisted Google Workspace hosted-domain (`hd`) claim. When true, an
     * identity lacking `hd` (e.g. a consumer gmail.com account) is rejected even if its email domain
     * is on {@link allowedDomains} — the email domain is no longer accepted as a substitute for
     * Workspace membership. Defaults to false (back-compat).
     */
    requireHostedDomain?: boolean;
    /**
     * Allowlist of origins (e.g. `https://app.example.com`) a post-sign-in redirect may target.
     * Absolute redirect URLs not on this list are rejected and rewritten to a same-origin relative
     * path. When omitted, ALL absolute redirect targets are refused (same-origin relative only).
     */
    allowedRedirectOrigins?: string[];
    /**
     * Trust the IdP-asserted SAML email as verified when no explicit attribute is present. Forwarded
     * to {@link validateSamlAcs}; defaults to false (fail closed).
     */
    samlTrustAssertedEmailVerified?: boolean;
    /**
     * Replay store for consumed SAML assertion ids (one-time-use enforcement). Defaults to an
     * in-process {@link InMemorySamlReplayStore}; supply a shared store for multi-process SAML.
     */
    samlReplayStore?: SamlReplayStore;
    /**
     * Add security response headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy,
     * X-Frame-Options) to every response. Defaults to true.
     */
    securityHeaders?: boolean;
    /** CORS allowlist for the auth endpoints. When set, matching Origins get credentialed CORS. */
    allowedCorsOrigins?: string[];
    /** Map a verified identity to roles/permissions/orgs. Defaults to a least-privilege grant. */
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
