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
     * Google OAuth Web-client id. **Optional** (sign-in fails closed with a 503 if absent). The
     * embedding app owns where the value is sourced from (its own secrets file/config) and passes it
     * in here; the library reads no environment variable and no app-specific file. Never hardcode or commit it.
     */
    clientId?: string;
    /**
     * Google OAuth Web-client secret. **Optional** — supplied the same way as {@link clientId}
     * (an explicit value here, sourced by the embedding app). Never hardcode the value or commit it.
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
    /**
     * HS256 secret used to sign the session cookie + access tokens. The SAME value is used to verify
     * those tokens (this function calls configureEmbeddedVerification with it). Supplied by the caller.
     */
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
     * Session **maximum lifetime** in seconds — the "maximum lifetime" knob. The absolute ceiling
     * after which the user must sign in again, regardless of activity. Defaults to ~4 months. The
     * session is a sliding window (re-issued on each token mint), so active use rolls the cookie
     * forward up to this ceiling. (Name kept as `sessionTtlSeconds` for back-compat.)
     */
    sessionTtlSeconds?: number;
    accessTokenTtlSeconds?: number;
    /**
     * Session **inactivity timeout** in seconds — the "inactivity timeout" knob. If a session
     * goes this long without a token refresh / touch, it is treated as signed out. `0` (the default)
     * disables it: combined with the long maximum lifetime, a user stays signed in "forever" as long
     * as they return within the maximum lifetime. Only enforced when a {@link sessionStore} is set
     * (the store is where `lastActiveAt` is durably tracked).
     */
    inactivityTimeoutSeconds?: number;
    /**
     * One-time migration opt-in: when true, a valid session cookie whose durable record is missing
     * re-creates that record from the cookie (instead of failing closed). Off by default. Supplied by
     * the API caller — never read from the environment.
     */
    sessionStoreMigrate?: boolean;
    /**
     * Durable server-side session store (the stateful half of the session model). When provided, each
     * sign-in writes a {@link StoredSession}; reads validate it (revocation, max-lifetime, inactivity)
     * and the record survives app restarts. When omitted, the library is purely stateless (the signed
     * cookie is the whole session) — backward compatible. See `session-store.ts` / {@link FileSessionStore}.
     */
    sessionStore?: SessionStore;
    /**
     * What a session-store READ error does (stateful mode). The store enforces revocation,
     * max-lifetime, and inactivity; if `store.get()` throws we must decide whether to trust the signed
     * cookie or treat the request as signed out.
     *   - `"closed"` (DEFAULT): fail closed — a store error returns null (signed out). Revocation is
     *     never silently bypassed, including under an attacker-induced store fault.
     *   - `"cookie-grace"`: fall back to the signed cookie on a store error (availability over the
     *     store-side checks). Use only for availability-sensitive apps that accept the documented risk
     *     that a revoked/aged-out session can slip through during a store outage.
     */
    sessionStoreFailMode?: "closed" | "cookie-grace";
    /**
     * Upper bound (seconds) on how old a session cookie may be for {@link sessionStoreMigrate} to
     * re-create a missing durable record from it. Migration trusts the cookie, so a lost tombstone
     * could otherwise resurrect a revoked session from an old-but-valid cookie. Only cookies issued
     * within this window are migrated; older ones fail closed. Defaults to 600 (10 minutes).
     */
    sessionStoreMigrateMaxAgeSeconds?: number;
    /**
     * Bound deprovision latency: re-resolve grants on token mint when the session's grants are older
     * than this many seconds. Grants are otherwise baked in at sign-in and reused until the session
     * ends, so an upstream demotion/offboard only takes effect at session end. When set (> 0), each
     * mint whose grants exceed this age re-runs {@link revalidateGrants} (or {@link resolveGrants})
     * from the session's identity; if the user no longer qualifies (a null result) the session is
     * treated as signed out. Additive and **off by default** (0/undefined = never re-resolve).
     */
    reresolveGrantsEverySeconds?: number;
    /**
     * Optional lighter-weight re-resolution used by {@link reresolveGrantsEverySeconds}. Given the
     * identity reconstructed from the current session, return fresh grants, or `null` to force
     * sign-out (e.g. the user was removed from the mapped upstream group). Defaults to
     * {@link resolveGrants} when omitted.
     */
    revalidateGrants?: (identity: OidcIdentity) => ResolvedGrants | null | Promise<ResolvedGrants | null>;
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
     * Per-app audience (`aud`) stamped on minted session/access tokens AND enforced on verify. This
     * function bridges the value into `configureEmbeddedVerification`, so `verifyToken()` requires the
     * same `aud` by default (not only when each verify call passes it) — a token minted for another
     * app (different `aud`) is rejected here.
     *
     * IMPORTANT: `audience` is defense-in-depth, NOT the primary isolation control. The primary
     * control is a DISTINCT per-app `sessionSecret`: two apps that share a secret can forge each
     * other's tokens regardless of `aud`. Give every app its own strong `sessionSecret` (and, when
     * setting `audience`, also a distinct {@link issuer} — two apps that both omit `issuer` share the
     * default `"openauthfederated"`). A construction-time warning fires if `audience` is set without a
     * distinct `issuer`.
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
