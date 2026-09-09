import type { IncomingMessage, ServerResponse } from "node:http";
import { type VerifyTokenOptions } from "./verify.js";
import type { TokenClaims } from "./types.js";
import type { SessionMembership, SessionStore } from "./session-store.js";
import { type SamlReplayStore, type SamlSpConfig } from "./saml.js";
/**
 * A verified upstream identity. Named for its first producer (Google's OIDC id_token); it is now
 * also what the SAML ACS and the X sign-in path hand to {@link finishSignIn}, so that every strategy
 * produces one identical session.
 */
export interface OidcIdentity {
    /** The provider's stable subject identifier (Google `sub`, SAML nameID, X numeric user id). */
    sub: string;
    email: string;
    emailVerified: boolean;
    /** Hosted-domain claim (Google Workspace). Absent for consumer gmail.com accounts. */
    hd?: string;
    name?: string;
    givenName?: string;
    familyName?: string;
    picture?: string;
    /**
     * WHICH STRATEGY VERIFIED THIS HUMAN. `finishSignIn` needs it because the admission rules are not
     * the same for all three: `requireHostedDomain` asks for a Google Workspace `hd` claim, which is a
     * thing only Google has. Optional, and absent means `google` — so every existing call site keeps
     * its exact behaviour.
     */
    provider?: "google" | "saml" | "x";
    /** The X handle, without the `@`. Set on the X path only; nothing else populates it. */
    username?: string;
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
/**
 * An X (Twitter) OAuth 2.0 sign-in connection. `strategy` mirrors Federated's `oauth_x`.
 *
 * ⚠️ THE APPLICATION MUST BE REGISTERED AS A CONFIDENTIAL CLIENT ("Web App, Automated App or Bot"
 * in the X developer portal). A "Native App" is a PUBLIC client: X issues it no secret, and the
 * token exchange below authenticates the client with HTTP Basic.
 */
export interface XConnectionConfig {
    strategy: "oauth_x";
    /**
     * X OAuth 2.0 client id. **Optional** (sign-in fails closed with a 503 if absent). Sourced and
     * passed in by the embedding app, exactly as {@link GoogleConnectionConfig.clientId} is; the
     * library reads no environment variable and no app-specific file.
     */
    clientId?: string;
    /** X OAuth 2.0 client secret. **Optional** — supplied the same way as {@link clientId}. */
    clientSecret?: string;
    /** Must exactly match a Callback URI registered in the X app's *User authentication settings*. */
    redirectUri: string;
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
export type FederatedConnectionConfig = GoogleConnectionConfig | SamlConnectionConfig | XConnectionConfig;
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
     * Admit an X sign-in on the strength of its `confirmed_email` alone, when
     * {@link requireHostedDomain} is on. Defaults to false — FAIL CLOSED.
     *
     * WHY THIS FLAG HAS TO EXIST. `requireHostedDomain` asks for a Google Workspace `hd` claim, and
     * its whole point is that membership of a Workspace is a stronger fact than an address that
     * merely ends in the right domain. X has no equivalent: `confirmed_email` says X delivered mail
     * to that address and nothing more. So an X sign-in CANNOT satisfy a hosted-domain requirement,
     * and silently exempting it would quietly downgrade the control the deployment asked for on
     * every account it protects. The operator says "I know, and the email is enough for X" here, in
     * one place, or X sign-in is refused with that reason. Mirrors
     * {@link samlTrustAssertedEmailVerified}, which exists for the same kind of reason.
     *
     * The {@link allowedDomains} allowlist still applies either way; this flag never bypasses it.
     */
    xTrustConfirmedEmail?: boolean;
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
    /**
     * Admit a SAML sign-in under {@link requireHostedDomain} when the IdP asserts no hosted-domain
     * attribute. Defaults to false — FAIL CLOSED.
     *
     * `requireHostedDomain` asks for a Google Workspace `hd` claim, which is a Google concept. A SAML
     * IdP may assert an equivalent attribute (`hd` / `hostedDomain` / `domain`), and when it does the
     * assertion satisfies the requirement on its own — this flag is not needed. Many IdPs assert
     * nothing of the kind while nonetheless being scoped to exactly one verified company directory;
     * an operator says so HERE, in one place, rather than the library quietly exempting every SAML
     * sign-in from a control the deployment explicitly asked for. Mirrors {@link xTrustConfirmedEmail}.
     *
     * {@link allowedDomains} still applies either way; this flag never bypasses it.
     */
    samlSatisfiesHostedDomain?: boolean;
    /**
     * Scope the minted user id to the strategy that authenticated it — `user_google_<sub>`,
     * `user_saml_<nameID>`, `user_x_<id>` — instead of the flat `user_<sub>`. Defaults to **false**
     * for back-compat.
     *
     * WHY IT MATTERS: without it, three strategies write into one identifier namespace. Google `sub`
     * and X account id are both numeric strings, and a SAML `persistent` NameID is an
     * operator-chosen opaque string, so nothing structurally prevents two different humans at two
     * different IdPs from resolving to the same `user_…`. It also means one human who signs in via
     * SAML on Monday and Google on Tuesday is silently two users with two grant sets.
     *
     * TURNING THIS ON IS A MIGRATION: every existing user id changes, so anything the host app
     * persisted against the old id must be migrated with it. New deployments should set it true.
     */
    namespaceUserIds?: boolean;
    /**
     * What a THROWN {@link revalidateGrants} does (only when `reresolveGrantsEverySeconds` is set).
     *   - `"keep"` (DEFAULT): keep the existing grants for this mint and retry next window —
     *     availability first, matching the historical behaviour.
     *   - `"closed"`: treat the failure as a loss of authorization and sign the session out.
     *
     * The default is the riskier one on purpose (it is the pre-existing behaviour), but note what it
     * means: if the resolver fails BECAUSE the upstream directory is unreachable — exactly when
     * someone may have just been offboarded — deprovision latency silently reverts to the full
     * session lifetime. Deployments that would rather sign a user out than carry stale grants through
     * a directory outage set `"closed"`.
     */
    revalidateFailMode?: "keep" | "closed";
    /**
     * Timeout, in milliseconds, for every outbound call this middleware makes to an upstream IdP
     * (Google's token endpoint, X's token and user endpoints). Defaults to 20000. A hung upstream
     * otherwise holds the request, its socket and its closure open with the human watching a spinner.
     */
    upstreamTimeoutMs?: number;
    /**
     * Per-request gate, consulted BEFORE any handler runs. Return false (or a rejected/false promise)
     * to answer `429` and stop.
     *
     * The library cannot own a rate limiter — it is mounted middleware with no store and no view of
     * the deployment — but it must expose the seam, because the routes that most need one are the
     * ones it owns: `/saml/acs` does XML signature work before it can cheaply refuse anything, and
     * `/oauth_callback/x` makes two outbound calls to X per unauthenticated request, which makes this
     * library an amplifier against a third party's limits. Every refusal also writes a log line, so an
     * unauthenticated flood is a log-volume DoS.
     *
     * A hook that THROWS is treated as a refusal (429): a limiter outage is not a reason to drop the
     * limit on the auth endpoints.
     */
    rateLimit?: (ctx: RateLimitContext) => boolean | Promise<boolean>;
}
/** What {@link FederatedFrontendConfig.rateLimit} is told about the request it is gating. */
export interface RateLimitContext {
    /** Upper-cased HTTP method. */
    method: string;
    /** Path within the mount point, e.g. `/client/sessions/sess_1/tokens`. */
    path: string;
    /** The raw request, for a limiter that keys on a header or the socket address. */
    req: IncomingMessage;
}
/**
 * @deprecated Use {@link FederatedFrontendConfig}. Alias retained so older imports resolve unchanged.
 */
export type AuthFrontendConfig = FederatedFrontendConfig;
/**
 * Who is signed in on a request — the PUBLIC, read-only view of a session.
 *
 * This is the shape {@link FederatedFrontend.readBrowserSession} hands back to a host app. It is
 * deliberately a subset of the library-internal `SessionRecord`: the bookkeeping field
 * `grantsResolvedAt` exists only to schedule grant re-resolution inside the middleware, so it is not
 * part of the contract a host app may depend on.
 *
 * A host app that server-renders a page (a consent screen, an admin view) must be able to answer
 * "who is this?" from the SAME code path the Frontend API's `GET /client` uses. Reading and
 * verifying the session cookie by hand in the host app is how the two halves drift apart — and a
 * hand-rolled read is exactly the place where revocation, expiry and inactivity checks get skipped.
 *
 * That answer is also DELIBERATELY not derivable outside this module. The session cookie is signed
 * with an HKDF subkey (`oaf:session`), not the master `sessionSecret`, precisely so that a leak of
 * the secret used for access tokens cannot forge a session cookie — which also means
 * `verifyToken()` cannot verify one, and a host that tried would have to re-derive the subkey and
 * keep that derivation in step with this file forever. One implementation, exposed once, is the
 * alternative to that drift.
 */
export interface BrowserSession {
    /** Session id (the `sid` claim); the handle the /client/sessions/:id routes address. */
    sid: string;
    /** Stable user id (`user_<hash>`). */
    userId: string;
    /** Verified email address of the signed-in human. */
    email: string;
    name?: string;
    firstName?: string;
    lastName?: string;
    /** Google Workspace hosted domain, when the upstream identity carried one. */
    hd?: string;
    roles: string[];
    permissions: string[];
    /** Active organization, or null when the session has not selected one. */
    orgId: string | null;
    memberships: OrgMembership[];
    /** When the human last proved their identity upstream (epoch seconds). */
    lastVerifiedAt: number;
}
/**
 * What {@link createFederatedFrontend} returns: the mountable Node/Express middleware, plus the
 * session reader the host app needs for its own server-rendered routes.
 *
 * It stays CALLABLE with the exact signature it always had — `app.use("/api/v1", frontend)` is
 * unchanged — so adding the method is not a breaking change for any existing embedder. The method
 * hangs off the function rather than the function becoming an object because every current call
 * site passes the return value straight to `app.use`.
 */
export interface FederatedFrontend {
    (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void): void;
    /**
     * Resolve the session on a request, or `null` when signed out.
     *
     * Runs the identical path `GET /client` runs — cookie signature verification, then, when a
     * `sessionStore` is configured, the durable record's revoked / expired / inactive checks and the
     * configured fail mode. So a session that was signed out, offboarded or timed out reads as
     * signed-OUT here too, and a server-rendered page cannot disagree with the SPA about who is
     * signed in.
     *
     * Read-only: it never mints, refreshes, touches or clears anything, and writes nothing to the
     * response — safe to call from any route, including a GET that must stay side-effect free.
     */
    readBrowserSession(req: IncomingMessage): Promise<BrowserSession | null>;
    /**
     * Verify an access token THIS frontend minted, using THIS frontend's secret, issuer and audience.
     *
     * Prefer it over the module-level `verifyToken()` in any process that mounts more than one
     * frontend. `configureEmbeddedVerification()` writes one process-global variable, so a second
     * `createFederatedFrontend()` would otherwise repoint the global at the second app — quietly
     * verifying app A's requests against app B's secret and destroying the per-app `aud` isolation
     * the config promises. This method reads no global state, so two apps in one process each keep
     * their own verifier.
     */
    verifyToken(token: string, opts?: VerifyTokenOptions): Promise<TokenClaims>;
}
/**
 * Alias for {@link FederatedFrontend}, kept because the callable-plus-method shape reads as a
 * "middleware" at the call sites that mount it. Both names describe the same value.
 */
export type FederatedFrontendMiddleware = FederatedFrontend;
/**
 * Create the embedded Frontend API middleware. Mount it where the SDK's `frontendApi` + `/v1`
 * resolves to — e.g. `app.use('/api/v1', createFederatedFrontend(cfg))` with `frontendApi: '/api'`.
 *
 * Pass connections the Federated-idiomatic way:
 *   `createFederatedFrontend({ connections: [{ strategy: 'oauth_google', clientId, clientSecret,
 *     redirectUri }], allowedDomains, sessionSecret })`
 */
export declare function createFederatedFrontend(config: FederatedFrontendConfig): FederatedFrontend;
/**
 * @deprecated Use {@link createFederatedFrontend}. Alias retained so existing
 * `createAuthFrontend({ google: { ... } })` call sites keep working unchanged (the deprecated
 * `google`/`saml` shorthand is still accepted).
 */
export declare const createAuthFrontend: typeof createFederatedFrontend;
