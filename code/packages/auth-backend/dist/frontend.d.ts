import type { IncomingMessage, ServerResponse } from "node:http";
import { type VerifyTokenOptions } from "./verify.js";
import type { TokenClaims } from "./types.js";
import { type ActionIdentity, type AdmissionActions, type AdmissionErrorCode, type AdmissionMessage, type AdmissionPhase, type AdmissionResult, type AdmissionUsers, type Identifier, type IdentityProvider, type Live, type Restrictions, type SignUpMode } from "./admission.js";
import { type EmailConnectionConfig } from "./email-auth.js";
import type { SessionMembership, SessionStore } from "./session-store.js";
import { type OidcIdentity } from "./oauth-providers.js";
import { type SamlReplayStore, type SamlSpConfig } from "./saml.js";
/**
 * In-process Frontend API — the embedded counterpart to a deployed OpenAuthFederated server.
 *
 * `createAuthFrontend()` returns an Express/Node-compatible middleware that the host app mounts
 * (e.g. `app.use('/api/v1', createAuthFrontend(cfg))`). It implements exactly the endpoints the
 * `@auth/react` `RealAuthCore` calls, so a SPA gets a *real* Google, X or SAML sign-in with no
 * separate auth server process:
 *
 *   GET  /sign_in/sso                         → 302 to Google's OAuth 2.0 / OIDC authorize URL
 *   GET  /sign_in/sso?strategy=x              → 302 to X's OAuth 2.0 authorize URL (PKCE, no OIDC)
 *   GET  /oauth_callback/x                    → code→token exchange, then GET /2/users/me for the
 *                                               identity, then the same finishSignIn() tail
 *   GET  /oauth_callback                      → code→token exchange, id_token + hd verification,
 *                                               establishes the session cookie, 302 back to the SPA
 *   GET  /environment                         → instance configuration (hosted-IdP-style, secret-free)
 *   GET  /client                              → rehydrate the current session (signed-out = empty)
 *   POST /client/sessions/:id/tokens          → mint a short-lived access JWT for API calls
 *   POST /client/sessions/:id/tokens/:tmpl    → templated token mint (same path, tagged)
 *   POST /client/sessions/:id/touch           → set the session's active organization
 *   GET  /client/sessions/:id/reverify        → step-up: refresh the session's verified-at time
 *   POST /client/sessions/:id/remove          → sign out (clear the session cookie)
 *
 * Everything runs in the host's own process. The human is authenticated by the provider (for
 * Google: a real OIDC round-trip, a real id_token signature check against Google's JWKS, a real
 * `email_verified` check). WHO is admitted is the embedding app's stated policy (see admission.ts);
 * this file executes it. The app *session* and the short-lived access tokens are signed with a single
 * in-process HS256 secret (`sessionSecret`) — the same secret `verifyToken()` checks in embedded
 * mode — so there is no JWKS endpoint and no second service to run.
 */
/** @see oauth-providers.ts — re-exported here so existing `import { OidcIdentity } from "./frontend.js"` keeps working. */
export type { OidcIdentity };
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
    /**
     * A fixed Google `hd` HINT sent on every authorize request (pre-selects that organization in
     * Google's account chooser). A hint only: admission is decided by {@link requireHostedDomain} /
     * {@link allowedHostedDomains} and the app's policy, never by this value.
     */
    hostedDomain?: string;
    /** Refuse an identity without a verified hd. Never a default. */
    requireHostedDomain?: boolean;
    /** When !== undefined: hd must be present and in this list ([] => nobody). Implies requireHostedDomain. */
    allowedHostedDomains?: string[];
    /**
     * Domains a client may pick as the hd hint via `?connection=conn_<slug>`. Legacy default: the
     * deprecated top-level `allowedDomains`. New-API default: `[]` (a client-chosen hint is ignored
     * and no hd is sent).
     */
    hostedDomainHints?: string[];
    /** Publish the hint domains in `/environment` `user_settings.connections`. Default false. */
    publishHintDomains?: boolean;
    /** Button label. Default "Google". */
    label?: string;
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
    /** Button label. Default "X". An X identity always requires a confirmed email. */
    label?: string;
}
/** A SAML 2.0 sign-in connection. `strategy` mirrors Federated's enterprise SSO vocabulary. */
export type SamlConnectionConfig = {
    strategy: "saml";
    /** Refuse an identity whose assertion carries no corroborated hosted-domain attribute. */
    requireHostedDomain?: boolean;
    /** When !== undefined: the corroborated hd must be in this list ([] => nobody). Implies requireHostedDomain. */
    allowedHostedDomains?: string[];
    /** Button label. Default "SSO". */
    label?: string;
} & SamlSpConfig;
/**
 * One configured sign-in connection. Mirrors Federated's connection/strategy model
 * (`oauth_google`, SAML) so credentials are passed by API in a Federated-idiomatic shape rather than
 * via a provider-specific block.
 */
export type FederatedConnectionConfig = GoogleConnectionConfig | SamlConnectionConfig | XConnectionConfig | EmailConnectionConfig;
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
    /**
     * @deprecated Use {@link signUpMode} + {@link restrictions} + {@link allowlistIdentifiers}
     * (`domains.map(d => "*@" + d)`) and, for the account-chooser hint, the Google connection's
     * `hostedDomainHints`.
     *
     * LEGACY GATE. When this key is PRESENT (it must then be an array of strings, or construction
     * throws {@link OafConfigError}), email/`hd` domains not on the list are refused — unless
     * {@link allowAnyDomain} is on. `[]` refuses everyone. Its presence also seeds the defaults for
     * `hostedDomainHints`, publishing `allowed_domains` in `/environment` and
     * `organization_settings.enabled`, unless those are set explicitly. Optional now (it used to be
     * required); omit it and state a policy with the new API instead.
     */
    allowedDomains?: string[];
    /**
     * @deprecated Omit the allowlist and use `signUpMode: "public"`.
     *
     * Admit a VERIFIED email on ANY domain, skipping the {@link allowedDomains} check. Defaults to
     * false — FAIL CLOSED.
     *
     * A public app's users arrive with every mailbox provider there is, and enumerating them is not
     * a control.
     *
     * WHAT IT DOES NOT LOOSEN. The provider must still assert a VERIFIED email — an identity without
     * one is refused exactly as before. {@link requireHostedDomain} still applies on its own terms,
     * so an operator who wants "any Workspace, any domain" can set both. And `allowedDomains` keeps
     * its other job: deciding which `hd` a connection may pre-select. Authorization (who is an admin,
     * what a user may do) is the host app's job and is untouched by this flag.
     */
    allowAnyDomain?: boolean;
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
     * after which the user must sign in again, regardless of activity. Defaults to 7 days. The
     * session is a sliding window (re-issued on each token mint), so active use rolls the cookie
     * forward up to this ceiling. (Name kept as `sessionTtlSeconds` for back-compat.)
     */
    sessionTtlSeconds?: number;
    accessTokenTtlSeconds?: number;
    /**
     * Session **inactivity timeout** in seconds — the "inactivity timeout" knob. If a session
     * goes this long without a token refresh / touch, it is treated as signed out. Defaults to 12
     * hours; `0` disables it (a user then stays signed in as long as they return within the maximum
     * lifetime). Only enforced when a {@link sessionStore} is set
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
     * @deprecated Use the per-connection `requireHostedDomain` / `allowedHostedDomains` on the
     * Google and SAML connections.
     *
     * LEGACY GATE. Require a present, allowlisted hosted-domain (`hd`) claim. When true, an identity
     * lacking `hd` (e.g. a consumer mailbox account) is rejected even if its email domain is on
     * {@link allowedDomains} — the email domain is no longer accepted as a substitute for
     * organization membership. Defaults to false (back-compat).
     */
    requireHostedDomain?: boolean;
    /**
     * Allowlist of origins (e.g. `https://app.example.com`) a post-sign-in redirect may target.
     * Absolute redirect URLs not on this list are rejected and rewritten to a same-origin relative
     * path. When omitted, ALL absolute redirect targets are refused (same-origin relative only).
     */
    allowedRedirectOrigins?: string[];
    /**
     * @deprecated HAS NO EFFECT (it never did). Set `trustAssertedEmailVerified` on the SAML
     * connection instead. A WARN is logged once per process when this key is present.
     */
    samlTrustAssertedEmailVerified?: boolean;
    /**
     * @deprecated Not needed with the new admission API (the legacy hosted-domain gate is the only
     * thing it exempts X from).
     *
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
    /**
     * Map a verified, ADMITTED identity to roles/permissions/orgs. Defaults to a least-privilege grant.
     * May be async (it is awaited). It runs after admission and cannot refuse; refuse with
     * {@link actions} instead.
     */
    resolveGrants?: (identity: OidcIdentity) => ResolvedGrants | Promise<ResolvedGrants>;
    logger?: (level: "info" | "warn" | "error", message: string, meta?: unknown) => void;
    /**
     * @deprecated Not needed with the new admission API (the legacy hosted-domain gate is the only
     * thing it exempts SAML from).
     *
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
     * Who may CREATE an account. `public`: any verified identity that passes the lists.
     * `restricted`: a new identity needs an allowlist match (a standing invitation) or
     * `users.lookup(...).invited`. `waitlist`: no new identity is admitted (requires {@link users}).
     * When no policy is stated at all the library defaults to `public` and WARNs once per process
     * (or throws, with {@link requirePolicy}).
     */
    signUpMode?: Live<SignUpMode>;
    /** Which lists are engaged. See {@link Restrictions}. */
    restrictions?: Live<Restrictions>;
    /** Allowlist identifiers (`ann@example.com`, `*@example.com`, `*@*.example.com`). Never published. */
    allowlistIdentifiers?: Live<readonly Identifier[]>;
    /** Blocklist identifiers, same grammar. The more specific match wins over the allowlist. Never published. */
    blocklistIdentifiers?: Live<readonly Identifier[]>;
    /** App callbacks that may Allow or Deny each attempt. A Deny mints nothing. */
    actions?: AdmissionActions;
    /** Optional app-owned user directory, so returning users can be told apart from new ones. */
    users?: AdmissionUsers;
    /** Override the default (neutral) copy for any refusal code. */
    messages?: Partial<Record<AdmissionErrorCode, AdmissionMessage>>;
    /** Throw at construction unless signUpMode, restrictions or a legacy key is present. Default false (WARN once). */
    requirePolicy?: boolean;
    /** What the unauthenticated `/environment` endpoint publishes. */
    environment?: {
        /** display_config.allowed_domains. New-API default false; legacy default true. An explicit value wins in mixed mode. */
        publishAllowedDomains?: boolean;
        /** organization_settings.enabled. New-API default false; legacy default true. An explicit value wins. */
        organizationsEnabled?: boolean;
    };
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
    /** Which strategy authenticated this session. Absent on very old sessions. */
    provider?: IdentityProvider;
    /** The upstream subject exactly as the provider asserted it. Absent on very old sessions. */
    providerSub?: string;
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
    /**
     * Run the full admission pipeline on a synthetic identity WITHOUT minting anything (no session,
     * no cookie, no store write, no `resolveGrants` call). For an app's boot self-test and for
     * tests. `isSignUp` (when given, including `null`) replaces `users.lookup`; `phase: "reverify"`
     * runs the reverify subset (no sign-up steps).
     */
    evaluateAdmission(identity: ActionIdentity, opts?: {
        isSignUp?: boolean | null;
        phase?: AdmissionPhase;
    }): Promise<AdmissionResult>;
    /**
     * Revoke every session of one user (by email) in the configured `sessionStore`. Throws when no
     * store is configured or the store has no `revokeAllForUser`. Returns the count revoked.
     * Cookie-only (store-less) sessions cannot be revoked server-side.
     */
    revokeUserSessions(email: string): Promise<number>;
}
/**
 * Alias for {@link FederatedFrontend}, kept because the callable-plus-method shape reads as a
 * "middleware" at the call sites that mount it. Both names describe the same value.
 */
export type FederatedFrontendMiddleware = FederatedFrontend;
export declare function createFederatedFrontend(config: FederatedFrontendConfig): FederatedFrontend;
/**
 * @deprecated Use {@link createFederatedFrontend}. Alias retained so existing
 * `createAuthFrontend({ google: { ... } })` call sites keep working unchanged (the deprecated
 * `google`/`saml` shorthand is still accepted).
 */
export declare const createAuthFrontend: typeof createFederatedFrontend;
