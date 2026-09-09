import { type AuthCore, type AuthenticateWithRedirectParams, type Connection, type LoadState, type PermissionCheck, type RedirectCallbackResult, type SessionSnapshot } from "./types.js";
/**
 * Shared subscribe/emit plumbing for the external store. Exported so a consuming app can build its
 * OWN {@link AuthCore} (e.g. a localhost-only dev core) on top of it and inject it via
 * `<FederatedProvider core={...}>`. OpenAuthFederated itself ships only {@link RealAuthCore} — it
 * provides no dev/mock core of its own.
 */
export declare abstract class BaseCore implements AuthCore {
    protected snapshot: SessionSnapshot;
    protected state: LoadState;
    private readonly listeners;
    getSnapshot(): SessionSnapshot;
    loadState(): LoadState;
    protected setState(next: LoadState): void;
    subscribe(listener: () => void): () => void;
    protected setSnapshot(next: SessionSnapshot): void;
    /** The permissions/roles that apply *right now*, given the active organization. */
    protected activeGrants(): {
        roles: string[];
        permissions: string[];
    };
    has(check?: PermissionCheck): boolean;
    isRecentlyVerified(maxAgeSeconds: number): boolean;
    protected readActiveOrg(): string | null;
    protected writeActiveOrg(orgId: string | null): void;
    setActiveOrg(orgId: string | null): Promise<void>;
    abstract load(): Promise<void>;
    abstract connections(): Connection[];
    abstract getToken(opts?: {
        template?: string;
    }): Promise<string | null>;
    abstract authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>;
    abstract completeRedirectCallback(): Promise<RedirectCallbackResult>;
    abstract signOut(opts?: {
        redirectUrl?: string;
    }): Promise<void>;
    abstract reverify(): Promise<void>;
}
/**
 * Narrow a caller-supplied post-sign-in destination to one that cannot leave this origin.
 *
 * `redirect_url_complete` arrives on the callback URL's query string, so it is attacker-supplied by
 * construction: anyone who can get a user to click a crafted sign-in link controls it. The value is
 * handed straight to `window.location.assign`, which makes an unchecked one a classic
 * post-authentication open redirect — the most convincing kind, because the victim really did just
 * sign in successfully before being sent somewhere else.
 *
 * It is checked HERE, in the library, rather than in each app's callback page, for the reason the
 * whole embedded design rests on: the app that forgets is the app that has the hole, and every app
 * that consumes this SDK reaches this line. The server's own `safeRedirectTarget` guards
 * `redirect_url`; this guards its sibling, which the server only ever passes through.
 *
 * Allowed: a root-relative path (`/oauth/cli/authorize?…`), and an absolute URL on this exact
 * origin. Everything else — another origin, a protocol-relative `//evil.com`, a `javascript:` URL,
 * an unparseable string — collapses to `/`. Protocol-relative is called out because it is the one
 * that reads as a path to a human and as an origin to `new URL`.
 */
export declare function sameOriginRedirect(target: string | null | undefined): string;
/**
 * Real client against the Frontend API: rehydrates the Client, mints short-lived JWTs, and
 * runs the SSO redirect handshake. Authorized with the publishable key + rotating session
 * cookie (`credentials: 'include'`). Requires a deployed OpenAuthFederated server.
 */
export declare class RealAuthCore extends BaseCore {
    private readonly frontendApi;
    private readonly publishableKey;
    private activeSessionId;
    private token;
    private tokenExp;
    private inflight;
    private autoRefresh;
    private refreshTimer;
    /**
     * The connection list, built ONCE.
     *
     * It is derived entirely from a constructor argument, so it can never change — but `connections()`
     * used to rebuild it with `.map` on every call, and the provider calls it inside a `useMemo` that
     * lists `snapshot` as a dependency. Every auth state change therefore handed every consumer of the
     * auth context a brand-new array with brand-new objects, re-rendering `<SignIn>`, `<SignInButton>`
     * and `<SignUpButton>` for a value that had not moved. Frozen so a stable reference cannot become
     * a shared mutable one.
     */
    private readonly connectionList;
    constructor(frontendApi: string, publishableKey: string, allowedDomains: string[]);
    private base;
    private headers;
    connections(): Connection[];
    private static readonly LOAD_BACKOFF_MS;
    load(): Promise<void>;
    private loadWithRetry;
    private parseMemberships;
    private applyClient;
    authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>;
    completeRedirectCallback(): Promise<RedirectCallbackResult>;
    getToken(opts?: {
        template?: string;
    }): Promise<string | null>;
    /**
     * Enable proactive access-token refresh. Idempotent. After each mint the SDK schedules a re-mint
     * shortly before the token's own `exp`, so an active tab keeps a valid Bearer without ever
     * surfacing a 401. Each mint also rolls the session cookie forward (server side), so an active tab
     * both keeps its Bearer AND slides its session ceiling. Call once after wiring the core.
     */
    enableAutoRefresh(): void;
    /** Stop proactive refresh and cancel any pending timer (e.g. on teardown). */
    disableAutoRefresh(): void;
    /** Force a fresh mint now, bypassing the cache. Returns the new token (or null if signed out). */
    refresh(): Promise<string | null>;
    private cancelRefreshTimer;
    /** Arm a single timer to re-mint ~30s before `exp` (never sooner than 5s out). */
    private scheduleRefresh;
    /** POST to the Frontend API to mint an access JWT. Caches the default (non-templated) token. */
    private mintToken;
    /** Drop the cached access token so the next getToken() re-mints with current grants. */
    private clearTokenCache;
    setActiveOrg(orgId: string | null): Promise<void>;
    reverify(): Promise<void>;
    signOut(opts?: {
        redirectUrl?: string;
    }): Promise<void>;
}
