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
 * Real client against the Frontend API: rehydrates the Client, mints short-lived JWTs, and
 * runs the SSO redirect handshake. Authorized with the publishable key + rotating session
 * cookie (`credentials: 'include'`). Requires a deployed OpenAuthFederated server.
 */
export declare class RealAuthCore extends BaseCore {
    private readonly frontendApi;
    private readonly publishableKey;
    private readonly allowedDomains;
    private activeSessionId;
    private token;
    private tokenExp;
    private inflight;
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
