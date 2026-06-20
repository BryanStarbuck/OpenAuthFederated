import { type AuthCore, type AuthenticateWithRedirectParams, type Connection, type PermissionCheck, type SessionSnapshot } from "./types.js";
/** Shared subscribe/emit plumbing for the external store. */
declare abstract class BaseCore implements AuthCore {
    protected snapshot: SessionSnapshot;
    private readonly listeners;
    getSnapshot(): SessionSnapshot;
    subscribe(listener: () => void): () => void;
    protected setSnapshot(next: SessionSnapshot): void;
    has(check?: PermissionCheck): boolean;
    abstract load(): Promise<void>;
    abstract connections(): Connection[];
    abstract getToken(opts?: {
        template?: string;
    }): Promise<string | null>;
    abstract authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>;
    abstract completeRedirectCallback(): Promise<{
        redirectTo: string;
    }>;
    abstract signOut(opts?: {
        redirectUrl?: string;
    }): Promise<void>;
}
/**
 * Local dev mock: no Google round-trip, no running server. Sign-in establishes a session
 * in localStorage and `getToken()` mints a short-lived HS256 JWT with the shared dev secret
 * that `@auth/backend` verifies in dev mode.
 */
export declare class DevAuthCore extends BaseCore {
    private readonly allowedDomains;
    private readonly devSharedSecret;
    private readonly issuer;
    private token;
    private tokenExp;
    constructor(allowedDomains: string[], devSharedSecret: string, issuer: string);
    connections(): Connection[];
    load(): Promise<void>;
    authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>;
    completeRedirectCallback(): Promise<{
        redirectTo: string;
    }>;
    private buildSession;
    getToken(): Promise<string | null>;
    signOut(opts?: {
        redirectUrl?: string;
    }): Promise<void>;
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
    constructor(frontendApi: string, publishableKey: string, allowedDomains: string[]);
    private base;
    private headers;
    connections(): Connection[];
    load(): Promise<void>;
    private applyClient;
    authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>;
    completeRedirectCallback(): Promise<{
        redirectTo: string;
    }>;
    getToken(): Promise<string | null>;
    signOut(opts?: {
        redirectUrl?: string;
    }): Promise<void>;
}
export {};
