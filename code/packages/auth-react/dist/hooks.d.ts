import type { AuthenticateWithRedirectParams, PermissionCheck, SdkMembership, SdkOrganization } from "./types.js";
/** Auth state + tokens without hydrating the full profile. Mirrors Federated's `useAuth()`. */
export declare function useAuth(): {
    isLoaded: boolean;
    /**
     * Raw load state: "loading" | "loaded" | "degraded" | "failed". A route guard should treat
     * "failed"/"degraded" as "backend unreachable, keep waiting" — NOT as "signed out" — so a
     * server restart never bounces an already-signed-in user to the sign-in page.
     */
    loadState: import("./types.js").LoadState;
    /**
     * Re-fetch the Client from the Frontend API (rehydrate the session from the still-valid
     * session cookie) and report whether a session is now active. Non-destructive — unlike
     * signOut() it never revokes the server session. Use it to recover from a transient 401
     * before deciding the user is really signed out.
     */
    reloadSession: () => Promise<boolean>;
    isSignedIn: boolean;
    userId: string | null;
    sessionId: string | null;
    orgId: string | null;
    /** Active-org role (Federated parity). Null when there is no active org. */
    orgRole: string | null;
    /** Active-org slug (Federated parity). Null when there is no active org. */
    orgSlug: string | null;
    /** Raw session claims are not exposed to the browser in embedded mode; always null. */
    sessionClaims: Record<string, unknown> | null;
    /** Impersonation actor (Federated parity); unused here, always null. */
    actor: Record<string, unknown> | null;
    getToken: (opts?: {
        template?: string;
    }) => Promise<string | null>;
    has: (check?: PermissionCheck) => boolean;
    signOut: (opts?: {
        redirectUrl?: string;
    }) => Promise<void>;
};
/** The current user's profile data. */
export declare function useUser(): {
    isLoaded: boolean;
    isSignedIn: boolean;
    user: import("./types.js").SdkUser | null;
};
/** The active session record. */
export declare function useSession(): {
    isLoaded: boolean;
    isSignedIn: boolean;
    session: {
        id: string | null;
        status: "active";
        user: import("./types.js").SdkUser | null;
        lastVerifiedAt: number | null;
    } | null;
};
/** All sessions for the current user (the snapshot surfaces only the active one). */
export declare function useSessionList(): {
    isLoaded: boolean;
    sessions: {
        id: string | null;
        status: "active";
    }[];
    setActive: (p: {
        session?: string | null;
        organization?: string | null;
    }) => Promise<void>;
};
/** Drive a custom sign-in flow against the upstream IdP. */
export declare function useSignIn(): {
    isLoaded: boolean;
    signIn: {
        authenticateWithRedirect: (p: AuthenticateWithRedirectParams) => Promise<void>;
    };
};
/** The sign-up counterpart (funnels into the same federated flow + JIT provisioning). */
export declare function useSignUp(): {
    isLoaded: boolean;
    signUp: {
        authenticateWithRedirect: (p: AuthenticateWithRedirectParams) => Promise<void>;
    };
};
/** Access the active organization/tenant and the current user's membership in it. */
export declare function useOrganization(): {
    isLoaded: boolean;
    organization: SdkOrganization | null;
    membership: SdkMembership | null;
};
/** List the organizations the user belongs to and switch the active one (tab-scoped). */
export declare function useOrganizationList(_opts?: {
    userMemberships?: boolean;
}): {
    isLoaded: boolean;
    userMemberships: {
        data: SdkMembership[];
    };
    setActive: (p: {
        organization: string | null;
    }) => Promise<void>;
};
/**
 * Wrap a sensitive action so a freshly-verified session is required before it runs
 * (step-up MFA inherited from the upstream IdP). If the session is too old the user is
 * prompted to reverify, then the action retries automatically.
 */
export declare function useReverification<Args extends unknown[], R>(action: (...args: Args) => Promise<R> | R, opts?: {
    maxAgeSeconds?: number;
}): (...args: Args) => Promise<R>;
/**
 * Imperative client object for actions not covered by the focused hooks. Mirrors Federated's
 * `useFederated()` — the handle to imperative methods (`setActive`, `signOut`) plus the current
 * user/session/organization snapshot.
 */
export declare function useFederated(): {
    loaded: boolean;
    user: import("./types.js").SdkUser | null;
    session: {
        id: string | null;
    } | null;
    organization: SdkOrganization | null;
    setActive: (p: {
        organization: string | null;
    }) => Promise<void>;
    signOut: (opts?: {
        redirectUrl?: string;
    }) => Promise<void>;
};
/**
 * @deprecated Use {@link useFederated}. Alias retained so existing `useOpenAuth()` call sites keep
 * working unchanged.
 */
export declare const useOpenAuth: typeof useFederated;
