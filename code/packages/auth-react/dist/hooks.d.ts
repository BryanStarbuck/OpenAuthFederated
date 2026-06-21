import type { AuthenticateWithRedirectParams, PermissionCheck, SdkMembership, SdkOrganization } from "./types.js";
/** Auth state + tokens without hydrating the full profile. */
export declare function useAuth(): {
    isLoaded: boolean;
    isSignedIn: boolean;
    userId: string | null;
    sessionId: string | null;
    orgId: string | null;
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
/** All sessions for the current user (the dev mock surfaces only the active one). */
export declare function useSessionList(): {
    isLoaded: boolean;
    sessions: {
        id: string | null;
        status: "active";
    }[];
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
/** Imperative client object for actions not covered by the focused hooks. */
export declare function useOpenAuth(): {
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
