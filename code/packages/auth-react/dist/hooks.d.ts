import type { AuthenticateWithRedirectParams, PermissionCheck } from "./types.js";
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
    } | null;
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
/** Imperative client object for actions not covered by the focused hooks. */
export declare function useOpenAuth(): {
    loaded: boolean;
    user: import("./types.js").SdkUser | null;
    session: {
        id: string | null;
    } | null;
    signOut: (opts?: {
        redirectUrl?: string;
    }) => Promise<void>;
};
