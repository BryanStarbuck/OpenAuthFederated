import { type ReactNode } from "react";
import type { Appearance, AuthCore, Connection, SessionSnapshot } from "./types.js";
interface AuthConfig {
    signInUrl: string;
    signUpUrl: string;
    afterSignOutUrl: string;
    appearance?: Appearance;
}
interface AuthContextValue {
    core: AuthCore;
    snapshot: SessionSnapshot;
    isLoaded: boolean;
    config: AuthConfig;
    connections: Connection[];
}
export declare function useAuthContext(): AuthContextValue;
export interface AuthProviderProps {
    children: ReactNode;
    /** Browser-safe publishable key (`pk_live_…` / `pk_test_…`). */
    publishableKey?: string;
    /** Frontend API base, e.g. https://auth.whitehatengineering.com. */
    frontendApi?: string;
    signInUrl?: string;
    signUpUrl?: string;
    afterSignOutUrl?: string;
    appearance?: Appearance;
    /** Local dev mock (no deployed server). The app passes VITE_AUTH_DEV_MODE. */
    devMode?: boolean;
    /** The company domains presented as "global logins" (the two SSO connections). */
    allowedDomains?: string[];
    /** Shared HS256 secret used to mint dev JWTs; must match the backend's AUTH_DEV_SHARED_SECRET. */
    devSharedSecret?: string;
}
export declare function AuthProvider(props: AuthProviderProps): ReactNode;
export {};
