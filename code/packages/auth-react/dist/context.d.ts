import { type ReactNode } from "react";
import type { Appearance, AuthCore, Connection, LoadState, SessionSnapshot } from "./types.js";
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
    loadState: LoadState;
    config: AuthConfig;
    connections: Connection[];
}
export declare function useAuthContext(): AuthContextValue;
export interface FederatedProviderProps {
    children: ReactNode;
    /** Browser-safe publishable key (`pk_live_…` / `pk_test_…`). */
    publishableKey?: string;
    /** Frontend API base, e.g. https://auth.whitehatengineering.com. */
    frontendApi?: string;
    signInUrl?: string;
    signUpUrl?: string;
    afterSignOutUrl?: string;
    appearance?: Appearance;
    /** The company domains presented as "global logins" (the two SSO connections). */
    allowedDomains?: string[];
    /**
     * Inject a custom {@link AuthCore} instead of the default real Frontend-API client. This is the
     * generic extension seam an embedding app uses to supply its OWN core — e.g. a localhost-only dev
     * sign-in core, which the app may engage only under its own gate (running on localhost AND no
     * credentials file). OpenAuthFederated ships no dev/mock core: when this is omitted it always
     * builds {@link RealAuthCore}. When provided, the app owns the gate — never this library.
     */
    core?: AuthCore;
}
/**
 * @deprecated Use {@link FederatedProviderProps}. Alias retained for existing imports.
 */
export type AuthProviderProps = FederatedProviderProps;
/**
 * Root provider `<FederatedProvider>`: wrap the app, pass `publishableKey` / `frontendApi`, and the
 * hooks/components become available. `<AuthProvider>` is kept as an alias.
 */
export declare function FederatedProvider(props: FederatedProviderProps): ReactNode;
/**
 * @deprecated Use {@link FederatedProvider}. Alias retained so existing `<AuthProvider>` usage keeps
 * working unchanged.
 */
export declare const AuthProvider: typeof FederatedProvider;
export {};
