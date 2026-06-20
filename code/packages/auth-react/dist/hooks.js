import { useAuthContext } from "./context.js";
/** Auth state + tokens without hydrating the full profile. */
export function useAuth() {
    const { core, snapshot, isLoaded } = useAuthContext();
    return {
        isLoaded,
        isSignedIn: snapshot.isSignedIn,
        userId: snapshot.userId,
        sessionId: snapshot.sessionId,
        orgId: snapshot.orgId,
        getToken: (opts) => core.getToken(opts),
        has: (check) => core.has(check),
        signOut: (opts) => core.signOut(opts),
    };
}
/** The current user's profile data. */
export function useUser() {
    const { snapshot, isLoaded } = useAuthContext();
    return { isLoaded, isSignedIn: snapshot.isSignedIn, user: snapshot.user };
}
/** The active session record. */
export function useSession() {
    const { snapshot, isLoaded } = useAuthContext();
    const session = snapshot.isSignedIn
        ? { id: snapshot.sessionId, status: "active", user: snapshot.user }
        : null;
    return { isLoaded, isSignedIn: snapshot.isSignedIn, session };
}
/** Drive a custom sign-in flow against the upstream IdP. */
export function useSignIn() {
    const { core, isLoaded } = useAuthContext();
    return {
        isLoaded,
        signIn: {
            authenticateWithRedirect: (p) => core.authenticateWithRedirect(p),
        },
    };
}
/** The sign-up counterpart (funnels into the same federated flow + JIT provisioning). */
export function useSignUp() {
    const { core, isLoaded } = useAuthContext();
    return {
        isLoaded,
        signUp: {
            authenticateWithRedirect: (p) => core.authenticateWithRedirect(p),
        },
    };
}
/** Imperative client object for actions not covered by the focused hooks. */
export function useOpenAuth() {
    const { core, snapshot, isLoaded } = useAuthContext();
    return {
        loaded: isLoaded,
        user: snapshot.user,
        session: snapshot.isSignedIn ? { id: snapshot.sessionId } : null,
        signOut: (opts) => core.signOut(opts),
    };
}
//# sourceMappingURL=hooks.js.map