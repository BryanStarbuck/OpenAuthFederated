import { useCallback } from "react";
import { useAuthContext } from "./context.js";
/** Auth state + tokens without hydrating the full profile. Mirrors Federated's `useAuth()`. */
export function useAuth() {
    const { core, snapshot, isLoaded } = useAuthContext();
    const activeMembership = snapshot.memberships.find((m) => m.organization.id === snapshot.orgId) ?? null;
    return {
        isLoaded,
        isSignedIn: snapshot.isSignedIn,
        userId: snapshot.userId,
        sessionId: snapshot.sessionId,
        orgId: snapshot.orgId,
        /** Active-org role (Federated parity). Null when there is no active org. */
        orgRole: activeMembership?.role ?? null,
        /** Active-org slug (Federated parity). Null when there is no active org. */
        orgSlug: activeMembership?.organization.slug ?? null,
        /** Raw session claims are not exposed to the browser in embedded mode; always null. */
        sessionClaims: null,
        /** Impersonation actor (Federated parity); unused here, always null. */
        actor: null,
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
        ? {
            id: snapshot.sessionId,
            status: "active",
            user: snapshot.user,
            lastVerifiedAt: snapshot.lastVerifiedAt,
        }
        : null;
    return { isLoaded, isSignedIn: snapshot.isSignedIn, session };
}
/** All sessions for the current user (the snapshot surfaces only the active one). */
export function useSessionList() {
    const { core, snapshot, isLoaded } = useAuthContext();
    const sessions = snapshot.isSignedIn
        ? [{ id: snapshot.sessionId, status: "active" }]
        : [];
    // Federated's useSessionList exposes setActive({ session?, organization? }). Single-session here,
    // so a session switch is a no-op; an organization switch routes to the tab-scoped active org.
    const setActive = useCallback(async (p) => {
        if (p.organization !== undefined)
            await core.setActiveOrg(p.organization);
    }, [core]);
    return { isLoaded, sessions, setActive };
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
/** Access the active organization/tenant and the current user's membership in it. */
export function useOrganization() {
    const { snapshot, isLoaded } = useAuthContext();
    const membership = snapshot.memberships.find((m) => m.organization.id === snapshot.orgId) ?? null;
    return { isLoaded, organization: membership?.organization ?? null, membership };
}
/** List the organizations the user belongs to and switch the active one (tab-scoped). */
export function useOrganizationList(_opts = {}) {
    const { core, snapshot, isLoaded } = useAuthContext();
    const setActive = useCallback((p) => core.setActiveOrg(p.organization), [core]);
    return {
        isLoaded,
        userMemberships: { data: snapshot.memberships },
        setActive,
    };
}
/**
 * Wrap a sensitive action so a freshly-verified session is required before it runs
 * (step-up MFA inherited from the upstream IdP). If the session is too old the user is
 * prompted to reverify, then the action retries automatically.
 */
export function useReverification(action, opts = {}) {
    const { core } = useAuthContext();
    const maxAge = opts.maxAgeSeconds ?? 600;
    return useCallback(async (...args) => {
        if (!core.isRecentlyVerified(maxAge)) {
            await core.reverify();
        }
        return await action(...args);
    }, [core, action, maxAge]);
}
/**
 * Imperative client object for actions not covered by the focused hooks. Mirrors Federated's
 * `useFederated()` — the handle to imperative methods (`setActive`, `signOut`) plus the current
 * user/session/organization snapshot.
 */
export function useFederated() {
    const { core, snapshot, isLoaded } = useAuthContext();
    const organization = snapshot.memberships.find((m) => m.organization.id === snapshot.orgId)?.organization ?? null;
    return {
        loaded: isLoaded,
        user: snapshot.user,
        session: snapshot.isSignedIn ? { id: snapshot.sessionId } : null,
        organization,
        setActive: (p) => core.setActiveOrg(p.organization),
        signOut: (opts) => core.signOut(opts),
    };
}
/**
 * @deprecated Use {@link useFederated}. Alias retained so existing `useOpenAuth()` call sites keep
 * working unchanged.
 */
export const useOpenAuth = useFederated;
//# sourceMappingURL=hooks.js.map