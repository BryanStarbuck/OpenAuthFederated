import { useCallback } from "react"
import { useAuthContext } from "./context.js"
import type {
  AuthenticateWithRedirectParams,
  PermissionCheck,
  SdkMembership,
  SdkOrganization,
} from "./types.js"

/** Auth state + tokens without hydrating the full profile. */
export function useAuth() {
  const { core, snapshot, isLoaded } = useAuthContext()
  return {
    isLoaded,
    isSignedIn: snapshot.isSignedIn,
    userId: snapshot.userId,
    sessionId: snapshot.sessionId,
    orgId: snapshot.orgId,
    getToken: (opts?: { template?: string }) => core.getToken(opts),
    has: (check?: PermissionCheck) => core.has(check),
    signOut: (opts?: { redirectUrl?: string }) => core.signOut(opts),
  }
}

/** The current user's profile data. */
export function useUser() {
  const { snapshot, isLoaded } = useAuthContext()
  return { isLoaded, isSignedIn: snapshot.isSignedIn, user: snapshot.user }
}

/** The active session record. */
export function useSession() {
  const { snapshot, isLoaded } = useAuthContext()
  const session = snapshot.isSignedIn
    ? {
        id: snapshot.sessionId,
        status: "active" as const,
        user: snapshot.user,
        lastVerifiedAt: snapshot.lastVerifiedAt,
      }
    : null
  return { isLoaded, isSignedIn: snapshot.isSignedIn, session }
}

/** All sessions for the current user (the dev mock surfaces only the active one). */
export function useSessionList() {
  const { snapshot, isLoaded } = useAuthContext()
  const sessions = snapshot.isSignedIn
    ? [{ id: snapshot.sessionId, status: "active" as const }]
    : []
  return { isLoaded, sessions }
}

/** Drive a custom sign-in flow against the upstream IdP. */
export function useSignIn() {
  const { core, isLoaded } = useAuthContext()
  return {
    isLoaded,
    signIn: {
      authenticateWithRedirect: (p: AuthenticateWithRedirectParams) =>
        core.authenticateWithRedirect(p),
    },
  }
}

/** The sign-up counterpart (funnels into the same federated flow + JIT provisioning). */
export function useSignUp() {
  const { core, isLoaded } = useAuthContext()
  return {
    isLoaded,
    signUp: {
      authenticateWithRedirect: (p: AuthenticateWithRedirectParams) =>
        core.authenticateWithRedirect(p),
    },
  }
}

/** Access the active organization/tenant and the current user's membership in it. */
export function useOrganization(): {
  isLoaded: boolean
  organization: SdkOrganization | null
  membership: SdkMembership | null
} {
  const { snapshot, isLoaded } = useAuthContext()
  const membership =
    snapshot.memberships.find((m) => m.organization.id === snapshot.orgId) ?? null
  return { isLoaded, organization: membership?.organization ?? null, membership }
}

/** List the organizations the user belongs to and switch the active one (tab-scoped). */
export function useOrganizationList(_opts: { userMemberships?: boolean } = {}): {
  isLoaded: boolean
  userMemberships: { data: SdkMembership[] }
  setActive: (p: { organization: string | null }) => Promise<void>
} {
  const { core, snapshot, isLoaded } = useAuthContext()
  const setActive = useCallback(
    (p: { organization: string | null }) => core.setActiveOrg(p.organization),
    [core],
  )
  return {
    isLoaded,
    userMemberships: { data: snapshot.memberships },
    setActive,
  }
}

/**
 * Wrap a sensitive action so a freshly-verified session is required before it runs
 * (step-up MFA inherited from the upstream IdP). If the session is too old the user is
 * prompted to reverify, then the action retries automatically.
 */
export function useReverification<Args extends unknown[], R>(
  action: (...args: Args) => Promise<R> | R,
  opts: { maxAgeSeconds?: number } = {},
): (...args: Args) => Promise<R> {
  const { core } = useAuthContext()
  const maxAge = opts.maxAgeSeconds ?? 600
  return useCallback(
    async (...args: Args): Promise<R> => {
      if (!core.isRecentlyVerified(maxAge)) {
        await core.reverify()
      }
      return await action(...args)
    },
    [core, action, maxAge],
  )
}

/** Imperative client object for actions not covered by the focused hooks. */
export function useOpenAuth() {
  const { core, snapshot, isLoaded } = useAuthContext()
  const organization =
    snapshot.memberships.find((m) => m.organization.id === snapshot.orgId)?.organization ?? null
  return {
    loaded: isLoaded,
    user: snapshot.user,
    session: snapshot.isSignedIn ? { id: snapshot.sessionId } : null,
    organization,
    setActive: (p: { organization: string | null }) => core.setActiveOrg(p.organization),
    signOut: (opts?: { redirectUrl?: string }) => core.signOut(opts),
  }
}
