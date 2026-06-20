/** Theming overrides for the drop-in components (`@auth/ui` is folded in here). */
export interface Appearance {
  variables?: { colorPrimary?: string } & Record<string, string>
}

/** The signed-in user as exposed to the app. */
export interface SdkUser {
  id: string
  firstName?: string
  lastName?: string
  primaryEmailAddress?: string
  imageUrl?: string
  publicMetadata?: Record<string, unknown>
  roles: string[]
  permissions: string[]
  /** Upstream hosted-domain (Google Workspace `hd`). */
  hd?: string
}

/** Immutable snapshot of auth state, surfaced through `useSyncExternalStore`. */
export interface SessionSnapshot {
  isSignedIn: boolean
  userId: string | null
  sessionId: string | null
  orgId: string | null
  user: SdkUser | null
}

/** A federated "global login" — one company Workspace domain/SSO connection. */
export interface Connection {
  id: string
  domain: string
  label: string
}

export interface AuthenticateWithRedirectParams {
  strategy?: string
  connectionId?: string
  redirectUrl: string
  redirectUrlComplete: string
}

export interface PermissionCheck {
  role?: string
  permission?: string
}

/**
 * The framework-agnostic engine behind the provider. Two implementations exist: a real
 * Frontend-API client and a local dev mock (see core.ts).
 */
export interface AuthCore {
  load(): Promise<void>
  getSnapshot(): SessionSnapshot
  subscribe(listener: () => void): () => void
  connections(): Connection[]
  getToken(opts?: { template?: string }): Promise<string | null>
  authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>
  completeRedirectCallback(): Promise<{ redirectTo: string }>
  signOut(opts?: { redirectUrl?: string }): Promise<void>
  has(check?: PermissionCheck): boolean
}

export const EMPTY_SNAPSHOT: SessionSnapshot = Object.freeze({
  isSignedIn: false,
  userId: null,
  sessionId: null,
  orgId: null,
  user: null,
})

/**
 * Wildcard-aware permission check — exact grant, feature wildcard (`film:*`), action
 * wildcard (`*:read`), or super-wildcard (`*:*`). Mirrors the backend SDK helper.
 */
export function hasPermission(granted: string[], permission: string): boolean {
  if (!permission) return true
  const [feature, action] = permission.split(":")
  return (
    granted.includes(permission) ||
    granted.includes(`${feature}:*`) ||
    granted.includes(`*:${action}`) ||
    granted.includes("*:*")
  )
}

export function domainSlug(domain: string): string {
  return domain.replace(/[^a-zA-Z0-9]+/g, "_")
}
