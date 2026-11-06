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
  /** Upstream hosted-domain (Google `hd`, or a corroborated SAML attribute). */
  hd?: string
}

/** An organization/tenant the signed-in user belongs to. */
export interface SdkOrganization {
  id: string
  name: string
  slug?: string
  membersCount?: number
  publicMetadata?: Record<string, unknown>
}

/** The current user's membership in an organization — carries their role + permissions. */
export interface SdkMembership {
  id: string
  organization: SdkOrganization
  role: string
  permissions: string[]
}

/** Immutable snapshot of auth state, surfaced through `useSyncExternalStore`. */
export interface SessionSnapshot {
  isSignedIn: boolean
  userId: string | null
  sessionId: string | null
  /** The active organization/tenant id (per browser tab). */
  orgId: string | null
  user: SdkUser | null
  /** Every organization the user belongs to (for the switcher / org list). */
  memberships: SdkMembership[]
  /** Epoch-seconds the active session was last verified — drives step-up reverification. */
  lastVerifiedAt: number | null
}

/**
 * One sign-in button: a strategy (Google, X, SAML) and, optionally, a domain whose id the server
 * may accept as an account-chooser hint. Build domain ids with {@link connectionIdForDomain} so they
 * always match the server mapping.
 */
export interface Connection {
  id: string
  label: string
  strategy?: "oauth_google" | "oauth_x" | "saml"
  /** A hint domain (Google `hd`), when this connection pre-selects one. */
  domain?: string
}

export interface AuthenticateWithRedirectParams {
  strategy?: string
  /** @deprecated Use {@link connection}. */
  connectionId?: string
  /** The connection id to start (e.g. from `connections`). Omitted: the first connection. */
  connection?: string
  /** UNTRUSTED hint carried to the server's admission actions; `useSignUp` sends 'sign_up'. */
  mode?: "sign_in" | "sign_up"
  redirectUrl: string
  redirectUrlComplete: string
}

/**
 * Refusal codes the server can send back on the callback. Branch on `code`, never on `message`.
 * Apps may also define their own codes through admission actions (`/^[a-z][a-z0-9_]{0,63}$/`).
 */
export type AuthRejectionCode =
  | "identity_email_unverified"
  | "identity_email_invalid"
  | "identity_domain_not_allowed"
  | "identity_hosted_domain_required"
  | "identity_blocked"
  | "identity_not_allowlisted"
  | "sign_up_restricted"
  | "sign_up_waitlisted"
  | "action_denied"
  | "action_failed"
  | "sign_in_not_completed"

/**
 * Structured context attached to a rejection, so the app can build a specific message
 * ("restricted to example.com — you used example.org") instead of a generic one. Mirrors the
 * platform error envelope's `meta` block (`docs/apis/frontend/errors.mdx`). Open-ended: the platform may add fields over time.
 */
export interface AuthRejectionMeta {
  /** The allowed domains, only when the server publishes them (`allowed_domains`). */
  allowedDomains?: string[]
  /** The verified domain the upstream identity actually presented, when known. */
  presentedDomain?: string
  /** Whether the upstream email was verified (OIDC `email_verified`). */
  emailVerified?: boolean
  /** Any further platform-supplied context (forward-compatible). */
  [key: string]: unknown
}

/**
 * An attempt that the platform refused — e.g. a valid upstream identity whose verified domain
 * is not on the allowlist (`identity_domain_not_allowed`). No user is created and no session is
 * established; the SDK surfaces this so the app can show a clear, specific message and the user
 * understands *why* they were turned away. It mirrors the platform error envelope (one entry of
 * the documented `errors[]` array: `code` + `message` + `long_message` + `meta`, plus the
 * correlating `trace_id`) so the frontend rejection is exactly as rich as the API error it came
 * from. See `docs/apis/frontend/errors.mdx` and `docs/apis/frontend/sign-up.mdx#domain-enforcement`.
 */
export interface AuthRejection {
  /** Stable, machine-readable code — branch on this, never on `message`. See {@link AuthRejectionCode}. */
  code: AuthRejectionCode | (string & {})
  /** Finer reason under a legacy code (the server's `error_reason`), e.g. `identity_email_unverified`. */
  reason?: string
  /** Short, human-readable summary, safe to show the user. */
  message: string
  /** Detailed, user-presentable explanation (the API `long_message`), when provided. */
  longMessage?: string
  /** The verified domain the upstream identity presented, when known (also in `meta`). */
  presentedDomain?: string
  /** Structured context for building a specific message. */
  meta?: AuthRejectionMeta
  /** Correlates with the platform audit log entry (`user.sign_in.rejected`) for support. */
  traceId?: string
}

/**
 * The outcome of completing a redirect handshake on the callback route. Exactly one of
 * `redirectTo` (success → forward the user on) or `error` (rejection → return to sign-in with
 * a message) is populated.
 */
export interface RedirectCallbackResult {
  redirectTo?: string
  error?: AuthRejection
}

export interface PermissionCheck {
  role?: string
  permission?: string
}

/** The SDK lifecycle state — drives `<AuthLoading>` / `<AuthLoaded>` / `<AuthFailed>`. */
export type LoadState = "loading" | "loaded" | "degraded" | "failed"

/**
 * The framework-agnostic engine behind the provider: the real Frontend-API client
 * (`RealAuthCore` in core.ts). OpenAuthFederated ships no dev mock.
 */
export interface AuthCore {
  load(): Promise<void>
  loadState(): LoadState
  getSnapshot(): SessionSnapshot
  subscribe(listener: () => void): () => void
  connections(): Connection[]
  getToken(opts?: { template?: string }): Promise<string | null>
  authenticateWithRedirect(params: AuthenticateWithRedirectParams): Promise<void>
  completeRedirectCallback(): Promise<RedirectCallbackResult>
  signOut(opts?: { redirectUrl?: string }): Promise<void>
  has(check?: PermissionCheck): boolean
  /** Switch the active organization for this tab; resolves once the snapshot reflects it. */
  setActiveOrg(orgId: string | null): Promise<void>
  /** Re-establish a freshly-verified session (step-up MFA) for sensitive actions. */
  reverify(): Promise<void>
  /** Whether the active session was verified within `maxAgeSeconds`. */
  isRecentlyVerified(maxAgeSeconds: number): boolean
}

export const EMPTY_SNAPSHOT: SessionSnapshot = Object.freeze({
  isSignedIn: false,
  userId: null,
  sessionId: null,
  orgId: null,
  user: null,
  memberships: [],
  lastVerifiedAt: null,
})

/**
 * Wildcard-aware permission check — exact grant, feature wildcard (`film:*`), action
 * wildcard (`*:read`), or super-wildcard (`*:*`). Also handles the spec's structured
 * three-part permissions (`org:invoices:create`, `org:sys_memberships:manage`) by treating
 * everything before the final `:` as the feature. Mirrors the backend SDK helper.
 */
export function hasPermission(granted: string[], permission: string): boolean {
  if (!permission) return true
  if (granted.includes(permission) || granted.includes("*:*")) return true
  const lastColon = permission.lastIndexOf(":")
  if (lastColon < 0) return false
  const feature = permission.slice(0, lastColon)
  const action = permission.slice(lastColon + 1)
  return granted.includes(`${feature}:*`) || granted.includes(`*:${action}`)
}

/** Role match — accepts a bare role (`admin`) or its `org:`-prefixed form interchangeably. */
export function hasRole(roles: string[], role: string): boolean {
  if (!role) return true
  if (roles.includes(role)) return true
  const bare = role.startsWith("org:") ? role.slice(4) : role
  return roles.includes(bare) || roles.includes(`org:${bare}`)
}

export function domainSlug(domain: string): string {
  return domain.replace(/[^a-zA-Z0-9]+/g, "_")
}

/**
 * Connection id for a domain. Identical to the backend's `connectionIdForDomain`, so a client-built
 * id always matches the server mapping.
 */
export function connectionIdForDomain(domain: string): string {
  return "conn_" + String(domain).toLowerCase().replace(/[^a-z0-9]/g, "_")
}

/** The generic Google button used when an app configures no connections at all. */
export const GENERIC_GOOGLE_CONNECTION: Readonly<Connection> = Object.freeze({
  id: "conn_google",
  label: "Google",
  strategy: "oauth_google",
})
