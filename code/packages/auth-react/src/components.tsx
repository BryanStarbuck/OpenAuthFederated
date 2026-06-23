import { type CSSProperties, type ReactNode, useEffect, useState } from "react"
import { useAuthContext } from "./context.js"
import {
  useAuth,
  useOrganization,
  useOrganizationList,
  useSignIn,
  useSignUp,
  useUser,
} from "./hooks.js"
import type { Appearance, AuthRejection, PermissionCheck } from "./types.js"

// Where a callback rejection (e.g. domain enforcement) is stashed so the sign-in screen can
// show a clear message after we bounce the user back. Read+cleared by <SignIn> / useAuthError.
const SS_AUTH_ERROR = "openauthfed_auth_error_v1"

/** Persist a callback rejection so the sign-in screen can surface it after the redirect. */
function stashAuthError(error: AuthRejection): void {
  try {
    sessionStorage.setItem(SS_AUTH_ERROR, JSON.stringify(error))
  } catch {
    // sessionStorage unavailable — the rejection still routes back; just without the message.
  }
}

/** Read and clear any stashed callback rejection (one-shot). */
export function readAuthError(): AuthRejection | null {
  try {
    const raw = sessionStorage.getItem(SS_AUTH_ERROR)
    if (!raw) return null
    sessionStorage.removeItem(SS_AUTH_ERROR)
    return JSON.parse(raw) as AuthRejection
  } catch {
    return null
  }
}

/**
 * Read the most recent sign-in rejection once, on mount. For apps that render their **own**
 * sign-in screen (instead of the drop-in `<SignIn>`) and still want to show why the last
 * attempt was refused — e.g. a wrong/unauthorized Google account. One-shot: the rejection is
 * cleared as it is read, so a refresh won't re-show a stale message.
 */
export function useAuthError(): AuthRejection | null {
  const [rejection, setRejection] = useState<AuthRejection | null>(null)
  useEffect(() => {
    setRejection(readAuthError())
  }, [])
  return rejection
}

const DEFAULT_PRIMARY = "#0f766e"

const card: CSSProperties = {
  width: "100%",
  maxWidth: 360,
  margin: "0 auto",
  padding: 24,
  borderRadius: 12,
  border: "1px solid #e5e7eb",
  background: "#fff",
  boxShadow: "0 1px 2px rgba(0,0,0,0.05)",
  fontFamily: "system-ui, sans-serif",
}

function bigButton(color: string): CSSProperties {
  return {
    display: "flex",
    width: "100%",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    padding: "10px 14px",
    marginTop: 10,
    borderRadius: 8,
    border: "1px solid #d1d5db",
    background: color,
    color: "#fff",
    fontSize: 14,
    fontWeight: 600,
    cursor: "pointer",
  }
}

function primaryColor(appearance?: Appearance, fallback?: Appearance): string {
  return (
    appearance?.variables?.colorPrimary ??
    fallback?.variables?.colorPrimary ??
    DEFAULT_PRIMARY
  )
}

interface SignInProps {
  routing?: "hash" | "path" | "virtual"
  path?: string
  signInUrl?: string
  signUpUrl?: string
  forceRedirectUrl?: string
  fallbackRedirectUrl?: string
  appearance?: Appearance
}

const rejectionBanner: CSSProperties = {
  marginTop: 12,
  padding: "8px 10px",
  borderRadius: 8,
  border: "1px solid #fca5a5",
  background: "#fef2f2",
  color: "#991b1b",
  fontSize: 12,
}

/** Internal: the federated, password-free sign-in/up surface — one button per company domain. */
function FederatedAuth(props: {
  mode: "sign-in" | "sign-up"
  forceRedirectUrl?: string
  fallbackRedirectUrl?: string
  appearance?: Appearance
}): ReactNode {
  const { connections, config } = useAuthContext()
  const { signIn } = useSignIn()
  const { signUp } = useSignUp()
  const complete = props.forceRedirectUrl ?? props.fallbackRedirectUrl ?? "/"
  const color = primaryColor(props.appearance, config.appearance)

  // Surface a rejection from a prior callback bounce (e.g. domain enforcement, §7.3). One-shot,
  // cleared on read, so a refresh doesn't re-show a stale message.
  const rejection = useAuthError()

  const start = (connectionId: string) => {
    const authenticate =
      props.mode === "sign-up"
        ? signUp.authenticateWithRedirect
        : signIn.authenticateWithRedirect
    authenticate({
      strategy: "oauth_google_workspace",
      connectionId,
      redirectUrl: "/sso-callback",
      redirectUrlComplete: complete,
    })
  }

  return (
    <div style={card}>
      <h1 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>Internal App</h1>
      <p style={{ fontSize: 13, color: "#6b7280", marginTop: 4 }}>
        Employees only. Continue with your company Google Workspace.
      </p>
      {rejection && (
        <div role="alert" style={rejectionBanner}>
          <strong style={{ display: "block" }}>{rejection.message}</strong>
          {rejection.longMessage && (
            <span style={{ display: "block", marginTop: 4 }}>{rejection.longMessage}</span>
          )}
          {rejection.meta?.allowedDomains?.length ? (
            <span style={{ display: "block", marginTop: 4 }}>
              Allowed company {rejection.meta.allowedDomains.length > 1 ? "domains" : "domain"}:{" "}
              {rejection.meta.allowedDomains.join(", ")}.
            </span>
          ) : null}
        </div>
      )}
      {connections.map((conn) => (
        <button
          key={conn.id}
          type="button"
          onClick={() => start(conn.id)}
          style={bigButton(color)}
        >
          Continue with {conn.domain}
        </button>
      ))}
      {/* Optional near-frictionless return sign-in, still subject to domain enforcement (§7.1). */}
      <GoogleOneTap fallbackRedirectUrl={complete} signInForceRedirectUrl={complete} />
      <p style={{ fontSize: 11, color: "#9ca3af", marginTop: 14 }}>
        No passwords. Access is restricted to company accounts.
      </p>
    </div>
  )
}

/** Complete federated sign-in experience (no password field). */
export function SignIn(props: SignInProps): ReactNode {
  return (
    <FederatedAuth
      mode="sign-in"
      forceRedirectUrl={props.forceRedirectUrl}
      fallbackRedirectUrl={props.fallbackRedirectUrl}
      appearance={props.appearance}
    />
  )
}

/** Sign-up surface — funnels into the same federated flow (JIT provisioning). */
export function SignUp(props: SignInProps): ReactNode {
  return (
    <FederatedAuth
      mode="sign-up"
      forceRedirectUrl={props.forceRedirectUrl}
      fallbackRedirectUrl={props.fallbackRedirectUrl}
      appearance={props.appearance}
    />
  )
}

interface TriggerButtonProps {
  children?: ReactNode
  mode?: "modal" | "redirect"
  forceRedirectUrl?: string
  fallbackRedirectUrl?: string
}

/** Lightweight trigger that starts the federated sign-in flow. */
export function SignInButton(props: TriggerButtonProps): ReactNode {
  const { connections } = useAuthContext()
  const { signIn } = useSignIn()
  const onClick = () =>
    signIn.authenticateWithRedirect({
      strategy: "oauth_google_workspace",
      connectionId: connections[0]?.id,
      redirectUrl: "/sso-callback",
      redirectUrlComplete: props.forceRedirectUrl ?? props.fallbackRedirectUrl ?? "/",
    })
  if (props.children) {
    return (
      <span onClick={onClick} style={{ cursor: "pointer" }}>
        {props.children}
      </span>
    )
  }
  return (
    <button type="button" onClick={onClick}>
      Sign in
    </button>
  )
}

/** Sign-up counterpart of <SignInButton>. */
export function SignUpButton(props: TriggerButtonProps): ReactNode {
  const { connections } = useAuthContext()
  const { signUp } = useSignUp()
  const onClick = () =>
    signUp.authenticateWithRedirect({
      strategy: "oauth_google_workspace",
      connectionId: connections[0]?.id,
      redirectUrl: "/sso-callback",
      redirectUrlComplete: props.forceRedirectUrl ?? props.fallbackRedirectUrl ?? "/",
    })
  if (props.children) {
    return (
      <span onClick={onClick} style={{ cursor: "pointer" }}>
        {props.children}
      </span>
    )
  }
  return (
    <button type="button" onClick={onClick}>
      Create account
    </button>
  )
}

interface SignOutButtonProps {
  children?: ReactNode
  redirectUrl?: string
}

/** Ends the session and revokes its server-side record immediately. */
export function SignOutButton(props: SignOutButtonProps): ReactNode {
  const { signOut } = useAuth()
  const onClick = () => signOut({ redirectUrl: props.redirectUrl ?? "/sign-in" })
  if (props.children) {
    return (
      <span onClick={onClick} style={{ cursor: "pointer" }}>
        {props.children}
      </span>
    )
  }
  return (
    <button type="button" onClick={onClick}>
      Sign out
    </button>
  )
}

/** Minimal account control: shows the signed-in email and a sign-out action. */
export function UserButton(props: { afterSignOutUrl?: string }): ReactNode {
  const { user } = useUser()
  const { signOut } = useAuth()
  if (!user) return null
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <span style={{ fontSize: 13, color: "#374151" }}>{user.primaryEmailAddress}</span>
      <button type="button" onClick={() => signOut({ redirectUrl: props.afterSignOutUrl ?? "/sign-in" })}>
        Sign out
      </button>
    </span>
  )
}

/** Google One Tap prompt. Renders nothing until the One Tap UI is wired to the real client. */
export function GoogleOneTap(_props: {
  cancelOnTapOutside?: boolean
  fallbackRedirectUrl?: string
  signInForceRedirectUrl?: string
}): ReactNode {
  return null
}

/**
 * Completes the SSO redirect handshake on the callback route. On success it forwards the user
 * on; on a rejection (e.g. domain enforcement — `identity_domain_not_allowed`) it stashes the
 * error and bounces back to the sign-in screen so the user sees a clear "restricted to company
 * accounts" message (§7.3). No session is created for a rejected identity.
 */
export function AuthenticateWithRedirectCallback(props: {
  signInForceRedirectUrl?: string
  signUpForceRedirectUrl?: string
  continueSignUpUrl?: string
  /** Where to return on a rejection (defaults to the configured sign-in URL). */
  signInUrl?: string
  /** Observe the rejection (e.g. to fire an audit/telemetry event) before the bounce. */
  onError?: (error: AuthRejection) => void
}): ReactNode {
  const { core, config } = useAuthContext()
  const { onError } = props
  useEffect(() => {
    let active = true
    core.completeRedirectCallback().then((result) => {
      if (!active) return
      if (result.error) {
        stashAuthError(result.error)
        onError?.(result.error)
        window.location.assign(props.signInUrl ?? config.signInUrl)
        return
      }
      const target =
        props.signInForceRedirectUrl ?? props.signUpForceRedirectUrl ?? result.redirectTo ?? "/"
      window.location.assign(target)
    })
    return () => {
      active = false
    }
  }, [
    core,
    config.signInUrl,
    onError,
    props.signInUrl,
    props.signInForceRedirectUrl,
    props.signUpForceRedirectUrl,
  ])
  return <div style={{ padding: 24, fontFamily: "system-ui, sans-serif" }}>Completing sign-in…</div>
}

interface ProtectProps {
  permission?: string
  role?: string
  condition?: (has: (check?: PermissionCheck) => boolean) => boolean
  fallback?: ReactNode
  children?: ReactNode
}

/** Gates children behind a role / `<feature>:<action>` permission (UX gating; backend is authoritative). */
export function Protect(props: ProtectProps): ReactNode {
  const { has } = useAuth()
  const allowed = props.condition
    ? props.condition(has)
    : has({ permission: props.permission, role: props.role })
  return <>{allowed ? props.children : (props.fallback ?? null)}</>
}

/** Conditionally render children by sign-in state. */
export function Show(props: {
  when: "signed-in" | "signed-out"
  fallback?: ReactNode
  children?: ReactNode
}): ReactNode {
  const { isSignedIn } = useAuth()
  const match = props.when === "signed-in" ? isSignedIn : !isSignedIn
  return <>{match ? props.children : (props.fallback ?? null)}</>
}

export function SignedIn(props: { children?: ReactNode }): ReactNode {
  return <Show when="signed-in">{props.children}</Show>
}

export function SignedOut(props: { children?: ReactNode }): ReactNode {
  return <Show when="signed-out">{props.children}</Show>
}

/** Immediately redirect to the federated sign-in flow. */
export function RedirectToSignIn(_props: { redirectUrl?: string }): ReactNode {
  const { config } = useAuthContext()
  useEffect(() => {
    window.location.assign(config.signInUrl)
  }, [config.signInUrl])
  return null
}

/** Immediately redirect to the federated sign-up flow (JIT provisioning). */
export function RedirectToSignUp(_props: { redirectUrl?: string }): ReactNode {
  const { config } = useAuthContext()
  useEffect(() => {
    window.location.assign(config.signUpUrl)
  }, [config.signUpUrl])
  return null
}

/** Renders children only after the SDK has fully initialized. */
export function AuthLoaded(props: { children?: ReactNode }): ReactNode {
  const { loadState } = useAuthContext()
  return <>{loadState === "loaded" || loadState === "degraded" ? props.children : null}</>
}

/** Renders children while the SDK is still initializing (spinner/skeleton slot). */
export function AuthLoading(props: { children?: ReactNode }): ReactNode {
  const { loadState } = useAuthContext()
  return <>{loadState === "loading" ? props.children : null}</>
}

/** Renders children when the SDK is reachable but degraded (soft warning slot). */
export function AuthDegraded(props: { children?: ReactNode }): ReactNode {
  const { loadState } = useAuthContext()
  return <>{loadState === "degraded" ? props.children : null}</>
}

/** Renders children when the SDK failed to initialize (hard error / retry slot). */
export function AuthFailed(props: { children?: ReactNode }): ReactNode {
  const { loadState } = useAuthContext()
  return <>{loadState === "failed" ? props.children : null}</>
}

interface OrganizationSwitcherProps {
  hidePersonal?: boolean
  afterSelectOrganizationUrl?: string
  appearance?: Appearance
}

/**
 * Dropdown for switching the active organization. Setting the active org updates `orgId`
 * (and the permissions that apply) throughout the SDK — tab-scoped, so two tabs can hold
 * different active orgs simultaneously (spec §14).
 */
export function OrganizationSwitcher(props: OrganizationSwitcherProps): ReactNode {
  const { isLoaded, userMemberships, setActive } = useOrganizationList()
  const { organization } = useOrganization()
  if (!isLoaded || userMemberships.data.length === 0) return null

  const onChange = async (value: string) => {
    await setActive({ organization: value === "__personal__" ? null : value })
    if (props.afterSelectOrganizationUrl) {
      window.location.assign(props.afterSelectOrganizationUrl)
    }
  }

  return (
    <select
      aria-label="Switch organization"
      value={organization?.id ?? "__personal__"}
      onChange={(e) => void onChange(e.target.value)}
      style={{
        padding: "6px 10px",
        borderRadius: 8,
        border: "1px solid #d1d5db",
        fontSize: 13,
        fontFamily: "system-ui, sans-serif",
      }}
    >
      {!props.hidePersonal && <option value="__personal__">Personal</option>}
      {userMemberships.data.map((m) => (
        <option key={m.organization.id} value={m.organization.id}>
          {m.organization.name}
        </option>
      ))}
    </select>
  )
}

interface OrganizationListProps {
  hidePersonal?: boolean
  afterSelectOrganizationUrl?: string
  appearance?: Appearance
}

/** Lists the user's organizations so they can select one — a post-sign-in landing page. */
export function OrganizationList(props: OrganizationListProps): ReactNode {
  const { isLoaded, userMemberships, setActive } = useOrganizationList()
  if (!isLoaded) return null

  const select = async (orgId: string | null) => {
    await setActive({ organization: orgId })
    if (props.afterSelectOrganizationUrl) {
      window.location.assign(props.afterSelectOrganizationUrl)
    }
  }

  return (
    <div style={card}>
      <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 8px" }}>Choose an organization</h2>
      {!props.hidePersonal && (
        <button type="button" style={bigButton(DEFAULT_PRIMARY)} onClick={() => void select(null)}>
          Personal workspace
        </button>
      )}
      {userMemberships.data.map((m) => (
        <button
          key={m.organization.id}
          type="button"
          style={bigButton(DEFAULT_PRIMARY)}
          onClick={() => void select(m.organization.id)}
        >
          {m.organization.name}
        </button>
      ))}
    </div>
  )
}

/**
 * A standalone create-organization form. Multi-tenancy onboarding actually provisions the
 * org through the Backend API; this drop-in captures the name and hands off via the callback.
 */
export function CreateOrganization(props: {
  afterCreateOrganizationUrl?: string
  onCreate?: (name: string) => void | Promise<void>
  appearance?: Appearance
}): ReactNode {
  return (
    <form
      style={card}
      onSubmit={(e) => {
        e.preventDefault()
        const name = String(new FormData(e.currentTarget).get("name") ?? "").trim()
        if (!name) return
        void Promise.resolve(props.onCreate?.(name)).then(() => {
          if (props.afterCreateOrganizationUrl) {
            window.location.assign(props.afterCreateOrganizationUrl)
          }
        })
      }}
    >
      <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 8px" }}>Create organization</h2>
      <input
        name="name"
        placeholder="Organization name"
        style={{
          width: "100%",
          padding: "8px 10px",
          borderRadius: 8,
          border: "1px solid #d1d5db",
          fontSize: 14,
        }}
      />
      <button type="submit" style={bigButton(DEFAULT_PRIMARY)}>
        Create
      </button>
    </form>
  )
}

/** A read-only management surface for the active org: name, your role, and member count. */
export function OrganizationProfile(_props: {
  routing?: "hash" | "path" | "virtual"
  path?: string
  appearance?: Appearance
}): ReactNode {
  const { isLoaded, organization, membership } = useOrganization()
  if (!isLoaded || !organization) return null
  return (
    <div style={card}>
      <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>{organization.name}</h2>
      <p style={{ fontSize: 13, color: "#6b7280", marginTop: 6 }}>
        Your role: <strong>{membership?.role ?? "—"}</strong>
      </p>
      {organization.membersCount != null && (
        <p style={{ fontSize: 13, color: "#6b7280", margin: 0 }}>
          Members: {organization.membersCount}
        </p>
      )}
    </div>
  )
}
