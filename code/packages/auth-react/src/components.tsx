import { type CSSProperties, type ReactNode, useEffect } from "react"
import { useAuthContext } from "./context.js"
import { useAuth, useSignIn, useSignUp, useUser } from "./hooks.js"
import type { Appearance, PermissionCheck } from "./types.js"

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

/** Google One Tap prompt. In the dev mock there is no real prompt, so it renders nothing. */
export function GoogleOneTap(_props: {
  cancelOnTapOutside?: boolean
  fallbackRedirectUrl?: string
  signInForceRedirectUrl?: string
}): ReactNode {
  return null
}

/** Completes the SSO redirect handshake on the callback route, then forwards the user on. */
export function AuthenticateWithRedirectCallback(props: {
  signInForceRedirectUrl?: string
  signUpForceRedirectUrl?: string
  continueSignUpUrl?: string
}): ReactNode {
  const { core } = useAuthContext()
  useEffect(() => {
    let active = true
    core.completeRedirectCallback().then(({ redirectTo }) => {
      if (!active) return
      const target = props.signInForceRedirectUrl ?? props.signUpForceRedirectUrl ?? redirectTo
      window.location.assign(target)
    })
    return () => {
      active = false
    }
  }, [core, props.signInForceRedirectUrl, props.signUpForceRedirectUrl])
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
