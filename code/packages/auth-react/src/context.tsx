import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react"
import { DevAuthCore, RealAuthCore } from "./core.js"
import type {
  Appearance,
  AuthCore,
  Connection,
  LoadState,
  SessionSnapshot,
} from "./types.js"

interface AuthConfig {
  signInUrl: string
  signUpUrl: string
  afterSignOutUrl: string
  appearance?: Appearance
}

interface AuthContextValue {
  core: AuthCore
  snapshot: SessionSnapshot
  isLoaded: boolean
  loadState: LoadState
  config: AuthConfig
  connections: Connection[]
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function useAuthContext(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error("OpenAuthFederated: hooks and components must be used inside <ClerkProvider>.")
  }
  return ctx
}

export interface ClerkProviderProps {
  children: ReactNode
  /** Browser-safe publishable key (`pk_live_…` / `pk_test_…`). */
  publishableKey?: string
  /** Frontend API base, e.g. https://auth.whitehatengineering.com. */
  frontendApi?: string
  signInUrl?: string
  signUpUrl?: string
  afterSignOutUrl?: string
  appearance?: Appearance
  /** Local dev mock (no deployed server). The app passes VITE_AUTH_DEV_MODE. */
  devMode?: boolean
  /** The company domains presented as "global logins" (the two SSO connections). */
  allowedDomains?: string[]
  /** Shared HS256 secret used to mint dev JWTs; must match the backend's AUTH_DEV_SHARED_SECRET. */
  devSharedSecret?: string
}

/**
 * @deprecated Use {@link ClerkProviderProps}. Alias retained for existing imports.
 */
export type AuthProviderProps = ClerkProviderProps

/**
 * Root provider. Mirrors Clerk's `<ClerkProvider>` (clerk.com/docs/react/reference/components/
 * clerk-provider): wrap the app, pass `publishableKey` / `frontendApi`, and the hooks/components
 * become available. `<AuthProvider>` is kept as an alias.
 */
export function ClerkProvider(props: ClerkProviderProps): ReactNode {
  const coreRef = useRef<AuthCore | null>(null)
  if (!coreRef.current) {
    const domains =
      props.allowedDomains && props.allowedDomains.length > 0
        ? props.allowedDomains
        : ["act3ai.com", "whitehatengineering.com"]
    coreRef.current = props.devMode
      ? new DevAuthCore(
          domains,
          props.devSharedSecret ?? "dev-shared-secret",
          props.frontendApi ?? "https://auth.dev.local",
        )
      : new RealAuthCore(props.frontendApi ?? "", props.publishableKey ?? "", domains)
  }
  const core = coreRef.current

  const [isLoaded, setIsLoaded] = useState(false)
  useEffect(() => {
    let active = true
    core.load().finally(() => {
      if (active) setIsLoaded(true)
    })
    return () => {
      active = false
    }
  }, [core])

  const snapshot = useSyncExternalStore(
    (cb) => core.subscribe(cb),
    () => core.getSnapshot(),
    () => core.getSnapshot(),
  )

  const loadState = useSyncExternalStore(
    (cb) => core.subscribe(cb),
    () => core.loadState(),
    () => core.loadState(),
  )

  const value = useMemo<AuthContextValue>(
    () => ({
      core,
      snapshot,
      isLoaded,
      loadState,
      connections: core.connections(),
      config: {
        signInUrl: props.signInUrl ?? "/sign-in",
        signUpUrl: props.signUpUrl ?? "/sign-up",
        afterSignOutUrl: props.afterSignOutUrl ?? "/sign-in",
        appearance: props.appearance,
      },
    }),
    [
      core,
      snapshot,
      isLoaded,
      loadState,
      props.signInUrl,
      props.signUpUrl,
      props.afterSignOutUrl,
      props.appearance,
    ],
  )

  return <AuthContext.Provider value={value}>{props.children}</AuthContext.Provider>
}

/**
 * @deprecated Use {@link ClerkProvider}. Alias retained so existing `<AuthProvider>` usage keeps
 * working unchanged.
 */
export const AuthProvider = ClerkProvider
