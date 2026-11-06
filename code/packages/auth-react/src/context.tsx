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
import { RealAuthCore } from "./core.js"
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
    throw new Error("OpenAuthFederated: hooks and components must be used inside <FederatedProvider>.")
  }
  return ctx
}

export interface FederatedProviderProps {
  children: ReactNode
  /** Browser-safe publishable key (`pk_live_…` / `pk_test_…`). */
  publishableKey?: string
  /** Frontend API base, e.g. https://auth.example.com or a same-origin path like "/api". */
  frontendApi?: string
  signInUrl?: string
  signUpUrl?: string
  afterSignOutUrl?: string
  appearance?: Appearance
  /**
   * The sign-in buttons (Google, X, SAML, or Google with a hint domain). Takes precedence over
   * everything else; an EMPTY array shows no buttons. When omitted (and no `allowedDomains`), the
   * server's `/environment` connections are used, else one generic Google button.
   */
  connections?: Connection[]
  /** @deprecated Use {@link connections}. One Google button per domain (`Continue with <domain>`). */
  allowedDomains?: string[]
  /**
   * Inject a custom {@link AuthCore} instead of the default real Frontend-API client. This is the
   * generic extension seam an embedding app uses to supply its OWN core — e.g. a localhost-only dev
   * sign-in core, which the app may engage only under its own gate (running on localhost AND no
   * credentials file). OpenAuthFederated ships no dev/mock core: when this is omitted it always
   * builds {@link RealAuthCore}. When provided, the app owns the gate — never this library.
   */
  core?: AuthCore
}

/**
 * @deprecated Use {@link FederatedProviderProps}. Alias retained for existing imports.
 */
export type AuthProviderProps = FederatedProviderProps

/**
 * Root provider `<FederatedProvider>`: wrap the app, pass `publishableKey` / `frontendApi`, and the
 * hooks/components become available. `<AuthProvider>` is kept as an alias.
 */
export function FederatedProvider(props: FederatedProviderProps): ReactNode {
  const coreRef = useRef<AuthCore | null>(null)
  if (!coreRef.current) {
    // Default to the real federated client. OpenAuthFederated ships no dev mock and NO default
    // domain list: the buttons come from the app (connections / allowedDomains), the server's
    // /environment, or one generic Google button. An app that wants a localhost-only dev core builds
    // its own and injects it via `core` (gated on its own side).
    coreRef.current =
      props.core ??
      new RealAuthCore(props.frontendApi ?? "", props.publishableKey ?? "", props.allowedDomains, props.connections)
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

  // ONE subscription, not two. Subscribing separately for `snapshot` and `loadState` registered two
  // listeners per provider and walked the listener set twice on every emit, for two values that
  // always change together and always come from the same store.
  const subscribe = useMemo(() => (cb: () => void) => core.subscribe(cb), [core])
  const snapshot = useSyncExternalStore(
    subscribe,
    () => core.getSnapshot(),
    () => core.getSnapshot(),
  )
  const loadState = useSyncExternalStore(
    subscribe,
    () => core.loadState(),
    () => core.loadState(),
  )

  // `connections` is a stable, frozen reference that changes at most once (when the server's
  // /environment supplies the buttons), so reading it through the store costs nothing per render.
  const connections = useSyncExternalStore(
    subscribe,
    () => core.connections(),
    () => core.connections(),
  )

  const value = useMemo<AuthContextValue>(
    () => ({
      core,
      snapshot,
      isLoaded,
      loadState,
      connections,
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
      connections,
      props.signInUrl,
      props.signUpUrl,
      props.afterSignOutUrl,
      props.appearance,
    ],
  )

  return <AuthContext.Provider value={value}>{props.children}</AuthContext.Provider>
}

/**
 * @deprecated Use {@link FederatedProvider}. Alias retained so existing `<AuthProvider>` usage keeps
 * working unchanged.
 */
export const AuthProvider = FederatedProvider
