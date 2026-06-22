// Root provider. `FederatedProvider` is the Federated-exact name; `AuthProvider` is the kept alias.
export { FederatedProvider, AuthProvider, useAuthContext } from "./context.js"
export type { FederatedProviderProps, AuthProviderProps } from "./context.js"
export {
  useAuth,
  useUser,
  useSession,
  useSessionList,
  useSignIn,
  useSignUp,
  useOrganization,
  useOrganizationList,
  useReverification,
  // `useFederated` is the Federated-exact name; `useOpenAuth` is the kept alias.
  useFederated,
  useOpenAuth,
} from "./hooks.js"
export {
  SignIn,
  SignUp,
  SignInButton,
  SignUpButton,
  SignOutButton,
  UserButton,
  GoogleOneTap,
  AuthenticateWithRedirectCallback,
  readAuthError,
  useAuthError,
  Protect,
  Show,
  SignedIn,
  SignedOut,
  RedirectToSignIn,
  RedirectToSignUp,
  AuthLoaded,
  AuthLoading,
  AuthDegraded,
  AuthFailed,
  // Federated-named aliases for the load-state gates.
  AuthLoaded as FederatedLoaded,
  AuthLoading as FederatedLoading,
  OrganizationSwitcher,
  OrganizationList,
  OrganizationProfile,
  CreateOrganization,
} from "./components.js"
export { hasPermission, hasRole } from "./types.js"
export type {
  Appearance,
  AuthRejection,
  AuthRejectionMeta,
  Connection,
  LoadState,
  RedirectCallbackResult,
  SdkUser,
  SdkOrganization,
  SdkMembership,
  SessionSnapshot,
  PermissionCheck,
} from "./types.js"
