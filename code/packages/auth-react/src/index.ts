// Root provider. `ClerkProvider` is the Clerk-exact name; `AuthProvider` is the kept alias.
export { ClerkProvider, AuthProvider, useAuthContext } from "./context.js"
export type { ClerkProviderProps, AuthProviderProps } from "./context.js"
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
  // `useClerk` is the Clerk-exact name; `useOpenAuth` is the kept alias.
  useClerk,
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
  // Clerk-named aliases for the load-state gates.
  AuthLoaded as ClerkLoaded,
  AuthLoading as ClerkLoading,
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
