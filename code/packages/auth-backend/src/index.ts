import { AuthClient } from "./client.js"
import type { CreateClerkClientOptions } from "./types.js"

// The backend client. `ClerkClient` is the Clerk-exact name; `AuthClient` is kept as an alias so
// the surface is a drop-in for `@clerk/backend` while existing imports keep resolving.
export { AuthClient, AuthClient as ClerkClient } from "./client.js"
export type {
  User,
  Session,
  Organization,
  OrganizationMembership,
  Invitation,
  JwtTemplate,
  PaginatedResourceResponse,
  // Deprecated aliases (Auth*-prefixed names + ListResponse) retained for existing imports.
  AuthUser,
  AuthSession,
  AuthOrganization,
  AuthMembership,
  AuthInvitation,
  AuthJwtTemplate,
  ListResponse,
} from "./client.js"
export type {
  TokenClaims,
  MachineClaims,
  PermissionCheck,
  CreateClerkClientOptions,
  CreateAuthClientOptions,
} from "./types.js"
export { verifyToken, verifyMachineToken, hasScope } from "./verify.js"
export type { VerifyTokenOptions } from "./verify.js"
export {
  requirePermission,
  requireRole,
  hasPermission,
  hasRole,
  checkClaims,
} from "./permissions.js"
export {
  authMiddleware,
  createRouteMatcher,
  getRequestAuth,
  authenticateRequest,
  bearerToken,
  AuthError,
} from "./middleware.js"
export type {
  AuthRequestLike,
  RouteMatcher,
  RequestAuth,
  AuthObject,
  RequestState,
} from "./middleware.js"
// Express adapter — drop-in for `@clerk/express`.
export { clerkMiddleware, requireAuth, getAuth } from "./express.js"
export type {
  ClerkMiddlewareOptions,
  ExpressLikeRequest,
  ExpressLikeResponse,
} from "./express.js"
// Embedded Frontend API. `createClerkFrontend` is the Clerk-idiomatic name (connections[]);
// `createAuthFrontend` is the kept alias (also accepts the deprecated google/saml shorthand).
export { createClerkFrontend, createAuthFrontend } from "./frontend.js"
export type {
  ClerkFrontendConfig,
  ClerkConnectionConfig,
  GoogleConnectionConfig,
  SamlConnectionConfig,
  LegacyGoogleConfig,
  AuthFrontendConfig,
  OidcIdentity,
  OrgMembership,
  ResolvedGrants,
} from "./frontend.js"
export {
  buildSamlClient,
  samlLoginRedirectUrl,
  samlSpMetadata,
  validateSamlAcs,
} from "./saml.js"
export type { SamlSpConfig, SamlAcsResult } from "./saml.js"
export {
  loadGoogleCredentials,
  assertGoogleCredentials,
  credentialsRemediation,
  OAuthCredentialsError,
} from "./credentials.js"
export type {
  GoogleCredentials,
  CredentialResolution,
  CredentialSource,
  LoadGoogleCredentialsOptions,
} from "./credentials.js"

/**
 * Construct a configured backend client. Mirrors Clerk's `createClerkClient(options)`
 * (clerk.com/docs/reference/backend/overview). Reads AUTH_SECRET_KEY / AUTH_BACKEND_API /
 * AUTH_JWT_ISSUER when the matching option is omitted.
 */
export function createClerkClient(options: CreateClerkClientOptions = {}): AuthClient {
  return new AuthClient(options)
}

/**
 * @deprecated Use {@link createClerkClient}. Alias retained so existing `createAuthClient(...)`
 * call sites keep working unchanged.
 */
export const createAuthClient = createClerkClient

// Preconfigured singleton for the common case. Lazily constructed on first use so the
// host's environment (e.g. NestJS ConfigModule loading .env) is in place before it reads
// AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER.
let singleton: AuthClient | null = null
function instance(): AuthClient {
  if (!singleton) singleton = new AuthClient()
  return singleton
}

/**
 * Preconfigured singleton client. `clerkClient` is the Clerk-exact name; `authClient` is the kept
 * alias. Both proxy to the same lazily-constructed instance.
 */
export const clerkClient: AuthClient = new Proxy({} as AuthClient, {
  get(_target, prop, receiver) {
    const value = Reflect.get(instance(), prop, receiver)
    return typeof value === "function" ? value.bind(instance()) : value
  },
})

/**
 * @deprecated Use {@link clerkClient}. Alias retained so existing `authClient.*` call sites keep
 * working unchanged.
 */
export const authClient: AuthClient = clerkClient
