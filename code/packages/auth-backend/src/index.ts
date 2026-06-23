import { AuthClient } from "./client.js"
import type { CreateFederatedClientOptions } from "./types.js"

// The backend client. `FederatedClient` is the primary name; `AuthClient` is kept as an alias so
// existing imports keep resolving.
export { AuthClient, AuthClient as FederatedClient, verifyWebhook } from "./client.js"
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
  CreateFederatedClientOptions,
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
// Express adapter.
export { federatedMiddleware, requireAuth, getAuth } from "./express.js"
export type {
  FederatedMiddlewareOptions,
  ExpressLikeRequest,
  ExpressLikeResponse,
} from "./express.js"
// Embedded Frontend API. `createFederatedFrontend` is the Federated-idiomatic name (connections[]);
// `createAuthFrontend` is the kept alias (also accepts the deprecated google/saml shorthand).
export { createFederatedFrontend, createAuthFrontend } from "./frontend.js"
export type {
  FederatedFrontendConfig,
  FederatedConnectionConfig,
  GoogleConnectionConfig,
  SamlConnectionConfig,
  LegacyGoogleConfig,
  AuthFrontendConfig,
  OidcIdentity,
  OrgMembership,
  ResolvedGrants,
} from "./frontend.js"
// Persistent, server-side session store (the stateful half of the Clerk-style session model).
// Pass a store to createFederatedFrontend({ sessionStore }) to make sessions survive app restarts
// and support revocation / listing / inactivity timeout.
export {
  FileSessionStore,
  InMemorySessionStore,
  loadOrCreateSecret,
} from "./session-store.js"
export type { SessionStore, StoredSession, SessionMembership } from "./session-store.js"
export {
  buildSamlClient,
  samlLoginRedirectUrl,
  samlSpMetadata,
  validateSamlAcs,
  InMemorySamlReplayStore,
} from "./saml.js"
export type { SamlSpConfig, SamlAcsResult, SamlReplayStore } from "./saml.js"
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
 * Construct a configured backend client via `createFederatedClient(options)`. Reads
 * AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER when the matching option is omitted.
 */
export function createFederatedClient(options: CreateFederatedClientOptions = {}): AuthClient {
  return new AuthClient(options)
}

/**
 * @deprecated Use {@link createFederatedClient}. Alias retained so existing `createAuthClient(...)`
 * call sites keep working unchanged.
 */
export const createAuthClient = createFederatedClient

// Preconfigured singleton for the common case. Lazily constructed on first use so the
// host's environment (e.g. NestJS ConfigModule loading .env) is in place before it reads
// AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER.
let singleton: AuthClient | null = null
function instance(): AuthClient {
  if (!singleton) singleton = new AuthClient()
  return singleton
}

/**
 * Preconfigured singleton client. `federatedClient` is the Federated-exact name; `authClient` is the kept
 * alias. Both proxy to the same lazily-constructed instance.
 */
export const federatedClient: AuthClient = new Proxy({} as AuthClient, {
  get(_target, prop, receiver) {
    const value = Reflect.get(instance(), prop, receiver)
    return typeof value === "function" ? value.bind(instance()) : value
  },
})

/**
 * @deprecated Use {@link federatedClient}. Alias retained so existing `authClient.*` call sites keep
 * working unchanged.
 */
export const authClient: AuthClient = federatedClient
