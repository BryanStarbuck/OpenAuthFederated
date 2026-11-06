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
export {
  verifyToken,
  verifyMachineToken,
  hasScope,
  configureEmbeddedVerification,
  // Build a verifier bound to ONE app's config — the multi-frontend-safe alternative to the
  // process-global `verifyToken`. `createFederatedFrontend()` returns one as `frontend.verifyToken`.
  createEmbeddedVerifier,
  // Diagnostics: how many issuers the (bounded) JWKS cache currently holds.
  jwksCacheSize,
} from "./verify.js"
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
  BrowserSession,
  FederatedFrontend,
  FederatedFrontendMiddleware,
  FederatedFrontendConfig,
  FederatedConnectionConfig,
  GoogleConnectionConfig,
  SamlConnectionConfig,
  XConnectionConfig,
  LegacyGoogleConfig,
  AuthFrontendConfig,
  OidcIdentity,
  OrgMembership,
  ResolvedGrants,
  RateLimitContext,
} from "./frontend.js"
// Admission: the app states who may sign in / sign up; the platform executes it. The pure helpers
// (parseEmail, matchIdentifier, decideRestrictions) let an app apply the same rule per request.
export {
  ADMISSION_API_VERSION,
  OafConfigError,
  parseEmail,
  matchIdentifier,
  decideRestrictions,
  connectionIdForDomain,
  DEFAULT_ADMISSION_MESSAGES,
} from "./admission.js"
export type {
  SignUpMode,
  Live,
  Restrictions,
  Identifier,
  IdentityProvider,
  AuthenticationMethod,
  ActionIdentity,
  UntrustedRequestHints,
  AdmissionPhase,
  AuthenticationActionContext,
  UserRegistrationActionContext,
  ActionVerdict,
  AdmissionActions,
  AdmissionUsers,
  AdmissionErrorCode,
  AdmissionMessage,
  IdentifierSpecificity,
  IdentifierMatch,
  MatchIdentifierOptions,
  RestrictionOutcome,
  AdmissionResult,
  AdmissionStep,
} from "./admission.js"
// The provider protocols on their own (authorize URL, PKCE, code exchange, verified identity), with
// no session, cookie or domain policy. createFederatedFrontend() is built on these; an app that keeps
// its own session model (its own accounts service) calls them directly.
export {
  createPkcePair,
  pkceChallenge,
  randomUrlToken,
  googleAuthorizeUrl,
  exchangeGoogleCode,
  xAuthorizeUrl,
  exchangeXCode,
  OAuthExchangeError,
  GOOGLE_ISSUERS,
  X_SCOPES,
} from "./oauth-providers.js"
export type {
  PkcePair,
  GoogleAuthorizeOptions,
  GoogleExchangeOptions,
  GoogleEndpoints,
  XAuthorizeOptions,
  XExchangeOptions,
  XExchangeResult,
  XEndpoints,
  OAuthExchangeErrorKind,
} from "./oauth-providers.js"
// Persistent, server-side session store (the stateful half of the session model).
// Pass a store to createFederatedFrontend({ sessionStore }) to make sessions survive app restarts
// and support revocation / listing / inactivity timeout.
export {
  FileSessionStore,
  InMemorySessionStore,
  loadOrCreateSecret,
} from "./session-store.js"
export type { SessionStore, StoredSession, SessionMembership } from "./session-store.js"
// The email connection: sign up and sign in with an email address (an emailed one-time code, and
// optionally a password). Pass `{ strategy: "email", sendCode, store }` in `connections`.
export {
  FileEmailAccountStore,
  InMemoryEmailAccountStore,
  hashPassword,
  verifyPassword,
  passwordProblem,
} from "./email-auth.js"
export type {
  EmailAccount,
  EmailAccountStore,
  EmailCodeMessage,
  EmailCodePurpose,
  EmailConnectionConfig,
  EmailDelivery,
  PendingEmailCode,
} from "./email-auth.js"
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
 * Construct a configured backend client via `createFederatedClient(options)`. All config (secretKey,
 * apiUrl, issuer) is supplied through `options` — the library reads no environment variables.
 */
export function createFederatedClient(options: CreateFederatedClientOptions = {}): AuthClient {
  return new AuthClient(options)
}

/**
 * @deprecated Use {@link createFederatedClient}. Alias retained so existing `createAuthClient(...)`
 * call sites keep working unchanged.
 */
export const createAuthClient = createFederatedClient

// Preconfigured singleton for the common case (lazily constructed on first use). It carries no
// secretKey/issuer — embedded-mode verification is configured by createFederatedFrontend() via
// configureEmbeddedVerification(), so federatedClient.verifyToken() works without per-client config.
// For authorized Backend REST calls, construct an explicit createFederatedClient({ secretKey, apiUrl }).
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
    // Resolve the singleton ONCE per access: `instance()` was called twice on every property read
    // (once for the lookup, once to bind), which is a lazy-init check and a call per access on a
    // proxy that fronts every backend API call.
    const client = instance()
    const value = Reflect.get(client, prop, receiver)
    return typeof value === "function" ? value.bind(client) : value
  },
})

/**
 * @deprecated Use {@link federatedClient}. Alias retained so existing `authClient.*` call sites keep
 * working unchanged.
 */
export const authClient: AuthClient = federatedClient
