import { AuthClient } from "./client.js"
import type { CreateAuthClientOptions } from "./types.js"

export { AuthClient } from "./client.js"
export type {
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
  CreateAuthClientOptions,
} from "./types.js"
export { verifyToken, verifyMachineToken, hasScope } from "./verify.js"
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
  bearerToken,
  AuthError,
} from "./middleware.js"
export type { AuthRequestLike, RouteMatcher, RequestAuth } from "./middleware.js"
export { createAuthFrontend } from "./frontend.js"
export type {
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

/** Construct a configured client. Reads AUTH_SECRET_KEY / AUTH_BACKEND_API when omitted. */
export function createAuthClient(options: CreateAuthClientOptions = {}): AuthClient {
  return new AuthClient(options)
}

// Preconfigured singleton for the common case. Lazily constructed on first use so the
// host's environment (e.g. NestJS ConfigModule loading .env) is in place before it reads
// AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER.
let singleton: AuthClient | null = null
function instance(): AuthClient {
  if (!singleton) singleton = new AuthClient()
  return singleton
}

export const authClient: AuthClient = new Proxy({} as AuthClient, {
  get(_target, prop, receiver) {
    const value = Reflect.get(instance(), prop, receiver)
    return typeof value === "function" ? value.bind(instance()) : value
  },
})
