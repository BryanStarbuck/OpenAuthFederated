import { AuthClient } from "./client.js";
import type { CreateFederatedClientOptions } from "./types.js";
export { AuthClient, AuthClient as FederatedClient } from "./client.js";
export type { User, Session, Organization, OrganizationMembership, Invitation, JwtTemplate, PaginatedResourceResponse, AuthUser, AuthSession, AuthOrganization, AuthMembership, AuthInvitation, AuthJwtTemplate, ListResponse, } from "./client.js";
export type { TokenClaims, MachineClaims, PermissionCheck, CreateFederatedClientOptions, CreateAuthClientOptions, } from "./types.js";
export { verifyToken, verifyMachineToken, hasScope } from "./verify.js";
export type { VerifyTokenOptions } from "./verify.js";
export { requirePermission, requireRole, hasPermission, hasRole, checkClaims, } from "./permissions.js";
export { authMiddleware, createRouteMatcher, getRequestAuth, authenticateRequest, bearerToken, AuthError, } from "./middleware.js";
export type { AuthRequestLike, RouteMatcher, RequestAuth, AuthObject, RequestState, } from "./middleware.js";
export { federatedMiddleware, requireAuth, getAuth } from "./express.js";
export type { FederatedMiddlewareOptions, ExpressLikeRequest, ExpressLikeResponse, } from "./express.js";
export { createFederatedFrontend, createAuthFrontend } from "./frontend.js";
export type { FederatedFrontendConfig, FederatedConnectionConfig, GoogleConnectionConfig, SamlConnectionConfig, LegacyGoogleConfig, AuthFrontendConfig, OidcIdentity, OrgMembership, ResolvedGrants, } from "./frontend.js";
export { FileSessionStore, InMemorySessionStore, loadOrCreateSecret, } from "./session-store.js";
export type { SessionStore, StoredSession, SessionMembership } from "./session-store.js";
export { buildSamlClient, samlLoginRedirectUrl, samlSpMetadata, validateSamlAcs, } from "./saml.js";
export type { SamlSpConfig, SamlAcsResult } from "./saml.js";
export { loadGoogleCredentials, assertGoogleCredentials, credentialsRemediation, OAuthCredentialsError, } from "./credentials.js";
export type { GoogleCredentials, CredentialResolution, CredentialSource, LoadGoogleCredentialsOptions, } from "./credentials.js";
/**
 * Construct a configured backend client via `createFederatedClient(options)`. Reads
 * AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER when the matching option is omitted.
 */
export declare function createFederatedClient(options?: CreateFederatedClientOptions): AuthClient;
/**
 * @deprecated Use {@link createFederatedClient}. Alias retained so existing `createAuthClient(...)`
 * call sites keep working unchanged.
 */
export declare const createAuthClient: typeof createFederatedClient;
/**
 * Preconfigured singleton client. `federatedClient` is the Federated-exact name; `authClient` is the kept
 * alias. Both proxy to the same lazily-constructed instance.
 */
export declare const federatedClient: AuthClient;
/**
 * @deprecated Use {@link federatedClient}. Alias retained so existing `authClient.*` call sites keep
 * working unchanged.
 */
export declare const authClient: AuthClient;
