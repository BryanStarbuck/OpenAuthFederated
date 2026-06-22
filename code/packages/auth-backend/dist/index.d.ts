import { AuthClient } from "./client.js";
import type { CreateClerkClientOptions } from "./types.js";
export { AuthClient, AuthClient as ClerkClient } from "./client.js";
export type { User, Session, Organization, OrganizationMembership, Invitation, JwtTemplate, PaginatedResourceResponse, AuthUser, AuthSession, AuthOrganization, AuthMembership, AuthInvitation, AuthJwtTemplate, ListResponse, } from "./client.js";
export type { TokenClaims, MachineClaims, PermissionCheck, CreateClerkClientOptions, CreateAuthClientOptions, } from "./types.js";
export { verifyToken, verifyMachineToken, hasScope } from "./verify.js";
export type { VerifyTokenOptions } from "./verify.js";
export { requirePermission, requireRole, hasPermission, hasRole, checkClaims, } from "./permissions.js";
export { authMiddleware, createRouteMatcher, getRequestAuth, authenticateRequest, bearerToken, AuthError, } from "./middleware.js";
export type { AuthRequestLike, RouteMatcher, RequestAuth, AuthObject, RequestState, } from "./middleware.js";
export { clerkMiddleware, requireAuth, getAuth } from "./express.js";
export type { ClerkMiddlewareOptions, ExpressLikeRequest, ExpressLikeResponse, } from "./express.js";
export { createClerkFrontend, createAuthFrontend } from "./frontend.js";
export type { ClerkFrontendConfig, ClerkConnectionConfig, GoogleConnectionConfig, SamlConnectionConfig, LegacyGoogleConfig, AuthFrontendConfig, OidcIdentity, OrgMembership, ResolvedGrants, } from "./frontend.js";
export { buildSamlClient, samlLoginRedirectUrl, samlSpMetadata, validateSamlAcs, } from "./saml.js";
export type { SamlSpConfig, SamlAcsResult } from "./saml.js";
export { loadGoogleCredentials, assertGoogleCredentials, credentialsRemediation, OAuthCredentialsError, } from "./credentials.js";
export type { GoogleCredentials, CredentialResolution, CredentialSource, LoadGoogleCredentialsOptions, } from "./credentials.js";
/**
 * Construct a configured backend client. Mirrors Clerk's `createClerkClient(options)`
 * (clerk.com/docs/reference/backend/overview). Reads AUTH_SECRET_KEY / AUTH_BACKEND_API /
 * AUTH_JWT_ISSUER when the matching option is omitted.
 */
export declare function createClerkClient(options?: CreateClerkClientOptions): AuthClient;
/**
 * @deprecated Use {@link createClerkClient}. Alias retained so existing `createAuthClient(...)`
 * call sites keep working unchanged.
 */
export declare const createAuthClient: typeof createClerkClient;
/**
 * Preconfigured singleton client. `clerkClient` is the Clerk-exact name; `authClient` is the kept
 * alias. Both proxy to the same lazily-constructed instance.
 */
export declare const clerkClient: AuthClient;
/**
 * @deprecated Use {@link clerkClient}. Alias retained so existing `authClient.*` call sites keep
 * working unchanged.
 */
export declare const authClient: AuthClient;
