import { AuthClient } from "./client.js";
import type { CreateAuthClientOptions } from "./types.js";
export { AuthClient } from "./client.js";
export type { AuthUser, AuthSession, AuthOrganization, AuthMembership, AuthInvitation, AuthJwtTemplate, ListResponse, } from "./client.js";
export type { TokenClaims, MachineClaims, PermissionCheck, CreateAuthClientOptions, } from "./types.js";
export { verifyToken, verifyMachineToken, hasScope } from "./verify.js";
export { requirePermission, requireRole, hasPermission, hasRole, checkClaims, } from "./permissions.js";
export { authMiddleware, createRouteMatcher, getRequestAuth, bearerToken, AuthError, } from "./middleware.js";
export type { AuthRequestLike, RouteMatcher, RequestAuth } from "./middleware.js";
export { createAuthFrontend } from "./frontend.js";
export type { AuthFrontendConfig, OidcIdentity, OrgMembership, ResolvedGrants, } from "./frontend.js";
/** Construct a configured client. Reads AUTH_SECRET_KEY / AUTH_BACKEND_API when omitted. */
export declare function createAuthClient(options?: CreateAuthClientOptions): AuthClient;
export declare const authClient: AuthClient;
