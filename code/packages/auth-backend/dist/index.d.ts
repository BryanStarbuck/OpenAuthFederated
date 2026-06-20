import { AuthClient } from "./client.js";
import type { CreateAuthClientOptions } from "./types.js";
export { AuthClient } from "./client.js";
export type { AuthUser, AuthSession, AuthOrganization, ListResponse } from "./client.js";
export type { TokenClaims, CreateAuthClientOptions } from "./types.js";
export { verifyToken } from "./verify.js";
export { requirePermission, hasPermission } from "./permissions.js";
/** Construct a configured client. Reads AUTH_SECRET_KEY / AUTH_BACKEND_API when omitted. */
export declare function createAuthClient(options?: CreateAuthClientOptions): AuthClient;
export declare const authClient: AuthClient;
