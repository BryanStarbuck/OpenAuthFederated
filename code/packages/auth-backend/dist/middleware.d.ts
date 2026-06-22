import type { PermissionCheck, TokenClaims } from "./types.js";
import { type VerifyTokenOptions } from "./verify.js";
/**
 * Edge/route protection helpers — the backend counterpart to the `<Protect>` component and
 * the `auth().protect({ permission })` pattern documented in the capability spec (§9).
 *
 * These are framework-agnostic: they read the Bearer token off a minimal request shape, so
 * the same helpers drop into a NestJS guard, a Next.js Middleware, an Express handler, or a
 * Fetch-API route handler.
 */
/** The minimal request shape the matcher/middleware need — a method, URL, and headers. */
export interface AuthRequestLike {
    method?: string;
    url?: string;
    /** Either a Fetch `Headers` instance or a plain header map (e.g. Node's `req.headers`). */
    headers?: Headers | Record<string, string | string[] | undefined>;
}
/** A predicate that tells whether a request targets one of the configured route patterns. */
export type RouteMatcher = (req: AuthRequestLike) => boolean;
/**
 * Build a matcher from one or more route patterns, e.g.
 * `createRouteMatcher(['/api/invoices/create(.*)'])`. `(.*)` is the only supported wildcard,
 * matching the spec's example syntax.
 */
export declare function createRouteMatcher(patterns: string[]): RouteMatcher;
/** Extract a Bearer token from the `Authorization` header (or an explicit token). */
export declare function bearerToken(req: AuthRequestLike): string | null;
/** Thrown by `auth().protect(...)` when a request is unauthenticated or lacks a grant. */
export declare class AuthError extends Error {
    /** 401 when no/invalid token, 403 when authenticated but not authorized. */
    readonly status: 401 | 403;
    constructor(message: string, 
    /** 401 when no/invalid token, 403 when authenticated but not authorized. */
    status: 401 | 403);
}
/** The resolved auth context for a request, with a `protect()` assertion helper. */
export interface RequestAuth {
    /** Verified claims, or `null` if the request carried no valid token. */
    claims: TokenClaims | null;
    userId: string | null;
    orgId: string | null;
    /** Non-throwing role/permission check (mirrors the front-end `has()`). */
    has(check?: PermissionCheck): boolean;
    /**
     * Assert the request is authenticated and (optionally) satisfies a role/permission.
     * Throws {@link AuthError} (401 unauthenticated, 403 unauthorized) otherwise.
     */
    protect(check?: PermissionCheck): TokenClaims;
}
/**
 * Resolve the auth context for a request: verify the Bearer token (if any) and return a
 * {@link RequestAuth}. Never throws on a missing token — call `protect()` to enforce.
 */
export declare function getRequestAuth(req: AuthRequestLike, opts?: VerifyTokenOptions): Promise<RequestAuth>;
/**
 * The Clerk-style **Auth object** (clerk.com/docs/reference/backend/types/auth-object) returned
 * by `getAuth(req)` / `requestState.toAuth()`. Discriminated on `isAuthenticated`; signed-out
 * requests carry `null` ids. `has()` mirrors the frontend `has()`; `getToken()` returns the
 * verified Bearer token (embedded mode has no separate token-mint round trip).
 */
export interface AuthObject {
    isAuthenticated: boolean;
    userId: string | null;
    sessionId: string | null;
    orgId: string | null;
    /** The full verified claim set (Clerk: `sessionClaims`). */
    sessionClaims: TokenClaims | null;
    has(check?: PermissionCheck): boolean;
    getToken(): Promise<string | null>;
}
/**
 * The result of {@link authenticateRequest}, mirroring Clerk's `RequestState`
 * (clerk.com/docs/reference/backend/authenticate-request). Call `toAuth()` for the Auth object.
 */
export interface RequestState {
    isAuthenticated: boolean;
    status: "signed-in" | "signed-out";
    token: string | null;
    tokenType: "session_token";
    toAuth(): AuthObject;
}
/**
 * Authenticate an incoming request, mirroring Clerk's
 * `clerkClient.authenticateRequest(request, options)`. Verifies the Bearer token (if any) and
 * returns a {@link RequestState}; never throws on a missing/invalid token. Accepts either a Fetch
 * `Request` or the minimal {@link AuthRequestLike} shape.
 */
export declare function authenticateRequest(req: AuthRequestLike, opts?: VerifyTokenOptions): Promise<RequestState>;
/**
 * Compose route protection like the spec's Next.js example (§9):
 *
 * ```ts
 * const isWriteRoute = createRouteMatcher(['/api/invoices/create(.*)'])
 * export default authMiddleware((auth, req) => {
 *   if (isWriteRoute(req)) auth().protect({ permission: 'org:invoices:create' })
 * })
 * ```
 *
 * Returns an async handler `(req) => Promise<void>`. The supplied callback receives a
 * lazily-resolved `auth()` accessor and the request; throwing {@link AuthError} from
 * `protect()` is how a request is rejected. The framework adapter maps the error's `status`
 * to a response.
 */
export declare function authMiddleware(handler: (auth: () => RequestAuth, req: AuthRequestLike) => void | Promise<void>, opts?: VerifyTokenOptions): (req: AuthRequestLike) => Promise<void>;
