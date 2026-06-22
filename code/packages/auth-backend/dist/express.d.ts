/**
 * Express adapter — the drop-in counterpart to `@clerk/express`
 * (clerk.com/docs/reference/express/{clerk-middleware,require-auth,get-auth}).
 *
 * Provides `clerkMiddleware()`, `requireAuth()`, and `getAuth(req)` with the same names, call
 * order, and semantics as Clerk's Express SDK, so a backend can swap `@clerk/express` for
 * `@auth/backend` without touching call sites:
 *
 * ```ts
 * import { clerkMiddleware, requireAuth, getAuth } from "@auth/backend"
 * app.use(clerkMiddleware())                 // attaches the Auth object to req.auth
 * app.get("/me", requireAuth(), (req, res) => res.json(getAuth(req)))
 * ```
 *
 * The library has no hard dependency on Express; the request/response are typed with the minimal
 * shapes these helpers actually touch, so they also work with any Express-compatible framework
 * (NestJS' underlying express, etc.).
 */
import { type AuthObject, type AuthRequestLike } from "./middleware.js";
import type { VerifyTokenOptions } from "./verify.js";
/** The minimal Express-like request these helpers read from / write `auth` onto. */
export interface ExpressLikeRequest extends AuthRequestLike {
    /** Populated by {@link clerkMiddleware}; read by {@link getAuth}. */
    auth?: AuthObject;
}
/** The minimal Express-like response these helpers write to when rejecting a request. */
export interface ExpressLikeResponse {
    statusCode?: number;
    setHeader(name: string, value: string): void;
    status?(code: number): ExpressLikeResponse;
    json?(body: unknown): unknown;
    end(body?: unknown): void;
}
type NextFn = (err?: unknown) => void;
/** Options accepted by {@link clerkMiddleware} / {@link requireAuth}. Superset is Clerk-compatible. */
export interface ClerkMiddlewareOptions extends VerifyTokenOptions {
    /** When set, {@link requireAuth} 302-redirects unauthenticated requests here (Clerk: `signInUrl`). */
    signInUrl?: string;
}
/**
 * Express middleware that authenticates the request and attaches the Clerk-style Auth object to
 * `req.auth`. Must run before any handler that calls {@link getAuth}. Never rejects — it only
 * resolves identity; use {@link requireAuth} to enforce it. Mirrors Clerk's `clerkMiddleware()`.
 */
export declare function clerkMiddleware(options?: ClerkMiddlewareOptions): (req: ExpressLikeRequest, _res: ExpressLikeResponse, next: NextFn) => void;
/**
 * Express middleware that protects a route: authenticates like {@link clerkMiddleware}, then
 * rejects unauthenticated requests. Mirrors Clerk's `requireAuth()` — when `signInUrl` is set it
 * 302-redirects (browser flows); otherwise it responds `401` (API flows). Authenticated requests
 * fall through with `req.auth` populated.
 */
export declare function requireAuth(options?: ClerkMiddlewareOptions): (req: ExpressLikeRequest, res: ExpressLikeResponse, next: NextFn) => void;
/**
 * Return the Clerk-style Auth object for a request. Reads what {@link clerkMiddleware} attached to
 * `req.auth`; if the middleware did not run, falls back to a synchronous best-effort read of the
 * Bearer token presence (a signed-out object when absent). Mirrors Clerk's `getAuth(req)`.
 */
export declare function getAuth(req: ExpressLikeRequest): AuthObject;
export {};
