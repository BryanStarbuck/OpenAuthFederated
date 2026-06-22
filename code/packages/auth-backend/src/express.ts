/**
 * Express adapter.
 *
 * Provides `federatedMiddleware()`, `requireAuth()`, and `getAuth(req)`, all imported from
 * `@auth/backend`:
 *
 * ```ts
 * import { federatedMiddleware, requireAuth, getAuth } from "@auth/backend"
 * app.use(federatedMiddleware())                 // attaches the Auth object to req.auth
 * app.get("/me", requireAuth(), (req, res) => res.json(getAuth(req)))
 * ```
 *
 * The library has no hard dependency on Express; the request/response are typed with the minimal
 * shapes these helpers actually touch, so they also work with any Express-compatible framework
 * (NestJS' underlying express, etc.).
 */

import { authenticateRequest, bearerToken, type AuthObject, type AuthRequestLike } from "./middleware.js"
import type { VerifyTokenOptions } from "./verify.js"

/** The minimal Express-like request these helpers read from / write `auth` onto. */
export interface ExpressLikeRequest extends AuthRequestLike {
  /** Populated by {@link federatedMiddleware}; read by {@link getAuth}. */
  auth?: AuthObject
}

/** The minimal Express-like response these helpers write to when rejecting a request. */
export interface ExpressLikeResponse {
  statusCode?: number
  setHeader(name: string, value: string): void
  status?(code: number): ExpressLikeResponse
  json?(body: unknown): unknown
  end(body?: unknown): void
}

type NextFn = (err?: unknown) => void

/** Options accepted by {@link federatedMiddleware} / {@link requireAuth}. Superset is Federated-compatible. */
export interface FederatedMiddlewareOptions extends VerifyTokenOptions {
  /** When set, {@link requireAuth} 302-redirects unauthenticated requests here (Federated: `signInUrl`). */
  signInUrl?: string
}

const SIGNED_OUT: AuthObject = {
  isAuthenticated: false,
  userId: null,
  sessionId: null,
  orgId: null,
  sessionClaims: null,
  has: () => false,
  getToken: async () => null,
}

/**
 * Express middleware that authenticates the request and attaches the Federated-style Auth object to
 * `req.auth`. Must run before any handler that calls {@link getAuth}. Never rejects — it only
 * resolves identity; use {@link requireAuth} to enforce it. Mirrors Federated's `federatedMiddleware()`.
 */
export function federatedMiddleware(options: FederatedMiddlewareOptions = {}) {
  return (req: ExpressLikeRequest, _res: ExpressLikeResponse, next: NextFn): void => {
    authenticateRequest(req, options)
      .then((state) => {
        req.auth = state.toAuth()
        next()
      })
      .catch(() => {
        req.auth = SIGNED_OUT
        next()
      })
  }
}

/**
 * Express middleware that protects a route: authenticates like {@link federatedMiddleware}, then
 * rejects unauthenticated requests. Mirrors Federated's `requireAuth()` — when `signInUrl` is set it
 * 302-redirects (browser flows); otherwise it responds `401` (API flows). Authenticated requests
 * fall through with `req.auth` populated.
 */
export function requireAuth(options: FederatedMiddlewareOptions = {}) {
  return (req: ExpressLikeRequest, res: ExpressLikeResponse, next: NextFn): void => {
    authenticateRequest(req, options)
      .then((state) => {
        req.auth = state.toAuth()
        if (state.isAuthenticated) return next()
        if (options.signInUrl) {
          res.statusCode = 302
          res.setHeader("Location", options.signInUrl)
          res.end()
          return
        }
        res.statusCode = 401
        res.setHeader("Content-Type", "application/json; charset=utf-8")
        res.end(JSON.stringify({ error: "unauthenticated" }))
      })
      .catch((err) => next(err))
  }
}

/**
 * Return the Federated-style Auth object for a request. Reads what {@link federatedMiddleware} attached to
 * `req.auth`; if the middleware did not run, falls back to a synchronous best-effort read of the
 * Bearer token presence (a signed-out object when absent). Mirrors Federated's `getAuth(req)`.
 */
export function getAuth(req: ExpressLikeRequest): AuthObject {
  if (req.auth) return req.auth
  // federatedMiddleware wasn't mounted — return signed-out rather than throw, but keep the token
  // around so callers that only check `isAuthenticated` behave predictably.
  return bearerToken(req) ? { ...SIGNED_OUT } : SIGNED_OUT
}
