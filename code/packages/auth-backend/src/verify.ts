import { createRemoteJWKSet, jwtVerify } from "jose"

import type { MachineClaims, TokenClaims } from "./types.js"

// `jose` v5 is a dual ESM/CJS package (its package.json `exports` has a `require` entry), so a
// plain static import is safe from a CommonJS host (NestJS): NodeNext compiles this to
// `require("jose")`, which resolves to jose's CJS build. We deliberately do NOT use a dynamic
// `import("jose")` here — under any vm-based module loader without `importModuleDynamically`
// (notably jest/ts-jest's CJS sandbox), a runtime `import()` throws
// ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG.

/** Per-issuer remote JWKS set, cached so verification is networkless after the first call. */
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function isDevMode(): boolean {
  return process.env.AUTH_DEV_MODE === "true"
}

/**
 * Embedded mode: OpenAuthFederated runs in-process as a library (no deployed server, no JWKS
 * endpoint). Access tokens are minted and verified with one shared HS256 secret
 * (`AUTH_SESSION_SECRET`) by `createAuthFrontend()` in the same process.
 */
function isEmbedded(): boolean {
  return process.env.AUTH_EMBEDDED === "true"
}

/**
 * Options for {@link verifyToken}, mirroring Clerk's `verifyToken(token, options)`
 * (clerk.com/docs/reference/backend/verify-token). Embedded mode honours `issuer`; the remaining
 * Clerk keys are accepted for drop-in source-compatibility and applied where they have meaning in
 * networkless verification.
 */
export interface VerifyTokenOptions {
  /** Expected token issuer (`iss`). Defaults to AUTH_JWT_ISSUER. */
  issuer?: string
  /** Expected audience (`aud`). Accepted for Clerk parity. */
  audience?: string | string[]
  /** Authorized parties (`azp`) accepted on the token. Accepted for Clerk parity. */
  authorizedParties?: string[]
  /** Clock-skew tolerance in ms (Clerk default 5000). Accepted for Clerk parity. */
  clockSkewInMs?: number
  /** JWKS public key for networkless RS256 verification. Accepted for Clerk parity. */
  jwtKey?: string
  /** Secret key override. Accepted for Clerk parity. */
  secretKey?: string
}

/** The shared HS256 secret for symmetric (dev / embedded) verification. */
function symmetricSecret(): Uint8Array {
  const secret = isEmbedded()
    ? process.env.AUTH_SESSION_SECRET ?? process.env.AUTH_DEV_SHARED_SECRET ?? "dev-shared-secret"
    : process.env.AUTH_DEV_SHARED_SECRET ?? "dev-shared-secret"
  return new TextEncoder().encode(secret)
}

/**
 * Verify a short-lived JWT access token and return its claims.
 *
 * - **Production:** validates the RS256 signature against the issuer's JWKS
 *   (`<issuer>/.well-known/jwks.json`) and checks `iss`/`exp`. No per-request round
 *   trip — the JWKS is cached.
 * - **Embedded mode** (`AUTH_EMBEDDED=true`): validates an HS256 token signed with
 *   `AUTH_SESSION_SECRET` — the secret the in-process `createAuthFrontend()` mints with — so a
 *   real Google sign-in works with no separate server and no JWKS endpoint.
 * - **Dev mode** (`AUTH_DEV_MODE=true`): validates an HS256 token signed with
 *   `AUTH_DEV_SHARED_SECRET` — the same secret the `@auth/react` dev client mints with —
 *   so the whole flow works locally with no deployed server.
 */
export async function verifyToken(
  token: string,
  opts: VerifyTokenOptions = {},
): Promise<TokenClaims> {
  if (!token) throw new Error("verifyToken: empty token")

  if (isDevMode() || isEmbedded()) {
    const verifyOpts: Parameters<typeof jwtVerify>[2] = {}
    if (opts.audience !== undefined) verifyOpts.audience = opts.audience
    if (opts.clockSkewInMs !== undefined) verifyOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000)
    const { payload } = await jwtVerify(token, symmetricSecret(), verifyOpts)
    return payload as TokenClaims
  }

  const issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER
  if (!issuer) throw new Error("verifyToken: AUTH_JWT_ISSUER is not set")

  let jwks = jwksCache.get(issuer)
  if (!jwks) {
    const url = new URL(`${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`)
    jwks = createRemoteJWKSet(url)
    jwksCache.set(issuer, jwks)
  }
  const jwksOpts: Parameters<typeof jwtVerify>[2] = { issuer }
  if (opts.audience !== undefined) jwksOpts.audience = opts.audience
  if (opts.clockSkewInMs !== undefined) jwksOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000)
  const { payload } = await jwtVerify(token, jwks, jwksOpts)
  return payload as TokenClaims
}

/**
 * Verify a **machine** token — an M2M access token or an API key minted for server-to-server
 * calls (spec §15) — and return its claims. Verification follows the same path as a user
 * token (HS256 dev secret in dev mode, JWKS in production) but asserts `token_type` is
 * `machine` so a human session JWT can never be mistaken for a service credential.
 */
export async function verifyMachineToken(
  token: string,
  opts: VerifyTokenOptions = {},
): Promise<MachineClaims> {
  const claims = (await verifyToken(token, opts)) as unknown as MachineClaims
  if (claims.token_type !== "machine") {
    throw new Error("verifyMachineToken: not a machine token")
  }
  return claims
}

/** True if `granted` covers the requested machine `scope` (exact or `*` super-scope). */
export function hasScope(granted: string[], scope: string): boolean {
  if (!scope) return true
  return granted.includes(scope) || granted.includes("*")
}
