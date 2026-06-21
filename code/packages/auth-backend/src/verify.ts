import type { MachineClaims, TokenClaims } from "./types.js"

// `jose` is ESM-only. Loading it through a real dynamic import() keeps this package
// consumable from a CommonJS host (NestJS) — NodeNext preserves import() verbatim.
type Jose = typeof import("jose")
let josePromise: Promise<Jose> | null = null
function jose(): Promise<Jose> {
  if (!josePromise) josePromise = import("jose")
  return josePromise
}

/** Per-issuer remote JWKS set, cached so verification is networkless after the first call. */
const jwksCache = new Map<string, ReturnType<Jose["createRemoteJWKSet"]>>()

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
  opts: { issuer?: string } = {},
): Promise<TokenClaims> {
  if (!token) throw new Error("verifyToken: empty token")
  const { jwtVerify, createRemoteJWKSet } = await jose()

  if (isDevMode() || isEmbedded()) {
    const { payload } = await jwtVerify(token, symmetricSecret())
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
  const { payload } = await jwtVerify(token, jwks, { issuer })
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
  opts: { issuer?: string } = {},
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
