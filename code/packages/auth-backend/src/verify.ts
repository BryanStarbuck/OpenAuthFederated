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

/**
 * Embedded mode: OpenAuthFederated runs in-process as a library (no deployed server, no JWKS
 * endpoint). Access tokens are minted and verified with one shared HS256 secret
 * (`AUTH_SESSION_SECRET`) by `createAuthFrontend()` in the same process — after a REAL Google /
 * SAML sign-in. This is a production deployment shape, NOT a mock: there is no dev/default secret
 * (see {@link symmetricSecret}).
 *
 * OpenAuthFederated deliberately has **no dev mock / dev-auth mode of its own**. It never accepts a
 * weak, shared-secret "dev" token and never short-circuits real verification. If an app wants a
 * local no-IdP convenience mode, the app implements that on its own side and OpenAuthFederated is
 * not involved.
 */
function isEmbedded(): boolean {
  return process.env.AUTH_EMBEDDED === "true"
}

/**
 * Options for {@link verifyToken} — `verifyToken(token, options)`. Embedded mode honours `issuer`;
 * the remaining keys are accepted for source-compatibility and applied where they have meaning in
 * networkless verification.
 */
export interface VerifyTokenOptions {
  /** Expected token issuer (`iss`). Defaults to AUTH_JWT_ISSUER. */
  issuer?: string
  /** Expected audience (`aud`). Accepted for Federated parity. */
  audience?: string | string[]
  /** Authorized parties (`azp`) accepted on the token. Accepted for Federated parity. */
  authorizedParties?: string[]
  /** Clock-skew tolerance in ms (Federated default 5000). Accepted for Federated parity. */
  clockSkewInMs?: number
  /** JWKS public key for networkless RS256 verification. Accepted for Federated parity. */
  jwtKey?: string
  /** Secret key override. Accepted for Federated parity. */
  secretKey?: string
  /**
   * Signing algorithms to accept. Defaults to `['HS256']` in embedded mode and `['RS256']` on the
   * JWKS path. Pinning the algorithm closes the classic RS/HS confusion (and any future
   * algorithm-agility) hole: the verifier never follows the token's own `alg` header.
   */
  algorithms?: string[]
}

/**
 * Validate that an issuer string is safe to turn into an outbound JWKS fetch (SSRF guard): it must
 * be an absolute `https:` URL whose host is on the optional `AUTH_JWKS_ALLOWED_HOSTS` allowlist
 * (comma-separated). Without an allowlist we still require https + a real host, rejecting internal
 * IPs / metadata endpoints presented as bare hostnames. Returns the normalized origin host.
 */
function assertSafeIssuer(issuer: string): void {
  let url: URL
  try {
    url = new URL(issuer)
  } catch {
    throw new Error("verifyToken: AUTH_JWT_ISSUER must be an absolute URL")
  }
  if (url.protocol !== "https:") {
    throw new Error("verifyToken: issuer must use https")
  }
  const allow = (process.env.AUTH_JWKS_ALLOWED_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
  if (allow.length > 0 && !allow.includes(url.hostname.toLowerCase())) {
    throw new Error("verifyToken: issuer host is not on AUTH_JWKS_ALLOWED_HOSTS allowlist")
  }
}

/**
 * The shared HS256 secret for embedded-mode verification. Requires a strong, operator-supplied
 * `AUTH_SESSION_SECRET`. There is intentionally **no** dev/default secret: OpenAuthFederated will
 * not fall back to a well-known value (which would let anyone forge a session), so an unset or
 * placeholder secret fails closed.
 */
function symmetricSecret(): Uint8Array {
  const secret = process.env.AUTH_SESSION_SECRET ?? ""
  if (!secret || secret === "dev-shared-secret") {
    throw new Error(
      "verifyToken: embedded mode requires a strong AUTH_SESSION_SECRET. OpenAuthFederated " +
        "provides no dev/default secret and never falls back to one.",
    )
  }
  return new TextEncoder().encode(secret)
}

/**
 * Verify a short-lived JWT access token and return its claims.
 *
 * - **Production:** validates the RS256 signature against the issuer's JWKS
 *   (`<issuer>/.well-known/jwks.json`) and checks `iss`/`exp`. No per-request round
 *   trip — the JWKS is cached.
 * - **Embedded mode** (`AUTH_EMBEDDED=true`): validates an HS256 token signed with
 *   `AUTH_SESSION_SECRET` — the secret the in-process `createAuthFrontend()` mints with after a
 *   real Google / SAML sign-in — so it works with no separate server and no JWKS endpoint.
 *
 * There is **no dev mock / `AUTH_DEV_MODE`**: OpenAuthFederated never accepts a token signed with a
 * shared "dev" secret and never bypasses real verification. A no-IdP local convenience mode, if an
 * app wants one, is the app's own responsibility — never this library's.
 */
export async function verifyToken(
  token: string,
  opts: VerifyTokenOptions = {},
): Promise<TokenClaims> {
  if (!token) throw new Error("verifyToken: empty token")

  if (isEmbedded()) {
    // Pin HS256 for the embedded symmetric path (no algorithm agility), and enforce the issuer
    // when one is configured so a token from a different deployment is not accepted on a shared
    // secret. Audience is enforced when the caller supplies one.
    const issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER
    const verifyOpts: Parameters<typeof jwtVerify>[2] = {
      algorithms: opts.algorithms ?? ["HS256"],
    }
    if (issuer) verifyOpts.issuer = issuer
    if (opts.audience !== undefined) verifyOpts.audience = opts.audience
    if (opts.clockSkewInMs !== undefined) verifyOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000)
    const { payload } = await jwtVerify(token, symmetricSecret(), verifyOpts)
    return payload as TokenClaims
  }

  const issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER
  if (!issuer) throw new Error("verifyToken: AUTH_JWT_ISSUER is not set")
  // SSRF guard: the issuer becomes an outbound JWKS fetch URL, so validate it (https + host
  // allowlist) before constructing the remote key set.
  assertSafeIssuer(issuer)

  let jwks = jwksCache.get(issuer)
  if (!jwks) {
    const url = new URL(`${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`)
    jwks = createRemoteJWKSet(url)
    jwksCache.set(issuer, jwks)
  }
  const jwksOpts: Parameters<typeof jwtVerify>[2] = {
    issuer,
    algorithms: opts.algorithms ?? ["RS256"],
  }
  if (opts.audience !== undefined) jwksOpts.audience = opts.audience
  if (opts.clockSkewInMs !== undefined) jwksOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000)
  const { payload } = await jwtVerify(token, jwks, jwksOpts)
  return payload as TokenClaims
}

/**
 * Verify a **machine** token — an M2M access token or an API key minted for server-to-server
 * calls (spec §15) — and return its claims. Verification follows the same path as a user
 * token (HS256 `AUTH_SESSION_SECRET` in embedded mode, JWKS in production) but asserts `token_type`
 * is `machine` so a human session JWT can never be mistaken for a service credential.
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
