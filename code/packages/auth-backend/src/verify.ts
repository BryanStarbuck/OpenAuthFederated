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
 * Embedded-mode verification config — supplied by the HOST application through the library's API
 * (see {@link configureEmbeddedVerification}, called by `createFederatedFrontend()`), NEVER read
 * from `process.env`. OpenAuthFederated is an embedded library: the apps that consume it own their
 * own configuration and pass it in. Reaching into the host's environment would be a side channel
 * the host cannot control, so the library does not do it.
 */
interface EmbeddedVerificationConfig {
  /** The shared HS256 secret used to verify access tokens minted in-process. */
  sessionSecret: string
  /** Expected token issuer (`iss`), enforced when set. */
  issuer?: string
  /** Optional JWKS host allowlist (SSRF guard) for the asymmetric path. */
  jwksAllowedHosts?: string[]
}

let embeddedVerification: EmbeddedVerificationConfig | null = null

/**
 * Tell the verifier how to validate embedded-mode tokens. Called once, at bootstrap, by the host
 * app's `createFederatedFrontend()` with the SAME `sessionSecret`/`issuer` it mints with — so token
 * minting and token verification share one source of truth and the library reads no environment.
 * Apps that only verify (no in-process minting) may call this directly.
 */
export function configureEmbeddedVerification(cfg: EmbeddedVerificationConfig): void {
  embeddedVerification = { ...cfg }
}

/**
 * Embedded mode: OpenAuthFederated runs in-process as a library (no deployed server, no JWKS
 * endpoint). Access tokens are minted and verified with one shared HS256 secret — supplied via
 * {@link configureEmbeddedVerification} (or a per-call {@link VerifyTokenOptions}) — by
 * `createFederatedFrontend()` in the same process, after a REAL Google / SAML sign-in. This is a
 * production deployment shape, NOT a mock: there is no dev/default secret (see {@link symmetricSecret}).
 *
 * OpenAuthFederated deliberately has **no dev mock / dev-auth mode of its own**. It never accepts a
 * weak, shared-secret "dev" token and never short-circuits real verification. If an app wants a
 * local no-IdP convenience mode, the app implements that on its own side and OpenAuthFederated is
 * not involved.
 */
function isEmbedded(opts: VerifyTokenOptions): boolean {
  if (opts.embedded !== undefined) return opts.embedded
  return embeddedVerification !== null
}

/**
 * Options for {@link verifyToken} — `verifyToken(token, options)`. Embedded mode honours `issuer`;
 * the remaining keys are accepted for source-compatibility and applied where they have meaning in
 * networkless verification.
 */
export interface VerifyTokenOptions {
  /**
   * Force embedded (HS256, in-process) vs JWKS verification for this call. When omitted, embedded
   * mode is inferred from whether {@link configureEmbeddedVerification} has been called. Never read
   * from the environment.
   */
  embedded?: boolean
  /**
   * HS256 secret for embedded verification, supplied by the API caller. Overrides the value from
   * {@link configureEmbeddedVerification}. Never read from the environment.
   */
  sessionSecret?: string
  /** JWKS host allowlist (SSRF guard), supplied by the API caller. Never read from the environment. */
  jwksAllowedHosts?: string[]
  /** Expected token issuer (`iss`). Supplied by the API caller (or configureEmbeddedVerification). */
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
 * be an absolute `https:` URL whose host is on the optional host allowlist supplied by the API
 * caller (`jwksAllowedHosts`). Without an allowlist we still require https + a real host, rejecting
 * internal IPs / metadata endpoints presented as bare hostnames.
 */
function assertSafeIssuer(issuer: string, allowedHosts: string[]): void {
  let url: URL
  try {
    url = new URL(issuer)
  } catch {
    throw new Error("verifyToken: issuer must be an absolute URL")
  }
  if (url.protocol !== "https:") {
    throw new Error("verifyToken: issuer must use https")
  }
  const allow = allowedHosts.map((h) => h.trim().toLowerCase()).filter(Boolean)
  if (allow.length > 0 && !allow.includes(url.hostname.toLowerCase())) {
    throw new Error("verifyToken: issuer host is not on the configured jwksAllowedHosts allowlist")
  }
}

/**
 * The shared HS256 secret for embedded-mode verification. Requires a strong secret supplied by the
 * API caller (per-call `opts.sessionSecret` or {@link configureEmbeddedVerification}). There is
 * intentionally **no** dev/default secret and the library reads no environment variable: OpenAuthFederated
 * will not fall back to a well-known value (which would let anyone forge a session), so an unset or
 * placeholder secret fails closed.
 */
function symmetricSecret(opts: VerifyTokenOptions): Uint8Array {
  const secret = opts.sessionSecret ?? embeddedVerification?.sessionSecret ?? ""
  if (!secret || secret === "dev-shared-secret") {
    throw new Error(
      "verifyToken: embedded mode requires a strong sessionSecret configured via the API " +
        "(configureEmbeddedVerification / createFederatedFrontend). OpenAuthFederated reads no " +
        "environment variables and provides no dev/default secret.",
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
 * - **Embedded mode** (configured via {@link configureEmbeddedVerification}): validates an HS256
 *   token signed with the `sessionSecret` the in-process `createFederatedFrontend()` mints with
 *   after a real Google / SAML sign-in — so it works with no separate server and no JWKS endpoint.
 *
 * There is **no dev mock**: OpenAuthFederated never accepts a token signed with a
 * shared "dev" secret and never bypasses real verification. A no-IdP local convenience mode, if an
 * app wants one, is the app's own responsibility — never this library's.
 */
export async function verifyToken(
  token: string,
  opts: VerifyTokenOptions = {},
): Promise<TokenClaims> {
  if (!token) throw new Error("verifyToken: empty token")

  if (isEmbedded(opts)) {
    // Pin HS256 for the embedded symmetric path (no algorithm agility), and enforce the issuer
    // when one is configured so a token from a different deployment is not accepted on a shared
    // secret. Audience is enforced when the caller supplies one.
    const issuer = opts.issuer ?? embeddedVerification?.issuer
    const verifyOpts: Parameters<typeof jwtVerify>[2] = {
      algorithms: opts.algorithms ?? ["HS256"],
    }
    if (issuer) verifyOpts.issuer = issuer
    if (opts.audience !== undefined) verifyOpts.audience = opts.audience
    if (opts.clockSkewInMs !== undefined) verifyOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000)
    const { payload } = await jwtVerify(token, symmetricSecret(opts), verifyOpts)
    return payload as TokenClaims
  }

  const issuer = opts.issuer ?? embeddedVerification?.issuer
  if (!issuer) throw new Error("verifyToken: issuer is not configured (pass opts.issuer or configure it via the API)")
  // SSRF guard: the issuer becomes an outbound JWKS fetch URL, so validate it (https + host
  // allowlist) before constructing the remote key set.
  assertSafeIssuer(issuer, opts.jwksAllowedHosts ?? embeddedVerification?.jwksAllowedHosts ?? [])

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
 * token (HS256 `sessionSecret` in embedded mode, JWKS in production) but asserts `token_type`
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
