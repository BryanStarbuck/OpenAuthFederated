import type { MachineClaims, TokenClaims } from "./types.js";
/**
 * Embedded-mode verification config — supplied by the HOST application through the library's API
 * (see {@link configureEmbeddedVerification}, called by `createFederatedFrontend()`), NEVER read
 * from `process.env`. OpenAuthFederated is an embedded library: the apps that consume it own their
 * own configuration and pass it in. Reaching into the host's environment would be a side channel
 * the host cannot control, so the library does not do it.
 */
interface EmbeddedVerificationConfig {
    /** The shared HS256 secret used to verify access tokens minted in-process. */
    sessionSecret: string;
    /** Expected token issuer (`iss`), enforced when set. */
    issuer?: string;
    /** Optional JWKS host allowlist (SSRF guard) for the asymmetric path. */
    jwksAllowedHosts?: string[];
}
/**
 * Tell the verifier how to validate embedded-mode tokens. Called once, at bootstrap, by the host
 * app's `createFederatedFrontend()` with the SAME `sessionSecret`/`issuer` it mints with — so token
 * minting and token verification share one source of truth and the library reads no environment.
 * Apps that only verify (no in-process minting) may call this directly.
 */
export declare function configureEmbeddedVerification(cfg: EmbeddedVerificationConfig): void;
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
    embedded?: boolean;
    /**
     * HS256 secret for embedded verification, supplied by the API caller. Overrides the value from
     * {@link configureEmbeddedVerification}. Never read from the environment.
     */
    sessionSecret?: string;
    /** JWKS host allowlist (SSRF guard), supplied by the API caller. Never read from the environment. */
    jwksAllowedHosts?: string[];
    /** Expected token issuer (`iss`). Supplied by the API caller (or configureEmbeddedVerification). */
    issuer?: string;
    /** Expected audience (`aud`). Accepted for Federated parity. */
    audience?: string | string[];
    /** Authorized parties (`azp`) accepted on the token. Accepted for Federated parity. */
    authorizedParties?: string[];
    /** Clock-skew tolerance in ms (Federated default 5000). Accepted for Federated parity. */
    clockSkewInMs?: number;
    /** JWKS public key for networkless RS256 verification. Accepted for Federated parity. */
    jwtKey?: string;
    /** Secret key override. Accepted for Federated parity. */
    secretKey?: string;
    /**
     * Signing algorithms to accept. Defaults to `['HS256']` in embedded mode and `['RS256']` on the
     * JWKS path. Pinning the algorithm closes the classic RS/HS confusion (and any future
     * algorithm-agility) hole: the verifier never follows the token's own `alg` header.
     */
    algorithms?: string[];
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
export declare function verifyToken(token: string, opts?: VerifyTokenOptions): Promise<TokenClaims>;
/**
 * Verify a **machine** token — an M2M access token or an API key minted for server-to-server
 * calls (spec §15) — and return its claims. Verification follows the same path as a user
 * token (HS256 `sessionSecret` in embedded mode, JWKS in production) but asserts `token_type`
 * is `machine` so a human session JWT can never be mistaken for a service credential.
 */
export declare function verifyMachineToken(token: string, opts?: VerifyTokenOptions): Promise<MachineClaims>;
/** True if `granted` covers the requested machine `scope` (exact or `*` super-scope). */
export declare function hasScope(granted: string[], scope: string): boolean;
export {};
