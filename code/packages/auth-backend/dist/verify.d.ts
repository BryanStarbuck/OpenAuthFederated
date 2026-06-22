import type { MachineClaims, TokenClaims } from "./types.js";
/**
 * Options for {@link verifyToken}, mirroring Clerk's `verifyToken(token, options)`
 * (clerk.com/docs/reference/backend/verify-token). Embedded mode honours `issuer`; the remaining
 * Clerk keys are accepted for drop-in source-compatibility and applied where they have meaning in
 * networkless verification.
 */
export interface VerifyTokenOptions {
    /** Expected token issuer (`iss`). Defaults to AUTH_JWT_ISSUER. */
    issuer?: string;
    /** Expected audience (`aud`). Accepted for Clerk parity. */
    audience?: string | string[];
    /** Authorized parties (`azp`) accepted on the token. Accepted for Clerk parity. */
    authorizedParties?: string[];
    /** Clock-skew tolerance in ms (Clerk default 5000). Accepted for Clerk parity. */
    clockSkewInMs?: number;
    /** JWKS public key for networkless RS256 verification. Accepted for Clerk parity. */
    jwtKey?: string;
    /** Secret key override. Accepted for Clerk parity. */
    secretKey?: string;
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
export declare function verifyToken(token: string, opts?: VerifyTokenOptions): Promise<TokenClaims>;
/**
 * Verify a **machine** token — an M2M access token or an API key minted for server-to-server
 * calls (spec §15) — and return its claims. Verification follows the same path as a user
 * token (HS256 dev secret in dev mode, JWKS in production) but asserts `token_type` is
 * `machine` so a human session JWT can never be mistaken for a service credential.
 */
export declare function verifyMachineToken(token: string, opts?: VerifyTokenOptions): Promise<MachineClaims>;
/** True if `granted` covers the requested machine `scope` (exact or `*` super-scope). */
export declare function hasScope(granted: string[], scope: string): boolean;
