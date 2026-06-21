import type { MachineClaims, TokenClaims } from "./types.js";
/**
 * Verify a short-lived JWT access token and return its claims.
 *
 * - **Production:** validates the RS256 signature against the issuer's JWKS
 *   (`<issuer>/.well-known/jwks.json`) and checks `iss`/`exp`. No per-request round
 *   trip — the JWKS is cached.
 * - **Dev mode** (`AUTH_DEV_MODE=true`): validates an HS256 token signed with
 *   `AUTH_DEV_SHARED_SECRET` — the same secret the `@auth/react` dev client mints with —
 *   so the whole flow works locally with no deployed server.
 */
export declare function verifyToken(token: string, opts?: {
    issuer?: string;
}): Promise<TokenClaims>;
/**
 * Verify a **machine** token — an M2M access token or an API key minted for server-to-server
 * calls (spec §15) — and return its claims. Verification follows the same path as a user
 * token (HS256 dev secret in dev mode, JWKS in production) but asserts `token_type` is
 * `machine` so a human session JWT can never be mistaken for a service credential.
 */
export declare function verifyMachineToken(token: string, opts?: {
    issuer?: string;
}): Promise<MachineClaims>;
/** True if `granted` covers the requested machine `scope` (exact or `*` super-scope). */
export declare function hasScope(granted: string[], scope: string): boolean;
