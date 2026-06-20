"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyToken = verifyToken;
let josePromise = null;
function jose() {
    if (!josePromise)
        josePromise = import("jose");
    return josePromise;
}
/** Per-issuer remote JWKS set, cached so verification is networkless after the first call. */
const jwksCache = new Map();
function isDevMode() {
    return process.env.AUTH_DEV_MODE === "true";
}
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
async function verifyToken(token, opts = {}) {
    if (!token)
        throw new Error("verifyToken: empty token");
    const { jwtVerify, createRemoteJWKSet } = await jose();
    if (isDevMode()) {
        const secret = process.env.AUTH_DEV_SHARED_SECRET ?? "dev-shared-secret";
        const key = new TextEncoder().encode(secret);
        const { payload } = await jwtVerify(token, key);
        return payload;
    }
    const issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER;
    if (!issuer)
        throw new Error("verifyToken: AUTH_JWT_ISSUER is not set");
    let jwks = jwksCache.get(issuer);
    if (!jwks) {
        const url = new URL(`${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`);
        jwks = createRemoteJWKSet(url);
        jwksCache.set(issuer, jwks);
    }
    const { payload } = await jwtVerify(token, jwks, { issuer });
    return payload;
}
//# sourceMappingURL=verify.js.map