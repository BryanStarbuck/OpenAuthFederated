"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyToken = verifyToken;
exports.verifyMachineToken = verifyMachineToken;
exports.hasScope = hasScope;
const jose_1 = require("jose");
// `jose` v5 is a dual ESM/CJS package (its package.json `exports` has a `require` entry), so a
// plain static import is safe from a CommonJS host (NestJS): NodeNext compiles this to
// `require("jose")`, which resolves to jose's CJS build. We deliberately do NOT use a dynamic
// `import("jose")` here — under any vm-based module loader without `importModuleDynamically`
// (notably jest/ts-jest's CJS sandbox), a runtime `import()` throws
// ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG.
/** Per-issuer remote JWKS set, cached so verification is networkless after the first call. */
const jwksCache = new Map();
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
function isEmbedded() {
    return process.env.AUTH_EMBEDDED === "true";
}
/**
 * The shared HS256 secret for embedded-mode verification. Requires a strong, operator-supplied
 * `AUTH_SESSION_SECRET`. There is intentionally **no** dev/default secret: OpenAuthFederated will
 * not fall back to a well-known value (which would let anyone forge a session), so an unset or
 * placeholder secret fails closed.
 */
function symmetricSecret() {
    const secret = process.env.AUTH_SESSION_SECRET ?? "";
    if (!secret || secret === "dev-shared-secret") {
        throw new Error("verifyToken: embedded mode requires a strong AUTH_SESSION_SECRET. OpenAuthFederated " +
            "provides no dev/default secret and never falls back to one.");
    }
    return new TextEncoder().encode(secret);
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
async function verifyToken(token, opts = {}) {
    if (!token)
        throw new Error("verifyToken: empty token");
    if (isEmbedded()) {
        const verifyOpts = {};
        if (opts.audience !== undefined)
            verifyOpts.audience = opts.audience;
        if (opts.clockSkewInMs !== undefined)
            verifyOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000);
        const { payload } = await (0, jose_1.jwtVerify)(token, symmetricSecret(), verifyOpts);
        return payload;
    }
    const issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER;
    if (!issuer)
        throw new Error("verifyToken: AUTH_JWT_ISSUER is not set");
    let jwks = jwksCache.get(issuer);
    if (!jwks) {
        const url = new URL(`${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`);
        jwks = (0, jose_1.createRemoteJWKSet)(url);
        jwksCache.set(issuer, jwks);
    }
    const jwksOpts = { issuer };
    if (opts.audience !== undefined)
        jwksOpts.audience = opts.audience;
    if (opts.clockSkewInMs !== undefined)
        jwksOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000);
    const { payload } = await (0, jose_1.jwtVerify)(token, jwks, jwksOpts);
    return payload;
}
/**
 * Verify a **machine** token — an M2M access token or an API key minted for server-to-server
 * calls (spec §15) — and return its claims. Verification follows the same path as a user
 * token (HS256 `AUTH_SESSION_SECRET` in embedded mode, JWKS in production) but asserts `token_type`
 * is `machine` so a human session JWT can never be mistaken for a service credential.
 */
async function verifyMachineToken(token, opts = {}) {
    const claims = (await verifyToken(token, opts));
    if (claims.token_type !== "machine") {
        throw new Error("verifyMachineToken: not a machine token");
    }
    return claims;
}
/** True if `granted` covers the requested machine `scope` (exact or `*` super-scope). */
function hasScope(granted, scope) {
    if (!scope)
        return true;
    return granted.includes(scope) || granted.includes("*");
}
//# sourceMappingURL=verify.js.map