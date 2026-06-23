"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.configureEmbeddedVerification = configureEmbeddedVerification;
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
let embeddedVerification = null;
/**
 * Tell the verifier how to validate embedded-mode tokens. Called once, at bootstrap, by the host
 * app's `createFederatedFrontend()` with the SAME `sessionSecret`/`issuer` it mints with — so token
 * minting and token verification share one source of truth and the library reads no environment.
 * Apps that only verify (no in-process minting) may call this directly.
 */
function configureEmbeddedVerification(cfg) {
    embeddedVerification = { ...cfg };
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
function isEmbedded(opts) {
    if (opts.embedded !== undefined)
        return opts.embedded;
    return embeddedVerification !== null;
}
/**
 * Validate that an issuer string is safe to turn into an outbound JWKS fetch (SSRF guard): it must
 * be an absolute `https:` URL whose host is on the optional host allowlist supplied by the API
 * caller (`jwksAllowedHosts`). Without an allowlist we still require https + a real host, rejecting
 * internal IPs / metadata endpoints presented as bare hostnames.
 */
function assertSafeIssuer(issuer, allowedHosts) {
    let url;
    try {
        url = new URL(issuer);
    }
    catch {
        throw new Error("verifyToken: issuer must be an absolute URL");
    }
    if (url.protocol !== "https:") {
        throw new Error("verifyToken: issuer must use https");
    }
    const allow = allowedHosts.map((h) => h.trim().toLowerCase()).filter(Boolean);
    if (allow.length > 0 && !allow.includes(url.hostname.toLowerCase())) {
        throw new Error("verifyToken: issuer host is not on the configured jwksAllowedHosts allowlist");
    }
}
/**
 * The shared HS256 secret for embedded-mode verification. Requires a strong secret supplied by the
 * API caller (per-call `opts.sessionSecret` or {@link configureEmbeddedVerification}). There is
 * intentionally **no** dev/default secret and the library reads no environment variable: OpenAuthFederated
 * will not fall back to a well-known value (which would let anyone forge a session), so an unset or
 * placeholder secret fails closed.
 */
function symmetricSecret(opts) {
    const secret = opts.sessionSecret ?? embeddedVerification?.sessionSecret ?? "";
    if (!secret || secret === "dev-shared-secret") {
        throw new Error("verifyToken: embedded mode requires a strong sessionSecret configured via the API " +
            "(configureEmbeddedVerification / createFederatedFrontend). OpenAuthFederated reads no " +
            "environment variables and provides no dev/default secret.");
    }
    return new TextEncoder().encode(secret);
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
async function verifyToken(token, opts = {}) {
    if (!token)
        throw new Error("verifyToken: empty token");
    if (isEmbedded(opts)) {
        // Pin HS256 for the embedded symmetric path (no algorithm agility), and enforce the issuer
        // when one is configured so a token from a different deployment is not accepted on a shared
        // secret. Audience is enforced when the caller supplies one.
        const issuer = opts.issuer ?? embeddedVerification?.issuer;
        const verifyOpts = {
            algorithms: opts.algorithms ?? ["HS256"],
        };
        if (issuer)
            verifyOpts.issuer = issuer;
        if (opts.audience !== undefined)
            verifyOpts.audience = opts.audience;
        if (opts.clockSkewInMs !== undefined)
            verifyOpts.clockTolerance = Math.ceil(opts.clockSkewInMs / 1000);
        const { payload } = await (0, jose_1.jwtVerify)(token, symmetricSecret(opts), verifyOpts);
        return payload;
    }
    const issuer = opts.issuer ?? embeddedVerification?.issuer;
    if (!issuer)
        throw new Error("verifyToken: issuer is not configured (pass opts.issuer or configure it via the API)");
    // SSRF guard: the issuer becomes an outbound JWKS fetch URL, so validate it (https + host
    // allowlist) before constructing the remote key set.
    assertSafeIssuer(issuer, opts.jwksAllowedHosts ?? embeddedVerification?.jwksAllowedHosts ?? []);
    let jwks = jwksCache.get(issuer);
    if (!jwks) {
        const url = new URL(`${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`);
        jwks = (0, jose_1.createRemoteJWKSet)(url);
        jwksCache.set(issuer, jwks);
    }
    const jwksOpts = {
        issuer,
        algorithms: opts.algorithms ?? ["RS256"],
    };
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
 * token (HS256 `sessionSecret` in embedded mode, JWKS in production) but asserts `token_type`
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