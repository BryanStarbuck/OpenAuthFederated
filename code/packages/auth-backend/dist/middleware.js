"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthError = void 0;
exports.createRouteMatcher = createRouteMatcher;
exports.bearerToken = bearerToken;
exports.getRequestAuth = getRequestAuth;
exports.authenticateRequest = authenticateRequest;
exports.authMiddleware = authMiddleware;
const permissions_js_1 = require("./permissions.js");
const verify_js_1 = require("./verify.js");
function patternToRegExp(pattern) {
    // Glob-ish: `(.*)` already valid; escape the rest, then restore `(.*)`.
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\\\(\.\\\*\\\)/g, "(.*)");
    return new RegExp(`^${escaped}$`);
}
function pathOf(req) {
    const raw = req.url ?? "/";
    try {
        return new URL(raw, "http://internal").pathname;
    }
    catch {
        return raw.split("?")[0] ?? raw;
    }
}
/**
 * Build a matcher from one or more route patterns, e.g.
 * `createRouteMatcher(['/api/invoices/create(.*)'])`. `(.*)` is the only supported wildcard,
 * matching the spec's example syntax.
 */
function createRouteMatcher(patterns) {
    const regexes = patterns.map(patternToRegExp);
    return (req) => {
        const path = pathOf(req);
        return regexes.some((re) => re.test(path));
    };
}
function readHeader(req, name) {
    const headers = req.headers;
    if (!headers)
        return undefined;
    if (typeof headers.get === "function") {
        return headers.get(name) ?? undefined;
    }
    const map = headers;
    const value = map[name] ?? map[name.toLowerCase()];
    return Array.isArray(value) ? value[0] : value;
}
/** Extract a Bearer token from the `Authorization` header (or an explicit token). */
function bearerToken(req) {
    const header = readHeader(req, "authorization") ?? readHeader(req, "Authorization");
    if (!header)
        return null;
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    return match ? (match[1] ?? null) : null;
}
/** Thrown by `auth().protect(...)` when a request is unauthenticated or lacks a grant. */
class AuthError extends Error {
    status;
    constructor(message, 
    /** 401 when no/invalid token, 403 when authenticated but not authorized. */
    status) {
        super(message);
        this.status = status;
        this.name = "AuthError";
    }
}
exports.AuthError = AuthError;
function buildAuth(claims) {
    return {
        claims,
        userId: claims?.sub ?? null,
        orgId: claims?.org_id ?? null,
        has(check = {}) {
            return claims ? (0, permissions_js_1.checkClaims)(claims, check) : false;
        },
        protect(check = {}) {
            if (!claims)
                throw new AuthError("Unauthenticated", 401);
            if (!(0, permissions_js_1.checkClaims)(claims, check))
                throw new AuthError("Forbidden", 403);
            return claims;
        },
    };
}
/**
 * Resolve the auth context for a request: verify the Bearer token (if any) and return a
 * {@link RequestAuth}. Never throws on a missing token — call `protect()` to enforce.
 */
async function getRequestAuth(req, opts = {}) {
    const token = bearerToken(req);
    if (!token)
        return buildAuth(null);
    try {
        return buildAuth(await (0, verify_js_1.verifyToken)(token, opts));
    }
    catch {
        return buildAuth(null);
    }
}
function buildAuthObject(claims, token) {
    return {
        isAuthenticated: Boolean(claims),
        userId: claims?.sub ?? null,
        sessionId: claims?.sid ?? null,
        orgId: claims?.org_id ?? null,
        sessionClaims: claims,
        has(check = {}) {
            return claims ? (0, permissions_js_1.checkClaims)(claims, check) : false;
        },
        async getToken() {
            return token;
        },
    };
}
/**
 * Authenticate an incoming request, mirroring Clerk's
 * `clerkClient.authenticateRequest(request, options)`. Verifies the Bearer token (if any) and
 * returns a {@link RequestState}; never throws on a missing/invalid token. Accepts either a Fetch
 * `Request` or the minimal {@link AuthRequestLike} shape.
 */
async function authenticateRequest(req, opts = {}) {
    const token = bearerToken(req);
    let claims = null;
    if (token) {
        try {
            claims = await (0, verify_js_1.verifyToken)(token, opts);
        }
        catch {
            claims = null;
        }
    }
    const isAuthenticated = Boolean(claims);
    return {
        isAuthenticated,
        status: isAuthenticated ? "signed-in" : "signed-out",
        token,
        tokenType: "session_token",
        toAuth: () => buildAuthObject(claims, token),
    };
}
/**
 * Compose route protection like the spec's Next.js example (§9):
 *
 * ```ts
 * const isWriteRoute = createRouteMatcher(['/api/invoices/create(.*)'])
 * export default authMiddleware((auth, req) => {
 *   if (isWriteRoute(req)) auth().protect({ permission: 'org:invoices:create' })
 * })
 * ```
 *
 * Returns an async handler `(req) => Promise<void>`. The supplied callback receives a
 * lazily-resolved `auth()` accessor and the request; throwing {@link AuthError} from
 * `protect()` is how a request is rejected. The framework adapter maps the error's `status`
 * to a response.
 */
function authMiddleware(handler, opts = {}) {
    return async (req) => {
        const resolved = await getRequestAuth(req, opts);
        await handler(() => resolved, req);
    };
}
//# sourceMappingURL=middleware.js.map