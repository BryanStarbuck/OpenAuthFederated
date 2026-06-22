"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authClient = exports.federatedClient = exports.createAuthClient = exports.OAuthCredentialsError = exports.credentialsRemediation = exports.assertGoogleCredentials = exports.loadGoogleCredentials = exports.validateSamlAcs = exports.samlSpMetadata = exports.samlLoginRedirectUrl = exports.buildSamlClient = exports.createAuthFrontend = exports.createFederatedFrontend = exports.getAuth = exports.requireAuth = exports.federatedMiddleware = exports.AuthError = exports.bearerToken = exports.authenticateRequest = exports.getRequestAuth = exports.createRouteMatcher = exports.authMiddleware = exports.checkClaims = exports.hasRole = exports.hasPermission = exports.requireRole = exports.requirePermission = exports.hasScope = exports.verifyMachineToken = exports.verifyToken = exports.FederatedClient = exports.AuthClient = void 0;
exports.createFederatedClient = createFederatedClient;
const client_js_1 = require("./client.js");
// The backend client. `FederatedClient` is the primary name; `AuthClient` is kept as an alias so
// existing imports keep resolving.
var client_js_2 = require("./client.js");
Object.defineProperty(exports, "AuthClient", { enumerable: true, get: function () { return client_js_2.AuthClient; } });
Object.defineProperty(exports, "FederatedClient", { enumerable: true, get: function () { return client_js_2.AuthClient; } });
var verify_js_1 = require("./verify.js");
Object.defineProperty(exports, "verifyToken", { enumerable: true, get: function () { return verify_js_1.verifyToken; } });
Object.defineProperty(exports, "verifyMachineToken", { enumerable: true, get: function () { return verify_js_1.verifyMachineToken; } });
Object.defineProperty(exports, "hasScope", { enumerable: true, get: function () { return verify_js_1.hasScope; } });
var permissions_js_1 = require("./permissions.js");
Object.defineProperty(exports, "requirePermission", { enumerable: true, get: function () { return permissions_js_1.requirePermission; } });
Object.defineProperty(exports, "requireRole", { enumerable: true, get: function () { return permissions_js_1.requireRole; } });
Object.defineProperty(exports, "hasPermission", { enumerable: true, get: function () { return permissions_js_1.hasPermission; } });
Object.defineProperty(exports, "hasRole", { enumerable: true, get: function () { return permissions_js_1.hasRole; } });
Object.defineProperty(exports, "checkClaims", { enumerable: true, get: function () { return permissions_js_1.checkClaims; } });
var middleware_js_1 = require("./middleware.js");
Object.defineProperty(exports, "authMiddleware", { enumerable: true, get: function () { return middleware_js_1.authMiddleware; } });
Object.defineProperty(exports, "createRouteMatcher", { enumerable: true, get: function () { return middleware_js_1.createRouteMatcher; } });
Object.defineProperty(exports, "getRequestAuth", { enumerable: true, get: function () { return middleware_js_1.getRequestAuth; } });
Object.defineProperty(exports, "authenticateRequest", { enumerable: true, get: function () { return middleware_js_1.authenticateRequest; } });
Object.defineProperty(exports, "bearerToken", { enumerable: true, get: function () { return middleware_js_1.bearerToken; } });
Object.defineProperty(exports, "AuthError", { enumerable: true, get: function () { return middleware_js_1.AuthError; } });
// Express adapter.
var express_js_1 = require("./express.js");
Object.defineProperty(exports, "federatedMiddleware", { enumerable: true, get: function () { return express_js_1.federatedMiddleware; } });
Object.defineProperty(exports, "requireAuth", { enumerable: true, get: function () { return express_js_1.requireAuth; } });
Object.defineProperty(exports, "getAuth", { enumerable: true, get: function () { return express_js_1.getAuth; } });
// Embedded Frontend API. `createFederatedFrontend` is the Federated-idiomatic name (connections[]);
// `createAuthFrontend` is the kept alias (also accepts the deprecated google/saml shorthand).
var frontend_js_1 = require("./frontend.js");
Object.defineProperty(exports, "createFederatedFrontend", { enumerable: true, get: function () { return frontend_js_1.createFederatedFrontend; } });
Object.defineProperty(exports, "createAuthFrontend", { enumerable: true, get: function () { return frontend_js_1.createAuthFrontend; } });
var saml_js_1 = require("./saml.js");
Object.defineProperty(exports, "buildSamlClient", { enumerable: true, get: function () { return saml_js_1.buildSamlClient; } });
Object.defineProperty(exports, "samlLoginRedirectUrl", { enumerable: true, get: function () { return saml_js_1.samlLoginRedirectUrl; } });
Object.defineProperty(exports, "samlSpMetadata", { enumerable: true, get: function () { return saml_js_1.samlSpMetadata; } });
Object.defineProperty(exports, "validateSamlAcs", { enumerable: true, get: function () { return saml_js_1.validateSamlAcs; } });
var credentials_js_1 = require("./credentials.js");
Object.defineProperty(exports, "loadGoogleCredentials", { enumerable: true, get: function () { return credentials_js_1.loadGoogleCredentials; } });
Object.defineProperty(exports, "assertGoogleCredentials", { enumerable: true, get: function () { return credentials_js_1.assertGoogleCredentials; } });
Object.defineProperty(exports, "credentialsRemediation", { enumerable: true, get: function () { return credentials_js_1.credentialsRemediation; } });
Object.defineProperty(exports, "OAuthCredentialsError", { enumerable: true, get: function () { return credentials_js_1.OAuthCredentialsError; } });
/**
 * Construct a configured backend client via `createFederatedClient(options)`. Reads
 * AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER when the matching option is omitted.
 */
function createFederatedClient(options = {}) {
    return new client_js_1.AuthClient(options);
}
/**
 * @deprecated Use {@link createFederatedClient}. Alias retained so existing `createAuthClient(...)`
 * call sites keep working unchanged.
 */
exports.createAuthClient = createFederatedClient;
// Preconfigured singleton for the common case. Lazily constructed on first use so the
// host's environment (e.g. NestJS ConfigModule loading .env) is in place before it reads
// AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER.
let singleton = null;
function instance() {
    if (!singleton)
        singleton = new client_js_1.AuthClient();
    return singleton;
}
/**
 * Preconfigured singleton client. `federatedClient` is the Federated-exact name; `authClient` is the kept
 * alias. Both proxy to the same lazily-constructed instance.
 */
exports.federatedClient = new Proxy({}, {
    get(_target, prop, receiver) {
        const value = Reflect.get(instance(), prop, receiver);
        return typeof value === "function" ? value.bind(instance()) : value;
    },
});
/**
 * @deprecated Use {@link federatedClient}. Alias retained so existing `authClient.*` call sites keep
 * working unchanged.
 */
exports.authClient = exports.federatedClient;
//# sourceMappingURL=index.js.map