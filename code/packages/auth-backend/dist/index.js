"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authClient = exports.CREDENTIALS_APP_KEY = exports.CREDENTIALS_PATH_ENV = exports.DEFAULT_CREDENTIALS_PATH = exports.OAuthCredentialsError = exports.credentialsRemediation = exports.resolveCredentialsPath = exports.assertGoogleCredentials = exports.googleCredentialsFromFile = exports.loadGoogleCredentials = exports.validateSamlAcs = exports.samlSpMetadata = exports.samlLoginRedirectUrl = exports.buildSamlClient = exports.createAuthFrontend = exports.AuthError = exports.bearerToken = exports.getRequestAuth = exports.createRouteMatcher = exports.authMiddleware = exports.checkClaims = exports.hasRole = exports.hasPermission = exports.requireRole = exports.requirePermission = exports.hasScope = exports.verifyMachineToken = exports.verifyToken = exports.AuthClient = void 0;
exports.createAuthClient = createAuthClient;
const client_js_1 = require("./client.js");
var client_js_2 = require("./client.js");
Object.defineProperty(exports, "AuthClient", { enumerable: true, get: function () { return client_js_2.AuthClient; } });
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
Object.defineProperty(exports, "bearerToken", { enumerable: true, get: function () { return middleware_js_1.bearerToken; } });
Object.defineProperty(exports, "AuthError", { enumerable: true, get: function () { return middleware_js_1.AuthError; } });
var frontend_js_1 = require("./frontend.js");
Object.defineProperty(exports, "createAuthFrontend", { enumerable: true, get: function () { return frontend_js_1.createAuthFrontend; } });
var saml_js_1 = require("./saml.js");
Object.defineProperty(exports, "buildSamlClient", { enumerable: true, get: function () { return saml_js_1.buildSamlClient; } });
Object.defineProperty(exports, "samlLoginRedirectUrl", { enumerable: true, get: function () { return saml_js_1.samlLoginRedirectUrl; } });
Object.defineProperty(exports, "samlSpMetadata", { enumerable: true, get: function () { return saml_js_1.samlSpMetadata; } });
Object.defineProperty(exports, "validateSamlAcs", { enumerable: true, get: function () { return saml_js_1.validateSamlAcs; } });
var credentials_js_1 = require("./credentials.js");
Object.defineProperty(exports, "loadGoogleCredentials", { enumerable: true, get: function () { return credentials_js_1.loadGoogleCredentials; } });
Object.defineProperty(exports, "googleCredentialsFromFile", { enumerable: true, get: function () { return credentials_js_1.googleCredentialsFromFile; } });
Object.defineProperty(exports, "assertGoogleCredentials", { enumerable: true, get: function () { return credentials_js_1.assertGoogleCredentials; } });
Object.defineProperty(exports, "resolveCredentialsPath", { enumerable: true, get: function () { return credentials_js_1.resolveCredentialsPath; } });
Object.defineProperty(exports, "credentialsRemediation", { enumerable: true, get: function () { return credentials_js_1.credentialsRemediation; } });
Object.defineProperty(exports, "OAuthCredentialsError", { enumerable: true, get: function () { return credentials_js_1.OAuthCredentialsError; } });
Object.defineProperty(exports, "DEFAULT_CREDENTIALS_PATH", { enumerable: true, get: function () { return credentials_js_1.DEFAULT_CREDENTIALS_PATH; } });
Object.defineProperty(exports, "CREDENTIALS_PATH_ENV", { enumerable: true, get: function () { return credentials_js_1.CREDENTIALS_PATH_ENV; } });
Object.defineProperty(exports, "CREDENTIALS_APP_KEY", { enumerable: true, get: function () { return credentials_js_1.CREDENTIALS_APP_KEY; } });
/** Construct a configured client. Reads AUTH_SECRET_KEY / AUTH_BACKEND_API when omitted. */
function createAuthClient(options = {}) {
    return new client_js_1.AuthClient(options);
}
// Preconfigured singleton for the common case. Lazily constructed on first use so the
// host's environment (e.g. NestJS ConfigModule loading .env) is in place before it reads
// AUTH_SECRET_KEY / AUTH_BACKEND_API / AUTH_JWT_ISSUER.
let singleton = null;
function instance() {
    if (!singleton)
        singleton = new client_js_1.AuthClient();
    return singleton;
}
exports.authClient = new Proxy({}, {
    get(_target, prop, receiver) {
        const value = Reflect.get(instance(), prop, receiver);
        return typeof value === "function" ? value.bind(instance()) : value;
    },
});
//# sourceMappingURL=index.js.map