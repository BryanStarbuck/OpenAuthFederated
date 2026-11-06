"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyPassword = exports.hashPassword = exports.InMemoryEmailAccountStore = exports.FileEmailAccountStore = exports.loadOrCreateSecret = exports.InMemorySessionStore = exports.FileSessionStore = exports.X_SCOPES = exports.GOOGLE_ISSUERS = exports.OAuthExchangeError = exports.exchangeXCode = exports.xAuthorizeUrl = exports.exchangeGoogleCode = exports.googleAuthorizeUrl = exports.randomUrlToken = exports.pkceChallenge = exports.createPkcePair = exports.DEFAULT_ADMISSION_MESSAGES = exports.connectionIdForDomain = exports.decideRestrictions = exports.matchIdentifier = exports.parseEmail = exports.OafConfigError = exports.ADMISSION_API_VERSION = exports.trustedSessionHd = exports.createAuthFrontend = exports.createFederatedFrontend = exports.getAuth = exports.requireAuth = exports.federatedMiddleware = exports.AuthError = exports.bearerToken = exports.authenticateRequest = exports.getRequestAuth = exports.createRouteMatcher = exports.authMiddleware = exports.checkClaims = exports.hasRole = exports.hasPermission = exports.requireRole = exports.requirePermission = exports.jwksCacheSize = exports.createEmbeddedVerifier = exports.configureEmbeddedVerification = exports.hasScope = exports.verifyMachineToken = exports.verifyToken = exports.verifyWebhook = exports.FederatedClient = exports.AuthClient = void 0;
exports.authClient = exports.federatedClient = exports.createAuthClient = exports.OAuthCredentialsError = exports.credentialsRemediation = exports.assertGoogleCredentials = exports.loadGoogleCredentials = exports.InMemorySamlReplayStore = exports.validateSamlAcs = exports.samlSpMetadata = exports.samlLoginRedirectUrl = exports.buildSamlClient = exports.passwordProblem = void 0;
exports.createFederatedClient = createFederatedClient;
const client_js_1 = require("./client.js");
// The backend client. `FederatedClient` is the primary name; `AuthClient` is kept as an alias so
// existing imports keep resolving.
var client_js_2 = require("./client.js");
Object.defineProperty(exports, "AuthClient", { enumerable: true, get: function () { return client_js_2.AuthClient; } });
Object.defineProperty(exports, "FederatedClient", { enumerable: true, get: function () { return client_js_2.AuthClient; } });
Object.defineProperty(exports, "verifyWebhook", { enumerable: true, get: function () { return client_js_2.verifyWebhook; } });
var verify_js_1 = require("./verify.js");
Object.defineProperty(exports, "verifyToken", { enumerable: true, get: function () { return verify_js_1.verifyToken; } });
Object.defineProperty(exports, "verifyMachineToken", { enumerable: true, get: function () { return verify_js_1.verifyMachineToken; } });
Object.defineProperty(exports, "hasScope", { enumerable: true, get: function () { return verify_js_1.hasScope; } });
Object.defineProperty(exports, "configureEmbeddedVerification", { enumerable: true, get: function () { return verify_js_1.configureEmbeddedVerification; } });
// Build a verifier bound to ONE app's config — the multi-frontend-safe alternative to the
// process-global `verifyToken`. `createFederatedFrontend()` returns one as `frontend.verifyToken`.
Object.defineProperty(exports, "createEmbeddedVerifier", { enumerable: true, get: function () { return verify_js_1.createEmbeddedVerifier; } });
// Diagnostics: how many issuers the (bounded) JWKS cache currently holds.
Object.defineProperty(exports, "jwksCacheSize", { enumerable: true, get: function () { return verify_js_1.jwksCacheSize; } });
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
Object.defineProperty(exports, "trustedSessionHd", { enumerable: true, get: function () { return frontend_js_1.trustedSessionHd; } });
// Admission: the app states who may sign in / sign up; the platform executes it. The pure helpers
// (parseEmail, matchIdentifier, decideRestrictions) let an app apply the same rule per request.
var admission_js_1 = require("./admission.js");
Object.defineProperty(exports, "ADMISSION_API_VERSION", { enumerable: true, get: function () { return admission_js_1.ADMISSION_API_VERSION; } });
Object.defineProperty(exports, "OafConfigError", { enumerable: true, get: function () { return admission_js_1.OafConfigError; } });
Object.defineProperty(exports, "parseEmail", { enumerable: true, get: function () { return admission_js_1.parseEmail; } });
Object.defineProperty(exports, "matchIdentifier", { enumerable: true, get: function () { return admission_js_1.matchIdentifier; } });
Object.defineProperty(exports, "decideRestrictions", { enumerable: true, get: function () { return admission_js_1.decideRestrictions; } });
Object.defineProperty(exports, "connectionIdForDomain", { enumerable: true, get: function () { return admission_js_1.connectionIdForDomain; } });
Object.defineProperty(exports, "DEFAULT_ADMISSION_MESSAGES", { enumerable: true, get: function () { return admission_js_1.DEFAULT_ADMISSION_MESSAGES; } });
// The provider protocols on their own (authorize URL, PKCE, code exchange, verified identity), with
// no session, cookie or domain policy. createFederatedFrontend() is built on these; an app that keeps
// its own session model (its own accounts service) calls them directly.
var oauth_providers_js_1 = require("./oauth-providers.js");
Object.defineProperty(exports, "createPkcePair", { enumerable: true, get: function () { return oauth_providers_js_1.createPkcePair; } });
Object.defineProperty(exports, "pkceChallenge", { enumerable: true, get: function () { return oauth_providers_js_1.pkceChallenge; } });
Object.defineProperty(exports, "randomUrlToken", { enumerable: true, get: function () { return oauth_providers_js_1.randomUrlToken; } });
Object.defineProperty(exports, "googleAuthorizeUrl", { enumerable: true, get: function () { return oauth_providers_js_1.googleAuthorizeUrl; } });
Object.defineProperty(exports, "exchangeGoogleCode", { enumerable: true, get: function () { return oauth_providers_js_1.exchangeGoogleCode; } });
Object.defineProperty(exports, "xAuthorizeUrl", { enumerable: true, get: function () { return oauth_providers_js_1.xAuthorizeUrl; } });
Object.defineProperty(exports, "exchangeXCode", { enumerable: true, get: function () { return oauth_providers_js_1.exchangeXCode; } });
Object.defineProperty(exports, "OAuthExchangeError", { enumerable: true, get: function () { return oauth_providers_js_1.OAuthExchangeError; } });
Object.defineProperty(exports, "GOOGLE_ISSUERS", { enumerable: true, get: function () { return oauth_providers_js_1.GOOGLE_ISSUERS; } });
Object.defineProperty(exports, "X_SCOPES", { enumerable: true, get: function () { return oauth_providers_js_1.X_SCOPES; } });
// Persistent, server-side session store (the stateful half of the session model).
// Pass a store to createFederatedFrontend({ sessionStore }) to make sessions survive app restarts
// and support revocation / listing / inactivity timeout.
var session_store_js_1 = require("./session-store.js");
Object.defineProperty(exports, "FileSessionStore", { enumerable: true, get: function () { return session_store_js_1.FileSessionStore; } });
Object.defineProperty(exports, "InMemorySessionStore", { enumerable: true, get: function () { return session_store_js_1.InMemorySessionStore; } });
Object.defineProperty(exports, "loadOrCreateSecret", { enumerable: true, get: function () { return session_store_js_1.loadOrCreateSecret; } });
// The email connection: sign up and sign in with an email address (an emailed one-time code, and
// optionally a password). Pass `{ strategy: "email", sendCode, store }` in `connections`.
var email_auth_js_1 = require("./email-auth.js");
Object.defineProperty(exports, "FileEmailAccountStore", { enumerable: true, get: function () { return email_auth_js_1.FileEmailAccountStore; } });
Object.defineProperty(exports, "InMemoryEmailAccountStore", { enumerable: true, get: function () { return email_auth_js_1.InMemoryEmailAccountStore; } });
Object.defineProperty(exports, "hashPassword", { enumerable: true, get: function () { return email_auth_js_1.hashPassword; } });
Object.defineProperty(exports, "verifyPassword", { enumerable: true, get: function () { return email_auth_js_1.verifyPassword; } });
Object.defineProperty(exports, "passwordProblem", { enumerable: true, get: function () { return email_auth_js_1.passwordProblem; } });
var saml_js_1 = require("./saml.js");
Object.defineProperty(exports, "buildSamlClient", { enumerable: true, get: function () { return saml_js_1.buildSamlClient; } });
Object.defineProperty(exports, "samlLoginRedirectUrl", { enumerable: true, get: function () { return saml_js_1.samlLoginRedirectUrl; } });
Object.defineProperty(exports, "samlSpMetadata", { enumerable: true, get: function () { return saml_js_1.samlSpMetadata; } });
Object.defineProperty(exports, "validateSamlAcs", { enumerable: true, get: function () { return saml_js_1.validateSamlAcs; } });
Object.defineProperty(exports, "InMemorySamlReplayStore", { enumerable: true, get: function () { return saml_js_1.InMemorySamlReplayStore; } });
var credentials_js_1 = require("./credentials.js");
Object.defineProperty(exports, "loadGoogleCredentials", { enumerable: true, get: function () { return credentials_js_1.loadGoogleCredentials; } });
Object.defineProperty(exports, "assertGoogleCredentials", { enumerable: true, get: function () { return credentials_js_1.assertGoogleCredentials; } });
Object.defineProperty(exports, "credentialsRemediation", { enumerable: true, get: function () { return credentials_js_1.credentialsRemediation; } });
Object.defineProperty(exports, "OAuthCredentialsError", { enumerable: true, get: function () { return credentials_js_1.OAuthCredentialsError; } });
/**
 * Construct a configured backend client via `createFederatedClient(options)`. All config (secretKey,
 * apiUrl, issuer) is supplied through `options` — the library reads no environment variables.
 */
function createFederatedClient(options = {}) {
    return new client_js_1.AuthClient(options);
}
/**
 * @deprecated Use {@link createFederatedClient}. Alias retained so existing `createAuthClient(...)`
 * call sites keep working unchanged.
 */
exports.createAuthClient = createFederatedClient;
// Preconfigured singleton for the common case (lazily constructed on first use). It carries no
// secretKey/issuer — embedded-mode verification is configured by createFederatedFrontend() via
// configureEmbeddedVerification(), so federatedClient.verifyToken() works without per-client config.
// For authorized Backend REST calls, construct an explicit createFederatedClient({ secretKey, apiUrl }).
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
        // Resolve the singleton ONCE per access: `instance()` was called twice on every property read
        // (once for the lookup, once to bind), which is a lazy-init check and a call per access on a
        // proxy that fronts every backend API call.
        const client = instance();
        const value = Reflect.get(client, prop, receiver);
        return typeof value === "function" ? value.bind(client) : value;
    },
});
/**
 * @deprecated Use {@link federatedClient}. Alias retained so existing `authClient.*` call sites keep
 * working unchanged.
 */
exports.authClient = exports.federatedClient;
//# sourceMappingURL=index.js.map