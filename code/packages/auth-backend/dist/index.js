"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authClient = exports.hasPermission = exports.requirePermission = exports.verifyToken = exports.AuthClient = void 0;
exports.createAuthClient = createAuthClient;
const client_js_1 = require("./client.js");
var client_js_2 = require("./client.js");
Object.defineProperty(exports, "AuthClient", { enumerable: true, get: function () { return client_js_2.AuthClient; } });
var verify_js_1 = require("./verify.js");
Object.defineProperty(exports, "verifyToken", { enumerable: true, get: function () { return verify_js_1.verifyToken; } });
var permissions_js_1 = require("./permissions.js");
Object.defineProperty(exports, "requirePermission", { enumerable: true, get: function () { return permissions_js_1.requirePermission; } });
Object.defineProperty(exports, "hasPermission", { enumerable: true, get: function () { return permissions_js_1.hasPermission; } });
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