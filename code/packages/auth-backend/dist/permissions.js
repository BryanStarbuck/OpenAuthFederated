"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hasPermission = hasPermission;
exports.requirePermission = requirePermission;
const verify_js_1 = require("./verify.js");
/**
 * Wildcard-aware permission check, matching the rule documented in
 * `docs/sdk/backend-sdk.mdx`: an exact `<feature>:<action>` grant, a feature wildcard
 * (`film:*`), an action wildcard (`*:read`), or the super-wildcard (`*:*`).
 */
function hasPermission(granted, permission) {
    if (!permission)
        return true;
    const [feature, action] = permission.split(":");
    return (granted.includes(permission) ||
        granted.includes(`${feature}:*`) ||
        granted.includes(`*:${action}`) ||
        granted.includes("*:*"));
}
/**
 * Verify a token and assert it carries `permission`. Throws `Forbidden` otherwise.
 * Returns the verified claims on success.
 */
async function requirePermission(token, permission) {
    const claims = await (0, verify_js_1.verifyToken)(token);
    const granted = claims.permissions ?? [];
    if (!hasPermission(granted, permission))
        throw new Error("Forbidden");
    return claims;
}
//# sourceMappingURL=permissions.js.map