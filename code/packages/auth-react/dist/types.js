export const EMPTY_SNAPSHOT = Object.freeze({
    isSignedIn: false,
    userId: null,
    sessionId: null,
    orgId: null,
    user: null,
});
/**
 * Wildcard-aware permission check — exact grant, feature wildcard (`film:*`), action
 * wildcard (`*:read`), or super-wildcard (`*:*`). Mirrors the backend SDK helper.
 */
export function hasPermission(granted, permission) {
    if (!permission)
        return true;
    const [feature, action] = permission.split(":");
    return (granted.includes(permission) ||
        granted.includes(`${feature}:*`) ||
        granted.includes(`*:${action}`) ||
        granted.includes("*:*"));
}
export function domainSlug(domain) {
    return domain.replace(/[^a-zA-Z0-9]+/g, "_");
}
//# sourceMappingURL=types.js.map