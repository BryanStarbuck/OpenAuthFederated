export const EMPTY_SNAPSHOT = Object.freeze({
    isSignedIn: false,
    userId: null,
    sessionId: null,
    orgId: null,
    user: null,
    memberships: [],
    lastVerifiedAt: null,
});
/**
 * Wildcard-aware permission check — exact grant, feature wildcard (`film:*`), action
 * wildcard (`*:read`), or super-wildcard (`*:*`). Also handles the spec's structured
 * three-part permissions (`org:invoices:create`, `org:sys_memberships:manage`) by treating
 * everything before the final `:` as the feature. Mirrors the backend SDK helper.
 */
export function hasPermission(granted, permission) {
    if (!permission)
        return true;
    if (granted.includes(permission) || granted.includes("*:*"))
        return true;
    const lastColon = permission.lastIndexOf(":");
    if (lastColon < 0)
        return false;
    const feature = permission.slice(0, lastColon);
    const action = permission.slice(lastColon + 1);
    return granted.includes(`${feature}:*`) || granted.includes(`*:${action}`);
}
/** Role match — accepts a bare role (`admin`) or its `org:`-prefixed form interchangeably. */
export function hasRole(roles, role) {
    if (!role)
        return true;
    if (roles.includes(role))
        return true;
    const bare = role.startsWith("org:") ? role.slice(4) : role;
    return roles.includes(bare) || roles.includes(`org:${bare}`);
}
export function domainSlug(domain) {
    return domain.replace(/[^a-zA-Z0-9]+/g, "_");
}
//# sourceMappingURL=types.js.map