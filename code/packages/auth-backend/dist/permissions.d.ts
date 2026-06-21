import type { PermissionCheck, TokenClaims } from "./types.js";
/**
 * Wildcard-aware permission check, matching the rule documented in
 * `docs/sdk/backend-sdk.mdx`: an exact `<feature>:<action>` grant, a feature wildcard
 * (`film:*`), an action wildcard (`*:read`), or the super-wildcard (`*:*`).
 *
 * Also understands the spec's structured permission shapes (§9): organization-scoped
 * permissions like `org:invoices:create` and system permissions like
 * `org:sys_memberships:manage`. For a three-part `org:<feature>:<action>` permission the
 * `org:<feature>` segment is treated as the feature and `<action>` as the action, so a
 * `org:invoices:*` or `*:create` grant still matches.
 */
export declare function hasPermission(granted: string[], permission: string): boolean;
/**
 * Role match. Roles follow the `org:<role>` convention (e.g. `org:admin`); a bare role name
 * (`admin`) matches its `org:`-prefixed form and vice-versa so callers can use either.
 */
export declare function hasRole(roles: string[], role: string): boolean;
/**
 * Evaluate a role and/or permission check against a set of token claims — the server-side
 * mirror of the front-end `has()` helper. Both conditions, when present, must hold.
 */
export declare function checkClaims(claims: TokenClaims, check: PermissionCheck): boolean;
/**
 * Verify a token and assert it carries `permission`. Throws `Forbidden` otherwise.
 * Returns the verified claims on success.
 */
export declare function requirePermission(token: string, permission: string): Promise<TokenClaims>;
/**
 * Verify a token and assert it carries `role`. Throws `Forbidden` otherwise.
 */
export declare function requireRole(token: string, role: string): Promise<TokenClaims>;
