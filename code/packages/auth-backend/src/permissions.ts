import type { PermissionCheck, TokenClaims } from "./types.js"
import { verifyToken } from "./verify.js"

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
export function hasPermission(granted: string[], permission: string): boolean {
  if (!permission) return true
  if (granted.includes(permission) || granted.includes("*:*")) return true

  const lastColon = permission.lastIndexOf(":")
  if (lastColon < 0) return false
  const feature = permission.slice(0, lastColon)
  const action = permission.slice(lastColon + 1)

  return granted.includes(`${feature}:*`) || granted.includes(`*:${action}`)
}

/**
 * Role match. Roles follow the `org:<role>` convention (e.g. `org:admin`); a bare role name
 * (`admin`) matches its `org:`-prefixed form and vice-versa so callers can use either.
 */
export function hasRole(roles: string[], role: string): boolean {
  if (!role) return true
  if (roles.includes(role)) return true
  const bare = role.startsWith("org:") ? role.slice(4) : role
  return roles.includes(bare) || roles.includes(`org:${bare}`)
}

/**
 * Evaluate a role and/or permission check against a set of token claims — the server-side
 * mirror of the front-end `has()` helper. Both conditions, when present, must hold.
 */
export function checkClaims(claims: TokenClaims, check: PermissionCheck): boolean {
  if (check.role && !hasRole(claims.roles ?? [], check.role)) return false
  if (check.permission && !hasPermission(claims.permissions ?? [], check.permission)) {
    return false
  }
  return true
}

/**
 * Verify a token and assert it carries `permission`. Throws `Forbidden` otherwise.
 * Returns the verified claims on success.
 */
export async function requirePermission(
  token: string,
  permission: string,
): Promise<TokenClaims> {
  const claims = await verifyToken(token)
  if (!hasPermission(claims.permissions ?? [], permission)) throw new Error("Forbidden")
  return claims
}

/**
 * Verify a token and assert it carries `role`. Throws `Forbidden` otherwise.
 */
export async function requireRole(token: string, role: string): Promise<TokenClaims> {
  const claims = await verifyToken(token)
  if (!hasRole(claims.roles ?? [], role)) throw new Error("Forbidden")
  return claims
}
