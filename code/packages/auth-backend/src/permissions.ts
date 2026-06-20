import type { TokenClaims } from "./types.js"
import { verifyToken } from "./verify.js"

/**
 * Wildcard-aware permission check, matching the rule documented in
 * `docs/sdk/backend-sdk.mdx`: an exact `<feature>:<action>` grant, a feature wildcard
 * (`film:*`), an action wildcard (`*:read`), or the super-wildcard (`*:*`).
 */
export function hasPermission(granted: string[], permission: string): boolean {
  if (!permission) return true
  const [feature, action] = permission.split(":")
  return (
    granted.includes(permission) ||
    granted.includes(`${feature}:*`) ||
    granted.includes(`*:${action}`) ||
    granted.includes("*:*")
  )
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
  const granted = claims.permissions ?? []
  if (!hasPermission(granted, permission)) throw new Error("Forbidden")
  return claims
}
