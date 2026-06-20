import type { TokenClaims } from "./types.js";
/**
 * Wildcard-aware permission check, matching the rule documented in
 * `docs/sdk/backend-sdk.mdx`: an exact `<feature>:<action>` grant, a feature wildcard
 * (`film:*`), an action wildcard (`*:read`), or the super-wildcard (`*:*`).
 */
export declare function hasPermission(granted: string[], permission: string): boolean;
/**
 * Verify a token and assert it carries `permission`. Throws `Forbidden` otherwise.
 * Returns the verified claims on success.
 */
export declare function requirePermission(token: string, permission: string): Promise<TokenClaims>;
