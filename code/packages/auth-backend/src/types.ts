/** Claims carried by an OpenAuthFederated short-lived JWT access token. */
export interface TokenClaims {
  /** Subject — the user id (`user_…`). */
  sub: string
  email?: string
  /** Session id (`sess_…`) of the server-side session backing this token. */
  sid?: string
  /** Active organization/tenant id (`org_…`). */
  org_id?: string
  /** Mapped RBAC roles, derived from upstream Google Workspace groups. */
  roles?: string[]
  /** Mapped `<feature>:<action>` permissions, derived from groups. */
  permissions?: string[]
  /** Upstream hosted-domain claim (Google Workspace `hd`). */
  hd?: string
  iss?: string
  aud?: string | string[]
  exp?: number
  iat?: number
  [claim: string]: unknown
}

/**
 * Claims carried by a **machine** token — an OAuth M2M access token or a long-lived API key
 * used for server-to-server calls (spec §15). Machine identities are not human users; they
 * are subjects of the form `mch_…` and carry coarse `scopes` rather than org-scoped RBAC.
 */
export interface MachineClaims {
  /** Subject — the machine identity id (`mch_…`). */
  sub: string
  /** Discriminates a machine token from a user token. */
  token_type: "machine"
  /** OAuth-style scopes granted to the machine, e.g. `users:read`. */
  scopes?: string[]
  iss?: string
  aud?: string | string[]
  exp?: number
  iat?: number
  [claim: string]: unknown
}

/** A role and/or `<feature>:<action>` permission to assert. Both, if present, must hold. */
export interface PermissionCheck {
  role?: string
  permission?: string
}

/**
 * Options for {@link createFederatedClient}: camelCase keys mapped to their roles. Keys that have
 * no embedded-mode effect (`publishableKey`, `jwtKey`, `apiVersion`, `audience`, `authorizedParties`)
 * are accepted for source-compatibility and used where they apply (e.g. token verification).
 */
export interface CreateFederatedClientOptions {
  /** Defaults to process.env.AUTH_SECRET_KEY. (Federated: `secretKey`, required there.) */
  secretKey?: string
  /** Browser-safe publishable key. Accepted for Federated parity; unused server-side in embedded mode. */
  publishableKey?: string
  /** JWKS public key for networkless RS256 verification. Maps to verifyToken's `jwtKey`. */
  jwtKey?: string
  /** Backend API base, e.g. https://api.<domain>/v1. Defaults to AUTH_BACKEND_API. (Federated: `apiUrl`.) */
  apiUrl?: string
  /** Backend API version segment. Accepted for Federated parity. */
  apiVersion?: string
  /** Expected token issuer for JWKS verification. Defaults to AUTH_JWT_ISSUER. */
  issuer?: string
  /** Expected token audience. Accepted for Federated parity; forwarded to verifyToken. */
  audience?: string | string[]
  /** Authorized parties (azp) accepted on tokens. Accepted for Federated parity. */
  authorizedParties?: string[]
}

/**
 * @deprecated Use {@link CreateFederatedClientOptions}. Retained as an alias so existing
 * `createAuthClient(options)` call sites keep type-checking unchanged.
 */
export type CreateAuthClientOptions = CreateFederatedClientOptions
