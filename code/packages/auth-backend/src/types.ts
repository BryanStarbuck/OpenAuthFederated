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

export interface CreateAuthClientOptions {
  /** Defaults to process.env.AUTH_SECRET_KEY. */
  secretKey?: string
  /** Backend API base, e.g. https://api.<domain>/v1. Defaults to AUTH_BACKEND_API. */
  apiUrl?: string
  /** Expected token issuer for JWKS verification. Defaults to AUTH_JWT_ISSUER. */
  issuer?: string
}
