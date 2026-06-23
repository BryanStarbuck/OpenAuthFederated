/**
 * Google OAuth client-credential resolution for the embedded Frontend API.
 *
 * Ownership boundary (deliberate): this library is embedded by many host applications, so it must
 * stay credential-*source*-agnostic. It **accepts** a Google OAuth client id/secret as explicit
 * arguments to `createAuthFrontend(...)` / `loadGoogleCredentials(...)` and **uses** them to run the
 * OAuth flow. It reads NO environment variable and does NOT know, and must never read, any host
 * application's secrets file, that file's path, its override env-var name, or its JSON layout:
 * sourcing a secret is entirely the embedding app's job, and the app passes the resolved value in.
 * This mirrors how a consumer of a hosted identity-platform SDK supplies keys — to the SDK
 * constructor — never by handing the SDK a path into the app's filesystem or the host environment.
 *
 * The credential is "missing" when no value is passed in: `loadGoogleCredentials().ok` is false,
 * `assertGoogleCredentials()` throws a secret-free {@link OAuthCredentialsError}, and the embedded
 * Frontend API fails closed (503) rather than redirecting to Google with an empty `client_id`.
 */

/** A resolved Google OAuth Web-client credential pair. */
export interface GoogleCredentials {
  clientId: string
  clientSecret: string
}

/** Where a resolved value originated. Used for diagnostics only — never carries the value. */
export type CredentialSource = "config" | "missing"

/** The outcome of resolving Google OAuth credentials passed in by the host. */
export interface CredentialResolution extends GoogleCredentials {
  /** True only when BOTH `clientId` and `clientSecret` are present and non-empty. */
  ok: boolean
  /** Origin of `clientId` (for logging; contains no secret material). */
  clientIdSource: CredentialSource
  /** Origin of `clientSecret` (for logging; contains no secret material). */
  clientSecretSource: CredentialSource
}

export interface LoadGoogleCredentialsOptions {
  /** An explicit client id (highest priority). The host resolves this from its own config/file. */
  clientId?: string
  /** An explicit client secret (highest priority). Resolved by the host the same way. */
  clientSecret?: string
}

/**
 * Thrown when Google OAuth credentials cannot be resolved. Its `message` is operator-actionable and
 * deliberately contains NO secret values — only how to supply the credentials — so it is safe to
 * surface in an API response. It names no host-app file path (the library knows none); a host app
 * that wants to point the operator at its own secrets file does so in its own error text.
 */
export class OAuthCredentialsError extends Error {
  /** Machine-readable code for API consumers. */
  readonly code = "oauth_not_configured"

  constructor(message: string) {
    super(message)
    this.name = "OAuthCredentialsError"
  }
}

/**
 * The full, secret-free remediation message. Describes how the embedding app must supply the
 * credentials (pass them to `createAuthFrontend`, or set the generic env vars). It names no
 * application-specific file, path, override env var, or JSON key — those are the host app's
 * concern — and never includes the credential values themselves.
 */
export function credentialsRemediation(): string {
  return [
    "OpenAuthFederated: Google OAuth client credentials are not configured, so sign-in cannot start.",
    "",
    'Supply a Google OAuth 2.0 "Web application" Client ID and Client Secret to the embedding app by',
    "passing them in (OpenAuthFederated reads no environment variables):",
    "",
    "  createFederatedFrontend({ connections: [{ strategy: 'oauth_google',",
    "       clientId, clientSecret, redirectUri }] }).",
    "",
    "Notes:",
    "  - The embedding application owns WHERE these values come from (e.g. its own out-of-repo",
    "    secrets file or deployment environment); OpenAuthFederated only receives the resolved value.",
    "  - Keep credentials OUT of any repository — never commit them.",
    '  - The OAuth client must be a "Web application" client whose Authorized redirect URI exactly',
    "    matches the app's redirect URI (dev: http://localhost:9111/api/v1/oauth_callback).",
  ].join("\n")
}

/**
 * Resolve Google OAuth credentials from the values the API caller passes in. The library reads no
 * environment variables and never touches the filesystem — the embedding app owns WHERE the values
 * come from (its own out-of-repo secrets file or deployment config) and passes the resolved pair in.
 * Never throws: inspect `.ok` to see whether both fields resolved. A host that wants a hard failure
 * on a missing credential calls {@link assertGoogleCredentials} (or relies on the embedded Frontend
 * API's fail-closed 503).
 */
export function loadGoogleCredentials(opts: LoadGoogleCredentialsOptions = {}): CredentialResolution {
  const clientId = (opts.clientId ?? "").trim()
  const clientSecret = (opts.clientSecret ?? "").trim()

  return {
    clientId,
    clientSecret,
    ok: Boolean(clientId && clientSecret),
    clientIdSource: originOf(clientId),
    clientSecretSource: originOf(clientSecret),
  }
}

function originOf(fromConfig: string): CredentialSource {
  return fromConfig ? "config" : "missing"
}

/**
 * Resolve and require Google OAuth credentials. Returns the pair when present; otherwise throws a
 * secret-free {@link OAuthCredentialsError} whose message explains how to supply them.
 */
export function assertGoogleCredentials(opts: LoadGoogleCredentialsOptions = {}): GoogleCredentials {
  const r = loadGoogleCredentials(opts)
  if (!r.ok) throw new OAuthCredentialsError(credentialsRemediation())
  return { clientId: r.clientId, clientSecret: r.clientSecret }
}
