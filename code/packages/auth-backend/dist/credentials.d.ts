/**
 * Google OAuth client-credential resolution for the embedded Frontend API.
 *
 * Ownership boundary (deliberate): this library is embedded by many host applications, so it must
 * stay credential-*source*-agnostic. It **accepts** a Google OAuth client id/secret — as explicit
 * arguments to `createAuthFrontend(...)` / `loadGoogleCredentials(...)`, or from its own generic
 * `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` environment variables — and it **uses** them to run
 * the OAuth flow. It does NOT know, and must never read, any host application's secrets file, that
 * file's path, its override env-var name, or its JSON layout: sourcing a secret from a file is the
 * embedding app's job, and the app passes the resolved value in. This mirrors how a consumer of a
 * hosted identity-platform SDK supplies keys — to the SDK constructor or via the SDK's own env
 * vars — never by handing the SDK a path into the app's filesystem.
 *
 * Resolution order for each of `clientId` / `clientSecret` (first non-empty wins):
 *   1. Explicit value passed in (resolved by the host from wherever it keeps its secrets).
 *   2. `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` environment variables.
 *
 * When neither yields a value the credential is "missing": `loadGoogleCredentials().ok` is false,
 * `assertGoogleCredentials()` throws a secret-free {@link OAuthCredentialsError}, and the embedded
 * Frontend API fails closed (503) rather than redirecting to Google with an empty `client_id`.
 */
/** A resolved Google OAuth Web-client credential pair. */
export interface GoogleCredentials {
    clientId: string;
    clientSecret: string;
}
/** Where a resolved value originated. Used for diagnostics only — never carries the value. */
export type CredentialSource = "config" | "env" | "missing";
/** The outcome of resolving Google OAuth credentials across config / env. */
export interface CredentialResolution extends GoogleCredentials {
    /** True only when BOTH `clientId` and `clientSecret` are present and non-empty. */
    ok: boolean;
    /** Origin of `clientId` (for logging; contains no secret material). */
    clientIdSource: CredentialSource;
    /** Origin of `clientSecret` (for logging; contains no secret material). */
    clientSecretSource: CredentialSource;
}
export interface LoadGoogleCredentialsOptions {
    /** An explicit client id (highest priority). The host resolves this from its own config/file. */
    clientId?: string;
    /** An explicit client secret (highest priority). Resolved by the host the same way. */
    clientSecret?: string;
    /** Read `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` from the environment. Default true. */
    useEnv?: boolean;
}
/**
 * Thrown when Google OAuth credentials cannot be resolved. Its `message` is operator-actionable and
 * deliberately contains NO secret values — only how to supply the credentials — so it is safe to
 * surface in an API response. It names no host-app file path (the library knows none); a host app
 * that wants to point the operator at its own secrets file does so in its own error text.
 */
export declare class OAuthCredentialsError extends Error {
    /** Machine-readable code for API consumers. */
    readonly code = "oauth_not_configured";
    constructor(message: string);
}
/**
 * The full, secret-free remediation message. Describes how the embedding app must supply the
 * credentials (pass them to `createAuthFrontend`, or set the generic env vars). It names no
 * application-specific file, path, override env var, or JSON key — those are the host app's
 * concern — and never includes the credential values themselves.
 */
export declare function credentialsRemediation(): string;
/**
 * Resolve Google OAuth credentials across config → generic env. Never reads the filesystem and
 * never throws: inspect `.ok` to see whether both fields resolved. A host that wants a hard failure
 * on a missing credential calls {@link assertGoogleCredentials} (or relies on the embedded Frontend
 * API's fail-closed 503).
 */
export declare function loadGoogleCredentials(opts?: LoadGoogleCredentialsOptions): CredentialResolution;
/**
 * Resolve and require Google OAuth credentials. Returns the pair when present; otherwise throws a
 * secret-free {@link OAuthCredentialsError} whose message explains how to supply them.
 */
export declare function assertGoogleCredentials(opts?: LoadGoogleCredentialsOptions): GoogleCredentials;
