/**
 * Out-of-repo credential loading for the embedded Frontend API (Google OAuth client id/secret).
 *
 * Why this lives in the library: the host Service-Provider app must NOT carry secret resolution
 * logic of its own, and the credential file must NEVER be committed to any repository. So
 * OpenAuthFederated owns reading the Google OAuth Web-client credentials from an out-of-repo JSON
 * file (and from environment variables), and — crucially — owns producing a *clear, secret-free*
 * error when they are absent. The APIs this module backs fail loudly with an operator-actionable
 * message that names the exact file path and JSON shape, and never echo the secret values.
 *
 * Resolution order for each of `clientId` / `clientSecret` (first non-empty wins):
 *   1. Explicit value passed in config (e.g. resolved by the host from its own env).
 *   2. `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` environment variables.
 *   3. The out-of-repo credentials file (default `~/.credentials/app_internal_act3.json`),
 *      under the nested key `act3_internal_app.google`.
 *
 * Credentials file shape (the hierarchy is exact):
 *
 *   {
 *     "act3_internal_app": {
 *       "google": {
 *         "clientId":     "<id>.apps.googleusercontent.com",
 *         "clientSecret": "<secret>"
 *       }
 *     }
 *   }
 *
 * The path is overridable with the `APP_INTERNAL_ACT3_CREDENTIALS_FILE` environment variable.
 */
/** Default location of the out-of-repo credentials file (tilde-expanded at read time). */
export declare const DEFAULT_CREDENTIALS_PATH = "~/.credentials/app_internal_act3.json";
/** Environment variable that overrides {@link DEFAULT_CREDENTIALS_PATH}. */
export declare const CREDENTIALS_PATH_ENV = "APP_INTERNAL_ACT3_CREDENTIALS_FILE";
/** Top-level key in the credentials file that scopes this app's secrets. */
export declare const CREDENTIALS_APP_KEY = "act3_internal_app";
/** A resolved Google OAuth Web-client credential pair. */
export interface GoogleCredentials {
    clientId: string;
    clientSecret: string;
}
/** Where a resolved value originated. Used for diagnostics only — never carries the value. */
export type CredentialSource = "config" | "env" | "file" | "missing";
/** The outcome of resolving Google OAuth credentials across config / env / file. */
export interface CredentialResolution extends GoogleCredentials {
    /** True only when BOTH `clientId` and `clientSecret` are present and non-empty. */
    ok: boolean;
    /** Origin of `clientId` (for logging; contains no secret material). */
    clientIdSource: CredentialSource;
    /** Origin of `clientSecret` (for logging; contains no secret material). */
    clientSecretSource: CredentialSource;
    /** Absolute path of the credentials file that was (or would be) read. */
    path: string;
}
export interface LoadGoogleCredentialsOptions {
    /** An explicit client id (highest priority). */
    clientId?: string;
    /** An explicit client secret (highest priority). */
    clientSecret?: string;
    /** Read `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` from the environment. Default true. */
    useEnv?: boolean;
    /** Override the credentials-file path. Defaults to the env override, then the default path. */
    path?: string;
}
/**
 * Thrown when Google OAuth credentials cannot be resolved (or the credentials file is present but
 * malformed). Its `message` is operator-actionable and deliberately contains NO secret values —
 * only the file path and the required JSON shape — so it is safe to surface in an API response.
 */
export declare class OAuthCredentialsError extends Error {
    /** Machine-readable code for API consumers. */
    readonly code = "oauth_not_configured";
    /** The credentials-file path the operator should create/fix. */
    readonly path: string;
    constructor(message: string, path: string);
}
/** The absolute credentials-file path, honoring the env override then the default. */
export declare function resolveCredentialsPath(override?: string): string;
/**
 * The full, secret-free remediation message. Names the exact file path and the JSON hierarchy the
 * operator must create, plus the environment-variable alternatives. Safe to log and to return in
 * an API body — it never includes the credential values themselves.
 */
export declare function credentialsRemediation(path: string): string;
/**
 * Read the Google credential pair from the out-of-repo credentials file only.
 *
 * Returns empty strings (with `found: false`) when the file is absent or unreadable — a missing
 * file is a normal, recoverable state handled by the caller's resolution chain. Throws
 * {@link OAuthCredentialsError} only when the file EXISTS but is malformed (invalid JSON), because
 * that is a misconfiguration the operator must see, not silently fall through.
 */
export declare function googleCredentialsFromFile(path?: string): {
    clientId: string;
    clientSecret: string;
    found: boolean;
    path: string;
};
/**
 * Resolve Google OAuth credentials across config → env → file. Never throws for a *missing*
 * credential (inspect `.ok`); only throws {@link OAuthCredentialsError} when the credentials file
 * is present but malformed. The file is read only when config + env do not already supply a value,
 * so a fully env-configured deployment never touches the filesystem.
 */
export declare function loadGoogleCredentials(opts?: LoadGoogleCredentialsOptions): CredentialResolution;
/**
 * Resolve and require Google OAuth credentials. Returns the pair when present; otherwise throws a
 * secret-free {@link OAuthCredentialsError} whose message names the file path and required shape.
 */
export declare function assertGoogleCredentials(opts?: LoadGoogleCredentialsOptions): GoogleCredentials;
