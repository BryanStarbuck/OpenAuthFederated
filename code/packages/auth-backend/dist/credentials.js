"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuthCredentialsError = void 0;
exports.credentialsRemediation = credentialsRemediation;
exports.loadGoogleCredentials = loadGoogleCredentials;
exports.assertGoogleCredentials = assertGoogleCredentials;
/**
 * Thrown when Google OAuth credentials cannot be resolved. Its `message` is operator-actionable and
 * deliberately contains NO secret values — only how to supply the credentials — so it is safe to
 * surface in an API response. It names no host-app file path (the library knows none); a host app
 * that wants to point the operator at its own secrets file does so in its own error text.
 */
class OAuthCredentialsError extends Error {
    /** Machine-readable code for API consumers. */
    code = "oauth_not_configured";
    constructor(message) {
        super(message);
        this.name = "OAuthCredentialsError";
    }
}
exports.OAuthCredentialsError = OAuthCredentialsError;
/**
 * The full, secret-free remediation message. Describes how the embedding app must supply the
 * credentials (pass them to `createAuthFrontend`, or set the generic env vars). It names no
 * application-specific file, path, override env var, or JSON key — those are the host app's
 * concern — and never includes the credential values themselves.
 */
function credentialsRemediation() {
    return [
        "OpenAuthFederated: Google OAuth client credentials are not configured, so sign-in cannot start.",
        "",
        'Supply a Google OAuth 2.0 "Web application" Client ID and Client Secret to the embedding app in',
        "ONE of these ways (checked in this order; the first non-empty value wins per field):",
        "",
        "  1. Pass them in: createFederatedFrontend({ connections: [{ strategy: 'oauth_google',",
        "       clientId, clientSecret, redirectUri }] }).",
        "  2. Set the environment variables: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.",
        "",
        "Notes:",
        "  - The embedding application owns WHERE these values come from (e.g. its own out-of-repo",
        "    secrets file or deployment environment); OpenAuthFederated only receives the resolved value.",
        "  - Keep credentials OUT of any repository — never commit them.",
        '  - The OAuth client must be a "Web application" client whose Authorized redirect URI exactly',
        "    matches the app's redirect URI (dev: http://localhost:9111/api/v1/oauth_callback).",
    ].join("\n");
}
/**
 * Resolve Google OAuth credentials across config → generic env. Never reads the filesystem and
 * never throws: inspect `.ok` to see whether both fields resolved. A host that wants a hard failure
 * on a missing credential calls {@link assertGoogleCredentials} (or relies on the embedded Frontend
 * API's fail-closed 503).
 */
function loadGoogleCredentials(opts = {}) {
    const cfgId = (opts.clientId ?? "").trim();
    const cfgSecret = (opts.clientSecret ?? "").trim();
    const useEnv = opts.useEnv !== false;
    const envId = useEnv ? (process.env.GOOGLE_CLIENT_ID ?? "").trim() : "";
    const envSecret = useEnv ? (process.env.GOOGLE_CLIENT_SECRET ?? "").trim() : "";
    const clientId = cfgId || envId;
    const clientSecret = cfgSecret || envSecret;
    return {
        clientId,
        clientSecret,
        ok: Boolean(clientId && clientSecret),
        clientIdSource: originOf(cfgId, envId),
        clientSecretSource: originOf(cfgSecret, envSecret),
    };
}
function originOf(fromConfig, fromEnv) {
    if (fromConfig)
        return "config";
    if (fromEnv)
        return "env";
    return "missing";
}
/**
 * Resolve and require Google OAuth credentials. Returns the pair when present; otherwise throws a
 * secret-free {@link OAuthCredentialsError} whose message explains how to supply them.
 */
function assertGoogleCredentials(opts = {}) {
    const r = loadGoogleCredentials(opts);
    if (!r.ok)
        throw new OAuthCredentialsError(credentialsRemediation());
    return { clientId: r.clientId, clientSecret: r.clientSecret };
}
//# sourceMappingURL=credentials.js.map