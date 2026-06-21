import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

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
export const DEFAULT_CREDENTIALS_PATH = "~/.credentials/app_internal_act3.json"

/** Environment variable that overrides {@link DEFAULT_CREDENTIALS_PATH}. */
export const CREDENTIALS_PATH_ENV = "APP_INTERNAL_ACT3_CREDENTIALS_FILE"

/** Top-level key in the credentials file that scopes this app's secrets. */
export const CREDENTIALS_APP_KEY = "act3_internal_app"

/** A resolved Google OAuth Web-client credential pair. */
export interface GoogleCredentials {
  clientId: string
  clientSecret: string
}

/** Where a resolved value originated. Used for diagnostics only — never carries the value. */
export type CredentialSource = "config" | "env" | "file" | "missing"

/** The outcome of resolving Google OAuth credentials across config / env / file. */
export interface CredentialResolution extends GoogleCredentials {
  /** True only when BOTH `clientId` and `clientSecret` are present and non-empty. */
  ok: boolean
  /** Origin of `clientId` (for logging; contains no secret material). */
  clientIdSource: CredentialSource
  /** Origin of `clientSecret` (for logging; contains no secret material). */
  clientSecretSource: CredentialSource
  /** Absolute path of the credentials file that was (or would be) read. */
  path: string
}

export interface LoadGoogleCredentialsOptions {
  /** An explicit client id (highest priority). */
  clientId?: string
  /** An explicit client secret (highest priority). */
  clientSecret?: string
  /** Read `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` from the environment. Default true. */
  useEnv?: boolean
  /** Override the credentials-file path. Defaults to the env override, then the default path. */
  path?: string
}

/**
 * Thrown when Google OAuth credentials cannot be resolved (or the credentials file is present but
 * malformed). Its `message` is operator-actionable and deliberately contains NO secret values —
 * only the file path and the required JSON shape — so it is safe to surface in an API response.
 */
export class OAuthCredentialsError extends Error {
  /** Machine-readable code for API consumers. */
  readonly code = "oauth_not_configured"
  /** The credentials-file path the operator should create/fix. */
  readonly path: string

  constructor(message: string, path: string) {
    super(message)
    this.name = "OAuthCredentialsError"
    this.path = path
  }
}

function expandHome(p: string): string {
  if (p === "~") return homedir()
  if (p.startsWith("~/") || p.startsWith("~\\")) return join(homedir(), p.slice(2))
  return p
}

/** The absolute credentials-file path, honoring the env override then the default. */
export function resolveCredentialsPath(override?: string): string {
  const fromArg = override?.trim()
  const fromEnv = process.env[CREDENTIALS_PATH_ENV]?.trim()
  const raw = fromArg || fromEnv || DEFAULT_CREDENTIALS_PATH
  return expandHome(raw)
}

/** The required JSON shape, rendered for error messages. Contains placeholders, never secrets. */
function shapeExample(): string {
  return [
    "  {",
    `    "${CREDENTIALS_APP_KEY}": {`,
    `      "google": {`,
    `        "clientId":     "<your-oauth-web-client-id>.apps.googleusercontent.com",`,
    `        "clientSecret": "<your-oauth-web-client-secret>"`,
    "      }",
    "    }",
    "  }",
  ].join("\n")
}

/**
 * The full, secret-free remediation message. Names the exact file path and the JSON hierarchy the
 * operator must create, plus the environment-variable alternatives. Safe to log and to return in
 * an API body — it never includes the credential values themselves.
 */
export function credentialsRemediation(path: string): string {
  return [
    "OpenAuthFederated: Google OAuth client credentials are not configured, so sign-in cannot start.",
    "",
    "Provide a Google OAuth 2.0 \"Web application\" Client ID and Client Secret in ONE of these",
    "sources (checked in this order; the first non-empty value wins per field):",
    "",
    "  1. Environment variables: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET",
    `  2. Out-of-repo credentials file: ${path}`,
    "",
    "The credentials file must be JSON with exactly this hierarchy:",
    "",
    shapeExample(),
    "",
    "Notes:",
    "  - Keep this file OUTSIDE any repository — never commit credentials.",
    `  - Override the file path with the ${CREDENTIALS_PATH_ENV} environment variable.`,
    "  - The OAuth client must be a \"Web application\" client whose Authorized redirect URI",
    "    exactly matches the app's redirect URI (dev: http://localhost:9111/api/v1/oauth_callback).",
  ].join("\n")
}

/**
 * Read the Google credential pair from the out-of-repo credentials file only.
 *
 * Returns empty strings (with `found: false`) when the file is absent or unreadable — a missing
 * file is a normal, recoverable state handled by the caller's resolution chain. Throws
 * {@link OAuthCredentialsError} only when the file EXISTS but is malformed (invalid JSON), because
 * that is a misconfiguration the operator must see, not silently fall through.
 */
export function googleCredentialsFromFile(path?: string): {
  clientId: string
  clientSecret: string
  found: boolean
  path: string
} {
  const filePath = resolveCredentialsPath(path)

  let text: string
  try {
    text = readFileSync(filePath, "utf8")
  } catch {
    // Absent or unreadable — let the resolution chain decide whether that is fatal.
    return { clientId: "", clientSecret: "", found: false, path: filePath }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new OAuthCredentialsError(
      `OpenAuthFederated: the credentials file at ${filePath} exists but is not valid JSON. ` +
        `Fix the JSON syntax. Expected hierarchy:\n\n${shapeExample()}`,
      filePath,
    )
  }

  const app = isRecord(parsed) ? parsed[CREDENTIALS_APP_KEY] : undefined
  const google = isRecord(app) ? app.google : undefined
  const clientId = isRecord(google) && typeof google.clientId === "string" ? google.clientId.trim() : ""
  const clientSecret =
    isRecord(google) && typeof google.clientSecret === "string" ? google.clientSecret.trim() : ""

  return { clientId, clientSecret, found: true, path: filePath }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null
}

/**
 * Resolve Google OAuth credentials across config → env → file. Never throws for a *missing*
 * credential (inspect `.ok`); only throws {@link OAuthCredentialsError} when the credentials file
 * is present but malformed. The file is read only when config + env do not already supply a value,
 * so a fully env-configured deployment never touches the filesystem.
 */
export function loadGoogleCredentials(opts: LoadGoogleCredentialsOptions = {}): CredentialResolution {
  const path = resolveCredentialsPath(opts.path)

  const cfgId = (opts.clientId ?? "").trim()
  const cfgSecret = (opts.clientSecret ?? "").trim()

  const useEnv = opts.useEnv !== false
  const envId = useEnv ? (process.env.GOOGLE_CLIENT_ID ?? "").trim() : ""
  const envSecret = useEnv ? (process.env.GOOGLE_CLIENT_SECRET ?? "").trim() : ""

  // Touch the filesystem only if either field is still unsatisfied by config/env.
  const needFile = !(cfgId || envId) || !(cfgSecret || envSecret)
  const file = needFile
    ? googleCredentialsFromFile(path)
    : { clientId: "", clientSecret: "", found: false, path }

  const clientId = cfgId || envId || file.clientId
  const clientSecret = cfgSecret || envSecret || file.clientSecret

  return {
    clientId,
    clientSecret,
    ok: Boolean(clientId && clientSecret),
    clientIdSource: originOf(cfgId, envId, file.clientId),
    clientSecretSource: originOf(cfgSecret, envSecret, file.clientSecret),
    path,
  }
}

function originOf(fromConfig: string, fromEnv: string, fromFile: string): CredentialSource {
  if (fromConfig) return "config"
  if (fromEnv) return "env"
  if (fromFile) return "file"
  return "missing"
}

/**
 * Resolve and require Google OAuth credentials. Returns the pair when present; otherwise throws a
 * secret-free {@link OAuthCredentialsError} whose message names the file path and required shape.
 */
export function assertGoogleCredentials(opts: LoadGoogleCredentialsOptions = {}): GoogleCredentials {
  const r = loadGoogleCredentials(opts)
  if (!r.ok) throw new OAuthCredentialsError(credentialsRemediation(r.path), r.path)
  return { clientId: r.clientId, clientSecret: r.clientSecret }
}
