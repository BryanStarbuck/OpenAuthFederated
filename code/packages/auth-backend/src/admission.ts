import { domainToASCII } from "node:url"

/**
 * ADMISSION — who may complete a sign-in, and who may create an account.
 *
 * The principle is "the platform executes, the app decides". OpenAuthFederated ships no domains, no
 * people and no application names. It enforces protocol hygiene (a verified email, state, PKCE,
 * signatures) and then executes whatever policy the embedding app STATES through these types:
 *
 *   * a sign-up mode (`public` / `restricted` / `waitlist`),
 *   * optional allowlist and blocklist identifiers (`ann@example.com`, `*@example.com`,
 *     `*@*.example.com`),
 *   * optional per-connection requirements (a verified hosted domain, an allowed set of them),
 *   * optional app callbacks ("actions") that may Allow or Deny each attempt,
 *   * an optional app-owned user directory so returning users can be told apart from new ones.
 *
 * Every value can be static or `Live` (re-read on each sign-in). A Live value that throws, times
 * out or returns something invalid refuses the attempt with `action_failed`; it never falls back to
 * a more permissive default.
 *
 * The pure helpers here (`parseEmail`, `matchIdentifier`, `decideRestrictions`) are exported so an
 * app can apply the exact same rule per request without re-implementing it.
 */

/** Bumped when the admission API changes shape. Apps assert it at boot so a stale dist fails loudly. */
export const ADMISSION_API_VERSION = 1

export type SignUpMode = "public" | "restricted" | "waitlist"

/** Static, or re-read on every sign-in. A throw, a timeout or an invalid value => 'action_failed' (never a fallback). */
export type Live<T> = T | (() => T | Promise<T>)

export interface Restrictions {
  /** Only identities matching allowlistIdentifiers may enter. On with zero entries => nobody. Default false. */
  allowlist?: boolean
  /** Identities matching blocklistIdentifiers are refused (subject to the precedence rule). Default false. */
  blocklist?: boolean
  /**
   * Apply the lists to returning users too. Default TRUE: OpenAuthFederated has no user store, so
   * without `users.lookup` it cannot tell sign-in from sign-up and fails closed.
   */
  applyToSignIn?: boolean
}

/**
 * Identifier grammar (trimmed, case-insensitive, matched against the VERIFIED email only, never hd):
 *   "ann@example.com"   exact               specificity 3
 *   "*@example.com"     that domain only    specificity 2
 *   "*@*.example.com"   subdomains only     specificity 1  (not the apex)
 * Anything else (e.g. "ann*@x") is treated as an exact string; WARN once per distinct entry per process.
 */
export type Identifier = string

/** `email` = the email connection (a one-time code or a password; email-auth.ts). */
export type IdentityProvider = "google" | "x" | "saml" | "email"
/** WorkOS spellings: `MagicAuth` is an emailed one-time code, `Password` a password. */
export type AuthenticationMethod = "GoogleOAuth" | "XOAuth" | "SSO" | "MagicAuth" | "Password"

/** Facts OpenAuthFederated verified. Every field here is TRUSTED. */
export interface ActionIdentity {
  provider: IdentityProvider
  /** Raw provider subject; namespace differs per provider; key on (provider, sub). */
  sub: string
  /** Lowercased; passed parseEmail(). */
  email: string
  emailVerified: true
  /**
   * Google: the hd claim of the verified id_token. SAML: the hd attribute, only when it equals the
   * email domain. X: never.
   */
  hd?: string
  name?: string
  /** X handle. */
  username?: string
}

/** Browser- or network-supplied. NEVER a security input. */
export interface UntrustedRequestHints {
  /** ?connection= as sent by the client. */
  connectionId?: string
  /** ?mode= as sent by the client (useSignUp sends 'sign_up'). */
  requestedMode: "sign_in" | "sign_up"
  ipAddress?: string
  userAgent?: string
}

export type AdmissionPhase = "sign_in" | "reverify"

export interface AuthenticationActionContext {
  object: "authentication_action_context"
  /** Also sent as trace_id on any refusal redirect. */
  id: string
  phase: AdmissionPhase
  identity: ActionIdentity
  authenticationMethod: AuthenticationMethod
  /** true = new, false = returning (always false on reverify), null = no users.lookup. */
  isSignUp: boolean | null
  signUpMode: SignUpMode
  matchedAllowlistIdentifier: string | null
  untrusted: UntrustedRequestHints
}

export interface UserRegistrationActionContext
  extends Omit<AuthenticationActionContext, "object" | "isSignUp" | "phase"> {
  object: "user_registration_action_context"
  phase: "sign_in"
  isSignUp: true
  invited: boolean
}

export type ActionVerdict =
  | { verdict: "Allow" }
  | {
      verdict: "Deny"
      /** /^[a-z][a-z0-9_]{0,63}$/; default 'action_denied'. */
      code?: string
      /** <= 500 chars; shown to the user. */
      errorMessage?: string
      /** <= 2000 chars. */
      errorLongMessage?: string
    }

export interface AdmissionActions {
  authentication?: (ctx: AuthenticationActionContext) => ActionVerdict | Promise<ActionVerdict>
  userRegistration?: (ctx: UserRegistrationActionContext) => ActionVerdict | Promise<ActionVerdict>
  /** Throw or timeout behaviour. Default 'deny' for both. */
  onError?: { authentication?: "deny" | "allow"; userRegistration?: "deny" | "allow" }
  /** Applies to each action, users.lookup and each Live resolver. Default 5000. */
  timeoutMs?: number
}

/** Optional app-owned user directory (OpenAuthFederated has no user store). */
export interface AdmissionUsers {
  lookup: (identity: ActionIdentity) => Promise<{ exists: boolean; invited?: boolean }>
}

export type AdmissionErrorCode =
  | "identity_email_unverified"
  | "identity_email_invalid"
  | "identity_domain_not_allowed" // legacy gate (code unchanged)
  | "identity_hosted_domain_required"
  | "identity_blocked"
  | "identity_not_allowlisted"
  | "sign_up_restricted"
  | "sign_up_waitlisted"
  | "action_denied"
  | "action_failed"
  | "sign_in_not_completed" // existing: state/PKCE/exchange/cancel; also reverify mismatch

export interface AdmissionMessage {
  message: string
  longMessage?: string
}

export type IdentifierSpecificity = 1 | 2 | 3
export interface IdentifierMatch {
  identifier: string
  specificity: IdentifierSpecificity
}

export type RestrictionOutcome =
  | { outcome: "allow"; matched: IdentifierMatch | null } // passes (allowlisted, or lists not engaged)
  | { outcome: "blocked"; matched: IdentifierMatch }
  | { outcome: "not_allowlisted" }

export type AdmissionStep =
  | "resolve_policy"
  | "email"
  | "legacy_gate"
  | "connection"
  | "users_lookup"
  | "restrictions"
  | "sign_up_mode"
  | "user_registration_action"
  | "authentication_action"
  | "reverify_binding"

export type AdmissionResult =
  | { allowed: true; matchedAllowlistIdentifier: string | null }
  | { allowed: false; code: AdmissionErrorCode | string; message: string; step: AdmissionStep }

/** A configuration the library refuses to run with. Thrown at construction, never at request time. */
export class OafConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "OafConfigError"
  }
}

/** The neutral, app-agnostic default copy for every refusal code. Apps override via `messages`. */
export const DEFAULT_ADMISSION_MESSAGES: Readonly<Record<AdmissionErrorCode, AdmissionMessage>> = Object.freeze({
  identity_email_unverified: {
    message: "Your sign-in provider has not verified this account's email address.",
  },
  identity_email_invalid: { message: "This account's email address cannot be used to sign in." },
  identity_domain_not_allowed: { message: "This account is not permitted to sign in to this application." },
  identity_hosted_domain_required: {
    message: "This application requires an organization-managed account from your sign-in provider.",
  },
  identity_blocked: { message: "This account is not permitted to sign in to this application." },
  identity_not_allowlisted: { message: "This account is not permitted to sign in to this application." },
  sign_up_restricted: { message: "Sign-up for this application is by invitation only." },
  sign_up_waitlisted: { message: "Sign-ups are currently waitlisted." },
  action_denied: { message: "This account is not permitted to sign in to this application." },
  action_failed: { message: "Sign-in could not be completed. Please try again." },
  sign_in_not_completed: { message: "Sign-in could not be completed. Please try again." },
})

// --- once-per-process warnings ---------------------------------------------------------------

const warnedOnce = new Set<string>()

/**
 * Emit a warning at most once per process for a given key. Several hosts rebuild the middleware
 * (per request or per config reload); a per-construction warning would flood their logs.
 */
export function warnOncePerProcess(key: string, emit: () => void): void {
  if (warnedOnce.has(key)) return
  warnedOnce.add(key)
  emit()
}

// --- email + identifier grammar --------------------------------------------------------------

/**
 * Strict parse: exactly one '@'; non-empty local part; no quoted local part; no trailing dot; domain
 * lowercased and converted with node:url domainToASCII (empty result => null). Returns null when invalid.
 */
export function parseEmail(email: string): { local: string; domain: string } | null {
  if (typeof email !== "string") return null
  const trimmed = email.trim()
  if (!trimmed || /[\s\u0000-\u001f\u007f]/.test(trimmed)) return null
  const at = trimmed.indexOf("@")
  if (at < 0 || trimmed.indexOf("@", at + 1) >= 0) return null
  const local = trimmed.slice(0, at)
  const rawDomain = trimmed.slice(at + 1)
  if (!local || !rawDomain) return null
  // A quoted local part ("a b"@x) is legal RFC 5321 and a classic matching-bypass vector; refuse it.
  if (local.startsWith('"') || local.endsWith('"')) return null
  if (local.endsWith(".") || local.startsWith(".") || local.includes("..")) return null
  if (rawDomain.endsWith(".") || rawDomain.startsWith(".")) return null
  const domain = domainToASCII(rawDomain.toLowerCase())
  if (!domain) return null
  if (domain.split(".").some((label) => label.length === 0)) return null
  return { local: local.toLowerCase(), domain }
}

/** Normalize a parsed email back to its canonical `local@domain` string. */
function canonicalEmail(p: { local: string; domain: string }): string {
  return `${p.local}@${p.domain}`
}

type ParsedIdentifier =
  | { kind: "exact"; value: string; specificity: 3 }
  | { kind: "domain"; domain: string; specificity: 2 }
  | { kind: "subdomain"; suffix: string; specificity: 1 }
  | { kind: "literal"; value: string; specificity: 3 }

function asciiDomain(d: string): string | null {
  if (!d || d.startsWith(".") || d.endsWith(".")) return null
  const out = domainToASCII(d.toLowerCase())
  if (!out || out.split(".").some((l) => l.length === 0)) return null
  return out
}

function parseIdentifier(raw: string): ParsedIdentifier {
  const id = raw.trim().toLowerCase()
  if (id.startsWith("*@*.")) {
    const suffix = asciiDomain(id.slice("*@*.".length))
    if (suffix && !suffix.includes("*")) return { kind: "subdomain", suffix, specificity: 1 }
  } else if (id.startsWith("*@")) {
    const domain = asciiDomain(id.slice(2))
    if (domain && !domain.includes("*")) return { kind: "domain", domain, specificity: 2 }
  } else if (!id.includes("*")) {
    const parsed = parseEmail(id)
    if (parsed) return { kind: "exact", value: canonicalEmail(parsed), specificity: 3 }
  }
  return { kind: "literal", value: id, specificity: 3 }
}

export interface MatchIdentifierOptions {
  /** Where the once-per-entry "not a recognized pattern" warning goes. Default: console.warn. */
  warn?: (message: string) => void
}

/** Most specific match, or null. Unparseable email => null. */
export function matchIdentifier(
  email: string,
  identifiers: readonly Identifier[],
  opts: MatchIdentifierOptions = {},
): IdentifierMatch | null {
  const parsed = parseEmail(email)
  if (!parsed) return null
  const canonical = canonicalEmail(parsed)
  let best: IdentifierMatch | null = null
  for (const raw of identifiers) {
    if (typeof raw !== "string" || !raw.trim()) continue
    const p = parseIdentifier(raw)
    let hit = false
    switch (p.kind) {
      case "exact":
        hit = canonical === p.value
        break
      case "domain":
        hit = parsed.domain === p.domain
        break
      case "subdomain":
        hit = parsed.domain.endsWith(`.${p.suffix}`)
        break
      case "literal": {
        const entry = raw.trim()
        warnOncePerProcess(`identifier-literal:${entry.toLowerCase()}`, () => {
          const msg =
            `admission identifier ${JSON.stringify(entry)} is not a recognized pattern ` +
            '("ann@example.com", "*@example.com", "*@*.example.com"); it is matched as an exact string'
          if (opts.warn) opts.warn(msg)
          else console.warn(`[auth-frontend] ${msg}`)
        })
        hit = canonical === p.value
        break
      }
    }
    if (hit && (!best || p.specificity > best.specificity)) {
      best = { identifier: raw.trim(), specificity: p.specificity }
      if (best.specificity === 3) break
    }
  }
  return best
}

/**
 * Precedence (pure; apps reuse it per request):
 *  - allow = restrictions.allowlist ? matchIdentifier(email, allowlist) : null
 *  - block = restrictions.blocklist ? matchIdentifier(email, blocklist) : null
 *  - block && (!allow || allow.specificity < block.specificity) => 'blocked'
 *  - restrictions.allowlist && !allow                           => 'not_allowlisted'
 *  - otherwise                                                   => 'allow'
 * Equal specificity: the allowlist wins. The allowlist override counts only when restrictions.allowlist is true.
 */
export function decideRestrictions(
  email: string,
  restrictions: Restrictions,
  allowlist: readonly Identifier[],
  blocklist: readonly Identifier[],
  opts: MatchIdentifierOptions = {},
): RestrictionOutcome {
  const allow = restrictions.allowlist === true ? matchIdentifier(email, allowlist, opts) : null
  const block = restrictions.blocklist === true ? matchIdentifier(email, blocklist, opts) : null
  if (block && (!allow || allow.specificity < block.specificity)) return { outcome: "blocked", matched: block }
  if (restrictions.allowlist === true && !allow) return { outcome: "not_allowlisted" }
  return { outcome: "allow", matched: allow }
}

// --- validation of policy values -------------------------------------------------------------

const SIGN_UP_MODES: readonly SignUpMode[] = ["public", "restricted", "waitlist"]

/** Returns an error sentence, or null when the value is a valid SignUpMode. */
export function invalidSignUpMode(v: unknown): string | null {
  return typeof v === "string" && (SIGN_UP_MODES as readonly string[]).includes(v)
    ? null
    : `signUpMode must be one of ${SIGN_UP_MODES.join(" | ")} (got ${JSON.stringify(v)})`
}

/** Returns an error sentence, or null when the value is a valid Restrictions object. */
export function invalidRestrictions(v: unknown): string | null {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return "restrictions must be an object"
  for (const k of ["allowlist", "blocklist", "applyToSignIn"] as const) {
    const val = (v as Record<string, unknown>)[k]
    if (val !== undefined && typeof val !== "boolean") return `restrictions.${k} must be a boolean`
  }
  return null
}

/** Returns an error sentence, or null when the value is an array of strings. */
export function invalidIdentifierList(v: unknown, name: string): string | null {
  if (!Array.isArray(v)) return `${name} must be an array of strings`
  if (v.some((x) => typeof x !== "string")) return `${name} must contain only strings`
  return null
}

// --- timeouts + Live resolution --------------------------------------------------------------

export class AdmissionTimeoutError extends Error {
  constructor(what: string, ms: number) {
    super(`${what} did not answer within ${ms} ms`)
    this.name = "AdmissionTimeoutError"
  }
}

/** Run `fn` (sync or async) under a timeout. A synchronous throw rejects like an async one. */
export async function withTimeout<T>(what: string, ms: number, fn: () => T | Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      Promise.resolve().then(fn),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new AdmissionTimeoutError(what, ms)), ms)
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

/** Resolve a {@link Live} value once: call it when it is a function, otherwise return it as is. */
export async function resolveLive<T>(what: string, value: Live<T> | undefined, ms: number): Promise<T | undefined> {
  if (typeof value !== "function") return value
  return await withTimeout(what, ms, value as () => T | Promise<T>)
}

const VERDICT_CODE = /^[a-z][a-z0-9_]{0,63}$/

export type NormalizedVerdict =
  | { allow: true }
  | { allow: false; code: string; message?: string; longMessage?: string }

/**
 * Validate what an action returned. Anything that is not a well-formed Allow/Deny is `null`, which
 * the caller treats exactly like a throw (onError). A Deny with a malformed code is coerced to
 * `action_denied`; over-long messages are truncated to their documented limits.
 */
export function normalizeVerdict(v: unknown): NormalizedVerdict | null {
  if (!v || typeof v !== "object") return null
  const verdict = (v as { verdict?: unknown }).verdict
  if (verdict === "Allow") return { allow: true }
  if (verdict !== "Deny") return null
  const d = v as { code?: unknown; errorMessage?: unknown; errorLongMessage?: unknown }
  const code = typeof d.code === "string" && VERDICT_CODE.test(d.code) ? d.code : "action_denied"
  const message = typeof d.errorMessage === "string" && d.errorMessage ? d.errorMessage.slice(0, 500) : undefined
  const longMessage =
    typeof d.errorLongMessage === "string" && d.errorLongMessage ? d.errorLongMessage.slice(0, 2000) : undefined
  return { allow: false, code, message, longMessage }
}

/**
 * Connection id for a domain, shared by the backend and the React SDK so a client-built id always
 * matches the server mapping: `'conn_' + domain.toLowerCase().replace(/[^a-z0-9]/g, '_')`.
 */
export function connectionIdForDomain(domain: string): string {
  return "conn_" + String(domain).toLowerCase().replace(/[^a-z0-9]/g, "_")
}
