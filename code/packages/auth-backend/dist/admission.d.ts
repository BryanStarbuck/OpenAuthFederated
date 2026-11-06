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
export declare const ADMISSION_API_VERSION = 1;
export type SignUpMode = "public" | "restricted" | "waitlist";
/** Static, or re-read on every sign-in. A throw, a timeout or an invalid value => 'action_failed' (never a fallback). */
export type Live<T> = T | (() => T | Promise<T>);
export interface Restrictions {
    /** Only identities matching allowlistIdentifiers may enter. On with zero entries => nobody. Default false. */
    allowlist?: boolean;
    /** Identities matching blocklistIdentifiers are refused (subject to the precedence rule). Default false. */
    blocklist?: boolean;
    /**
     * Apply the lists to returning users too. Default TRUE: OpenAuthFederated has no user store, so
     * without `users.lookup` it cannot tell sign-in from sign-up and fails closed.
     */
    applyToSignIn?: boolean;
}
/**
 * Identifier grammar (trimmed, case-insensitive, matched against the VERIFIED email only, never hd):
 *   "ann@example.com"   exact               specificity 3
 *   "*@example.com"     that domain only    specificity 2
 *   "*@*.example.com"   subdomains only     specificity 1  (not the apex)
 * Anything else (e.g. "ann*@x") is treated as an exact string; WARN once per distinct entry per process.
 */
export type Identifier = string;
/** `email` = the email connection (a one-time code or a password; email-auth.ts). */
export type IdentityProvider = "google" | "x" | "saml" | "email";
/** WorkOS spellings: `MagicAuth` is an emailed one-time code, `Password` a password. */
export type AuthenticationMethod = "GoogleOAuth" | "XOAuth" | "SSO" | "MagicAuth" | "Password";
/** Facts OpenAuthFederated verified. Every field here is TRUSTED. */
export interface ActionIdentity {
    provider: IdentityProvider;
    /** Raw provider subject; namespace differs per provider; key on (provider, sub). */
    sub: string;
    /** Lowercased; passed parseEmail(). */
    email: string;
    emailVerified: true;
    /**
     * Google: the hd claim of the verified id_token. SAML: the hd attribute, only when it equals the
     * email domain. X: never.
     */
    hd?: string;
    name?: string;
    /** X handle. */
    username?: string;
}
/** Browser- or network-supplied. NEVER a security input. */
export interface UntrustedRequestHints {
    /** ?connection= as sent by the client. */
    connectionId?: string;
    /** ?mode= as sent by the client (useSignUp sends 'sign_up'). */
    requestedMode: "sign_in" | "sign_up";
    ipAddress?: string;
    userAgent?: string;
}
export type AdmissionPhase = "sign_in" | "reverify";
export interface AuthenticationActionContext {
    object: "authentication_action_context";
    /** Also sent as trace_id on any refusal redirect. */
    id: string;
    phase: AdmissionPhase;
    identity: ActionIdentity;
    authenticationMethod: AuthenticationMethod;
    /** true = new, false = returning (always false on reverify), null = no users.lookup. */
    isSignUp: boolean | null;
    signUpMode: SignUpMode;
    matchedAllowlistIdentifier: string | null;
    untrusted: UntrustedRequestHints;
}
export interface UserRegistrationActionContext extends Omit<AuthenticationActionContext, "object" | "isSignUp" | "phase"> {
    object: "user_registration_action_context";
    phase: "sign_in";
    isSignUp: true;
    invited: boolean;
}
export type ActionVerdict = {
    verdict: "Allow";
} | {
    verdict: "Deny";
    /** /^[a-z][a-z0-9_]{0,63}$/; default 'action_denied'. */
    code?: string;
    /** <= 500 chars; shown to the user. */
    errorMessage?: string;
    /** <= 2000 chars. */
    errorLongMessage?: string;
};
export interface AdmissionActions {
    authentication?: (ctx: AuthenticationActionContext) => ActionVerdict | Promise<ActionVerdict>;
    userRegistration?: (ctx: UserRegistrationActionContext) => ActionVerdict | Promise<ActionVerdict>;
    /** Throw or timeout behaviour. Default 'deny' for both. */
    onError?: {
        authentication?: "deny" | "allow";
        userRegistration?: "deny" | "allow";
    };
    /** Applies to each action, users.lookup and each Live resolver. Default 5000. */
    timeoutMs?: number;
}
/** Optional app-owned user directory (OpenAuthFederated has no user store). */
export interface AdmissionUsers {
    lookup: (identity: ActionIdentity) => Promise<{
        exists: boolean;
        invited?: boolean;
    }>;
}
export type AdmissionErrorCode = "identity_email_unverified" | "identity_email_invalid" | "identity_domain_not_allowed" | "identity_hosted_domain_required" | "identity_blocked" | "identity_not_allowlisted" | "sign_up_restricted" | "sign_up_waitlisted" | "action_denied" | "action_failed" | "sign_in_not_completed";
export interface AdmissionMessage {
    message: string;
    longMessage?: string;
}
export type IdentifierSpecificity = 1 | 2 | 3;
export interface IdentifierMatch {
    identifier: string;
    specificity: IdentifierSpecificity;
}
export type RestrictionOutcome = {
    outcome: "allow";
    matched: IdentifierMatch | null;
} | {
    outcome: "blocked";
    matched: IdentifierMatch;
} | {
    outcome: "not_allowlisted";
};
export type AdmissionStep = "resolve_policy" | "email" | "legacy_gate" | "connection" | "users_lookup" | "restrictions" | "sign_up_mode" | "user_registration_action" | "authentication_action" | "reverify_binding";
export type AdmissionResult = {
    allowed: true;
    matchedAllowlistIdentifier: string | null;
} | {
    allowed: false;
    code: AdmissionErrorCode | string;
    message: string;
    step: AdmissionStep;
};
/** A configuration the library refuses to run with. Thrown at construction, never at request time. */
export declare class OafConfigError extends Error {
    constructor(message: string);
}
/** The neutral, app-agnostic default copy for every refusal code. Apps override via `messages`. */
export declare const DEFAULT_ADMISSION_MESSAGES: Readonly<Record<AdmissionErrorCode, AdmissionMessage>>;
/**
 * Emit a warning at most once per process for a given key. Several hosts rebuild the middleware
 * (per request or per config reload); a per-construction warning would flood their logs.
 */
export declare function warnOncePerProcess(key: string, emit: () => void): void;
/**
 * Strict parse: exactly one '@'; non-empty local part; no quoted local part; no trailing dot; domain
 * lowercased and converted with node:url domainToASCII (empty result => null). Returns null when invalid.
 */
export declare function parseEmail(email: string): {
    local: string;
    domain: string;
} | null;
export interface MatchIdentifierOptions {
    /** Where the once-per-entry "not a recognized pattern" warning goes. Default: console.warn. */
    warn?: (message: string) => void;
}
/** Most specific match, or null. Unparseable email => null. */
export declare function matchIdentifier(email: string, identifiers: readonly Identifier[], opts?: MatchIdentifierOptions): IdentifierMatch | null;
/**
 * Precedence (pure; apps reuse it per request):
 *  - allow = restrictions.allowlist ? matchIdentifier(email, allowlist) : null
 *  - block = restrictions.blocklist ? matchIdentifier(email, blocklist) : null
 *  - block && (!allow || allow.specificity < block.specificity) => 'blocked'
 *  - restrictions.allowlist && !allow                           => 'not_allowlisted'
 *  - otherwise                                                   => 'allow'
 * Equal specificity: the allowlist wins. The allowlist override counts only when restrictions.allowlist is true.
 */
export declare function decideRestrictions(email: string, restrictions: Restrictions, allowlist: readonly Identifier[], blocklist: readonly Identifier[], opts?: MatchIdentifierOptions): RestrictionOutcome;
/** Returns an error sentence, or null when the value is a valid SignUpMode. */
export declare function invalidSignUpMode(v: unknown): string | null;
/** Returns an error sentence, or null when the value is a valid Restrictions object. */
export declare function invalidRestrictions(v: unknown): string | null;
/** Returns an error sentence, or null when the value is an array of strings. */
export declare function invalidIdentifierList(v: unknown, name: string): string | null;
export declare class AdmissionTimeoutError extends Error {
    constructor(what: string, ms: number);
}
/** Run `fn` (sync or async) under a timeout. A synchronous throw rejects like an async one. */
export declare function withTimeout<T>(what: string, ms: number, fn: () => T | Promise<T>): Promise<T>;
/** Resolve a {@link Live} value once: call it when it is a function, otherwise return it as is. */
export declare function resolveLive<T>(what: string, value: Live<T> | undefined, ms: number): Promise<T | undefined>;
export type NormalizedVerdict = {
    allow: true;
} | {
    allow: false;
    code: string;
    message?: string;
    longMessage?: string;
};
/**
 * Validate what an action returned. Anything that is not a well-formed Allow/Deny is `null`, which
 * the caller treats exactly like a throw (onError). A Deny with a malformed code is coerced to
 * `action_denied`; over-long messages are truncated to their documented limits.
 */
export declare function normalizeVerdict(v: unknown): NormalizedVerdict | null;
/**
 * Connection id for a domain, shared by the backend and the React SDK so a client-built id always
 * matches the server mapping: `'conn_' + domain.toLowerCase().replace(/[^a-z0-9]/g, '_')`.
 */
export declare function connectionIdForDomain(domain: string): string;
