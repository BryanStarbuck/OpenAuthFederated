"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AdmissionTimeoutError = exports.DEFAULT_ADMISSION_MESSAGES = exports.OafConfigError = exports.ADMISSION_API_VERSION = void 0;
exports.warnOncePerProcess = warnOncePerProcess;
exports.parseEmail = parseEmail;
exports.matchIdentifier = matchIdentifier;
exports.decideRestrictions = decideRestrictions;
exports.invalidSignUpMode = invalidSignUpMode;
exports.invalidRestrictions = invalidRestrictions;
exports.invalidIdentifierList = invalidIdentifierList;
exports.withTimeout = withTimeout;
exports.resolveLive = resolveLive;
exports.normalizeVerdict = normalizeVerdict;
exports.connectionIdForDomain = connectionIdForDomain;
const node_url_1 = require("node:url");
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
exports.ADMISSION_API_VERSION = 1;
/** A configuration the library refuses to run with. Thrown at construction, never at request time. */
class OafConfigError extends Error {
    constructor(message) {
        super(message);
        this.name = "OafConfigError";
    }
}
exports.OafConfigError = OafConfigError;
/** The neutral, app-agnostic default copy for every refusal code. Apps override via `messages`. */
exports.DEFAULT_ADMISSION_MESSAGES = Object.freeze({
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
});
// --- once-per-process warnings ---------------------------------------------------------------
const warnedOnce = new Set();
/**
 * Emit a warning at most once per process for a given key. Several hosts rebuild the middleware
 * (per request or per config reload); a per-construction warning would flood their logs.
 */
function warnOncePerProcess(key, emit) {
    if (warnedOnce.has(key))
        return;
    warnedOnce.add(key);
    emit();
}
// --- email + identifier grammar --------------------------------------------------------------
/**
 * Strict parse: exactly one '@'; non-empty local part; no quoted local part; no trailing dot; domain
 * lowercased and converted with node:url domainToASCII (empty result => null). Returns null when invalid.
 */
function parseEmail(email) {
    if (typeof email !== "string")
        return null;
    const trimmed = email.trim();
    if (!trimmed || /[\s\u0000-\u001f\u007f]/.test(trimmed))
        return null;
    const at = trimmed.indexOf("@");
    if (at < 0 || trimmed.indexOf("@", at + 1) >= 0)
        return null;
    const local = trimmed.slice(0, at);
    const rawDomain = trimmed.slice(at + 1);
    if (!local || !rawDomain)
        return null;
    // A quoted local part ("a b"@x) is legal RFC 5321 and a classic matching-bypass vector; refuse it.
    if (local.startsWith('"') || local.endsWith('"'))
        return null;
    if (local.endsWith(".") || local.startsWith(".") || local.includes(".."))
        return null;
    if (rawDomain.endsWith(".") || rawDomain.startsWith("."))
        return null;
    const domain = (0, node_url_1.domainToASCII)(rawDomain.toLowerCase());
    if (!domain)
        return null;
    if (domain.split(".").some((label) => label.length === 0))
        return null;
    return { local: local.toLowerCase(), domain };
}
/** Normalize a parsed email back to its canonical `local@domain` string. */
function canonicalEmail(p) {
    return `${p.local}@${p.domain}`;
}
function asciiDomain(d) {
    if (!d || d.startsWith(".") || d.endsWith("."))
        return null;
    const out = (0, node_url_1.domainToASCII)(d.toLowerCase());
    if (!out || out.split(".").some((l) => l.length === 0))
        return null;
    return out;
}
function parseIdentifier(raw) {
    const id = raw.trim().toLowerCase();
    if (id.startsWith("*@*.")) {
        const suffix = asciiDomain(id.slice("*@*.".length));
        if (suffix && !suffix.includes("*"))
            return { kind: "subdomain", suffix, specificity: 1 };
    }
    else if (id.startsWith("*@")) {
        const domain = asciiDomain(id.slice(2));
        if (domain && !domain.includes("*"))
            return { kind: "domain", domain, specificity: 2 };
    }
    else if (!id.includes("*")) {
        const parsed = parseEmail(id);
        if (parsed)
            return { kind: "exact", value: canonicalEmail(parsed), specificity: 3 };
    }
    return { kind: "literal", value: id, specificity: 3 };
}
/** Most specific match, or null. Unparseable email => null. */
function matchIdentifier(email, identifiers, opts = {}) {
    const parsed = parseEmail(email);
    if (!parsed)
        return null;
    const canonical = canonicalEmail(parsed);
    let best = null;
    for (const raw of identifiers) {
        if (typeof raw !== "string" || !raw.trim())
            continue;
        const p = parseIdentifier(raw);
        let hit = false;
        switch (p.kind) {
            case "exact":
                hit = canonical === p.value;
                break;
            case "domain":
                hit = parsed.domain === p.domain;
                break;
            case "subdomain":
                hit = parsed.domain.endsWith(`.${p.suffix}`);
                break;
            case "literal": {
                const entry = raw.trim();
                warnOncePerProcess(`identifier-literal:${entry.toLowerCase()}`, () => {
                    const msg = `admission identifier ${JSON.stringify(entry)} is not a recognized pattern ` +
                        '("ann@example.com", "*@example.com", "*@*.example.com"); it is matched as an exact string';
                    if (opts.warn)
                        opts.warn(msg);
                    else
                        console.warn(`[auth-frontend] ${msg}`);
                });
                hit = canonical === p.value;
                break;
            }
        }
        if (hit && (!best || p.specificity > best.specificity)) {
            best = { identifier: raw.trim(), specificity: p.specificity };
            if (best.specificity === 3)
                break;
        }
    }
    return best;
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
function decideRestrictions(email, restrictions, allowlist, blocklist, opts = {}) {
    const allow = restrictions.allowlist === true ? matchIdentifier(email, allowlist, opts) : null;
    const block = restrictions.blocklist === true ? matchIdentifier(email, blocklist, opts) : null;
    if (block && (!allow || allow.specificity < block.specificity))
        return { outcome: "blocked", matched: block };
    if (restrictions.allowlist === true && !allow)
        return { outcome: "not_allowlisted" };
    return { outcome: "allow", matched: allow };
}
// --- validation of policy values -------------------------------------------------------------
const SIGN_UP_MODES = ["public", "restricted", "waitlist"];
/** Returns an error sentence, or null when the value is a valid SignUpMode. */
function invalidSignUpMode(v) {
    return typeof v === "string" && SIGN_UP_MODES.includes(v)
        ? null
        : `signUpMode must be one of ${SIGN_UP_MODES.join(" | ")} (got ${JSON.stringify(v)})`;
}
/** Returns an error sentence, or null when the value is a valid Restrictions object. */
function invalidRestrictions(v) {
    if (v === null || typeof v !== "object" || Array.isArray(v))
        return "restrictions must be an object";
    for (const k of ["allowlist", "blocklist", "applyToSignIn"]) {
        const val = v[k];
        if (val !== undefined && typeof val !== "boolean")
            return `restrictions.${k} must be a boolean`;
    }
    return null;
}
/** Returns an error sentence, or null when the value is an array of strings. */
function invalidIdentifierList(v, name) {
    if (!Array.isArray(v))
        return `${name} must be an array of strings`;
    if (v.some((x) => typeof x !== "string"))
        return `${name} must contain only strings`;
    return null;
}
// --- timeouts + Live resolution --------------------------------------------------------------
class AdmissionTimeoutError extends Error {
    constructor(what, ms) {
        super(`${what} did not answer within ${ms} ms`);
        this.name = "AdmissionTimeoutError";
    }
}
exports.AdmissionTimeoutError = AdmissionTimeoutError;
/** Run `fn` (sync or async) under a timeout. A synchronous throw rejects like an async one. */
async function withTimeout(what, ms, fn) {
    let timer;
    try {
        return await Promise.race([
            Promise.resolve().then(fn),
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new AdmissionTimeoutError(what, ms)), ms);
            }),
        ]);
    }
    finally {
        if (timer)
            clearTimeout(timer);
    }
}
/** Resolve a {@link Live} value once: call it when it is a function, otherwise return it as is. */
async function resolveLive(what, value, ms) {
    if (typeof value !== "function")
        return value;
    return await withTimeout(what, ms, value);
}
const VERDICT_CODE = /^[a-z][a-z0-9_]{0,63}$/;
/**
 * Validate what an action returned. Anything that is not a well-formed Allow/Deny is `null`, which
 * the caller treats exactly like a throw (onError). A Deny with a malformed code is coerced to
 * `action_denied`; over-long messages are truncated to their documented limits.
 */
function normalizeVerdict(v) {
    if (!v || typeof v !== "object")
        return null;
    const verdict = v.verdict;
    if (verdict === "Allow")
        return { allow: true };
    if (verdict !== "Deny")
        return null;
    const d = v;
    const code = typeof d.code === "string" && VERDICT_CODE.test(d.code) ? d.code : "action_denied";
    const message = typeof d.errorMessage === "string" && d.errorMessage ? d.errorMessage.slice(0, 500) : undefined;
    const longMessage = typeof d.errorLongMessage === "string" && d.errorLongMessage ? d.errorLongMessage.slice(0, 2000) : undefined;
    return { allow: false, code, message, longMessage };
}
/**
 * Connection id for a domain, shared by the backend and the React SDK so a client-built id always
 * matches the server mapping: `'conn_' + domain.toLowerCase().replace(/[^a-z0-9]/g, '_')`.
 */
function connectionIdForDomain(domain) {
    return "conn_" + String(domain).toLowerCase().replace(/[^a-z0-9]/g, "_");
}
//# sourceMappingURL=admission.js.map