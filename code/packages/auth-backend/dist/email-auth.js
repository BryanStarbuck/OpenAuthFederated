"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileEmailAccountStore = exports.InMemoryEmailAccountStore = void 0;
exports.hashPassword = hashPassword;
exports.verifyPassword = verifyPassword;
exports.passwordProblem = passwordProblem;
exports.newEmailCode = newEmailCode;
exports.hashEmailCode = hashEmailCode;
exports.codeMatches = codeMatches;
exports.newCodeSalt = newCodeSalt;
exports.newEmailAccountId = newEmailAccountId;
exports.normalizeEmailAddress = normalizeEmailAddress;
/**
 * EMAIL SIGN-IN — the `email` connection (Clerk's "email address" identifier with the
 * `email_code` and `password` strategies; WorkOS's Magic Auth and Password methods).
 *
 * A citizen creates an account with nothing but an email address: OpenAuthFederated sends a
 * one-time code, the person types it back, and that proves the mailbox exactly as Google's
 * `email_verified` or X's `confirmed_email` does. From there the identity goes through the SAME
 * admission pipeline and the SAME session minting as every other connection — the app's policy,
 * blocklist and actions apply unchanged.
 *
 * What lives here is pure and transport-free:
 *   * {@link hashPassword} / {@link verifyPassword} — scrypt from node:crypto, no dependency.
 *   * {@link newEmailCode} / {@link hashEmailCode} — six digits from a CSPRNG, stored only as a
 *     salted HMAC.
 *   * {@link EmailAccountStore} — where accounts and pending codes live; the app may supply its own
 *     (a database), or use {@link FileEmailAccountStore} / {@link InMemoryEmailAccountStore}.
 *
 * TWO RULES THE ROUTES IN frontend.ts KEEP, written here because they are the security model:
 *   1. A PASSWORD IS NEVER STORED BEFORE THE MAILBOX IS PROVEN. It is submitted together with the
 *      code and written only when the code verifies. So there is no "unverified account with an
 *      attacker's password waiting for the real owner" (the pre-verification takeover).
 *   2. THE LIBRARY NEVER SENDS MAIL. The app's `sendCode` callback owns the transport and the copy;
 *      it says whether the message actually went out, and a code that was not delivered is not
 *      reported as sent.
 */
const node_crypto_1 = require("node:crypto");
const promises_1 = require("node:fs/promises");
const node_path_1 = require("node:path");
// ---------------------------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------------------------
/** scrypt cost. N=2^15, r=8, p=1 (OWASP's floor is N=2^17 with p=1 OR N=2^15 with higher memory; we
 *  take 2^15 so a sign-in costs ~50 ms on a shared 4-core host). maxmem covers 128*N*r. */
const SCRYPT_N = 1 << 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
function scrypt(password, salt, n, r, p, keylen) {
    return new Promise((resolve, reject) => {
        (0, node_crypto_1.scrypt)(password.normalize("NFKC"), salt, keylen, { N: n, r, p, maxmem: SCRYPT_MAXMEM }, (err, key) => err ? reject(err) : resolve(key));
    });
}
/** Hash a password for storage. */
async function hashPassword(password) {
    const salt = (0, node_crypto_1.randomBytes)(16);
    const key = await scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_KEYLEN);
    return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString("base64url")}$${key.toString("base64url")}`;
}
/** Constant-time check of a password against a stored hash. A malformed hash is a mismatch. */
async function verifyPassword(password, stored) {
    const parts = (stored ?? "").split("$");
    if (parts.length !== 6 || parts[0] !== "scrypt") {
        // Spend the same time as a real check, so "no such account" and "wrong password" look alike.
        await scrypt(password, Buffer.alloc(16), SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_KEYLEN).catch(() => null);
        return false;
    }
    const [, n, r, p, saltB64, keyB64] = parts;
    const want = Buffer.from(keyB64, "base64url");
    const N = Number(n), R = Number(r), P = Number(p);
    if (!Number.isInteger(N) || !Number.isInteger(R) || !Number.isInteger(P) || want.length === 0)
        return false;
    try {
        const got = await scrypt(password, Buffer.from(saltB64, "base64url"), N, R, P, want.length);
        return got.length === want.length && (0, node_crypto_1.timingSafeEqual)(got, want);
    }
    catch {
        return false;
    }
}
/** Why a password is not acceptable, or null when it is. */
function passwordProblem(password, minLength) {
    if (typeof password !== "string")
        return "Enter a password.";
    const len = [...password].length;
    if (len < minLength)
        return `Use at least ${minLength} characters.`;
    if (len > 256)
        return "Use at most 256 characters.";
    if (!password.trim())
        return "A password cannot be only spaces.";
    return null;
}
// ---------------------------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------------------------
/** Six digits, uniformly from a CSPRNG (leading zeros kept). */
function newEmailCode() {
    return String((0, node_crypto_1.randomInt)(0, 1_000_000)).padStart(6, "0");
}
/** The stored form of a code: HMAC-SHA256 keyed by a per-code salt, bound to address and purpose. */
function hashEmailCode(salt, email, purpose, code) {
    return (0, node_crypto_1.createHmac)("sha256", Buffer.from(salt, "base64url")).update(`${purpose}\n${email}\n${code}`).digest("base64url");
}
/** Constant-time comparison of a typed code against a pending one (purpose-bound). */
function codeMatches(pending, email, code) {
    const typed = String(code ?? "").replace(/\s+/g, "");
    if (!/^\d{6}$/.test(typed))
        return false;
    const got = Buffer.from(hashEmailCode(pending.salt, email, pending.purpose, typed));
    const want = Buffer.from(pending.codeHash);
    return got.length === want.length && (0, node_crypto_1.timingSafeEqual)(got, want);
}
/** A fresh salt for {@link hashEmailCode}. */
function newCodeSalt() {
    return (0, node_crypto_1.randomBytes)(16).toString("base64url");
}
/** A fresh account subject. */
function newEmailAccountId() {
    return `em_${(0, node_crypto_1.randomBytes)(12).toString("base64url")}`;
}
/** Trim + lowercase. (Address syntax is checked by admission's parseEmail before this is used.) */
function normalizeEmailAddress(email) {
    return typeof email === "string" ? email.trim().toLowerCase() : "";
}
// ---------------------------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------------------------
/** Process-local store, for tests and single-process demos. Loses everything on restart. */
class InMemoryEmailAccountStore {
    accounts = new Map();
    pending = new Map();
    async getAccount(email) {
        const a = this.accounts.get(email);
        return a ? structuredClone(a) : null;
    }
    async putAccount(account) {
        this.accounts.set(account.email, structuredClone(account));
    }
    async getPending(email) {
        const p = this.pending.get(email);
        return p ? structuredClone(p) : null;
    }
    async putPending(p) {
        this.pending.set(p.email, structuredClone(p));
    }
    async deletePending(email) {
        this.pending.delete(email);
    }
}
exports.InMemoryEmailAccountStore = InMemoryEmailAccountStore;
/**
 * One JSON file per address under `dir/accounts/` and `dir/codes/`, named by a SHA-256 of the
 * address (so a directory listing is not a mailing list). Files are 0600, written atomically
 * (temp + rename). Fits a single-replica app with a persistent state directory; a multi-replica app
 * supplies a database-backed store instead.
 */
class FileEmailAccountStore {
    dir;
    constructor(dir) {
        this.dir = dir;
    }
    file(kind, email) {
        return (0, node_path_1.join)(this.dir, kind, `${(0, node_crypto_1.createHash)("sha256").update(email).digest("hex")}.json`);
    }
    async read(path) {
        try {
            return JSON.parse(await (0, promises_1.readFile)(path, "utf8"));
        }
        catch (err) {
            if (err?.code === "ENOENT")
                return null;
            throw err;
        }
    }
    async write(path, value) {
        await (0, promises_1.mkdir)((0, node_path_1.join)(path, ".."), { recursive: true, mode: 0o700 });
        const tmp = `${path}.${(0, node_crypto_1.randomBytes)(6).toString("hex")}.tmp`;
        await (0, promises_1.writeFile)(tmp, JSON.stringify(value), { mode: 0o600 });
        await (0, promises_1.rename)(tmp, path);
    }
    getAccount(email) {
        return this.read(this.file("accounts", email));
    }
    putAccount(account) {
        return this.write(this.file("accounts", account.email), account);
    }
    getPending(email) {
        return this.read(this.file("codes", email));
    }
    putPending(p) {
        return this.write(this.file("codes", p.email), p);
    }
    async deletePending(email) {
        await (0, promises_1.rm)(this.file("codes", email), { force: true });
    }
}
exports.FileEmailAccountStore = FileEmailAccountStore;
//# sourceMappingURL=email-auth.js.map