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
import { createHmac, randomBytes, randomInt, scrypt as scryptCb, timingSafeEqual, createHash } from "node:crypto"
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"

/** Why a code is being sent. Only the copy differs; every purpose proves the mailbox. */
export type EmailCodePurpose = "sign_up" | "sign_in" | "reset_password"

/** What the app's `sendCode` callback is asked to deliver. */
export interface EmailCodeMessage {
  /** The normalized (trimmed, lowercased) address. */
  to: string
  /** Six digits. Put it in the message; never log it on a shared server. */
  code: string
  purpose: EmailCodePurpose
  expiresInMinutes: number
  /**
   * Whether a verified account already exists for this address. The RESPONSE to the browser is
   * identical either way (no account enumeration); the EMAIL may say "here is your sign-in code"
   * instead of "confirm your new account".
   */
  accountExists: boolean
}

/** The app's answer: did the message actually leave? */
export interface EmailDelivery {
  delivered: boolean
  /** One sentence for the log when it did not. */
  problem?: string | null
}

/** The `email` connection, passed in `connections[]`. */
export interface EmailConnectionConfig {
  strategy: "email"
  /** Deliver a one-time code. The app owns the transport (SendGrid, SES, SMTP...) and the wording. */
  sendCode: (message: EmailCodeMessage) => EmailDelivery | Promise<EmailDelivery>
  /** Where email accounts and pending codes live. Required. */
  store: EmailAccountStore
  /** Offer a password as a second way back in (set at sign-up or by reset). Default true. */
  password?: boolean
  /** Code lifetime. Default 600 (10 minutes). */
  codeTtlSeconds?: number
  /** Wrong guesses allowed per code before it is burned. Default 5. */
  maxCodeAttempts?: number
  /** Minimum gap between two codes to one address. Default 30. */
  resendCooldownSeconds?: number
  /** Codes per address per rolling hour. Default 10. */
  maxCodesPerHour?: number
  /** Default 8 (Clerk's default). Maximum is always 256. */
  minPasswordLength?: number
  /** Failed password attempts before the account's password is locked. Default 10. */
  maxPasswordFailures?: number
  /** How long the password lock lasts. Default 900 (15 minutes). A code sign-in still works. */
  passwordLockSeconds?: number
  /** Button / heading label. Default "Email". */
  label?: string
}

/** One email account. `id` is the stable subject (`em_...`); key app rows on (provider "email", id). */
export interface EmailAccount {
  id: string
  email: string
  /** `scrypt$N$r$p$salt$hash`, or null for a code-only account. */
  passwordHash: string | null
  /** Unix seconds when the mailbox was first proven. Accounts are only ever written verified. */
  verifiedAt: number
  createdAt: number
  updatedAt: number
  failedPasswordAttempts?: number
  passwordLockedUntil?: number | null
}

/** A code waiting to be typed back. Only a salted HMAC of the code is stored. */
export interface PendingEmailCode {
  email: string
  purpose: EmailCodePurpose
  salt: string
  codeHash: string
  expiresAt: number
  attempts: number
  /** Unix seconds of each code sent in the last hour (the throttle). */
  sentAt: number[]
}

/** Persistence for the `email` connection. Every method is keyed by the normalized address. */
export interface EmailAccountStore {
  getAccount(email: string): Promise<EmailAccount | null>
  putAccount(account: EmailAccount): Promise<void>
  getPending(email: string): Promise<PendingEmailCode | null>
  putPending(pending: PendingEmailCode): Promise<void>
  deletePending(email: string): Promise<void>
}

// ---------------------------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------------------------

/** scrypt cost. N=2^15, r=8, p=1 (OWASP's floor is N=2^17 with p=1 OR N=2^15 with higher memory; we
 *  take 2^15 so a sign-in costs ~50 ms on a shared 4-core host). maxmem covers 128*N*r. */
const SCRYPT_N = 1 << 15
const SCRYPT_R = 8
const SCRYPT_P = 1
const SCRYPT_KEYLEN = 64
const SCRYPT_MAXMEM = 64 * 1024 * 1024

function scrypt(password: string, salt: Buffer, n: number, r: number, p: number, keylen: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password.normalize("NFKC"), salt, keylen, { N: n, r, p, maxmem: SCRYPT_MAXMEM }, (err, key) =>
      err ? reject(err) : resolve(key),
    )
  })
}

/** Hash a password for storage. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const key = await scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_KEYLEN)
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString("base64url")}$${key.toString("base64url")}`
}

/** Constant-time check of a password against a stored hash. A malformed hash is a mismatch. */
export async function verifyPassword(password: string, stored: string | null | undefined): Promise<boolean> {
  const parts = (stored ?? "").split("$")
  if (parts.length !== 6 || parts[0] !== "scrypt") {
    // Spend the same time as a real check, so "no such account" and "wrong password" look alike.
    await scrypt(password, Buffer.alloc(16), SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_KEYLEN).catch(() => null)
    return false
  }
  const [, n, r, p, saltB64, keyB64] = parts
  const want = Buffer.from(keyB64, "base64url")
  const N = Number(n), R = Number(r), P = Number(p)
  if (!Number.isInteger(N) || !Number.isInteger(R) || !Number.isInteger(P) || want.length === 0) return false
  try {
    const got = await scrypt(password, Buffer.from(saltB64, "base64url"), N, R, P, want.length)
    return got.length === want.length && timingSafeEqual(got, want)
  } catch {
    return false
  }
}

/** Why a password is not acceptable, or null when it is. */
export function passwordProblem(password: unknown, minLength: number): string | null {
  if (typeof password !== "string") return "Enter a password."
  const len = [...password].length
  if (len < minLength) return `Use at least ${minLength} characters.`
  if (len > 256) return "Use at most 256 characters."
  if (!password.trim()) return "A password cannot be only spaces."
  return null
}

// ---------------------------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------------------------

/** Six digits, uniformly from a CSPRNG (leading zeros kept). */
export function newEmailCode(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, "0")
}

/** The stored form of a code: HMAC-SHA256 keyed by a per-code salt, bound to address and purpose. */
export function hashEmailCode(salt: string, email: string, purpose: EmailCodePurpose, code: string): string {
  return createHmac("sha256", Buffer.from(salt, "base64url")).update(`${purpose}\n${email}\n${code}`).digest("base64url")
}

/** Constant-time comparison of a typed code against a pending one (purpose-bound). */
export function codeMatches(pending: PendingEmailCode, email: string, code: string): boolean {
  const typed = String(code ?? "").replace(/\s+/g, "")
  if (!/^\d{6}$/.test(typed)) return false
  const got = Buffer.from(hashEmailCode(pending.salt, email, pending.purpose, typed))
  const want = Buffer.from(pending.codeHash)
  return got.length === want.length && timingSafeEqual(got, want)
}

/** A fresh salt for {@link hashEmailCode}. */
export function newCodeSalt(): string {
  return randomBytes(16).toString("base64url")
}

/** A fresh account subject. */
export function newEmailAccountId(): string {
  return `em_${randomBytes(12).toString("base64url")}`
}

/** Trim + lowercase. (Address syntax is checked by admission's parseEmail before this is used.) */
export function normalizeEmailAddress(email: unknown): string {
  return typeof email === "string" ? email.trim().toLowerCase() : ""
}

// ---------------------------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------------------------

/** Process-local store, for tests and single-process demos. Loses everything on restart. */
export class InMemoryEmailAccountStore implements EmailAccountStore {
  private readonly accounts = new Map<string, EmailAccount>()
  private readonly pending = new Map<string, PendingEmailCode>()
  async getAccount(email: string) {
    const a = this.accounts.get(email)
    return a ? structuredClone(a) : null
  }
  async putAccount(account: EmailAccount) {
    this.accounts.set(account.email, structuredClone(account))
  }
  async getPending(email: string) {
    const p = this.pending.get(email)
    return p ? structuredClone(p) : null
  }
  async putPending(p: PendingEmailCode) {
    this.pending.set(p.email, structuredClone(p))
  }
  async deletePending(email: string) {
    this.pending.delete(email)
  }
}

/**
 * One JSON file per address under `dir/accounts/` and `dir/codes/`, named by a SHA-256 of the
 * address (so a directory listing is not a mailing list). Files are 0600, written atomically
 * (temp + rename). Fits a single-replica app with a persistent state directory; a multi-replica app
 * supplies a database-backed store instead.
 */
export class FileEmailAccountStore implements EmailAccountStore {
  constructor(private readonly dir: string) {}

  private file(kind: "accounts" | "codes", email: string): string {
    return join(this.dir, kind, `${createHash("sha256").update(email).digest("hex")}.json`)
  }

  private async read<T>(path: string): Promise<T | null> {
    try {
      return JSON.parse(await readFile(path, "utf8")) as T
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return null
      throw err
    }
  }

  private async write(path: string, value: unknown): Promise<void> {
    await mkdir(join(path, ".."), { recursive: true, mode: 0o700 })
    const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`
    await writeFile(tmp, JSON.stringify(value), { mode: 0o600 })
    await rename(tmp, path)
  }

  getAccount(email: string) {
    return this.read<EmailAccount>(this.file("accounts", email))
  }
  putAccount(account: EmailAccount) {
    return this.write(this.file("accounts", account.email), account)
  }
  getPending(email: string) {
    return this.read<PendingEmailCode>(this.file("codes", email))
  }
  putPending(p: PendingEmailCode) {
    return this.write(this.file("codes", p.email), p)
  }
  async deletePending(email: string) {
    await rm(this.file("codes", email), { force: true })
  }
}
