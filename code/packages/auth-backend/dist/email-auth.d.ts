/** Why a code is being sent. Only the copy differs; every purpose proves the mailbox. */
export type EmailCodePurpose = "sign_up" | "sign_in" | "reset_password";
/** What the app's `sendCode` callback is asked to deliver. */
export interface EmailCodeMessage {
    /** The normalized (trimmed, lowercased) address. */
    to: string;
    /** Six digits. Put it in the message; never log it on a shared server. */
    code: string;
    purpose: EmailCodePurpose;
    expiresInMinutes: number;
    /**
     * Whether a verified account already exists for this address. The RESPONSE to the browser is
     * identical either way (no account enumeration); the EMAIL may say "here is your sign-in code"
     * instead of "confirm your new account".
     */
    accountExists: boolean;
}
/** The app's answer: did the message actually leave? */
export interface EmailDelivery {
    delivered: boolean;
    /** One sentence for the log when it did not. */
    problem?: string | null;
}
/** The `email` connection, passed in `connections[]`. */
export interface EmailConnectionConfig {
    strategy: "email";
    /** Deliver a one-time code. The app owns the transport (SendGrid, SES, SMTP...) and the wording. */
    sendCode: (message: EmailCodeMessage) => EmailDelivery | Promise<EmailDelivery>;
    /** Where email accounts and pending codes live. Required. */
    store: EmailAccountStore;
    /** Offer a password as a second way back in (set at sign-up or by reset). Default true. */
    password?: boolean;
    /** Code lifetime. Default 600 (10 minutes). */
    codeTtlSeconds?: number;
    /** Wrong guesses allowed per code before it is burned. Default 5. */
    maxCodeAttempts?: number;
    /** Minimum gap between two codes to one address. Default 30. */
    resendCooldownSeconds?: number;
    /** Codes per address per rolling hour. Default 10. */
    maxCodesPerHour?: number;
    /** Default 8 (Clerk's default). Maximum is always 256. */
    minPasswordLength?: number;
    /** Failed password attempts before the account's password is locked. Default 10. */
    maxPasswordFailures?: number;
    /** How long the password lock lasts. Default 900 (15 minutes). A code sign-in still works. */
    passwordLockSeconds?: number;
    /** Button / heading label. Default "Email". */
    label?: string;
}
/** One email account. `id` is the stable subject (`em_...`); key app rows on (provider "email", id). */
export interface EmailAccount {
    id: string;
    email: string;
    /** `scrypt$N$r$p$salt$hash`, or null for a code-only account. */
    passwordHash: string | null;
    /** Unix seconds when the mailbox was first proven. Accounts are only ever written verified. */
    verifiedAt: number;
    createdAt: number;
    updatedAt: number;
    failedPasswordAttempts?: number;
    passwordLockedUntil?: number | null;
}
/** A code waiting to be typed back. Only a salted HMAC of the code is stored. */
export interface PendingEmailCode {
    email: string;
    purpose: EmailCodePurpose;
    salt: string;
    codeHash: string;
    expiresAt: number;
    attempts: number;
    /** Unix seconds of each code sent in the last hour (the throttle). */
    sentAt: number[];
}
/** Persistence for the `email` connection. Every method is keyed by the normalized address. */
export interface EmailAccountStore {
    getAccount(email: string): Promise<EmailAccount | null>;
    putAccount(account: EmailAccount): Promise<void>;
    getPending(email: string): Promise<PendingEmailCode | null>;
    putPending(pending: PendingEmailCode): Promise<void>;
    deletePending(email: string): Promise<void>;
}
/** Hash a password for storage. */
export declare function hashPassword(password: string): Promise<string>;
/** Constant-time check of a password against a stored hash. A malformed hash is a mismatch. */
export declare function verifyPassword(password: string, stored: string | null | undefined): Promise<boolean>;
/** Why a password is not acceptable, or null when it is. */
export declare function passwordProblem(password: unknown, minLength: number): string | null;
/** Six digits, uniformly from a CSPRNG (leading zeros kept). */
export declare function newEmailCode(): string;
/** The stored form of a code: HMAC-SHA256 keyed by a per-code salt, bound to address and purpose. */
export declare function hashEmailCode(salt: string, email: string, purpose: EmailCodePurpose, code: string): string;
/** Constant-time comparison of a typed code against a pending one (purpose-bound). */
export declare function codeMatches(pending: PendingEmailCode, email: string, code: string): boolean;
/** A fresh salt for {@link hashEmailCode}. */
export declare function newCodeSalt(): string;
/** A fresh account subject. */
export declare function newEmailAccountId(): string;
/** Trim + lowercase. (Address syntax is checked by admission's parseEmail before this is used.) */
export declare function normalizeEmailAddress(email: unknown): string;
/** Process-local store, for tests and single-process demos. Loses everything on restart. */
export declare class InMemoryEmailAccountStore implements EmailAccountStore {
    private readonly accounts;
    private readonly pending;
    getAccount(email: string): Promise<EmailAccount | null>;
    putAccount(account: EmailAccount): Promise<void>;
    getPending(email: string): Promise<PendingEmailCode | null>;
    putPending(p: PendingEmailCode): Promise<void>;
    deletePending(email: string): Promise<void>;
}
/**
 * One JSON file per address under `dir/accounts/` and `dir/codes/`, named by a SHA-256 of the
 * address (so a directory listing is not a mailing list). Files are 0600, written atomically
 * (temp + rename). Fits a single-replica app with a persistent state directory; a multi-replica app
 * supplies a database-backed store instead.
 */
export declare class FileEmailAccountStore implements EmailAccountStore {
    private readonly dir;
    constructor(dir: string);
    private file;
    private read;
    private write;
    getAccount(email: string): Promise<EmailAccount | null>;
    putAccount(account: EmailAccount): Promise<void>;
    getPending(email: string): Promise<PendingEmailCode | null>;
    putPending(p: PendingEmailCode): Promise<void>;
    deletePending(email: string): Promise<void>;
}
