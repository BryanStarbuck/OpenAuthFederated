/**
 * Persistent, server-side session store — the *stateful* half of a hosted-identity-provider-style
 * session model.
 *
 * A hosted-identity-provider-style session model keeps a long-lived session RECORD on the server (so
 * a session can be listed, revoked, and aged out by inactivity) while the browser only ever holds a
 * short-lived session *token* that is refreshed on an interval. OpenAuthFederated's embedded
 * `createFederatedFrontend()` already implements the short-token + sliding-cookie half; this module
 * adds the durable record.
 *
 * Why this matters for "stay logged in forever, even across app restarts": with only a stateless
 * signed cookie, the cookie alone carries the session, so a restart is survivable ONLY as long as
 * the signing secret is stable. Persisting the record to disk makes the session a real, durable
 * object the app owns — it survives restarts, supports revocation (sign out everywhere), and can
 * enforce an inactivity timeout — without forcing the human to sign in again.
 *
 * The default {@link FileSessionStore} writes one JSON file per session under
 *   `<root>/users/<email>/sessions/<sid>.json`
 * which matches the per-user disk layout both consuming web apps already use (`~/T/_mai/users/...`
 * and `~/T/_act3_app/users/...`). No database required.
 */
/** One organization membership carried on a stored session (structurally identical to OrgMembership). */
export interface SessionMembership {
    id: string;
    organization: {
        id: string;
        name: string;
        slug?: string;
    };
    role: string;
    permissions: string[];
}
/**
 * The durable session record. Times are epoch SECONDS (matching the JWT `exp`/`iat` convention the
 * rest of the library uses), not milliseconds.
 */
export interface StoredSession {
    /** Session id (`sess_…`). Primary key within a user's folder. */
    sid: string;
    /** Stable user id (`user_<google-sub>`). */
    userId: string;
    /** Verified email — also the folder key on disk. */
    email: string;
    name?: string;
    firstName?: string;
    lastName?: string;
    hd?: string;
    roles: string[];
    permissions: string[];
    orgId: string | null;
    memberships: SessionMembership[];
    /** Last step-up / reverify time (epoch seconds). */
    lastVerifiedAt: number;
    /**
     * When the grants (roles/permissions/memberships) on this record were last resolved (epoch
     * seconds). Optional for back-compat with records written before grant re-resolution existed.
     */
    grantsResolvedAt?: number;
    /**
     * The upstream subject exactly as the IdP asserted it, and the strategy that asserted it. Stored
     * rather than recovered from {@link userId}, whose shape is configurable (`namespaceUserIds`):
     * these are what grant re-resolution asks the host about, so they must be the IdP's values, not a
     * parse of one of ours. Optional for back-compat with records written before they existed.
     */
    providerSub?: string;
    provider?: "google" | "saml" | "x";
    /** When the session was first established (epoch seconds). */
    createdAt: number;
    /** Last time a token was minted / the session was touched (epoch seconds) — drives inactivity. */
    lastActiveAt: number;
    /** Absolute maximum-lifetime ceiling (epoch seconds). After this the user must sign in again. */
    expireAt: number;
    /**
     * Tombstone flag. `remove()` sets this rather than only deleting the file so a revoked session
     * cannot be silently re-created by the lazy self-heal path while a valid cookie is still around.
     */
    revoked?: boolean;
}
/**
 * Pluggable persistence for {@link StoredSession}. All methods may be sync or async; the frontend
 * awaits them. A user key (the email) scopes every operation so the on-disk layout can be
 * per-user and no global index is needed — the session cookie always carries the email.
 */
export interface SessionStore {
    /** Persist a freshly-established session. */
    create(session: StoredSession): Promise<void> | void;
    /** Fetch a session by user + sid. Returns null when absent (never existed or hard-deleted). */
    get(userKey: string, sid: string): Promise<StoredSession | null> | StoredSession | null;
    /** Update the activity timestamp (and optionally other mutable fields) for a session. */
    touch(userKey: string, sid: string, patch: Partial<StoredSession>): Promise<void> | void;
    /** Revoke (tombstone) a session so it can no longer be used. */
    remove(userKey: string, sid: string): Promise<void> | void;
    /** List a user's non-revoked sessions (the "active sessions" surface). */
    list(userKey: string): Promise<StoredSession[]> | StoredSession[];
}
/**
 * Disk-backed {@link SessionStore}. One JSON file per session:
 *   `<root>/users/<email>/sessions/<sid>.json`
 *
 * Directories are created lazily on first write; reads of a brand-new user return nothing without
 * creating anything. Every method is ASYNCHRONOUS — this store sits on the request path (a single
 * token mint does a read plus a read-modify-write), and Node has one JS thread, so a synchronous
 * `readFileSync`/`writeFileSync` here pauses every other in-flight request in the process. Writes
 * go through a scratch file and `rename()`, so a reader can never observe a half-written record.
 */
export declare class FileSessionStore implements SessionStore {
    private readonly root;
    constructor(root: string);
    /**
     * Directories we have already created in this process. `mkdir` is idempotent but still a syscall,
     * and it runs on the write path of every token mint; after the first sign-in for a user it is
     * pure overhead.
     */
    private readonly ensured;
    private sessionsDir;
    private sessionFile;
    private ensureDir;
    /**
     * Write a session record ATOMICALLY: a scratch file in the same directory, then `rename()` over
     * the target. Rename is atomic within a filesystem, so a reader sees either the whole previous
     * record or the whole new one — never a truncated file.
     *
     * The previous in-place `writeFileSync` could be interrupted by a crash or interleaved with a
     * concurrent write, leaving JSON that `get()` swallows as "absent". Under the default fail-closed
     * mode that reads as a spurious sign-out; under `cookie-grace` it bypasses revocation. Neither is
     * an acceptable outcome for a torn write of a session record.
     *
     * The scratch name carries random bytes so two concurrent writers cannot collide on it.
     */
    create(session: StoredSession): Promise<void>;
    get(userKey: string, sid: string): Promise<StoredSession | null>;
    touch(userKey: string, sid: string, patch: Partial<StoredSession>): Promise<void>;
    remove(userKey: string, sid: string): Promise<void>;
    list(userKey: string): Promise<StoredSession[]>;
}
/** In-memory {@link SessionStore} — handy for tests or stateless deployments. Lost on restart. */
export declare class InMemorySessionStore implements SessionStore {
    private readonly map;
    private key;
    create(session: StoredSession): void;
    get(userKey: string, sid: string): StoredSession | null;
    touch(userKey: string, sid: string, patch: Partial<StoredSession>): void;
    remove(userKey: string, sid: string): void;
    list(userKey: string): StoredSession[];
}
/**
 * Load a stable HS256 signing secret from disk, creating one (cryptographically random, 0600) on
 * first run. Use this when no `AUTH_SESSION_SECRET` is provided so the secret is BOTH strong AND
 * stable across restarts — a random per-process secret would silently invalidate every session on
 * every restart. An explicit env secret should still win over this; callers pass it as a fallback.
 *
 * NOTE: only adopt this where the signing secret is not also shared with another process (e.g. a
 * frontend dev-core that signs tokens with a known shared default) — in that case keep the shared
 * value so both sides still agree.
 */
export declare function loadOrCreateSecret(filePath: string): string;
