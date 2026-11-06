"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemorySessionStore = exports.FileSessionStore = void 0;
exports.loadOrCreateSecret = loadOrCreateSecret;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const promises_1 = require("node:fs/promises");
const node_path_1 = require("node:path");
/**
 * Reduce a value to something safe to use as one filesystem path segment.
 *
 * An ALLOWLIST, not a denylist. The previous denylist (`/`, `\`, NUL, `..`) missed everything it had
 * not thought of — `:` opens an NTFS alternate data stream, and a leading `.` hides the entry.
 *
 * The set is deliberately wide enough for the two things that actually reach it, so tightening the
 * check cannot lock anyone out:
 *   - a session id we generate ourselves — `sess_` plus base64url, so alphanumerics, `-` and `_`;
 *   - an email verified by an upstream IdP — RFC 5322 `atext` allows `!#$%&'*+-/=?^_`{|}~` in the
 *     local part, and all of those are permitted here EXCEPT the ones that are meaningful to a
 *     filesystem (`/ \ : * ? " < > |`) or to a shell-ish path (backtick), which the old denylist
 *     mostly let through.
 */
const SAFE_SEGMENT = /^[A-Za-z0-9._%+@!#$&'=^~{}-]+$/;
function sanitizeSegment(value) {
    const trimmed = (value ?? "").trim();
    if (trimmed === "" || trimmed === "." || trimmed === ".." || !SAFE_SEGMENT.test(trimmed)) {
        throw new Error(`Illegal path segment: ${JSON.stringify(value)}`);
    }
    return trimmed;
}
/** Lowercase + sanitize an email into a safe, human-browsable folder name. */
function userFolderKey(email) {
    return sanitizeSegment(email).toLowerCase();
}
/**
 * Separator for {@link InMemorySessionStore}'s `"<email><SEP><sid>"` composite key.
 *
 * NUL can appear in neither half (both go through {@link sanitizeSegment}), so it cannot be used to
 * make two different (email, sid) pairs collide on one key. It was previously written as a RAW NUL
 * BYTE in this source file, which made git classify the file as binary — no diff, no blame, no
 * review of anything in it — and made the character invisible in an editor. Same value, spelled as
 * an escape.
 */
const KEY_SEP = "\u0000";
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
class FileSessionStore {
    root;
    constructor(root) {
        this.root = root;
    }
    /**
     * Directories we have already created in this process. `mkdir` is idempotent but still a syscall,
     * and it runs on the write path of every token mint; after the first sign-in for a user it is
     * pure overhead.
     */
    ensured = new Set();
    sessionsDir(email) {
        return (0, node_path_1.join)(this.root, "users", userFolderKey(email), "sessions");
    }
    sessionFile(email, sid) {
        return (0, node_path_1.join)(this.sessionsDir(email), `${sanitizeSegment(sid)}.json`);
    }
    async ensureDir(dir) {
        if (this.ensured.has(dir))
            return;
        await (0, promises_1.mkdir)(dir, { recursive: true });
        this.ensured.add(dir);
    }
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
    async create(session) {
        const file = this.sessionFile(session.email, session.sid);
        const dir = (0, node_path_1.dirname)(file);
        await this.ensureDir(dir);
        const scratch = `${file}.${(0, node_crypto_1.randomBytes)(6).toString("hex")}.tmp`;
        try {
            await (0, promises_1.writeFile)(scratch, JSON.stringify(session, null, 2), { encoding: "utf8", mode: 0o600 });
            await (0, promises_1.rename)(scratch, file);
        }
        catch (err) {
            // Never leave scratch behind on a failed write — it would accumulate in the user's directory.
            await (0, promises_1.rm)(scratch, { force: true }).catch(() => { });
            throw err;
        }
    }
    async get(userKey, sid) {
        let file;
        try {
            file = this.sessionFile(userKey, sid);
        }
        catch {
            return null;
        }
        try {
            return JSON.parse(await (0, promises_1.readFile)(file, "utf8"));
        }
        catch {
            // Absent (ENOENT) or unparseable. With atomic writes a torn file is no longer reachable, so
            // this is genuinely "no such session" — which the caller treats as signed out.
            return null;
        }
    }
    async touch(userKey, sid, patch) {
        const current = await this.get(userKey, sid);
        if (!current)
            return;
        await this.create({ ...current, ...patch, sid: current.sid, email: current.email });
    }
    async remove(userKey, sid) {
        const current = await this.get(userKey, sid);
        if (current) {
            // Tombstone (keep the file, mark revoked) so a lingering cookie can't re-heal it.
            await this.create({ ...current, revoked: true });
            return;
        }
        // No record to tombstone — make sure nothing stale lingers.
        try {
            await (0, promises_1.rm)(this.sessionFile(userKey, sid), { force: true });
        }
        catch {
            /* best-effort */
        }
    }
    async list(userKey) {
        let dir;
        try {
            dir = this.sessionsDir(userKey);
        }
        catch {
            return [];
        }
        let names;
        try {
            names = await (0, promises_1.readdir)(dir);
        }
        catch {
            return []; // no directory yet — a user who has never signed in
        }
        // Read the files concurrently: this is the one method that touches N files, and doing them in
        // series made "list my sessions" scale with the user's session count.
        const records = await Promise.all(names
            .filter((n) => n.endsWith(".json"))
            .map(async (name) => {
            try {
                return JSON.parse(await (0, promises_1.readFile)((0, node_path_1.join)(dir, name), "utf8"));
            }
            catch {
                return null; // skip unreadable
            }
        }));
        return records.filter((r) => r !== null && !r.revoked);
    }
    /** Tombstone every non-revoked session under `users/<email>/sessions/`. */
    async revokeAllForUser(userKey) {
        const active = await this.list(userKey);
        let count = 0;
        for (const s of active) {
            await this.create({ ...s, revoked: true });
            count++;
        }
        return count;
    }
}
exports.FileSessionStore = FileSessionStore;
/** In-memory {@link SessionStore} — handy for tests or stateless deployments. Lost on restart. */
class InMemorySessionStore {
    map = new Map();
    key(userKey, sid) {
        return `${userFolderKey(userKey)}${KEY_SEP}${sid}`;
    }
    create(session) {
        this.map.set(this.key(session.email, session.sid), { ...session });
    }
    get(userKey, sid) {
        return this.map.get(this.key(userKey, sid)) ?? null;
    }
    touch(userKey, sid, patch) {
        const cur = this.get(userKey, sid);
        if (cur)
            this.map.set(this.key(userKey, sid), { ...cur, ...patch });
    }
    remove(userKey, sid) {
        const cur = this.get(userKey, sid);
        if (cur)
            this.map.set(this.key(userKey, sid), { ...cur, revoked: true });
    }
    list(userKey) {
        const prefix = `${userFolderKey(userKey)}${KEY_SEP}`;
        return [...this.map.entries()]
            .filter(([k, v]) => k.startsWith(prefix) && !v.revoked)
            .map(([, v]) => ({ ...v }));
    }
    /** Delete every session of one user (an in-memory store has no lingering cookie to out-live). */
    revokeAllForUser(userKey) {
        const prefix = `${userFolderKey(userKey)}${KEY_SEP}`;
        let count = 0;
        for (const [k, v] of [...this.map.entries()]) {
            if (!k.startsWith(prefix))
                continue;
            if (!v.revoked)
                count++;
            this.map.delete(k);
        }
        return count;
    }
}
exports.InMemorySessionStore = InMemorySessionStore;
/**
 * Load a stable HS256 signing secret from disk, creating one (cryptographically random, 0600) on
 * first run. Use this when the embedding app has no explicitly supplied secret, so the secret is
 * BOTH strong AND stable across restarts — a random per-process secret would silently invalidate
 * every session on every restart. A secret the app supplies explicitly should still win over this.
 *
 * NOTE: only adopt this where the signing secret is not also shared with another process (e.g. a
 * frontend dev-core that signs tokens with a known shared default) — in that case keep the shared
 * value so both sides still agree.
 */
function loadOrCreateSecret(filePath) {
    try {
        if ((0, node_fs_1.existsSync)(filePath)) {
            const existing = (0, node_fs_1.readFileSync)(filePath, "utf8").trim();
            if (existing)
                return existing;
        }
    }
    catch {
        /* fall through to generate */
    }
    const secret = (0, node_crypto_1.randomBytes)(48).toString("base64url");
    try {
        (0, node_fs_1.mkdirSync)((0, node_path_1.dirname)(filePath), { recursive: true });
        (0, node_fs_1.writeFileSync)(filePath, secret, { encoding: "utf8", mode: 0o600 });
    }
    catch {
        // If we can't persist it we still return a usable secret for this process; restarts would
        // rotate it, but that's strictly better than crashing, and callers log the situation.
    }
    return secret;
}
//# sourceMappingURL=session-store.js.map