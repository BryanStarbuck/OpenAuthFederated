import { randomBytes } from "node:crypto"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"

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
 * which matches a simple per-user disk layout (`<data-dir>/users/<email>/...`). No database
 * required.
 */

/** One organization membership carried on a stored session (structurally identical to OrgMembership). */
export interface SessionMembership {
  id: string
  organization: { id: string; name: string; slug?: string }
  role: string
  permissions: string[]
}

/**
 * The durable session record. Times are epoch SECONDS (matching the JWT `exp`/`iat` convention the
 * rest of the library uses), not milliseconds.
 */
export interface StoredSession {
  /** Session id (`sess_…`). Primary key within a user's folder. */
  sid: string
  /** Stable user id (`user_<google-sub>`). */
  userId: string
  /** Verified email — also the folder key on disk. */
  email: string
  name?: string
  firstName?: string
  lastName?: string
  hd?: string
  roles: string[]
  permissions: string[]
  orgId: string | null
  memberships: SessionMembership[]
  /** Last step-up / reverify time (epoch seconds). */
  lastVerifiedAt: number
  /**
   * When the grants (roles/permissions/memberships) on this record were last resolved (epoch
   * seconds). Optional for back-compat with records written before grant re-resolution existed.
   */
  grantsResolvedAt?: number
  /**
   * The upstream subject exactly as the IdP asserted it, and the strategy that asserted it. Stored
   * rather than recovered from {@link userId}, whose shape is configurable (`namespaceUserIds`):
   * these are what grant re-resolution asks the host about, so they must be the IdP's values, not a
   * parse of one of ours. Optional for back-compat with records written before they existed.
   */
  providerSub?: string
  provider?: "google" | "saml" | "x" | "email"
  /** True when the session was established after admission required a verified email. */
  emailVerified?: boolean
  /** When the session was first established (epoch seconds). */
  createdAt: number
  /** Last time a token was minted / the session was touched (epoch seconds) — drives inactivity. */
  lastActiveAt: number
  /** Absolute maximum-lifetime ceiling (epoch seconds). After this the user must sign in again. */
  expireAt: number
  /**
   * Tombstone flag. `remove()` sets this rather than only deleting the file so a revoked session
   * cannot be silently re-created by the lazy self-heal path while a valid cookie is still around.
   */
  revoked?: boolean
}

/**
 * Pluggable persistence for {@link StoredSession}. All methods may be sync or async; the frontend
 * awaits them. A user key (the email) scopes every operation so the on-disk layout can be
 * per-user and no global index is needed — the session cookie always carries the email.
 */
export interface SessionStore {
  /** Persist a freshly-established session. */
  create(session: StoredSession): Promise<void> | void
  /** Fetch a session by user + sid. Returns null when absent (never existed or hard-deleted). */
  get(userKey: string, sid: string): Promise<StoredSession | null> | StoredSession | null
  /** Update the activity timestamp (and optionally other mutable fields) for a session. */
  touch(
    userKey: string,
    sid: string,
    patch: Partial<StoredSession>,
  ): Promise<void> | void
  /** Revoke (tombstone) a session so it can no longer be used. */
  remove(userKey: string, sid: string): Promise<void> | void
  /** List a user's non-revoked sessions (the "active sessions" surface). */
  list(userKey: string): Promise<StoredSession[]> | StoredSession[]
  /**
   * Revoke EVERY session of one user ("sign out everywhere", offboarding, a newly blocked
   * identity). Optional so third-party stores keep type-checking; the frontend's
   * `revokeUserSessions()` throws when it is missing. Returns the number of sessions revoked.
   */
  revokeAllForUser?(userKey: string): Promise<number> | number
}

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
const SAFE_SEGMENT = /^[A-Za-z0-9._%+@!#$&'=^~{}-]+$/
function sanitizeSegment(value: string): string {
  const trimmed = (value ?? "").trim()
  if (trimmed === "" || trimmed === "." || trimmed === ".." || !SAFE_SEGMENT.test(trimmed)) {
    throw new Error(`Illegal path segment: ${JSON.stringify(value)}`)
  }
  return trimmed
}

/** Lowercase + sanitize an email into a safe, human-browsable folder name. */
function userFolderKey(email: string): string {
  return sanitizeSegment(email).toLowerCase()
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
const KEY_SEP = "\u0000"

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
export class FileSessionStore implements SessionStore {
  constructor(private readonly root: string) {}

  /**
   * Directories we have already created in this process. `mkdir` is idempotent but still a syscall,
   * and it runs on the write path of every token mint; after the first sign-in for a user it is
   * pure overhead.
   */
  private readonly ensured = new Set<string>()

  private sessionsDir(email: string): string {
    return join(this.root, "users", userFolderKey(email), "sessions")
  }

  private sessionFile(email: string, sid: string): string {
    return join(this.sessionsDir(email), `${sanitizeSegment(sid)}.json`)
  }

  private async ensureDir(dir: string): Promise<void> {
    if (this.ensured.has(dir)) return
    await mkdir(dir, { recursive: true })
    this.ensured.add(dir)
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
  async create(session: StoredSession): Promise<void> {
    const file = this.sessionFile(session.email, session.sid)
    const dir = dirname(file)
    await this.ensureDir(dir)
    const scratch = `${file}.${randomBytes(6).toString("hex")}.tmp`
    try {
      await writeFile(scratch, JSON.stringify(session, null, 2), { encoding: "utf8", mode: 0o600 })
      await rename(scratch, file)
    } catch (err) {
      // Never leave scratch behind on a failed write — it would accumulate in the user's directory.
      await rm(scratch, { force: true }).catch(() => {})
      throw err
    }
  }

  async get(userKey: string, sid: string): Promise<StoredSession | null> {
    let file: string
    try {
      file = this.sessionFile(userKey, sid)
    } catch {
      return null
    }
    try {
      return JSON.parse(await readFile(file, "utf8")) as StoredSession
    } catch {
      // Absent (ENOENT) or unparseable. With atomic writes a torn file is no longer reachable, so
      // this is genuinely "no such session" — which the caller treats as signed out.
      return null
    }
  }

  async touch(userKey: string, sid: string, patch: Partial<StoredSession>): Promise<void> {
    const current = await this.get(userKey, sid)
    if (!current) return
    await this.create({ ...current, ...patch, sid: current.sid, email: current.email })
  }

  async remove(userKey: string, sid: string): Promise<void> {
    const current = await this.get(userKey, sid)
    if (current) {
      // Tombstone (keep the file, mark revoked) so a lingering cookie can't re-heal it.
      await this.create({ ...current, revoked: true })
      return
    }
    // No record to tombstone — make sure nothing stale lingers.
    try {
      await rm(this.sessionFile(userKey, sid), { force: true })
    } catch {
      /* best-effort */
    }
  }

  async list(userKey: string): Promise<StoredSession[]> {
    let dir: string
    try {
      dir = this.sessionsDir(userKey)
    } catch {
      return []
    }
    let names: string[]
    try {
      names = await readdir(dir)
    } catch {
      return [] // no directory yet — a user who has never signed in
    }
    // Read the files concurrently: this is the one method that touches N files, and doing them in
    // series made "list my sessions" scale with the user's session count.
    const records = await Promise.all(
      names
        .filter((n) => n.endsWith(".json"))
        .map(async (name) => {
          try {
            return JSON.parse(await readFile(join(dir, name), "utf8")) as StoredSession
          } catch {
            return null // skip unreadable
          }
        }),
    )
    return records.filter((r): r is StoredSession => r !== null && !r.revoked)
  }

  /** Tombstone every non-revoked session under `users/<email>/sessions/`. */
  async revokeAllForUser(userKey: string): Promise<number> {
    const active = await this.list(userKey)
    let count = 0
    for (const s of active) {
      await this.create({ ...s, revoked: true })
      count++
    }
    return count
  }
}

/** In-memory {@link SessionStore} — handy for tests or stateless deployments. Lost on restart. */
export class InMemorySessionStore implements SessionStore {
  private readonly map = new Map<string, StoredSession>()
  private key(userKey: string, sid: string): string {
    return `${userFolderKey(userKey)}${KEY_SEP}${sid}`
  }
  create(session: StoredSession): void {
    this.map.set(this.key(session.email, session.sid), { ...session })
  }
  get(userKey: string, sid: string): StoredSession | null {
    return this.map.get(this.key(userKey, sid)) ?? null
  }
  touch(userKey: string, sid: string, patch: Partial<StoredSession>): void {
    const cur = this.get(userKey, sid)
    if (cur) this.map.set(this.key(userKey, sid), { ...cur, ...patch })
  }
  remove(userKey: string, sid: string): void {
    const cur = this.get(userKey, sid)
    if (cur) this.map.set(this.key(userKey, sid), { ...cur, revoked: true })
  }
  list(userKey: string): StoredSession[] {
    const prefix = `${userFolderKey(userKey)}${KEY_SEP}`
    return [...this.map.entries()]
      .filter(([k, v]) => k.startsWith(prefix) && !v.revoked)
      .map(([, v]) => ({ ...v }))
  }
  /** Delete every session of one user (an in-memory store has no lingering cookie to out-live). */
  revokeAllForUser(userKey: string): number {
    const prefix = `${userFolderKey(userKey)}${KEY_SEP}`
    let count = 0
    for (const [k, v] of [...this.map.entries()]) {
      if (!k.startsWith(prefix)) continue
      if (!v.revoked) count++
      this.map.delete(k)
    }
    return count
  }
}

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
export function loadOrCreateSecret(filePath: string): string {
  try {
    if (existsSync(filePath)) {
      const existing = readFileSync(filePath, "utf8").trim()
      if (existing) return existing
    }
  } catch {
    /* fall through to generate */
  }
  const secret = randomBytes(48).toString("base64url")
  try {
    mkdirSync(dirname(filePath), { recursive: true })
    writeFileSync(filePath, secret, { encoding: "utf8", mode: 0o600 })
  } catch {
    // If we can't persist it we still return a usable secret for this process; restarts would
    // rotate it, but that's strictly better than crashing, and callers log the situation.
  }
  return secret
}
