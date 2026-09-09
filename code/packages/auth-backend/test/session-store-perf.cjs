/**
 * P1 — FileSessionStore must not block the event loop, and must not be able to publish a
 * half-written record.
 *
 * Every method is synchronous fs today (`existsSync`/`readFileSync`/`writeFileSync`/`readdirSync`),
 * and every one of them sits on the request path: a single `/tokens` mint does 2 stats, 2 reads, a
 * mkdir and a write. Node has one JS thread, so each of those pauses every other in-flight request
 * in the process.
 *
 * `create()` also writes in place with no temp-file + rename. A crash or a concurrent write mid-
 * `writeFileSync` leaves truncated JSON, which `get()` swallows as "absent" — under the default
 * fail-closed mode that logs the user out; under `cookie-grace` it bypasses revocation.
 */
const assert = require("node:assert")
const { mkdtempSync, readdirSync } = require("node:fs")
const { tmpdir } = require("node:os")
const { join } = require("node:path")
const { readFile } = require("node:fs/promises")

const { FileSessionStore } = require("../dist/index.js")

const EMAIL = "bryan@act3ai.com"

function record(sid, extra = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    sid,
    userId: "user_abc",
    email: EMAIL,
    roles: ["employee"],
    permissions: [],
    orgId: null,
    // A realistic, non-trivial payload — a truncated write of a 2-byte file is hard to observe.
    memberships: Array.from({ length: 40 }, (_, i) => ({
      id: `orgmem_${i}`,
      organization: { id: `org_${i}`, name: `Organization number ${i}`.padEnd(120, "."), slug: `org-${i}` },
      role: "employee",
      permissions: ["code:read", "jfk:read"],
    })),
    lastVerifiedAt: now,
    grantsResolvedAt: now,
    createdAt: now,
    lastActiveAt: now,
    expireAt: now + 3600,
    revoked: false,
    ...extra,
  }
}

async function main() {
  const root = mkdtempSync(join(tmpdir(), "oaf-perf-"))
  const store = new FileSessionStore(root)

  // --- The store must be async: every method returns a thenable ---------------------------------
  const created = store.create(record("sess_async"))
  assert.strictEqual(
    typeof created?.then,
    "function",
    "create() must be asynchronous — a sync write blocks every other request in the process",
  )
  await created
  for (const [name, thenable] of [
    ["get", store.get(EMAIL, "sess_async")],
    ["touch", store.touch(EMAIL, "sess_async", { lastActiveAt: 1 })],
    ["list", store.list(EMAIL)],
    ["remove", store.remove(EMAIL, "sess_async")],
  ]) {
    assert.strictEqual(typeof thenable?.then, "function", `${name}() must be asynchronous`)
    await thenable
  }
  console.log("  ✓ every FileSessionStore method is asynchronous (P1)")

  // --- No synchronous fs may remain in the compiled store ---------------------------------------
  // A behavioural test cannot distinguish "async wrapper around a sync call"; the source can.
  // Scoped to the FileSessionStore class only: `loadOrCreateSecret` is a bootstrap helper that runs
  // once at startup, not on the request path, so synchronous fs is the right choice there.
  const compiled = await readFile(join(__dirname, "..", "dist", "session-store.js"), "utf8")
  const storeBody = compiled.slice(
    compiled.indexOf("class FileSessionStore"),
    compiled.indexOf("class InMemorySessionStore"),
  )
  const syncCalls = [...storeBody.matchAll(/\b(readFileSync|writeFileSync|existsSync|readdirSync|rmSync|mkdirSync)\s*\(/g)]
  assert.deepStrictEqual(
    syncCalls.map((m) => m[1]),
    [],
    "FileSessionStore must contain no synchronous fs calls — they block the shared event loop",
  )
  console.log("  ✓ no synchronous fs calls remain inside FileSessionStore (P1)")

  // --- A reader must never observe a partially-written record -----------------------------------
  // Hammer one session with concurrent writes while reading it. With an in-place writeFileSync a
  // reader eventually catches a truncated file, which get() reports as `null` (a spurious logout).
  await store.create(record("sess_hot"))
  const writes = []
  const reads = []
  for (let i = 0; i < 60; i++) {
    writes.push(store.touch(EMAIL, "sess_hot", { lastActiveAt: 1000 + i }))
    reads.push(store.get(EMAIL, "sess_hot"))
  }
  await Promise.all(writes)
  const observed = await Promise.all(reads)
  const torn = observed.filter((r) => r !== null && (!Array.isArray(r.memberships) || r.memberships.length !== 40))
  assert.deepStrictEqual(torn, [], "a reader observed a torn record — the write is not atomic")
  const vanished = observed.filter((r) => r === null)
  assert.deepStrictEqual(
    vanished,
    [],
    "a live session read as absent during concurrent writes — that is a spurious sign-out",
  )
  console.log("  ✓ concurrent writes never publish a torn or momentarily-absent record (P1)")

  // --- Temp files must not be left behind -------------------------------------------------------
  const dir = join(root, "users", EMAIL, "sessions")
  const leftovers = readdirSync(dir).filter((n) => !n.endsWith(".json"))
  assert.deepStrictEqual(leftovers, [], `atomic-write scratch files were left behind: ${leftovers}`)
  console.log("  ✓ no scratch files are left in the session directory")

  // --- The path-segment allowlist must admit every real key, and refuse traversal ----------------
  // Tightening this check to an allowlist is exactly the kind of change that quietly locks people
  // out, so both directions are pinned. The generated sid alphabet is base64url (`-` and `_`), and
  // RFC 5322 allows a lot more than [a-z] in an email local part.
  {
    const legit = [
      ["sess_abc-DEF_123", "bryan@act3ai.com"],
      ["sess_-_-_-", "john_doe@act3ai.com"],
      ["sess_x", "o'brien@act3ai.com"],
      ["sess_y", "first.last+tag@act3ai.com"],
      ["sess_z", "a!#$%&'=^~@act3ai.com"],
    ]
    for (const [sid, email] of legit) {
      await store.create(record(sid, { email }))
      const back = await store.get(email, sid)
      assert.ok(back, `a legitimate key was rejected: ${email} / ${sid}`)
    }
    console.log("  ✓ real session ids and RFC-legal email local parts are all accepted")

    const hostile = [
      ["../../etc/passwd", "bryan@act3ai.com"],
      ["sess_1", "../../../root"],
      ["sess/1", "bryan@act3ai.com"],
      ["sess\\1", "bryan@act3ai.com"],
      ["sess_1", "bryan@act3ai.com:stream"],
      ["", "bryan@act3ai.com"],
    ]
    for (const [sid, email] of hostile) {
      // A rejected key must never resolve to a record — whether it throws or reads as absent, it
      // must not reach outside the session directory.
      const got = await store.get(email, sid).catch(() => null)
      assert.strictEqual(got, null, `a path-hostile key resolved: ${email} / ${sid}`)
    }
    console.log("  ✓ traversal and filesystem-hostile segments are refused")
  }

  // --- The event loop must keep turning while the store is busy ---------------------------------
  // A blocking store starves the timer entirely; an async one lets it fire throughout.
  let ticks = 0
  const timer = setInterval(() => ticks++, 5)
  try {
    for (let i = 0; i < 150; i++) await store.touch(EMAIL, "sess_hot", { lastActiveAt: 2000 + i })
  } finally {
    clearInterval(timer)
  }
  assert.ok(ticks > 0, "the event loop never turned during 150 store writes — the store is blocking")
  console.log(`  ✓ the event loop kept turning during 150 writes (${ticks} timer ticks) (P1)`)

  console.log("\nAll session-store performance checks passed.")
}

main().catch((e) => {
  console.error("FAILED:", e.message)
  process.exit(1)
})
