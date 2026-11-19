/**
 * A session the Frontend API no longer accepts must not be asked for tokens forever.
 *
 * Seen in production (2026-11-19): one idle browser tab POSTed /client/sessions/<id>/tokens and got 401 about
 * twice a minute for days (1,424 a day). The tab's in-memory session id outlived the server session (its cookie
 * was gone), and every caller that asked for a token (an SSE stream that re-checks auth every 60 s) minted again.
 * `mintToken` answered null and changed nothing, so the next caller did the same.
 *
 * Clerk's behaviour, which we match: a 401 from the token endpoint means "the session is not valid any more" —
 * re-read the client once; if the server says signed out, become signed out (no more mints, the app's guard shows
 * sign-in); if the server still lists the session, back off instead of retrying on every call.
 */
import assert from "node:assert"

import { RealAuthCore } from "../dist/index.js"

const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
const fakeJwt = (ttl = 300) =>
  `eyJhbGciOiJIUzI1NiJ9.${b64url({ exp: Math.floor(Date.now() / 1000) + ttl })}.sig`

const clientBody = (sessionId) => ({
  object: "client",
  last_active_session_id: sessionId,
  org_id: null,
  organization_memberships: [],
  sessions: sessionId
    ? [
        {
          id: sessionId,
          status: "active",
          user_id: "user_test",
          last_verified_at: Date.now(),
          user: { id: "user_test", primary_email_address: "someone@example.com", roles: [], permissions: [] },
        },
      ]
    : [],
})

/** /client answers from state.sessionId; /tokens answers state.tokenStatus. Counts both. */
function stubFetch(state) {
  globalThis.fetch = async (url) => {
    const href = String(url)
    if (href.endsWith("/client")) {
      state.clients++
      return new Response(JSON.stringify(clientBody(state.sessionId)), { status: 200 })
    }
    if (href.includes("/tokens")) {
      state.mints++
      if (state.tokenStatus !== 200) {
        return new Response(JSON.stringify({ errors: [{ code: "authentication_invalid" }] }), {
          status: state.tokenStatus,
        })
      }
      return new Response(JSON.stringify({ jwt: fakeJwt() }), { status: 200 })
    }
    return new Response("{}", { status: 200 })
  }
}

const quiet = () => {
  const warn = console.warn
  const lines = []
  console.warn = (...a) => lines.push(a.join(" "))
  return { lines, restore: () => (console.warn = warn) }
}

async function main() {
  // --- 1. the server ended the session: one 401 → re-read the client → signed out, no more mints ----------------
  {
    const state = { sessionId: "sess_dead", tokenStatus: 200, mints: 0, clients: 0 }
    stubFetch(state)
    const core = new RealAuthCore("http://127.0.0.1:1", "pk_test", ["example.com"])
    await core.load()
    assert.ok(core.getSnapshot().isSignedIn, "starts signed in")

    // The server session ends (cookie gone / revoked): /client now says signed out, /tokens says 401.
    state.sessionId = null
    state.tokenStatus = 401
    const q = quiet()
    try {
      assert.strictEqual(await core.getToken(), null, "a rejected mint yields no token")
    } finally {
      q.restore()
    }
    assert.strictEqual(state.mints, 1, "one mint was tried")
    assert.strictEqual(state.clients, 2, "and the client was re-read once to learn why")
    assert.strictEqual(core.getSnapshot().isSignedIn, false, "the core is now signed out")
    assert.ok(q.lines.some((l) => /ended|signed out/i.test(l)), "and said so once in the console")

    for (let i = 0; i < 20; i++) await core.getToken()
    assert.strictEqual(state.mints, 1, "a signed-out core never asks /tokens again")
    console.log("  ✓ a 401 from /tokens re-reads the client once and signs out; no more mints")
  }

  // --- 2. the server still lists the session (inconsistent): back off, never mint on every call ------------------
  {
    const state = { sessionId: "sess_odd", tokenStatus: 200, mints: 0, clients: 0 }
    stubFetch(state)
    const core = new RealAuthCore("http://127.0.0.1:1", "pk_test", ["example.com"])
    await core.load()
    state.tokenStatus = 401
    const realNow = Date.now
    let now = realNow()
    Date.now = () => now
    const q = quiet()
    try {
      assert.strictEqual(await core.getToken(), null)
      assert.strictEqual(state.mints, 1)
      assert.strictEqual(core.getSnapshot().isSignedIn, true, "the server still says signed in")

      // 50 callers over the next 20 s: none of them reaches the network.
      for (let i = 0; i < 50; i++) {
        now += 400
        assert.strictEqual(await core.getToken(), null)
      }
      assert.strictEqual(state.mints, 1, "inside the back-off window nothing is minted")

      // After the window one mint is tried again; it fails again → a LONGER window.
      now += 30_000
      await core.getToken()
      assert.strictEqual(state.mints, 2, "one retry after the window")
      now += 35_000
      await core.getToken()
      assert.strictEqual(state.mints, 2, "the second window is longer than the first")

      // The server recovers: the next allowed mint succeeds and the back-off is forgotten.
      state.tokenStatus = 200
      now += 10 * 60_000
      assert.ok(await core.getToken(), "a recovered session mints again")
      assert.strictEqual(state.mints, 3)
    } finally {
      Date.now = realNow
      q.restore()
    }
    console.log("  ✓ a session the server still lists backs off (30 s, then longer) instead of minting per call")
  }

  // --- 3. a transient 5xx is not a dead session: no client re-read, no sign-out --------------------------------
  {
    const state = { sessionId: "sess_ok", tokenStatus: 503, mints: 0, clients: 0 }
    stubFetch(state)
    const core = new RealAuthCore("http://127.0.0.1:1", "pk_test", ["example.com"])
    await core.load()
    assert.strictEqual(await core.getToken(), null)
    assert.strictEqual(state.clients, 1, "a 503 does not re-read the client")
    assert.strictEqual(core.getSnapshot().isSignedIn, true, "and does not sign anyone out")
    state.tokenStatus = 200
    assert.ok(await core.getToken(), "the next call mints normally")
    console.log("  ✓ a 5xx from /tokens stays a transient failure (no sign-out)")
  }

  console.log("dead-session: all checks passed")
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
