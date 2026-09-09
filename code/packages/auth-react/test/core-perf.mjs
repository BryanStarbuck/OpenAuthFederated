/**
 * P6 + P9 + P10 — client-side allocation and network churn.
 *
 * P6: `context.tsx` builds the context value with `connections: core.connections()` inside a
 *     `useMemo` that lists `snapshot` as a dependency. `connections()` rebuilds its array by
 *     `.map` on every call, so every auth state change hands every consumer of `useAuthContext()`
 *     a brand-new array — and the connection list is derived from a constructor argument that can
 *     never change. Memoizing it in the core fixes it for React and for anyone else.
 *
 * P9: `applyClient` opens with `clearTokenCache()` unconditionally. That is correct when the
 *     session identity changed and wasteful when it did not — so `reloadSession()`, which exists
 *     precisely to recover from a transient 401, always forces an extra `/tokens` round trip.
 *
 * P10: `@auth/react` declares a dependency on `jose` and never imports it.
 */
import assert from "node:assert"
import { readFile } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

import { RealAuthCore } from "../dist/index.js"

const here = dirname(fileURLToPath(import.meta.url))

const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
// `jti` makes each minted token a distinct STRING, so "was a new token issued?" is answerable by
// comparing values. Without it two mints in the same second are byte-identical and the assertion
// that a token is never reused across a session change cannot fail even when it should.
let jti = 0
const fakeJwt = (ttl = 300) =>
  `eyJhbGciOiJIUzI1NiJ9.${b64url({ exp: Math.floor(Date.now() / 1000) + ttl, jti: ++jti })}.sig`

/** A client snapshot in the shape the Frontend API returns. */
const clientBody = (sessionId) => ({
  object: "client",
  last_active_session_id: sessionId,
  org_id: null,
  organization_memberships: [],
  sessions: [
    {
      id: sessionId,
      status: "active",
      user_id: "user_abc",
      last_verified_at: Date.now(),
      user: { id: "user_abc", primary_email_address: "bryan@act3ai.com", roles: [], permissions: [] },
    },
  ],
})

/** Install a fetch stub that serves /client from `sessionId` and counts token mints. */
function stubFetch(state) {
  globalThis.fetch = async (url) => {
    const href = String(url)
    if (href.endsWith("/client")) {
      return new Response(JSON.stringify(clientBody(state.sessionId)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    }
    if (href.includes("/tokens")) {
      state.mints++
      return new Response(JSON.stringify({ jwt: fakeJwt() }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    }
    return new Response("{}", { status: 200 })
  }
}

async function main() {
  // --- P6: connections() must be a stable reference ---------------------------------------------
  {
    const core = new RealAuthCore("http://127.0.0.1:1", "pk_test", ["act3ai.com", "whitehatengineering.com"])
    const a = core.connections()
    const b = core.connections()
    assert.strictEqual(
      a,
      b,
      "connections() must return the same array each call — it is derived from a constructor " +
        "argument, and a fresh array re-renders every consumer of the auth context on every state change",
    )
    assert.strictEqual(a.length, 2, "both configured domains must still be offered")
    assert.strictEqual(a[0].domain, "act3ai.com")
    console.log("  ✓ connections() returns a stable reference (P6)")

    // Stable must not mean mutable-shared: a caller must not be able to edit the SDK's list.
    assert.ok(Object.isFrozen(a), "the shared connections array must be frozen against caller mutation")
    console.log("  ✓ the shared connections array is frozen against caller mutation")
  }

  // --- P9: a reload that finds the SAME session must keep the cached access token ---------------
  {
    const state = { sessionId: "sess_1", mints: 0 }
    stubFetch(state)
    const core = new RealAuthCore("http://127.0.0.1:1", "pk_test", ["act3ai.com"])

    await core.load()
    const first = await core.getToken()
    assert.ok(first, "a signed-in core must mint a token")
    assert.strictEqual(state.mints, 1, "the first getToken mints once")

    await core.load() // same session — e.g. reloadSession() after a transient 401
    const second = await core.getToken()
    assert.strictEqual(
      state.mints,
      1,
      "reloading the SAME session must not discard a still-valid access token",
    )
    assert.strictEqual(second, first, "and must serve the cached token")
    console.log("  ✓ reloading an unchanged session keeps the cached token (P9)")

    // A DIFFERENT session must still invalidate — never serve a token across an identity change.
    state.sessionId = "sess_2"
    await core.load()
    const third = await core.getToken()
    assert.strictEqual(state.mints, 2, "a changed session id must force a fresh mint")
    assert.notStrictEqual(third, first, "a token must never be served across a session change")
    console.log("  ✓ a changed session id still invalidates the cached token (P9)")

    // Signing out must invalidate too.
    state.sessionId = null
    await core.load()
    assert.strictEqual(await core.getToken(), null, "a signed-out core must not serve a cached token")
    console.log("  ✓ signing out drops the cached token")
  }

  // --- P10: no declared dependency may go unused -------------------------------------------------
  {
    const pkg = JSON.parse(await readFile(join(here, "..", "package.json"), "utf8"))
    const deps = Object.keys(pkg.dependencies ?? {})
    const sources = await Promise.all(
      ["core.ts", "components.tsx", "context.tsx", "hooks.ts", "index.ts", "types.ts"].map((f) =>
        readFile(join(here, "..", "src", f), "utf8"),
      ),
    )
    const all = sources.join("\n")
    const unused = deps.filter((d) => !new RegExp(`from ["']${d}(/|["'])`).test(all))
    assert.deepStrictEqual(
      unused,
      [],
      `declared but never imported: ${unused.join(", ")} — it installs into every consuming app`,
    )
    console.log("  ✓ every declared runtime dependency is actually imported (P10)")
  }

  console.log("\nAll auth-react core performance checks passed.")
}

main().catch((e) => {
  console.error("FAILED:", e.message)
  process.exit(1)
})
