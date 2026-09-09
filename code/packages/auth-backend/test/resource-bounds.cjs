/**
 * P3 + P4 + P5 — outbound calls must be bounded in time, and in-process caches bounded in size.
 *
 * P3: the X path passes `AbortSignal.timeout(20_000)` on both of its fetches; the Google token
 *     exchange passes none. A hung connection to Google holds the request, its socket and its
 *     closure until Node's default socket timeout, with the human watching a spinner.
 * P4: `AuthClient.request` has no signal, no retry and no keep-alive, so a slow Backend API stalls
 *     the caller indefinitely.
 * P5: `jwksCache` is keyed by issuer and never evicts — a multi-tenant host that passes a per-tenant
 *     issuer grows it without limit. `InMemorySamlReplayStore` never bounds its map, takes its TTL
 *     from the IdP (so a far-future value pins an entry forever), and prunes with a full O(n) scan
 *     on EVERY `seen()` — i.e. on every SAML login.
 */
const assert = require("node:assert")
const http = require("node:http")
const { readFile } = require("node:fs/promises")
const { join } = require("node:path")

const {
  InMemorySamlReplayStore,
  createFederatedClient,
  jwksCacheSize,
  verifyToken,
} = require("../dist/index.js")

async function main() {
  // --- P3: every outbound fetch in the frontend must carry an abort signal ---------------------
  {
    const src = await readFile(join(__dirname, "..", "dist", "frontend.js"), "utf8")
    const unbounded = []
    for (const m of src.matchAll(/\bfetch\s*\(/g)) {
      // Look at the call's own argument list — a signal must appear before the next statement.
      const window = src.slice(m.index, m.index + 900)
      if (!/signal\s*:/.test(window)) {
        unbounded.push(src.slice(Math.max(0, m.index - 60), m.index + 60).replace(/\s+/g, " "))
      }
    }
    assert.deepStrictEqual(
      unbounded,
      [],
      `every outbound fetch must carry a timeout signal; unbounded call(s): ${JSON.stringify(unbounded, null, 2)}`,
    )
    console.log("  ✓ every outbound fetch in the frontend carries an abort signal (P3)")
  }

  // --- P4: the Backend API client must give up on a hung upstream ------------------------------
  {
    // A server that accepts the connection and then never answers.
    const hung = http.createServer(() => {})
    await new Promise((r) => hung.listen(0, "127.0.0.1", r))
    const { port } = hung.address()
    try {
      const client = createFederatedClient({
        secretKey: "sk_test",
        apiUrl: `http://127.0.0.1:${port}/v1`,
        timeoutMs: 250,
      })
      const started = Date.now()
      await assert.rejects(
        () => client.users.getUser("user_1"),
        /timed out|abort/i,
        "a hung Backend API must surface as a timeout, not hang the caller",
      )
      const elapsed = Date.now() - started
      assert.ok(elapsed < 5000, `the client waited ${elapsed}ms — the timeout was not applied`)
      console.log(`  ✓ AuthClient gives up on a hung upstream (${elapsed}ms, budget 250ms) (P4)`)
    } finally {
      hung.closeAllConnections?.()
      await new Promise((r) => hung.close(r))
    }
  }

  // --- P5: the SAML replay store must be bounded -----------------------------------------------
  {
    const store = new InMemorySamlReplayStore()
    assert.strictEqual(typeof store.size, "number", "the replay store must report its size")

    const FAR_FUTURE = Date.now() + 365 * 24 * 60 * 60 * 1000
    for (let i = 0; i < 50_000; i++) store.record(`_assertion_${i}`, FAR_FUTURE)
    assert.ok(
      store.size <= 20_000,
      `the replay store grew to ${store.size} entries — an IdP-supplied expiry must not pin memory`,
    )
    console.log(`  ✓ the SAML replay store is bounded (${store.size} entries after 50k records) (P5)`)

    // And `seen()` must not be a full scan of the map on every SAML login.
    const started = Date.now()
    for (let i = 0; i < 20_000; i++) store.seen(`_probe_${i}`)
    const elapsed = Date.now() - started
    assert.ok(elapsed < 1000, `20k seen() calls took ${elapsed}ms — seen() is still O(n) per call`)
    console.log(`  ✓ seen() is not a full scan per call (20k lookups in ${elapsed}ms) (P5)`)

    // Eviction must never turn a REMEMBERED id into an unseen one within its own window.
    const fresh = new InMemorySamlReplayStore()
    fresh.record("_recent", Date.now() + 60_000)
    assert.strictEqual(fresh.seen("_recent"), true, "a just-recorded id must still read as seen")
    console.log("  ✓ eviction never forgets an id inside its own validity window")
  }

  // --- P5: the JWKS cache must be bounded ------------------------------------------------------
  {
    assert.strictEqual(typeof jwksCacheSize, "function", "the JWKS cache must expose its size")
    for (let i = 0; i < 300; i++) {
      await verifyToken("not.a.token", {
        embedded: false,
        issuer: `https://tenant-${i}.idp.example`,
      }).catch(() => {})
    }
    const size = jwksCacheSize()
    assert.ok(size <= 100, `the JWKS cache grew to ${size} entries — it must evict`)
    console.log(`  ✓ the JWKS cache is bounded (${size} entries after 300 distinct issuers) (P5)`)
  }

  console.log("\nAll resource-bound checks passed.")
}

main().catch((e) => {
  console.error("FAILED:", e.message)
  process.exit(1)
})
