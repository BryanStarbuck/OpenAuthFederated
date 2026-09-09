/**
 * S5 + S11 — endpoint-level hardening on the mounted middleware.
 *
 * S5: nothing bounds request rate on any route. `/saml/acs` does XML signature work before it can
 *     cheaply refuse anything, and `/oauth_callback/x` makes TWO outbound calls to X per
 *     unauthenticated request — so the library is an amplifier against a third party's rate limits.
 *     Every refusal also writes a warn line, making an unauthenticated flood a log-volume DoS.
 *     The library cannot own the limiter (it is mounted middleware), but it must expose the seam.
 *
 * S11: `Vary: Origin` is set only inside the CORS-match branch, so a response that varies on
 *     Origin can be emitted without declaring that it does.
 */
const assert = require("node:assert")

const { createFederatedFrontend } = require("../dist/index.js")
const { serve, call, recordingLogger } = require("./helpers.cjs")

const SECRET = "another-strong-test-session-secret-32-chars"

function build(overrides = {}) {
  return createFederatedFrontend({
    sessionSecret: SECRET,
    allowedDomains: ["act3ai.com"],
    cookieSecure: false,
    logger: recordingLogger(),
    connections: [
      {
        strategy: "oauth_google",
        clientId: "id",
        clientSecret: "sec",
        redirectUri: "http://localhost:9111/api/v1/oauth_callback",
      },
    ],
    ...overrides,
  })
}

async function main() {
  // --- S5: the rate-limit seam exists and can refuse before any work is done ------------------
  {
    const seen = []
    const srv = await serve(
      build({
        rateLimit: (ctx) => {
          seen.push(ctx)
          return false // refuse everything
        },
      }),
    )
    try {
      const sso = await call(srv.base, "/sign_in/sso")
      assert.strictEqual(sso.status, 429, "a refused request must answer 429, not redirect to Google")
      assert.strictEqual(
        sso.location,
        null,
        "a rate-limited sign-in must not hand the browser an IdP redirect",
      )

      const acs = await call(srv.base, "/saml/acs", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "SAMLResponse=x",
      })
      assert.strictEqual(acs.status, 429, "the ACS must be refusable before it parses any XML")

      assert.ok(seen.length >= 2, "the hook must be consulted for each request")
      assert.ok(
        seen.every((c) => typeof c.path === "string" && typeof c.method === "string"),
        "the hook must receive enough context (method + path) to make a decision",
      )
      console.log("  ✓ a rateLimit hook can refuse a request with 429 before any handler runs (S5)")
    } finally {
      await srv.close()
    }
  }

  // Allowing the request must leave behaviour exactly as it was.
  {
    const srv = await serve(build({ rateLimit: () => true }))
    try {
      const sso = await call(srv.base, "/sign_in/sso")
      assert.strictEqual(sso.status, 302, "an allowed request must proceed unchanged")
      assert.match(sso.location, /accounts\.google\.com/, "and still reach the IdP")
      console.log("  ✓ an allowing hook leaves the flow untouched")
    } finally {
      await srv.close()
    }
  }

  // No hook configured at all must stay the historical behaviour.
  {
    const srv = await serve(build())
    try {
      const sso = await call(srv.base, "/sign_in/sso")
      assert.strictEqual(sso.status, 302, "with no hook the flow is unchanged (back-compat)")
      console.log("  ✓ with no rateLimit configured nothing changes (back-compat)")
    } finally {
      await srv.close()
    }
  }

  // An async hook is supported (a real limiter talks to Redis).
  {
    const srv = await serve(build({ rateLimit: async () => false }))
    try {
      const res = await call(srv.base, "/environment")
      assert.strictEqual(res.status, 429, "an async hook must be awaited, not coerced to truthy")
      console.log("  ✓ an async rateLimit hook is awaited")
    } finally {
      await srv.close()
    }
  }

  // A throwing hook must fail CLOSED — a limiter outage is not a reason to drop the limit.
  {
    const srv = await serve(
      build({
        rateLimit: () => {
          throw new Error("redis down")
        },
      }),
    )
    try {
      const res = await call(srv.base, "/sign_in/sso")
      assert.strictEqual(res.status, 429, "a throwing limiter must refuse, not wave the request through")
      console.log("  ✓ a throwing rateLimit hook fails closed")
    } finally {
      await srv.close()
    }
  }

  // --- S11: Vary: Origin on every response when CORS is configured -----------------------------
  {
    const srv = await serve(build({ allowedCorsOrigins: ["https://app.example.com"] }))
    try {
      const matched = await call(srv.base, "/environment", {
        headers: { Origin: "https://app.example.com" },
      })
      assert.strictEqual(matched.headers.get("access-control-allow-origin"), "https://app.example.com")
      assert.match(matched.headers.get("vary") ?? "", /Origin/i, "matched origin must Vary")

      const unmatched = await call(srv.base, "/environment", {
        headers: { Origin: "https://evil.example" },
      })
      assert.strictEqual(
        unmatched.headers.get("access-control-allow-origin"),
        null,
        "a non-allowlisted origin gets no CORS grant",
      )
      assert.match(
        unmatched.headers.get("vary") ?? "",
        /Origin/i,
        "a response whose content depends on Origin must declare Vary: Origin even when it does not match",
      )
      console.log("  ✓ Vary: Origin is emitted on matched AND unmatched origins (S11)")
    } finally {
      await srv.close()
    }
  }

  console.log("\nAll endpoint hardening checks passed.")
}

main().catch((e) => {
  console.error("FAILED:", e.message)
  process.exit(1)
})
