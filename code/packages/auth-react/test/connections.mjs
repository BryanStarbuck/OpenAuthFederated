/**
 * Connections, copy and sign-up mode: the SDK carries NO built-in domain list and no app's copy.
 *
 *   * a core built without connections offers one generic Google button (no default domains);
 *   * the `connections` argument/prop takes precedence; an EMPTY array means no buttons;
 *   * the server's /environment connections are adopted when the app configured none;
 *   * the sign-in URL defaults to strategy oauth_google and sends no connection when there is none;
 *   * useSignUp sends mode=sign_up;
 *   * connectionIdForDomain matches the backend's mapping byte for byte;
 *   * <SignIn> renders the app's title/subtitle/footer and no built-in company wording.
 */
import assert from "node:assert"
import { createRequire } from "node:module"

import { createElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"

import {
  RealAuthCore,
  BaseCore,
  FederatedProvider,
  SignIn,
  SignUp,
  useSignUp,
  useSignIn,
  connectionIdForDomain,
  GENERIC_GOOGLE_CONNECTION,
} from "../dist/index.js"

const require = createRequire(import.meta.url)
let passed = 0
const ok = (m) => {
  passed++
  console.log(`  ✓ ${m}`)
}

const API = "http://127.0.0.1:1/api"

function urlOf(core, params) {
  return new URL(core.signInUrl({ redirectUrl: "/sso-callback", redirectUrlComplete: "/", ...params }))
}

async function main() {
  // --- no default domains ------------------------------------------------------------------------
  {
    const core = new RealAuthCore(API, "pk_test")
    const conns = core.connections()
    assert.deepStrictEqual(conns, [GENERIC_GOOGLE_CONNECTION], "no configuration => one generic Google button only")
    assert.ok(!JSON.stringify(conns).includes(".com"), "no built-in domain connection")
    const u = urlOf(core, {})
    assert.strictEqual(u.searchParams.get("strategy"), "oauth_google", "default strategy is oauth_google")
    assert.strictEqual(u.searchParams.get("connection"), "conn_google")
    assert.strictEqual(u.searchParams.get("mode"), null, "no mode unless asked")
    ok("no configured connections => one generic Google button, strategy oauth_google")
  }

  // --- precedence ----------------------------------------------------------------------------------
  {
    const mine = [
      { id: "conn_x", label: "X", strategy: "oauth_x" },
      { id: connectionIdForDomain("corp.example"), label: "Corp", strategy: "oauth_google", domain: "corp.example" },
    ]
    const core = new RealAuthCore(API, "pk_test", ["legacy.example"], mine)
    assert.deepStrictEqual(core.connections().map((c) => c.id), ["conn_x", "conn_corp_example"], "connections beat allowedDomains")
    assert.ok(Object.isFrozen(core.connections()))
    assert.strictEqual(urlOf(core, {}).searchParams.get("strategy"), "oauth_x", "the connection's own strategy is used")
    assert.strictEqual(urlOf(core, { connection: "conn_corp_example" }).searchParams.get("strategy"), "oauth_google")
    assert.strictEqual(urlOf(core, { connection: "conn_corp_example" }).searchParams.get("connection"), "conn_corp_example")

    const legacy = new RealAuthCore(API, "pk_test", ["corp.example"])
    assert.deepStrictEqual(legacy.connections().map((c) => [c.id, c.label, c.domain]), [["conn_corp_example", "corp.example", "corp.example"]], "the 3-argument form is unchanged")

    const none = new RealAuthCore(API, "pk_test", undefined, [])
    assert.deepStrictEqual(none.connections(), [], "an explicitly empty connections list shows no buttons (no fallback)")
    const u = urlOf(none, {})
    assert.strictEqual(u.searchParams.get("connection"), null, "no connection is sent when there is none")
    ok("precedence: connections > allowedDomains > /environment > generic; [] means no buttons")
  }

  // --- /environment connections adopted when none configured ---------------------------------------
  {
    let envCalls = 0
    globalThis.fetch = async (url) => {
      const href = String(url)
      if (href.endsWith("/environment")) {
        envCalls++
        return new Response(
          JSON.stringify({
            user_settings: {
              connections: [
                { id: "conn_google", strategy: "oauth_google", label: "Google" },
                { id: "conn_x", strategy: "oauth_x", label: "X" },
              ],
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        )
      }
      if (href.endsWith("/client")) {
        return new Response(JSON.stringify({ object: "client", last_active_session_id: null, sessions: [] }), { status: 200 })
      }
      return new Response("{}", { status: 200 })
    }
    const core = new RealAuthCore(API, "pk_test")
    let notified = 0
    core.subscribe(() => notified++)
    await core.load()
    assert.deepStrictEqual(core.connections().map((c) => c.id), ["conn_google", "conn_x"], "the server's connections are adopted")
    assert.ok(notified > 0, "subscribers are told the connection list changed")
    await core.load()
    assert.strictEqual(envCalls, 1, "/environment is read once per core")

    const configured = new RealAuthCore(API, "pk_test", ["corp.example"])
    await configured.load()
    assert.strictEqual(envCalls, 1, "a core with app-supplied connections never reads /environment for them")
    ok("/environment connections are adopted once when the app configured none")
  }

  // --- useSignUp sends mode=sign_up --------------------------------------------------------------
  {
    const seen = []
    class FakeCore extends BaseCore {
      async load() {}
      connections() {
        return [{ id: "conn_google", label: "Google", strategy: "oauth_google" }]
      }
      async getToken() {
        return null
      }
      async authenticateWithRedirect(p) {
        seen.push(p)
      }
      async completeRedirectCallback() {
        return {}
      }
      async signOut() {}
      async reverify() {}
    }
    const core = new FakeCore()
    let signUp = null
    let signIn = null
    function Probe() {
      signUp = useSignUp().signUp
      signIn = useSignIn().signIn
      return null
    }
    renderToStaticMarkup(createElement(FederatedProvider, { core }, createElement(Probe)))
    await signUp.authenticateWithRedirect({ redirectUrl: "/sso-callback", redirectUrlComplete: "/" })
    await signIn.authenticateWithRedirect({ redirectUrl: "/sso-callback", redirectUrlComplete: "/" })
    assert.strictEqual(seen[0].mode, "sign_up", "useSignUp sends mode=sign_up")
    assert.strictEqual(seen[1].mode, undefined, "useSignIn sends no mode")
    const real = new RealAuthCore(API, "pk_test")
    assert.strictEqual(urlOf(real, { mode: "sign_up" }).searchParams.get("mode"), "sign_up", "the mode reaches the sign-in URL")
    ok("useSignUp passes mode 'sign_up' through to /sign_in/sso")

    // <SignIn> copy: the app's own, nothing built in.
    const plain = renderToStaticMarkup(createElement(FederatedProvider, { core }, createElement(SignIn)))
    assert.ok(plain.includes("Sign in") && plain.includes("Continue with Google"), "neutral defaults")
    for (const banned of ["Internal App", "Employees only", "Workspace", "company"]) {
      assert.ok(!plain.includes(banned), `no built-in "${banned}" copy`)
    }
    const custom = renderToStaticMarkup(
      createElement(
        FederatedProvider,
        { core },
        createElement(SignUp, {
          title: "Join the movement",
          subtitle: "Pick a provider.",
          footer: "No passwords.",
          connections: [{ id: "conn_x", label: "X", strategy: "oauth_x" }],
        }),
      ),
    )
    assert.ok(custom.includes("Join the movement") && custom.includes("Pick a provider.") && custom.includes("No passwords."))
    assert.ok(custom.includes("Continue with X") && !custom.includes("Continue with Google"), "the connections prop overrides per screen")
    ok("<SignIn>/<SignUp> render the app's title/subtitle/footer/connections and no built-in company copy")
  }

  // --- connectionIdForDomain parity with the backend ---------------------------------------------
  {
    let backend
    try {
      backend = require("../../auth-backend/dist/index.js")
    } catch {
      backend = null
    }
    const samples = ["corp.example", "Corp-1.Example.COM", "a_b.example", "xn--bcher-kva.example", "x..y"]
    if (backend) {
      for (const d of samples) assert.strictEqual(connectionIdForDomain(d), backend.connectionIdForDomain(d), `parity for ${d}`)
      ok("connectionIdForDomain matches @auth/backend for every sample")
    } else {
      assert.strictEqual(connectionIdForDomain("Corp-1.Example.COM"), "conn_corp_1_example_com")
      ok("connectionIdForDomain mapping (backend dist not built, parity skipped)")
    }
  }

  console.log(`\nAll auth-react connection checks passed (${passed}).`)
}

main().catch((e) => {
  console.error("FAILED:", e.stack || e.message)
  process.exit(1)
})
