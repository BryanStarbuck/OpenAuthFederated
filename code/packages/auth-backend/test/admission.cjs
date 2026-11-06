/**
 * Admission: "the platform executes, the app decides".
 *
 * Drives the real middleware over a real loopback socket (real signed SAML assertions from the test
 * IdP in test/fixtures) plus the side-effect-free `evaluateAdmission()`, and checks the pure helpers
 * directly. Fixture identities use example.com / example.org / *.example only.
 *
 *   npm run build && node test/admission.cjs
 */
const assert = require("node:assert")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const { hkdfSync } = require("node:crypto")
const { SignJWT } = require("jose")

const {
  createFederatedFrontend,
  InMemorySessionStore,
  FileSessionStore,
  OafConfigError,
  ADMISSION_API_VERSION,
  parseEmail,
  matchIdentifier,
  decideRestrictions,
  connectionIdForDomain,
} = require("../dist/index.js")
const { serve, call, cookieValue, cookieHeader, jwtPayload, recordingLogger } = require("./helpers.cjs")
const { signedResponse, samlConfig, b64 } = require("./saml-fixture.cjs")

const SECRET = "a-strong-test-session-secret-of-32-plus-chars"
let passed = 0
const ok = (msg) => {
  passed++
  console.log(`  ✓ ${msg}`)
}

/** A frontend whose SAML ACS points back at its own ephemeral port. NO legacy keys unless given. */
async function startApp(overrides = {}, samlExtra = {}, opts = {}) {
  const logger = recordingLogger()
  const store = opts.noStore ? undefined : (opts.store ?? new InMemorySessionStore())
  let frontend = null
  const srv = await serve((req, res, next) => frontend(req, res, next))
  const acs = `${srv.base}/api/v1/saml/acs`
  const saml = samlConfig(acs, samlExtra)
  const base = {
    sessionSecret: SECRET,
    cookieSecure: false,
    logger,
    ...(store ? { sessionStore: store } : {}),
  }
  if (opts.samlAsConnection) {
    base.connections = [{ strategy: "saml", ...saml, ...(opts.samlConnectionExtra ?? {}) }]
  } else {
    base.saml = saml
  }
  frontend = createFederatedFrontend({ ...base, ...overrides })
  return { srv, acs, logger, store, frontend: () => frontend, close: () => srv.close() }
}

/** SP-initiated SAML round trip; returns the ACS response. */
async function samlSignIn(app, { email = "ann@example.com", attributes, mode } = {}) {
  const q = new URLSearchParams({ redirect_url: "/sso-callback", redirect_url_complete: "/home" })
  if (mode) q.set("mode", mode)
  const login = await call(app.srv.base, `/saml/login?${q}`)
  assert.strictEqual(login.status, 302, "/saml/login must redirect to the IdP")
  const relayState = new URL(login.location).searchParams.get("RelayState")
  const relayCookie = cookieValue(login.setCookie, "oaf_saml_relay")
  const xml = signedResponse({ acs: app.acs, email, attributes })
  return await call(app.srv.base, "/saml/acs", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: cookieHeader({ oaf_saml_relay: relayCookie }),
    },
    body: new URLSearchParams({ SAMLResponse: b64(xml), RelayState: relayState }).toString(),
  })
}

/** SAML step-up reverify for an existing session cookie. */
async function samlReverify(app, sessionCookie, { email, attributes } = {}) {
  const sid = jwtPayload(sessionCookie).sid
  const start = await call(app.srv.base, `/client/sessions/${sid}/reverify?redirect_url=/home`, {
    headers: { Cookie: cookieHeader({ oaf_session: sessionCookie }) },
  })
  assert.strictEqual(start.status, 302, "reverify must redirect to the IdP")
  const relayState = new URL(start.location).searchParams.get("RelayState")
  const relayCookie = cookieValue(start.setCookie, "oaf_saml_relay")
  const xml = signedResponse({ acs: app.acs, email, attributes })
  return await call(app.srv.base, "/saml/acs", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: cookieHeader({ oaf_saml_relay: relayCookie, oaf_session: sessionCookie }),
    },
    body: new URLSearchParams({ SAMLResponse: b64(xml), RelayState: relayState }).toString(),
  })
}

function params(res) {
  return res.location ? new URL(res.location, "http://internal").searchParams : new URLSearchParams()
}
const code = (res) => params(res).get("error")

async function mint(app, sessionCookie) {
  const sid = jwtPayload(sessionCookie).sid
  return await call(app.srv.base, `/client/sessions/${sid}/tokens`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookieHeader({ oaf_session: sessionCookie }) },
    body: "{}",
  })
}

async function clientSnapshot(app, sessionCookie) {
  return (await call(app.srv.base, "/client", { headers: { Cookie: cookieHeader({ oaf_session: sessionCookie }) } })).json
}

/** Assert a refusal established nothing: no session cookie and no stored record for the email. */
async function assertNothingMinted(app, res, email, label) {
  assert.strictEqual(cookieValue(res.setCookie, "oaf_session"), null, `${label}: no session cookie may be set`)
  if (app.store) {
    const rows = await app.store.list(email)
    assert.strictEqual(rows.length, 0, `${label}: no session record may be stored`)
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const id = (email, extra = {}) => ({ provider: "google", sub: `sub-${email}`, email, emailVerified: true, ...extra })

async function main() {
  assert.strictEqual(ADMISSION_API_VERSION, 1)
  ok("ADMISSION_API_VERSION is exported (1)")

  // ==== no policy stated: WARN once per process, public ====================================
  {
    const logger = recordingLogger()
    const fe = createFederatedFrontend({ sessionSecret: SECRET, cookieSecure: false, logger })
    const warns = logger.lines.filter((l) => l.level === "warn" && /no admission policy stated/.test(l.message))
    assert.strictEqual(warns.length, 1, "no stated policy must WARN")
    const r = await fe.evaluateAdmission(id("ann@personal.example"))
    assert.strictEqual(r.allowed, true, "no stated policy defaults to public")
    const logger2 = recordingLogger()
    createFederatedFrontend({ sessionSecret: SECRET, cookieSecure: false, logger: logger2 })
    assert.strictEqual(
      logger2.lines.filter((l) => /no admission policy stated/.test(l.message)).length,
      0,
      "the no-policy WARN is printed once per process, not per construction",
    )
    ok("no policy stated: WARN once per process and default to public")
  }

  // ==== construction-time validation ========================================================
  {
    const expectThrow = (cfg, label) => {
      assert.throws(
        () => createFederatedFrontend({ sessionSecret: SECRET, cookieSecure: false, logger: () => {}, ...cfg }),
        (e) => e instanceof OafConfigError,
        label,
      )
    }
    expectThrow({ allowedDomains: undefined }, "{ allowedDomains: undefined } must throw (key presence = legacy)")
    expectThrow({ allowedDomains: ["example.com"], requireHostedDomain: "yes" }, "a non-boolean legacy flag must throw")
    expectThrow({ xTrustConfirmedEmail: true }, "a legacy flag without allowedDomains must throw")
    expectThrow({ requirePolicy: true }, "requirePolicy with no policy must throw")
    expectThrow({ signUpMode: "Public" }, "an invalid static signUpMode must throw")
    expectThrow({ signUpMode: "public", restrictions: { allowlist: "yes" } }, "a non-boolean restriction must throw")
    expectThrow({ signUpMode: "public", allowlistIdentifiers: "*@example.com" }, "a non-array list must throw")
    expectThrow({ signUpMode: "waitlist" }, "waitlist without users must throw")
    expectThrow(
      { signUpMode: "restricted", restrictions: { applyToSignIn: false } },
      "restricted + applyToSignIn false + no users must throw",
    )
    expectThrow({ signUpMode: "public", actions: { timeoutMs: 0 } }, "actions.timeoutMs must be a positive integer")
    expectThrow({ signUpMode: "public", actions: { onError: { authentication: "maybe" } } }, "onError must be deny|allow")
    // requirePolicy is satisfied by a legacy key (it IS a stated policy).
    createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, allowedDomains: ["example.com"], requirePolicy: true })
    ok("construction refuses malformed legacy keys, missing policy (requirePolicy), invalid static values")
  }

  // ==== a list without its restrictions flag is never silently ignored ======================
  {
    const expectThrow = (cfg, label) =>
      assert.throws(
        () => createFederatedFrontend({ sessionSecret: SECRET, cookieSecure: false, logger: () => {}, ...cfg }),
        (e) => e instanceof OafConfigError && /would be silently ignored/.test(e.message),
        label,
      )
    // The two fail-open shapes from the review probe.
    expectThrow({ signUpMode: "public", blocklistIdentifiers: ["mallory@evil.example"] }, "blocklist without restrictions.blocklist must throw")
    expectThrow(
      { signUpMode: "public", allowlistIdentifiers: ["*@corp.example"], requirePolicy: true },
      "allowlist without restrictions.allowlist must throw (even with requirePolicy)",
    )
    expectThrow(
      { signUpMode: "restricted", restrictions: { allowlist: true }, blocklistIdentifiers: ["x@corp.example"] },
      "the blocklist flag is checked separately from the allowlist flag",
    )
    expectThrow(
      { signUpMode: "public", restrictions: { allowlist: false }, allowlistIdentifiers: ["*@corp.example"] },
      "an explicit false flag with a non-empty list must throw",
    )
    // An empty list without a flag is harmless and stays allowed.
    createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, signUpMode: "public", allowlistIdentifiers: [], blocklistIdentifiers: [] })

    // Live: cannot be judged at construction, so WARN once per process and keep the documented semantics.
    const logger = recordingLogger()
    const fe = createFederatedFrontend({
      sessionSecret: SECRET,
      logger,
      signUpMode: "public",
      blocklistIdentifiers: () => ["mallory@evil.example"],
    })
    await fe.evaluateAdmission(id("ann@ok.example"))
    await fe.evaluateAdmission(id("bob@ok.example"))
    const listWarns = logger.lines.filter((l) => l.level === "warn" && /blocklistIdentifiers .* is IGNORED/.test(l.message))
    assert.strictEqual(listWarns.length, 1, "a Live blocklist without its flag WARNs once per process")
    const liveRestr = recordingLogger()
    const fe2 = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: liveRestr,
      signUpMode: "public",
      restrictions: () => ({ blocklist: false }),
      allowlistIdentifiers: ["*@corp.example"],
    })
    await fe2.evaluateAdmission(id("ann@ok.example"))
    assert.strictEqual(
      liveRestr.lines.filter((l) => l.level === "warn" && /allowlistIdentifiers .* is IGNORED/.test(l.message)).length,
      1,
      "Live restrictions + a static list without the flag WARNs at resolution",
    )
    ok("a non-empty list without its restrictions flag: static throws OafConfigError, Live WARNs once per process")
  }

  // ==== pure helpers ========================================================================
  {
    assert.strictEqual(parseEmail("a@b@example.com"), null, "two @")
    assert.strictEqual(parseEmail("ann.example.com"), null, "zero @")
    assert.strictEqual(parseEmail('"ann smith"@example.com'), null, "quoted local part")
    assert.strictEqual(parseEmail("ann@example.com."), null, "trailing dot")
    assert.strictEqual(parseEmail("@example.com"), null, "empty local part")
    assert.deepStrictEqual(parseEmail("Ann@Bücher.Example"), { local: "ann", domain: "xn--bcher-kva.example" })
    ok("parseEmail is strict and converts a non-ASCII domain with domainToASCII")

    assert.ok(matchIdentifier("ann@eu.example.com", ["*@*.example.com"]), "subdomain wildcard matches a subdomain")
    assert.strictEqual(matchIdentifier("ann@example.com", ["*@*.example.com"]), null, "subdomain wildcard does not match the apex")
    assert.strictEqual(matchIdentifier("ann@evilexample.com", ["*@*.example.com"]), null, "subdomain suffix is label-aligned")
    assert.strictEqual(matchIdentifier("ann@example.com.evil.example", ["*@example.com"]), null, "domain match is exact")
    assert.strictEqual(matchIdentifier("ANN@Example.com", ["ann@example.com"]).specificity, 3, "exact is case-insensitive")
    const warned = []
    assert.strictEqual(matchIdentifier("ann@x.example", ["ann*@x.example"], { warn: (m) => warned.push(m) }), null)
    assert.ok(matchIdentifier("ann*@x.example", ["ann*@x.example"], { warn: (m) => warned.push(m) }), "a literal matches only itself")
    assert.strictEqual(warned.length, 1, "an unrecognized pattern WARNs once per distinct entry")
    assert.strictEqual(matchIdentifier("not-an-email", ["*@example.com"]), null, "an unparseable email never matches")
    const best = matchIdentifier("ann@example.com", ["*@example.com", "ann@example.com"])
    assert.deepStrictEqual(best, { identifier: "ann@example.com", specificity: 3 }, "the most specific match is returned")
    ok("matchIdentifier: subdomain-not-apex, exact, literal-with-WARN-once, most specific wins")

    const R = { allowlist: true, blocklist: true }
    assert.strictEqual(decideRestrictions("ann@example.com", R, ["*@example.com"], ["ann@example.com"]).outcome, "blocked", "exact block beats *@d allow")
    assert.strictEqual(decideRestrictions("ann@example.com", R, ["ann@example.com"], ["ann@example.com"]).outcome, "allow", "exact allow beats exact block (tie)")
    assert.strictEqual(decideRestrictions("ann@example.com", R, ["*@example.com"], ["*@example.com"]).outcome, "allow", "*@d allow beats *@d block (tie)")
    assert.strictEqual(
      decideRestrictions("ann@example.com", { allowlist: false, blocklist: true }, ["ann@example.com"], ["*@example.com"]).outcome,
      "blocked",
      "with the allowlist OFF a stale allowlist does not rescue a blocked identity",
    )
    assert.strictEqual(decideRestrictions("bob@other.example", R, ["*@example.com"], []).outcome, "not_allowlisted")
    assert.strictEqual(decideRestrictions("bob@other.example", { allowlist: true }, [], []).outcome, "not_allowlisted", "allowlist on with [] => nobody")
    assert.strictEqual(decideRestrictions("bob@other.example", {}, ["*@example.com"], ["bob@other.example"]).outcome, "allow", "lists not engaged")
    ok("decideRestrictions precedence: specific wins, tie to allowlist, allowlist override only when on")

    assert.strictEqual(connectionIdForDomain("Corp-1.Example.com"), "conn_corp_1_example_com")
    ok("connectionIdForDomain maps lowercase, non-alphanumerics to _")
  }

  // ==== public sign-up mode admits any verified email =======================================
  {
    const app = await startApp({ signUpMode: "public", requirePolicy: true })
    try {
      const res = await samlSignIn(app, { email: "citizen@personal.example" })
      assert.strictEqual(code(res), null, "public must admit a verified email with no hd on any domain")
      const session = cookieValue(res.setCookie, "oaf_session")
      assert.ok(session, "an admitted sign-in sets the session cookie")
      const claims = jwtPayload(session)
      assert.deepStrictEqual(claims.roles, ["member"], "default grants are a neutral least-privilege member")
      assert.strictEqual(claims.org_id, "org_default", "default org is neutral")
      const minted = await mint(app, session)
      assert.strictEqual(minted.status, 200)
      const tok = jwtPayload(minted.json.jwt)
      assert.strictEqual(tok.provider, "saml", "minted tokens carry the provider")
      assert.strictEqual(tok.email_verified, true, "minted tokens carry email_verified")
      ok("public mode admits any verified email; default grants neutral; tokens carry provider + email_verified")
    } finally {
      await app.close()
    }
  }

  // ==== unverified email: new mode vs legacy-only ===========================================
  {
    const app = await startApp({ signUpMode: "public" }, { trustAssertedEmailVerified: false })
    try {
      const res = await samlSignIn(app, { email: "ann@example.com" })
      assert.strictEqual(code(res), "identity_email_unverified", "new mode refuses an unverified email with its own code")
      assert.strictEqual(params(res).get("email_verified"), "false")
      assert.ok(params(res).get("trace_id"), "every refusal carries a trace_id")
      await assertNothingMinted(app, res, "ann@example.com", "unverified")
      ok("new mode: unverified email => identity_email_unverified + email_verified=false + trace_id")
    } finally {
      await app.close()
    }
  }
  {
    const app = await startApp({ allowedDomains: ["example.com"] }, { trustAssertedEmailVerified: false })
    try {
      const res = await samlSignIn(app, { email: "ann@example.com" })
      const p = params(res)
      assert.strictEqual(p.get("error"), "identity_domain_not_allowed", "legacy-only keeps the old code")
      assert.strictEqual(p.get("error_reason"), "identity_email_unverified", "additive error_reason")
      assert.strictEqual(p.get("email_verified"), "false", "additive email_verified")
      assert.strictEqual(p.get("presented_domain"), "", "presented_domain is still sent")
      ok("legacy-only: unverified email keeps identity_domain_not_allowed + error_reason + email_verified=false")
    } finally {
      await app.close()
    }
  }

  // ==== restricted mode + allowlist =========================================================
  {
    const app = await startApp({
      signUpMode: "restricted",
      restrictions: { allowlist: true },
      allowlistIdentifiers: ["*@corp.example"],
    })
    try {
      const yes = await samlSignIn(app, { email: "ann@corp.example" })
      assert.strictEqual(code(yes), null, "an allowlisted identity is admitted in restricted mode")
      const no = await samlSignIn(app, { email: "bob@other.example" })
      assert.strictEqual(code(no), "identity_not_allowlisted", "a non-allowlisted identity is refused")
      assert.strictEqual(params(no).get("allowed_domains"), null, "new-API refusals never publish allowed domains")
      await assertNothingMinted(app, no, "bob@other.example", "not allowlisted")
      ok("restricted + allowlist: allowlisted admitted, others refused identity_not_allowlisted, nothing minted")
    } finally {
      await app.close()
    }
  }
  {
    // Restricted with invitations from the app's own directory, allowlist off.
    const fe = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      signUpMode: "restricted",
      users: { lookup: async (i) => ({ exists: false, invited: i.email === "invited@example.org" }) },
    })
    assert.strictEqual((await fe.evaluateAdmission(id("invited@example.org"))).allowed, true, "invited is admitted")
    const r = await fe.evaluateAdmission(id("stranger@example.org"))
    assert.strictEqual(r.allowed, false)
    assert.strictEqual(r.code, "sign_up_restricted", "not invited => sign_up_restricted")
    // Without users, a non-allowlisted RETURNING user cannot be told apart from a new one: refused.
    const noUsers = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, signUpMode: "restricted" })
    const r2 = await noUsers.evaluateAdmission(id("returning@example.org"))
    assert.strictEqual(r2.code, "sign_up_restricted", "restricted without users refuses a non-allowlisted returning user")
    ok("restricted: invited (users.lookup) admitted, others sign_up_restricted; no users => fail closed")
  }

  // ==== waitlist ===========================================================================
  {
    const known = new Set(["old@example.org"])
    const fe = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      signUpMode: "waitlist",
      users: { lookup: async (i) => ({ exists: known.has(i.email) }) },
    })
    assert.strictEqual((await fe.evaluateAdmission(id("old@example.org"))).allowed, true, "waitlist admits a returning user")
    const r = await fe.evaluateAdmission(id("new@example.org"))
    assert.strictEqual(r.code, "sign_up_waitlisted", "waitlist refuses a new user")
    ok("waitlist refuses a new user and admits a returning one")
  }

  // ==== blocklist ==========================================================================
  {
    const app = await startApp({
      signUpMode: "public",
      restrictions: { blocklist: true },
      blocklistIdentifiers: ["mallory@example.org", "*@*.spam.example"],
    })
    try {
      const blocked = await samlSignIn(app, { email: "Mallory@Example.org" })
      assert.strictEqual(code(blocked), "identity_blocked", "an exact blocklist entry refuses (case-insensitive)")
      await assertNothingMinted(app, blocked, "mallory@example.org", "blocked")
      const sub = await samlSignIn(app, { email: "x@a.spam.example" })
      assert.strictEqual(code(sub), "identity_blocked", "a subdomain blocklist entry refuses")
      const fine = await samlSignIn(app, { email: "ann@example.org" })
      assert.strictEqual(code(fine), null, "everyone else is admitted in public mode")
      ok("blocklist refuses exact and subdomain entries in public mode; others admitted")
    } finally {
      await app.close()
    }
    const fe = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      signUpMode: "restricted",
      restrictions: { allowlist: true, blocklist: true },
      allowlistIdentifiers: ["*@corp.example"],
      blocklistIdentifiers: ["fired@corp.example"],
    })
    assert.strictEqual((await fe.evaluateAdmission(id("fired@corp.example"))).code, "identity_blocked", "one employee can be blocked inside an allowlisted domain")
    assert.strictEqual((await fe.evaluateAdmission(id("ann@corp.example"))).allowed, true)
    ok("an exact block beats a *@domain allow (block one person in an allowlisted domain)")
  }

  // ==== admission actions ==================================================================
  {
    let grantsCalls = 0
    const app = await startApp({
      signUpMode: "public",
      resolveGrants: () => {
        grantsCalls++
        return { roles: ["member"], permissions: [], orgId: null, memberships: [] }
      },
      actions: {
        authentication: (ctx) => {
          assert.strictEqual(ctx.object, "authentication_action_context")
          assert.strictEqual(ctx.identity.provider, "saml")
          assert.strictEqual(ctx.identity.emailVerified, true)
          assert.strictEqual(ctx.untrusted.requestedMode, ctx.identity.email.startsWith("signup") ? "sign_up" : "sign_in")
          assert.ok(Object.isFrozen(ctx.identity), "the trusted identity is frozen")
          if (ctx.identity.email === "deny@example.org") {
            return { verdict: "Deny", code: "account_suspended", errorMessage: "Your account is suspended.", errorLongMessage: "Contact support." }
          }
          if (ctx.identity.email === "badcode@example.org") return { verdict: "Deny", code: "Bad-Code" }
          return { verdict: "Allow" }
        },
      },
    })
    try {
      const denied = await samlSignIn(app, { email: "deny@example.org" })
      const p = params(denied)
      assert.strictEqual(p.get("error"), "account_suspended", "a Deny carries its code")
      assert.strictEqual(p.get("error_message"), "Your account is suspended.", "a Deny carries its message")
      assert.strictEqual(p.get("error_long_message"), "Contact support.")
      assert.strictEqual(p.get("trace_id").startsWith("trc_"), true)
      await assertNothingMinted(app, denied, "deny@example.org", "action deny")
      assert.strictEqual(grantsCalls, 0, "resolveGrants never runs for a denied identity")
      const bad = await samlSignIn(app, { email: "badcode@example.org" })
      assert.strictEqual(code(bad), "action_denied", "a malformed Deny code is coerced to action_denied")
      const allowed = await samlSignIn(app, { email: "signup@example.org", mode: "sign_up" })
      assert.strictEqual(code(allowed), null, "an Allow admits (and the untrusted mode hint arrives)")
      assert.strictEqual(grantsCalls, 1)
      ok("authentication action: Deny code/message/long message carried, NO session/token minted, bad code coerced")
    } finally {
      await app.close()
    }
  }
  {
    const make = (authentication, extra = {}) =>
      createFederatedFrontend({
        sessionSecret: SECRET,
        logger: () => {},
        signUpMode: "public",
        actions: { authentication, timeoutMs: 50, ...extra },
      })
    assert.strictEqual((await make(() => { throw new Error("boom") }).evaluateAdmission(id("a@example.org"))).code, "action_failed", "a throw => action_failed")
    assert.strictEqual((await make(() => sleep(300).then(() => ({ verdict: "Allow" }))).evaluateAdmission(id("a@example.org"))).code, "action_failed", "a timeout => action_failed")
    assert.strictEqual((await make(() => ({ verdict: "allow" })).evaluateAdmission(id("a@example.org"))).code, "action_failed", "an invalid verdict => action_failed")
    assert.strictEqual(
      (await make(() => { throw new Error("boom") }, { onError: { authentication: "allow" } }).evaluateAdmission(id("a@example.org"))).allowed,
      true,
      "onError 'allow' admits on a throw",
    )
    ok("actions: throw / timeout / invalid verdict => action_failed; onError 'allow' admits")
  }
  {
    const seen = []
    const fe = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      signUpMode: "public",
      users: { lookup: async (i) => ({ exists: i.email === "old@example.org" }) },
      actions: {
        userRegistration: (ctx) => {
          seen.push(ctx.identity.email)
          assert.strictEqual(ctx.object, "user_registration_action_context")
          assert.strictEqual(ctx.isSignUp, true)
          return ctx.identity.email.endsWith("@blocked-signups.example") ? { verdict: "Deny", code: "no_signups_here" } : { verdict: "Allow" }
        },
      },
    })
    assert.strictEqual((await fe.evaluateAdmission(id("x@blocked-signups.example"))).code, "no_signups_here", "userRegistration can deny a new user")
    assert.strictEqual((await fe.evaluateAdmission(id("new@example.org"))).allowed, true)
    assert.strictEqual((await fe.evaluateAdmission(id("old@example.org"))).allowed, true)
    assert.deepStrictEqual(seen, ["x@blocked-signups.example", "new@example.org"], "userRegistration runs for new users only")
    ok("userRegistration action runs only for a new identity and can deny it")
  }

  // ==== Live resolvers fail closed =========================================================
  {
    for (const [label, signUpMode] of [
      ["a throwing signUpMode()", () => { throw new Error("config read failed") }],
      ["signUpMode() returning 'Public'", () => "Public"],
      ["signUpMode() returning undefined", () => undefined],
    ]) {
      const fe = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, signUpMode })
      const r = await fe.evaluateAdmission(id("a@example.org"))
      assert.strictEqual(r.code, "action_failed", `${label} => action_failed`)
      assert.strictEqual(r.step, "resolve_policy")
    }
    const fe = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      signUpMode: () => "restricted",
      restrictions: () => ({ allowlist: true }),
      allowlistIdentifiers: () => "*@example.org",
    })
    assert.strictEqual((await fe.evaluateAdmission(id("a@example.org"))).code, "action_failed", "a non-array Live list => action_failed")
    let mode = "public"
    const live = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, signUpMode: () => mode, users: { lookup: async () => ({ exists: false }) } })
    assert.strictEqual((await live.evaluateAdmission(id("a@example.org"))).allowed, true)
    mode = "waitlist"
    assert.strictEqual((await live.evaluateAdmission(id("a@example.org"))).code, "sign_up_waitlisted", "a Live value is re-read on every attempt")
    ok("Live resolvers: throw, 'Public', undefined, non-array => action_failed; values re-read per attempt")
  }
  {
    const app = await startApp({ signUpMode: () => { throw new Error("nope") } })
    try {
      const env = await call(app.srv.base, "/environment")
      assert.strictEqual(env.json.user_settings.sign_up.mode, "restricted", "/environment reports restricted when the Live mode fails")
      ok("/environment reports 'restricted' when a Live value fails to resolve")
    } finally {
      await app.close()
    }
  }

  // ==== connection-level hosted-domain requirement =========================================
  {
    const app = await startApp({ signUpMode: "public" }, {}, { samlAsConnection: true, samlConnectionExtra: { requireHostedDomain: true } })
    try {
      const noHd = await samlSignIn(app, { email: "ann@corp.example" })
      assert.strictEqual(code(noHd), "identity_hosted_domain_required", "requireHostedDomain refuses an assertion with no hd")
      await assertNothingMinted(app, noHd, "ann@corp.example", "no hd")
      const withHd = await samlSignIn(app, { email: "ann@corp.example", attributes: { hd: "corp.example" } })
      assert.strictEqual(code(withHd), null, "a corroborated hd satisfies the connection")
      const lying = await samlSignIn(app, { email: "mallory@other.example", attributes: { hd: "corp.example" } })
      assert.strictEqual(code(lying), "identity_hosted_domain_required", "an hd that does not match the email is dropped, so refused")
    } finally {
      await app.close()
    }
    const empty = await startApp({ signUpMode: "public" }, {}, { samlAsConnection: true, samlConnectionExtra: { allowedHostedDomains: [] } })
    try {
      const res = await samlSignIn(empty, { email: "ann@corp.example", attributes: { hd: "corp.example" } })
      assert.strictEqual(code(res), "identity_hosted_domain_required", "allowedHostedDomains: [] refuses everyone")
    } finally {
      await empty.close()
    }
    const listed = await startApp({ signUpMode: "public" }, {}, { samlAsConnection: true, samlConnectionExtra: { allowedHostedDomains: ["corp.example"] } })
    try {
      assert.strictEqual(code(await samlSignIn(listed, { email: "ann@corp.example", attributes: { hd: "corp.example" } })), null)
      assert.strictEqual(
        code(await samlSignIn(listed, { email: "ann@other.example", attributes: { hd: "other.example" } })),
        "identity_hosted_domain_required",
        "an hd off the connection's list is refused",
      )
    } finally {
      await listed.close()
    }
    // Google connection, via evaluateAdmission.
    const google = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      signUpMode: "public",
      connections: [{ strategy: "oauth_google", clientId: "id", clientSecret: "sec", redirectUri: "http://127.0.0.1/cb", allowedHostedDomains: ["corp.example"] }],
    })
    assert.strictEqual((await google.evaluateAdmission(id("a@corp.example", { hd: "corp.example" }))).allowed, true)
    assert.strictEqual((await google.evaluateAdmission(id("a@personal.example"))).code, "identity_hosted_domain_required", "Google without hd refused")
    assert.strictEqual((await google.evaluateAdmission(id("a@x.example", { provider: "x" }))).allowed, true, "the Google requirement does not apply to X")
    ok("connection-level hd: requireHostedDomain, allowedHostedDomains ([] = nobody), per connection only")
  }

  // ==== hint domains + /environment publishing =============================================
  {
    const mk = (extra) => {
      const fe = createFederatedFrontend({
        sessionSecret: SECRET,
        cookieSecure: false,
        logger: () => {},
        connections: [{ strategy: "oauth_google", clientId: "id", clientSecret: "sec", redirectUri: "http://127.0.0.1/cb", ...(extra.google ?? {}) }],
        ...(extra.top ?? {}),
      })
      return serve(fe)
    }
    const hdOf = async (srv, conn) => new URL((await call(srv.base, `/sign_in/sso${conn ? `?connection=${conn}` : ""}`)).location).searchParams.get("hd")
    let srv = await mk({ top: { signUpMode: "public" }, google: { hostedDomainHints: ["corp.example"] } })
    try {
      assert.strictEqual(await hdOf(srv, connectionIdForDomain("corp.example")), "corp.example", "a configured hint is sent")
      assert.strictEqual(await hdOf(srv, "conn_other_example"), null, "an unknown connection sends no hd")
      assert.strictEqual(await hdOf(srv, ""), null, "no connection sends no hd")
      const env = (await call(srv.base, "/environment")).json
      assert.ok(!JSON.stringify(env).includes("corp.example"), "publishHintDomains false keeps hint domains out of /environment")
      assert.strictEqual(env.display_config.allowed_domains, undefined, "new-API default: allowed_domains not published")
      assert.strictEqual(env.organization_settings.enabled, false, "new-API default: organizations off")
      assert.strictEqual(env.user_settings.sign_up.mode, "public")
      assert.deepStrictEqual(env.user_settings.connections, [{ id: "conn_google", strategy: "oauth_google", label: "Google" }])
    } finally {
      await srv.close()
    }
    srv = await mk({ top: { signUpMode: "public" } })
    try {
      assert.strictEqual(await hdOf(srv, "conn_corp_example"), null, "new-API default: no hints, a client-chosen hd is ignored")
    } finally {
      await srv.close()
    }
    srv = await mk({ top: { allowedDomains: ["corp.example"] } })
    try {
      assert.strictEqual(await hdOf(srv, "conn_corp_example"), "corp.example", "legacy: allowedDomains still seeds the hints")
      const env = (await call(srv.base, "/environment")).json
      assert.deepStrictEqual(env.display_config.allowed_domains, ["corp.example"], "legacy default keeps publishing allowed_domains")
      assert.strictEqual(env.organization_settings.enabled, true, "legacy default keeps organizations on")
    } finally {
      await srv.close()
    }
    srv = await mk({
      top: {
        signUpMode: "restricted",
        restrictions: { allowlist: true, blocklist: true },
        allowlistIdentifiers: ["*@secret-allow.example"],
        blocklistIdentifiers: ["someone@secret-block.example"],
      },
      google: { hostedDomainHints: ["hint.example"], publishHintDomains: true },
    })
    try {
      const env = (await call(srv.base, "/environment")).json
      const text = JSON.stringify(env)
      assert.ok(!text.includes("secret-allow") && !text.includes("secret-block"), "/environment never contains identifiers")
      assert.ok(env.user_settings.connections.some((c) => c.domain === "hint.example" && c.id === "conn_hint_example"), "publishHintDomains publishes hints")
      assert.deepStrictEqual(env.user_settings.sign_up, { mode: "restricted", allowlist_only: true })
    } finally {
      await srv.close()
    }
    ok("hostedDomainHints decide the hd hint; /environment publishes no identifiers and hints only on opt-in")
  }

  // ==== reverify binding + reverify admission ==============================================
  {
    const app = await startApp({ signUpMode: "public" })
    try {
      const first = await samlSignIn(app, { email: "sub-a", attributes: { email: "ann@example.com" } })
      assert.strictEqual(code(first), null)
      const session = cookieValue(first.setCookie, "oaf_session")
      const before = (await clientSnapshot(app, session)).sessions[0].last_verified_at
      await sleep(1100)
      const other = await samlReverify(app, session, { email: "sub-b", attributes: { email: "ann@example.com" } })
      assert.strictEqual(code(other), "sign_in_not_completed", "a different subject cannot reverify this session")
      assert.strictEqual(cookieValue(other.setCookie, "oaf_session"), null, "a mismatch neither re-stamps nor clears the cookie")
      assert.strictEqual((await clientSnapshot(app, session)).sessions[0].last_verified_at, before, "no stamp on mismatch")
      assert.strictEqual((await mint(app, session)).status, 200, "the session is kept on mismatch")
      assert.ok(app.logger.messages().some((m) => /reverify identity mismatch/.test(m)), "the mismatch is logged")
      const otherEmail = await samlReverify(app, session, { email: "bob@example.com" })
      assert.strictEqual(code(otherEmail), "sign_in_not_completed", "a different email cannot reverify this session")
      const same = await samlReverify(app, session, { email: "sub-a", attributes: { email: "ann@example.com" } })
      assert.strictEqual(code(same), null, "the session's own identity reverifies")
      const restamped = cookieValue(same.setCookie, "oaf_session")
      assert.ok(restamped, "a good reverify re-signs the session cookie")
      assert.ok((await clientSnapshot(app, restamped)).sessions[0].last_verified_at > before, "and stamps lastVerifiedAt")
      ok("reverify: different sub or email => no stamp, session kept, sign_in_not_completed; own identity stamps")
    } finally {
      await app.close()
    }
  }
  {
    let allow = ["*@corp.example"]
    const app = await startApp({
      signUpMode: "restricted",
      restrictions: { allowlist: true },
      allowlistIdentifiers: () => allow,
    })
    try {
      const res = await samlSignIn(app, { email: "ann@corp.example" })
      const session = cookieValue(res.setCookie, "oaf_session")
      assert.ok(session)
      allow = [] // the domain leaves the allowlist
      const rv = await samlReverify(app, session, { email: "ann@corp.example" })
      assert.strictEqual(code(rv), "identity_not_allowlisted", "reverify re-runs admission")
      assert.strictEqual(cookieValue(rv.setCookie, "oaf_session"), "", "a refused reverify clears the session cookie")
      assert.strictEqual((await mint(app, session)).status, 401, "the old cookie no longer mints: the session was removed")
      ok("reverify after the domain leaves the allowlist: session removed, cookie no longer mints")
    } finally {
      await app.close()
    }
  }

  // ==== legacy sessions mint without the new claims ========================================
  {
    const app = await startApp({ signUpMode: "public" }, {}, { noStore: true })
    try {
      const key = new Uint8Array(hkdfSync("sha256", Buffer.from(SECRET, "utf8"), new Uint8Array(0), "oaf:session", 32))
      const old = await new SignJWT({ sid: "sess_old", email: "ann@example.com", roles: [], permissions: [], org_id: null, memberships: [] })
        .setProtectedHeader({ alg: "HS256" })
        .setSubject("user_old")
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(key)
      const m = await mint(app, old)
      assert.strictEqual(m.status, 200)
      const tok = jwtPayload(m.json.jwt)
      assert.strictEqual(tok.provider, undefined, "a pre-upgrade session mints without provider")
      assert.strictEqual(tok.email_verified, undefined, "a pre-upgrade session mints without email_verified")
      ok("pre-upgrade session records mint tokens without provider / email_verified")
    } finally {
      await app.close()
    }
  }

  // ==== revokeUserSessions in both stores ==================================================
  {
    const app = await startApp({ signUpMode: "public" })
    try {
      const a = cookieValue((await samlSignIn(app, { email: "ann@example.com" })).setCookie, "oaf_session")
      const b = cookieValue((await samlSignIn(app, { email: "ann@example.com" })).setCookie, "oaf_session")
      const keep = cookieValue((await samlSignIn(app, { email: "bob@example.com" })).setCookie, "oaf_session")
      const n = await app.frontend().revokeUserSessions("Ann@example.com")
      assert.strictEqual(n, 2, "both of ann's sessions revoked")
      assert.strictEqual((await mint(app, a)).status, 401)
      assert.strictEqual((await mint(app, b)).status, 401)
      assert.strictEqual((await mint(app, keep)).status, 200, "another user's session is untouched")
    } finally {
      await app.close()
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "oaf-revoke-"))
    try {
      const store = new FileSessionStore(dir)
      const app2 = await startApp({ signUpMode: "public" }, {}, { store })
      try {
        const a = cookieValue((await samlSignIn(app2, { email: "ann@example.com" })).setCookie, "oaf_session")
        cookieValue((await samlSignIn(app2, { email: "ann@example.com" })).setCookie, "oaf_session")
        assert.strictEqual(await app2.frontend().revokeUserSessions("ann@example.com"), 2)
        assert.strictEqual((await store.list("ann@example.com")).length, 0, "tombstoned sessions are not listed")
        assert.strictEqual((await mint(app2, a)).status, 401)
        assert.strictEqual(await store.revokeAllForUser("ann@example.com"), 0, "already revoked sessions are not counted twice")
      } finally {
        await app2.close()
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
    const noStore = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, signUpMode: "public" })
    await assert.rejects(() => noStore.revokeUserSessions("ann@example.com"), /revokeAllForUser/, "no store => throws")
    ok("revokeUserSessions revokes every session for the email in InMemory and File stores; throws without a store")
  }

  // ==== async resolveGrants is awaited =====================================================
  {
    const app = await startApp({
      signUpMode: "public",
      resolveGrants: async () => {
        await sleep(20)
        return { roles: ["async_role"], permissions: ["x:read"], orgId: null, memberships: [] }
      },
    })
    try {
      const claims = jwtPayload(cookieValue((await samlSignIn(app)).setCookie, "oaf_session"))
      assert.deepStrictEqual(claims.roles, ["async_role"], "an async resolveGrants is awaited")
      ok("an async resolveGrants is awaited")
    } finally {
      await app.close()
    }
  }

  // ==== mixed mode: legacy keys narrow, never widen ========================================
  {
    const app = await startApp({
      allowedDomains: ["corp.example"],
      signUpMode: "public",
      restrictions: { allowlist: true },
      allowlistIdentifiers: ["*@corp.example", "*@other.example"],
    })
    try {
      assert.strictEqual(code(await samlSignIn(app, { email: "ann@corp.example" })), null)
      const res = await samlSignIn(app, { email: "ann@other.example" })
      assert.strictEqual(code(res), "identity_domain_not_allowed", "the legacy gate narrows an allowlist that would admit")
      assert.strictEqual(params(res).get("presented_domain"), "other.example")
      ok("mixed mode: the legacy gate runs first and narrows; it never widens")
    } finally {
      await app.close()
    }
    const narrowNew = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      allowedDomains: ["corp.example"],
      signUpMode: "public",
      restrictions: { blocklist: true },
      blocklistIdentifiers: ["fired@corp.example"],
    })
    assert.strictEqual((await narrowNew.evaluateAdmission(id("fired@corp.example"))).code, "identity_blocked", "new keys also narrow a legacy gate")
    ok("mixed mode: new keys narrow the legacy gate too")
  }

  // ==== legacy-only behaviour maps identically ==============================================
  {
    const legacy = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, allowedDomains: ["corp.example"], requireHostedDomain: true })
    assert.strictEqual((await legacy.evaluateAdmission(id("a@corp.example", { hd: "corp.example" }))).allowed, true)
    const r = await legacy.evaluateAdmission(id("a@corp.example"))
    assert.strictEqual(r.code, "identity_domain_not_allowed", "legacy requireHostedDomain keeps its code")
    assert.strictEqual(r.step, "legacy_gate")
    assert.strictEqual((await legacy.evaluateAdmission(id("a@corp.example.evil.example", { hd: "corp.example.evil.example" }))).allowed, false)
    const any = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, allowedDomains: [], allowAnyDomain: true })
    assert.strictEqual((await any.evaluateAdmission(id("a@personal.example"))).allowed, true, "allowAnyDomain admits any verified email")
    const none = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, allowedDomains: [] })
    assert.strictEqual((await none.evaluateAdmission(id("a@corp.example"))).allowed, false, "legacy allowedDomains: [] refuses all")
    ok("legacy-only options keep their semantics through evaluateAdmission (hd gate, allowAnyDomain, [] = nobody)")
  }

  // ==== legacy options map onto the new model with the same outcome =========================
  {
    const google = (extra = {}) => [{ strategy: "oauth_google", clientId: "id", clientSecret: "sec", redirectUri: "http://127.0.0.1/cb", ...extra }]
    const pairs = [
      {
        label: "allowedDomains",
        legacy: { allowedDomains: ["corp.example"] },
        modern: { signUpMode: "restricted", restrictions: { allowlist: true }, allowlistIdentifiers: ["*@corp.example"] },
      },
      {
        label: "allowedDomains + requireHostedDomain",
        legacy: { allowedDomains: ["corp.example"], requireHostedDomain: true },
        modern: {
          signUpMode: "restricted",
          restrictions: { allowlist: true },
          allowlistIdentifiers: ["*@corp.example"],
          // The legacy top-level flag covered every hd-capable connection, so the new model states
          // it on each: Google AND SAML. (X never satisfies it; a deployment that refused X under the
          // legacy flag simply does not configure an X connection.)
          connections: [
            ...google({ allowedHostedDomains: ["corp.example"] }),
            { strategy: "saml", ...samlConfig("http://127.0.0.1/acs"), allowedHostedDomains: ["corp.example"] },
          ],
        },
      },
      {
        label: "allowAnyDomain",
        legacy: { allowedDomains: [], allowAnyDomain: true },
        modern: { signUpMode: "public" },
      },
    ]
    const cases = [
      id("ann@corp.example", { hd: "corp.example" }),
      id("ann@corp.example"),
      id("ann@personal.example"),
      id("ann@corp.example.evil.example", { hd: "corp.example.evil.example" }),
      id("ann@other.example", { hd: "other.example" }),
      id("ann@corp.example", { provider: "saml" }),
      id("ann@personal.example", { provider: "x" }),
      { ...id("ann@corp.example", { hd: "corp.example" }), emailVerified: false },
    ]
    for (const p of pairs) {
      const legacyFe = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, connections: google(), ...p.legacy })
      const modernFe = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, connections: google(), ...p.modern })
      for (const c of cases) {
        const a = (await legacyFe.evaluateAdmission(c)).allowed
        const b = (await modernFe.evaluateAdmission(c)).allowed
        assert.strictEqual(b, a, `${p.label}: ${c.provider} ${c.email} hd=${c.hd ?? "-"} verified=${c.emailVerified} legacy=${a} new=${b}`)
      }
    }
    // The one documented difference: hd on the list but the email in an alias domain off the list.
    const alias = id("ann@alias.example", { hd: "corp.example" })
    const l = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, connections: google(), allowedDomains: ["corp.example"], requireHostedDomain: true })
    const m = createFederatedFrontend({ sessionSecret: SECRET, logger: () => {}, ...pairs[1].modern })
    assert.strictEqual((await l.evaluateAdmission(alias)).allowed, true, "legacy admitted an alias-domain email under an allowed hd")
    assert.strictEqual((await m.evaluateAdmission(alias)).allowed, false, "the new model checks the email itself (documented narrowing)")
    ok("legacy allowedDomains / requireHostedDomain / allowAnyDomain map to the new model with identical outcomes (alias-domain narrowing documented)")
  }

  // ==== evaluateAdmission mints nothing =====================================================
  {
    const store = new InMemorySessionStore()
    let grants = 0
    const fe = createFederatedFrontend({
      sessionSecret: SECRET,
      logger: () => {},
      signUpMode: "public",
      sessionStore: store,
      resolveGrants: () => {
        grants++
        return { roles: [], permissions: [], orgId: null, memberships: [] }
      },
    })
    const r = await fe.evaluateAdmission(id("ann@example.com"))
    assert.strictEqual(r.allowed, true)
    assert.strictEqual((await store.list("ann@example.com")).length, 0, "evaluateAdmission stores no session")
    assert.strictEqual(grants, 0, "evaluateAdmission does not run resolveGrants")
    ok("evaluateAdmission runs the pipeline but mints, stores and grants nothing")
  }

  // ==== messages override + neutral defaults ================================================
  {
    const app = await startApp({
      signUpMode: "restricted",
      restrictions: { allowlist: true },
      allowlistIdentifiers: ["*@corp.example"],
      messages: { identity_not_allowlisted: { message: "Ask an organizer for an invite.", longMessage: "Invites come from organizers." } },
    })
    try {
      const p = params(await samlSignIn(app, { email: "ann@other.example" }))
      assert.strictEqual(p.get("error_message"), "Ask an organizer for an invite.")
      assert.strictEqual(p.get("error_long_message"), "Invites come from organizers.")
      ok("messages override the default copy per code")
    } finally {
      await app.close()
    }
  }

  // ==== no hardcoded company default anywhere in the shipped source ==========================
  {
    const roots = [path.join(__dirname, "..", "src"), path.join(__dirname, "..", "..", "auth-react", "src")]
    const banned = ["act3ai.com", "whitehatengineering.com", "gmail.com"]
    const hits = []
    const walk = (dir) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, ent.name)
        if (ent.isDirectory()) walk(p)
        else if (/\.(ts|tsx|js|mjs|cjs)$/.test(ent.name)) {
          const text = fs.readFileSync(p, "utf8").toLowerCase()
          for (const b of banned) if (text.includes(b)) hits.push(`${path.relative(path.join(__dirname, "..", ".."), p)}: ${b}`)
        }
      }
    }
    for (const r of roots) walk(r)
    assert.deepStrictEqual(hits, [], `hardcoded company/provider domains in src: ${hits.join("; ")}`)
    ok("no act3ai.com / whitehatengineering.com / gmail.com anywhere in auth-backend/src or auth-react/src")
  }

  console.log(`\nAll admission checks passed (${passed}).`)
}

main().catch((e) => {
  console.error("FAILED:", e.stack || e.message)
  process.exit(1)
})
