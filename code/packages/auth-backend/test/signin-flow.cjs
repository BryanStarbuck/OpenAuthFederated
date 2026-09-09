/**
 * End-to-end SP-initiated SAML sign-in through the mounted middleware, over a real socket.
 *
 * Covers the findings that only show up once the whole tail runs — admission, the identifier the
 * session is keyed on, the claims stamped on the cookie, and what lands in the audit trail:
 *
 *   S2  SAML must be admissible under `requireHostedDomain`, and must be NAMED in the log line.
 *   S4  User ids from different IdPs must not share one flat namespace (`user_${sub}`).
 *   S6  `hd` must mean "the upstream asserted a hosted domain", never "the email ended in one".
 *   S8  Attacker-influenced strings must not be able to forge extra log lines.
 */
const assert = require("node:assert")

const { createFederatedFrontend } = require("../dist/index.js")
const { serve, call, cookieValue, cookieHeader, jwtPayload, recordingLogger } = require("./helpers.cjs")
const { signedResponse, samlConfig, b64 } = require("./saml-fixture.cjs")

/** Start a frontend whose SAML ACS points back at its own ephemeral port. */
async function startApp(overrides = {}, samlExtra = {}) {
  const logger = recordingLogger()
  // The ACS URL must match what the assertion is destined for, and the port is only known after
  // listen() — so mount a thunk first and swap in the real frontend once the port is allocated.
  let frontend = null
  const srv = await serve((req, res, next) => frontend(req, res, next))
  const acs = `${srv.base}/api/v1/saml/acs`
  frontend = createFederatedFrontend({
    sessionSecret: "a-strong-test-session-secret-of-32-plus-chars",
    allowedDomains: ["act3ai.com"],
    cookieSecure: false,
    saml: samlConfig(acs, samlExtra),
    logger,
    ...overrides,
  })
  return { srv, acs, logger, close: () => srv.close() }
}

/** Run the SP-initiated round trip and return the ACS response. */
async function samlSignIn(app, { email, attributes } = {}) {
  const login = await call(app.srv.base, "/saml/login?redirect_url=/sso-callback&redirect_url_complete=/home")
  assert.strictEqual(login.status, 302, "/saml/login must redirect to the IdP")
  const relayState = new URL(login.location).searchParams.get("RelayState")
  const relayCookie = cookieValue(login.setCookie, "oaf_saml_relay")
  assert.ok(relayState && relayCookie, "the login redirect must carry a RelayState and set its cookie")

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

/** The error code the callback bounced back with, or null on a successful sign-in. */
function rejectionCode(acsRes) {
  if (!acsRes.location) return null
  return new URL(acsRes.location, "http://internal").searchParams.get("error")
}

async function main() {
  // --- S6 + S4 default: a plain, admitted SAML sign-in ----------------------------------------
  {
    const app = await startApp()
    try {
      const res = await samlSignIn(app)
      assert.strictEqual(rejectionCode(res), null, "a valid company assertion must be admitted")
      const session = cookieValue(res.setCookie, "oaf_session")
      assert.ok(session, "an admitted sign-in must set the session cookie")
      const claims = jwtPayload(session)

      assert.strictEqual(
        claims.hd,
        undefined,
        "hd must stay absent when the IdP asserted none — an email suffix is not Workspace membership",
      )
      console.log("  ✓ hd is not back-filled from the email domain (S6)")

      assert.strictEqual(
        claims.sub,
        "user_bryan@act3ai.com",
        "default (un-namespaced) user id must be unchanged for back-compat",
      )
      console.log("  ✓ the default user id shape is unchanged (no silent breaking migration)")
    } finally {
      await app.close()
    }
  }

  // --- S4: opting in namespaces the identifier per provider -----------------------------------
  {
    const app = await startApp({ namespaceUserIds: true })
    try {
      const res = await samlSignIn(app)
      const claims = jwtPayload(cookieValue(res.setCookie, "oaf_session"))
      assert.strictEqual(
        claims.sub,
        "user_saml_bryan@act3ai.com",
        "with namespaceUserIds the subject must carry the strategy that authenticated it",
      )
      console.log("  ✓ namespaceUserIds scopes the user id to the issuing strategy (S4)")
    } finally {
      await app.close()
    }
  }

  // --- S2: SAML under requireHostedDomain -----------------------------------------------------
  {
    const app = await startApp({ requireHostedDomain: true })
    try {
      const res = await samlSignIn(app)
      assert.strictEqual(
        rejectionCode(res),
        "identity_domain_not_allowed",
        "an assertion with no hd must still be refused when the deployment demands one",
      )
      const line = app.logger.messages().find((m) => /Rejecting .* sign-in/.test(m))
      assert.ok(line, "the refusal must be logged")
      assert.match(
        line,
        /saml/i,
        `the refusal must name the SAML strategy, not report it as google (got: ${line})`,
      )
      console.log("  ✓ a SAML refusal names the SAML strategy in the audit trail (S2)")
    } finally {
      await app.close()
    }
  }

  // An IdP that DOES assert a hosted domain satisfies the requirement.
  {
    const app = await startApp({ requireHostedDomain: true })
    try {
      const res = await samlSignIn(app, { attributes: { hd: "act3ai.com" } })
      assert.strictEqual(
        rejectionCode(res),
        null,
        "an assertion carrying an allowlisted hd must be admitted under requireHostedDomain",
      )
      console.log("  ✓ a SAML assertion carrying an allowlisted hd is admitted (S2)")
    } finally {
      await app.close()
    }
  }

  // An operator can vouch for a domain-scoped IdP that asserts no hd attribute — explicitly,
  // in one place, the way xTrustConfirmedEmail works for X.
  {
    const app = await startApp({ requireHostedDomain: true, samlSatisfiesHostedDomain: true })
    try {
      const res = await samlSignIn(app)
      assert.strictEqual(
        rejectionCode(res),
        null,
        "samlSatisfiesHostedDomain must let a domain-scoped IdP through, as X's flag does",
      )
      console.log("  ✓ samlSatisfiesHostedDomain is the explicit, documented opt-in (S2)")
    } finally {
      await app.close()
    }
  }

  // --- The asserted `hd` must not become a way around allowedDomains --------------------------
  // Mapping an IdP attribute onto `hd` (the S2 fix) is only safe if that attribute cannot stand in
  // for the email domain when the allowlist is evaluated. A SAML `hd` is an attribute the IdP
  // chose — attribute mapping is precisely what gets misconfigured — whereas Google computes its
  // `hd` from real Workspace membership. If the asserted value could satisfy the allowlist, then
  // an assertion for an out-of-domain address carrying `hd: act3ai.com` would be admitted, and the
  // allowlist would be gating the IdP's claim rather than the identity.
  for (const extra of [{}, { requireHostedDomain: true }]) {
    const label = extra.requireHostedDomain ? "requireHostedDomain ON" : "requireHostedDomain OFF"
    const app = await startApp(extra)
    try {
      const res = await samlSignIn(app, {
        email: "attacker@evil.example",
        attributes: { hd: "act3ai.com" },
      })
      assert.strictEqual(
        rejectionCode(res),
        "identity_domain_not_allowed",
        `${label}: an asserted hd must not admit an out-of-allowlist email address`,
      )
      assert.strictEqual(
        cookieValue(res.setCookie, "oaf_session"),
        null,
        `${label}: no session may be established for a refused identity`,
      )
    } finally {
      await app.close()
    }
    console.log(`  ✓ ${label}: an asserted hd cannot substitute for the email domain`)
  }

  // --- Grant re-resolution must be asked about the subject the IdP actually named ---------------
  // `userId` is a value WE mint and its shape is configurable, so recovering the upstream subject by
  // stripping a prefix desynchronises the moment the minting rule changes. That matters here
  // because re-resolution is the authoritative "is this person still allowed?" call: under
  // `namespaceUserIds` the old strip produced `saml_alice@corp.com`, a subject that never existed
  // upstream, so every host lookup keyed on `sub` silently missed.
  for (const namespaceUserIds of [false, true]) {
    const seen = []
    const app = await startApp({
      namespaceUserIds,
      reresolveGrantsEverySeconds: 1,
      revalidateGrants: (identity) => {
        seen.push(identity)
        return { roles: ["employee"], permissions: [], orgId: null, memberships: [] }
      },
    })
    try {
      const res = await samlSignIn(app)
      const session = cookieValue(res.setCookie, "oaf_session")
      assert.ok(session, "sign-in should have succeeded")
      const sid = jwtPayload(session).sid

      // Wait past the re-resolution window, then mint — which triggers revalidateGrants. The
      // window is compared in whole epoch SECONDS, so 1.1s can still round to "not yet".
      await new Promise((r) => setTimeout(r, 2200))
      const mint = await call(app.srv.base, `/client/sessions/${sid}/tokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookieHeader({ oaf_session: session }) },
        body: "{}",
      })
      assert.strictEqual(mint.status, 200, "the token mint should succeed")
      assert.strictEqual(seen.length, 1, "grant re-resolution should have run exactly once")
      assert.strictEqual(
        seen[0].sub,
        "bryan@act3ai.com",
        `namespaceUserIds=${namespaceUserIds}: re-resolution must receive the IdP's own subject, ` +
          `got ${JSON.stringify(seen[0].sub)}`,
      )
      assert.strictEqual(
        seen[0].provider,
        "saml",
        "re-resolution must be told which strategy asserted the subject",
      )
    } finally {
      await app.close()
    }
    console.log(`  ✓ namespaceUserIds=${namespaceUserIds}: re-resolution gets the upstream subject`)
  }

  // --- S8: a hostile NameID must not be able to forge log lines --------------------------------
  {
    const app = await startApp()
    try {
      // The domain half is what gets interpolated into the "non-allowed domain" warning.
      await samlSignIn(app, { email: "attacker@evil.example\r\nWARN forged-audit-line" })
      const offending = app.logger.lines.filter(
        (l) => typeof l.message === "string" && /[\r\n]/.test(l.message),
      )
      assert.deepStrictEqual(
        offending,
        [],
        "no log message may contain a raw newline — that is a forged audit line",
      )
      console.log("  ✓ attacker-influenced values cannot inject newlines into the audit trail (S8)")
    } finally {
      await app.close()
    }
  }

  console.log("\nAll sign-in flow checks passed.")
}

main().catch((e) => {
  console.error("FAILED:", e.message)
  process.exit(1)
})
