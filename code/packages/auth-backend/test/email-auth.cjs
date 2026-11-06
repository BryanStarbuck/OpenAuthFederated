/**
 * The email connection: sign up and sign in with an email address (an emailed one-time code, and
 * optionally a password). Drives the real middleware over a loopback socket. Fixture identities use
 * example.com / example.org only.
 *
 *   npm run build && node test/email-auth.cjs
 */
const assert = require("node:assert")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")

const {
  createFederatedFrontend,
  InMemorySessionStore,
  InMemoryEmailAccountStore,
  FileEmailAccountStore,
  OafConfigError,
  hashPassword,
  verifyPassword,
  passwordProblem,
} = require("../dist/index.js")
const { serve, call, cookieValue, jwtPayload, recordingLogger } = require("./helpers.cjs")

const SECRET = "a-strong-test-session-secret-of-32-plus-chars"
let passed = 0
const ok = (msg) => {
  passed++
  console.log(`  ✓ ${msg}`)
}

/** An app offering ONLY the email connection. `sent` collects every code the app was asked to send. */
async function startApp({ policy = { signUpMode: "public" }, email = {}, deliver = () => ({ delivered: true }), store } = {}) {
  const logger = recordingLogger()
  const sent = []
  const accounts = store ?? new InMemoryEmailAccountStore()
  let frontend = null
  const srv = await serve((req, res, next) => frontend(req, res, next))
  frontend = createFederatedFrontend({
    sessionSecret: SECRET,
    cookieSecure: false,
    logger,
    sessionStore: new InMemorySessionStore(),
    connections: [
      {
        strategy: "email",
        store: accounts,
        sendCode: async (m) => {
          sent.push(m)
          return deliver(m)
        },
        ...email,
      },
    ],
    ...policy,
  })
  const post = (p, body, headers = { "Content-Type": "application/json" }) =>
    call(srv.base, p, { method: "POST", headers, body: JSON.stringify(body) })
  const lastCode = () => sent[sent.length - 1].code
  return { srv, logger, sent, accounts, post, lastCode, close: () => srv.close() }
}

/** A code that is not the one just sent. */
const wrong = (c) => String((Number(c) + 1) % 1_000_000).padStart(6, "0")

async function main() {
  console.log("email connection")

  // --- construction --------------------------------------------------------------------------
  assert.throws(
    () => createFederatedFrontend({ sessionSecret: SECRET, connections: [{ strategy: "email", store: new InMemoryEmailAccountStore() }] }),
    OafConfigError,
  )
  assert.throws(
    () => createFederatedFrontend({ sessionSecret: SECRET, connections: [{ strategy: "email", sendCode: () => ({ delivered: true }) }] }),
    OafConfigError,
  )
  ok("construction refuses an email connection without sendCode or without a store")

  // --- pure helpers --------------------------------------------------------------------------
  const h = await hashPassword("correct horse battery")
  assert.match(h, /^scrypt\$32768\$8\$1\$/)
  assert.strictEqual(await verifyPassword("correct horse battery", h), true)
  assert.strictEqual(await verifyPassword("correct horse batterY", h), false)
  assert.strictEqual(await verifyPassword("anything", null), false)
  assert.strictEqual(await verifyPassword("anything", "garbage$hash"), false)
  assert.strictEqual(passwordProblem("short", 8), "Use at least 8 characters.")
  assert.strictEqual(passwordProblem("        ", 8), "A password cannot be only spaces.")
  assert.strictEqual(passwordProblem("long enough", 8), null)
  ok("scrypt hashing verifies, rejects a wrong or malformed hash, and the password rules hold")

  // --- environment ---------------------------------------------------------------------------
  {
    const app = await startApp()
    const env = (await call(app.srv.base, "/environment")).json
    assert.deepStrictEqual(env.user_settings.email.strategies, ["email_code", "password"])
    assert.strictEqual(env.user_settings.email.enabled, true)
    assert.ok(env.user_settings.connections.some((c) => c.strategy === "email_code"))
    app.close()
    const noPw = await startApp({ email: { password: false } })
    const env2 = (await call(noPw.srv.base, "/environment")).json
    assert.deepStrictEqual(env2.user_settings.email.strategies, ["email_code"])
    const pw = await noPw.post("/email/password", { email: "ann@example.com", password: "whatever-long" })
    assert.strictEqual(pw.status, 404)
    noPw.close()
    ok("/environment publishes the email strategies; password: false turns the password route off")
  }

  // --- sign up with a code and a password ----------------------------------------------------
  {
    const app = await startApp()
    const form = await app.post("/email/code", { email: "Ann@Example.com" }, { "Content-Type": "text/plain" })
    assert.strictEqual(form.status, 415, "a non-JSON body (a cross-site form) is refused")
    assert.strictEqual((await app.post("/email/code", { email: "not-an-email" })).status, 422)
    ok("non-JSON requests and invalid addresses are refused before anything is sent")

    const r = await app.post("/email/code", { email: " Ann@Example.com ", purpose: "sign_up", password: "ignored-here-123" })
    assert.strictEqual(r.status, 200)
    assert.strictEqual(r.json.status, "code_sent")
    assert.strictEqual(r.json.email, "ann@example.com")
    assert.strictEqual(app.sent.length, 1)
    assert.match(app.sent[0].code, /^\d{6}$/)
    assert.strictEqual(app.sent[0].accountExists, false)
    assert.strictEqual(await app.accounts.getAccount("ann@example.com"), null, "no account before the mailbox is proven")
    assert.ok(!JSON.stringify(app.logger.lines).includes(app.sent[0].code), "the code is never logged")
    ok("a code is sent; no account (and no password) exists before the code is typed back")

    const again = await app.post("/email/code", { email: "ann@example.com" })
    assert.strictEqual(again.status, 429)
    assert.strictEqual(again.json.error, "too_many_requests")
    ok("a second code inside the cooldown is refused")

    const bad = await app.post("/email/verify", { email: "ann@example.com", code: wrong(app.lastCode()) })
    assert.strictEqual(bad.status, 422)
    assert.strictEqual(bad.json.error, "form_code_incorrect")
    assert.strictEqual(bad.json.attempts_remaining, 4)
    const weak = await app.post("/email/verify", { email: "ann@example.com", code: app.lastCode(), password: "short" })
    assert.strictEqual(weak.status, 422)
    assert.strictEqual(weak.json.error, "form_password_invalid")
    ok("a wrong code counts down; a weak password is refused WITHOUT spending the code")

    const good = await app.post("/email/verify", {
      email: "ann@example.com",
      code: app.lastCode(),
      password: "correct horse battery",
      redirect_url_complete: "//evil.example/steal",
    })
    assert.strictEqual(good.status, 200, JSON.stringify(good.json))
    assert.strictEqual(good.json.status, "complete")
    assert.strictEqual(good.json.redirect_url_complete, "/", "a protocol-relative target is neutralized")
    const cookie = cookieValue(good.setCookie, "oaf_session")
    assert.ok(cookie, "a session cookie is set")
    const claims = jwtPayload(cookie)
    assert.strictEqual(claims.email, "ann@example.com")
    assert.strictEqual(claims.prv, "email")
    const acct = await app.accounts.getAccount("ann@example.com")
    assert.match(acct.id, /^em_/)
    assert.ok(acct.verifiedAt > 0)
    assert.ok(await verifyPassword("correct horse battery", acct.passwordHash))
    ok("the right code signs the person in with provider email, and only now stores the password")

    const reuse = await app.post("/email/verify", { email: "ann@example.com", code: app.lastCode() })
    assert.strictEqual(reuse.status, 410)
    ok("a code is single use")

    // Password sign-in.
    const pw = await app.post("/email/password", { email: "ANN@example.com", password: "correct horse battery" })
    assert.strictEqual(pw.status, 200)
    assert.strictEqual(jwtPayload(cookieValue(pw.setCookie, "oaf_session")).sub, `user_${acct.id}`)
    const pwBad = await app.post("/email/password", { email: "ann@example.com", password: "wrong horse battery" })
    const pwNobody = await app.post("/email/password", { email: "nobody@example.com", password: "wrong horse battery" })
    assert.strictEqual(pwBad.status, 401)
    assert.deepStrictEqual(pwBad.json, pwNobody.json, "wrong password and unknown account answer identically")
    assert.strictEqual(cookieValue(pwBad.setCookie, "oaf_session"), null)
    ok("password sign-in works; a wrong password and an unknown account look the same")
    app.close()
  }

  // --- lockout, burn, expiry, reset ----------------------------------------------------------
  {
    const app = await startApp({ email: { maxPasswordFailures: 3, maxCodeAttempts: 2, resendCooldownSeconds: 1 } })
    await app.post("/email/code", { email: "bob@example.org" })
    await app.post("/email/verify", { email: "bob@example.org", code: app.lastCode(), password: "bobs-password-1" })
    for (let i = 0; i < 3; i++) await app.post("/email/password", { email: "bob@example.org", password: "nope-nope-nope" })
    const locked = await app.post("/email/password", { email: "bob@example.org", password: "bobs-password-1" })
    assert.strictEqual(locked.status, 429)
    assert.strictEqual(locked.json.error, "user_locked")
    ok("repeated wrong passwords lock password sign-in, even against the right password")

    await new Promise((r) => setTimeout(r, 1100))
    await app.post("/email/code", { email: "bob@example.org", purpose: "reset_password" })
    assert.strictEqual(app.sent[app.sent.length - 1].accountExists, true)
    const noPw = await app.post("/email/verify", { email: "bob@example.org", code: app.lastCode() })
    assert.strictEqual(noPw.status, 422, "a reset needs a new password")
    const reset = await app.post("/email/verify", { email: "bob@example.org", code: app.lastCode(), password: "bobs-new-password" })
    assert.strictEqual(reset.status, 200)
    assert.strictEqual((await app.post("/email/password", { email: "bob@example.org", password: "bobs-password-1" })).status, 401)
    assert.strictEqual((await app.post("/email/password", { email: "bob@example.org", password: "bobs-new-password" })).status, 200)
    ok("a reset code clears the lock and replaces the password")

    await new Promise((r) => setTimeout(r, 1100))
    await app.post("/email/code", { email: "bob@example.org" })
    const c = app.lastCode()
    assert.strictEqual((await app.post("/email/verify", { email: "bob@example.org", code: wrong(c) })).status, 422)
    const burned = await app.post("/email/verify", { email: "bob@example.org", code: wrong(c) })
    assert.strictEqual(burned.json.error, "verification_failed")
    assert.strictEqual((await app.post("/email/verify", { email: "bob@example.org", code: c })).status, 410)
    ok("too many wrong codes burn the code; the right one no longer works")
    app.close()

    const quick = await startApp({ email: { codeTtlSeconds: 1 } })
    await quick.post("/email/code", { email: "cy@example.com" })
    await new Promise((r) => setTimeout(r, 1100))
    assert.strictEqual((await quick.post("/email/verify", { email: "cy@example.com", code: quick.lastCode() })).status, 410)
    ok("an expired code is refused")
    quick.close()
  }

  // --- admission applies unchanged -----------------------------------------------------------
  {
    const blocked = await startApp({
      policy: { signUpMode: "public", restrictions: { blocklist: true }, blocklistIdentifiers: ["*@evil.example"] },
    })
    await blocked.post("/email/code", { email: "mallory@evil.example" })
    const r = await blocked.post("/email/verify", { email: "mallory@evil.example", code: blocked.lastCode(), password: "mallory-password" })
    assert.strictEqual(r.status, 403)
    assert.strictEqual(r.json.error, "identity_blocked")
    assert.strictEqual(cookieValue(r.setCookie, "oaf_session"), null)
    assert.strictEqual(await blocked.accounts.getAccount("mallory@evil.example"), null, "a refused identity leaves no account")
    blocked.close()

    const restricted = await startApp({
      policy: { signUpMode: "restricted", restrictions: { allowlist: true }, allowlistIdentifiers: ["*@example.org"] },
    })
    await restricted.post("/email/code", { email: "dan@example.com" })
    const r2 = await restricted.post("/email/verify", { email: "dan@example.com", code: restricted.lastCode() })
    assert.strictEqual(r2.status, 403)
    assert.strictEqual(r2.json.error, "identity_not_allowlisted")
    await restricted.post("/email/code", { email: "eve@example.org" })
    assert.strictEqual((await restricted.post("/email/verify", { email: "eve@example.org", code: restricted.lastCode() })).status, 200)
    restricted.close()
    ok("the app's blocklist and allowlist decide email identities exactly as they decide Google ones")
  }

  // --- delivery failure ----------------------------------------------------------------------
  {
    const app = await startApp({ deliver: () => ({ delivered: false, problem: "no SendGrid key" }) })
    const r = await app.post("/email/code", { email: "fay@example.com" })
    assert.strictEqual(r.status, 503)
    assert.strictEqual(r.json.error, "email_not_delivered")
    assert.strictEqual((await app.post("/email/verify", { email: "fay@example.com", code: app.lastCode() })).status, 410)
    const r2 = await app.post("/email/code", { email: "fay@example.com" })
    assert.strictEqual(r2.status, 503, "an undelivered code does not start the resend cooldown")
    app.close()
    ok("an undelivered code is reported as not sent and cannot be spent")
  }

  // --- the file store ------------------------------------------------------------------------
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "oaf-email-"))
    const store = new FileEmailAccountStore(dir)
    const app = await startApp({ store })
    await app.post("/email/code", { email: "gil@example.com" })
    assert.strictEqual((await app.post("/email/verify", { email: "gil@example.com", code: app.lastCode(), password: "gils-password-1" })).status, 200)
    const files = fs.readdirSync(path.join(dir, "accounts"))
    assert.strictEqual(files.length, 1)
    assert.ok(!files[0].includes("gil"), "file names do not carry the address")
    assert.strictEqual(fs.statSync(path.join(dir, "accounts", files[0])).mode & 0o777, 0o600)
    const reread = await new FileEmailAccountStore(dir).getAccount("gil@example.com")
    assert.ok(await verifyPassword("gils-password-1", reread.passwordHash))
    app.close()
    fs.rmSync(dir, { recursive: true, force: true })
    ok("FileEmailAccountStore persists 0600 files named by a hash of the address")
  }

  console.log(`\n${passed} passed`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
