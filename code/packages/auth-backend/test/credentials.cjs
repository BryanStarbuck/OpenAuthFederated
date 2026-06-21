/**
 * Credential-loading + fail-loud-guard test (standalone Node, no jest needed — mirrors
 * saml-roundtrip.cjs). Covers the blocker fixed in this library: the embedded Frontend API must
 * read the Google OAuth client id/secret from the out-of-repo credentials file (and env), fail
 * CLOSED with a clear, secret-free error when they are absent, and never leak the secret values.
 *
 *   1. build:  pnpm --filter @auth/backend build
 *   2. run:    node packages/auth-backend/test/credentials.cjs
 *
 * Exits non-zero on any failure. Uses a throwaway temp credentials file (never a real secret).
 */
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const http = require("node:http")
const assert = require("node:assert")

const {
  loadGoogleCredentials,
  googleCredentialsFromFile,
  assertGoogleCredentials,
  credentialsRemediation,
  OAuthCredentialsError,
  CREDENTIALS_PATH_ENV,
  createAuthFrontend,
} = require("../dist/index.js")

const FAKE_ID = "1234567890-fakeclientid.apps.googleusercontent.com"
const FAKE_SECRET = "GOCSPX-thisIsAFakeTestSecretValue"

// Isolate from any real env/credentials on the machine.
delete process.env.GOOGLE_CLIENT_ID
delete process.env.GOOGLE_CLIENT_SECRET
delete process.env[CREDENTIALS_PATH_ENV]

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oaf-creds-"))
const credFile = path.join(tmpDir, "app_internal_act3.json")
const badFile = path.join(tmpDir, "bad.json")
const missingFile = path.join(tmpDir, "does_not_exist.json")

function writeCreds(obj) {
  fs.writeFileSync(credFile, JSON.stringify(obj, null, 2))
}

let passed = 0
function ok(name) {
  passed++
  console.log(`  ✓ ${name}`)
}

// --- 1. File resolution: exact act3_internal_app.google hierarchy --------------------------
writeCreds({ act3_internal_app: { google: { clientId: FAKE_ID, clientSecret: FAKE_SECRET } } })
{
  const r = loadGoogleCredentials({ path: credFile })
  assert.strictEqual(r.clientId, FAKE_ID, "clientId from file")
  assert.strictEqual(r.clientSecret, FAKE_SECRET, "clientSecret from file")
  assert.strictEqual(r.ok, true, "ok when both present")
  assert.strictEqual(r.clientIdSource, "file", "clientId source = file")
  ok("reads clientId/clientSecret from act3_internal_app.google in the JSON file")
}

// --- 2. Env overrides file (resolution order) ----------------------------------------------
{
  process.env.GOOGLE_CLIENT_ID = "env-id.apps.googleusercontent.com"
  process.env.GOOGLE_CLIENT_SECRET = "env-secret"
  const r = loadGoogleCredentials({ path: credFile })
  assert.strictEqual(r.clientId, "env-id.apps.googleusercontent.com", "env wins over file")
  assert.strictEqual(r.clientIdSource, "env", "source = env")
  delete process.env.GOOGLE_CLIENT_ID
  delete process.env.GOOGLE_CLIENT_SECRET
  ok("environment variables override the credentials file")
}

// --- 3. Explicit config overrides env + file -----------------------------------------------
{
  process.env.GOOGLE_CLIENT_ID = "env-id"
  const r = loadGoogleCredentials({ clientId: "cfg-id", clientSecret: "cfg-secret", path: credFile })
  assert.strictEqual(r.clientId, "cfg-id", "config wins")
  assert.strictEqual(r.clientIdSource, "config", "source = config")
  delete process.env.GOOGLE_CLIENT_ID
  ok("explicit config overrides env and file")
}

// --- 4. Missing file → not ok, no throw, clear remediation ---------------------------------
{
  const r = loadGoogleCredentials({ path: missingFile })
  assert.strictEqual(r.ok, false, "not ok when file missing")
  assert.strictEqual(r.clientId, "", "empty clientId when missing")
  const msg = credentialsRemediation(r.path)
  assert.ok(msg.includes(missingFile), "remediation names the file path")
  assert.ok(msg.includes("act3_internal_app"), "remediation shows the JSON hierarchy")
  assert.ok(msg.includes("GOOGLE_CLIENT_ID"), "remediation lists env-var alternative")
  ok("missing credentials → not ok, with a path+shape remediation message")
}

// --- 5. assertGoogleCredentials throws a secret-free OAuthCredentialsError ------------------
{
  let threw = null
  try {
    assertGoogleCredentials({ path: missingFile })
  } catch (e) {
    threw = e
  }
  assert.ok(threw instanceof OAuthCredentialsError, "throws OAuthCredentialsError")
  assert.strictEqual(threw.code, "oauth_not_configured", "machine code present")
  assert.ok(threw.message.includes(missingFile), "error names the path")
  ok("assertGoogleCredentials throws a clear OAuthCredentialsError when unconfigured")
}

// --- 6. Malformed JSON file → OAuthCredentialsError -----------------------------------------
{
  fs.writeFileSync(badFile, "{ not valid json ")
  let threw = null
  try {
    googleCredentialsFromFile(badFile)
  } catch (e) {
    threw = e
  }
  assert.ok(threw instanceof OAuthCredentialsError, "malformed JSON throws")
  assert.ok(threw.message.includes(badFile), "error names the malformed file")
  ok("a malformed credentials file raises a clear error (not a silent fallthrough)")
}

// --- 7. No-secret-leak guarantee: error text never contains the secret ---------------------
{
  writeCreds({ act3_internal_app: { google: { clientId: "", clientSecret: "" } } })
  const r = loadGoogleCredentials({ path: credFile })
  const msg = credentialsRemediation(r.path)
  assert.ok(!msg.includes(FAKE_SECRET), "remediation must not contain any real secret")
  // even with a populated file, the remediation/asserts never echo the secret
  writeCreds({ act3_internal_app: { google: { clientId: FAKE_ID, clientSecret: FAKE_SECRET } } })
  assert.ok(!credentialsRemediation(credFile).includes(FAKE_SECRET), "no secret in remediation")
  ok("error/remediation output never leaks the secret credential values")
}

// --- 8. Fail-loud guard: SSO start returns 503 oauth_not_configured (no Google redirect) ----
async function testGuard() {
  // Build the embedded middleware with NO credentials available.
  const mw = createAuthFrontend({
    google: { redirectUri: "http://localhost:9111/api/v1/oauth_callback", credentialsFile: missingFile },
    allowedDomains: ["act3ai.com"],
    sessionSecret: "test-secret",
    logger: () => {}, // silence expected warn/error
  })

  const server = http.createServer((req, res) => mw(req, res))
  await new Promise((resolve) => server.listen(0, resolve))
  const port = server.address().port
  try {
    const res = await fetch(`http://localhost:${port}/sign_in/sso?redirect_url=/cb`, {
      redirect: "manual",
    })
    assert.strictEqual(res.status, 503, "503, not a 302 to Google")
    const loc = res.headers.get("location")
    assert.ok(!loc || !/accounts\.google\.com/.test(loc), "never redirects to Google")
    const body = await res.json()
    assert.strictEqual(body.error, "oauth_not_configured", "machine code in body")
    assert.ok(body.remediation.includes("act3_internal_app"), "remediation in body")
    assert.ok(!body.remediation.includes(FAKE_SECRET), "body leaks no secret")
    ok("/sign_in/sso fails closed with 503 oauth_not_configured instead of redirecting to Google")
  } finally {
    server.close()
  }

  // And the happy path: with a real (fake) credential, /sign_in/sso DOES 302 to Google with a
  // non-empty client_id.
  const mw2 = createAuthFrontend({
    google: {
      clientId: FAKE_ID,
      clientSecret: FAKE_SECRET,
      redirectUri: "http://localhost:9111/api/v1/oauth_callback",
    },
    allowedDomains: ["act3ai.com"],
    sessionSecret: "test-secret",
    logger: () => {},
  })
  const server2 = http.createServer((req, res) => mw2(req, res))
  await new Promise((resolve) => server2.listen(0, resolve))
  const port2 = server2.address().port
  try {
    const res = await fetch(`http://localhost:${port2}/sign_in/sso?redirect_url=/cb`, {
      redirect: "manual",
    })
    assert.strictEqual(res.status, 302, "302 to Google on the happy path")
    const loc = res.headers.get("location")
    assert.ok(/accounts\.google\.com/.test(loc), "redirects to Google")
    const u = new URL(loc)
    assert.strictEqual(u.searchParams.get("client_id"), FAKE_ID, "non-empty client_id")
    ok("with credentials present, /sign_in/sso 302s to Google with the configured client_id")
  } finally {
    server2.close()
  }
}

testGuard()
  .then(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
    console.log(`\nAll ${passed} credential tests passed.`)
  })
  .catch((err) => {
    console.error("\nTEST FAILED:", err)
    fs.rmSync(tmpDir, { recursive: true, force: true })
    process.exit(1)
  })
