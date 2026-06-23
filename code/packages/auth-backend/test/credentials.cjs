/**
 * Credential-loading + fail-loud-guard test (standalone Node, no jest needed — mirrors
 * saml-roundtrip.cjs). Covers the library contract: OpenAuthFederated is credential-SOURCE-agnostic.
 * It resolves the Google OAuth client id/secret from an explicit config argument, then from its own
 * generic GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET env vars — and from NO host-app file. When neither
 * supplies a value it fails CLOSED with a clear, secret-free error and never leaks the values.
 *
 *   1. build:  pnpm --filter @auth/backend build
 *   2. run:    node packages/auth-backend/test/credentials.cjs
 *
 * Exits non-zero on any failure.
 */
const http = require("node:http")
const assert = require("node:assert")

const {
  loadGoogleCredentials,
  assertGoogleCredentials,
  credentialsRemediation,
  OAuthCredentialsError,
  createFederatedFrontend,
  createAuthFrontend,
} = require("../dist/index.js")

const FAKE_ID = "1234567890-fakeclientid.apps.googleusercontent.com"
const FAKE_SECRET = "GOCSPX-thisIsAFakeTestSecretValue"

// Isolate from any real env on the machine.
delete process.env.GOOGLE_CLIENT_ID
delete process.env.GOOGLE_CLIENT_SECRET

let passed = 0
function ok(name) {
  passed++
  console.log(`  ✓ ${name}`)
}

// --- 1. Env resolution: generic GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET ---------------------
{
  process.env.GOOGLE_CLIENT_ID = FAKE_ID
  process.env.GOOGLE_CLIENT_SECRET = FAKE_SECRET
  const r = loadGoogleCredentials()
  assert.strictEqual(r.clientId, FAKE_ID, "clientId from env")
  assert.strictEqual(r.clientSecret, FAKE_SECRET, "clientSecret from env")
  assert.strictEqual(r.ok, true, "ok when both present")
  assert.strictEqual(r.clientIdSource, "env", "clientId source = env")
  delete process.env.GOOGLE_CLIENT_ID
  delete process.env.GOOGLE_CLIENT_SECRET
  ok("reads clientId/clientSecret from the generic GOOGLE_CLIENT_ID/SECRET env vars")
}

// --- 2. Explicit config overrides env (resolution order) -----------------------------------
{
  process.env.GOOGLE_CLIENT_ID = "env-id.apps.googleusercontent.com"
  process.env.GOOGLE_CLIENT_SECRET = "env-secret"
  const r = loadGoogleCredentials({ clientId: "cfg-id", clientSecret: "cfg-secret" })
  assert.strictEqual(r.clientId, "cfg-id", "config wins over env")
  assert.strictEqual(r.clientIdSource, "config", "source = config")
  delete process.env.GOOGLE_CLIENT_ID
  delete process.env.GOOGLE_CLIENT_SECRET
  ok("an explicit config value (passed in by the host app) overrides the env var")
}

// --- 3. No file fallback: the library reads no host-app credentials file -------------------
{
  // With nothing passed and no env, the credential is simply "missing" — the library does NOT go
  // looking in ~/.credentials/<anything>. (Resolution is config → env only.)
  const r = loadGoogleCredentials()
  assert.strictEqual(r.ok, false, "not ok when neither config nor env supplies a value")
  assert.strictEqual(r.clientId, "", "empty clientId")
  assert.strictEqual(r.clientIdSource, "missing", "source = missing (never 'file')")
  ok("resolves config → env only; there is no host-app file fallback in the library")
}

// --- 4. Remediation is generic + secret-free -----------------------------------------------
{
  const msg = credentialsRemediation()
  assert.ok(msg.includes("createFederatedFrontend"), "remediation names the API entry point")
  assert.ok(msg.includes("GOOGLE_CLIENT_ID"), "remediation lists the generic env-var alternative")
  // It must NOT name any host application's file/path/key — the library knows none.
  assert.ok(!msg.includes("app_internal_act3"), "remediation names no app-specific JSON key")
  assert.ok(!msg.includes(".credentials"), "remediation names no app-specific file path")
  assert.ok(!msg.includes(FAKE_SECRET), "remediation never echoes a secret")
  ok("remediation is generic (API + env), secret-free, and names no host-app file")
}

// --- 5. assertGoogleCredentials throws a secret-free OAuthCredentialsError ------------------
{
  let threw = null
  try {
    assertGoogleCredentials()
  } catch (e) {
    threw = e
  }
  assert.ok(threw instanceof OAuthCredentialsError, "throws OAuthCredentialsError")
  assert.strictEqual(threw.code, "oauth_not_configured", "machine code present")
  assert.ok(!threw.message.includes("app_internal_act3"), "error names no app-specific key")
  ok("assertGoogleCredentials throws a clear, generic OAuthCredentialsError when unconfigured")
}

// --- 6. Fail-loud guard: SSO start returns 503 oauth_not_configured (no Google redirect) ----
async function testGuard() {
  // Build the embedded middleware with NO credentials available (none passed, none in env).
  const mw = createAuthFrontend({
    google: { redirectUri: "http://localhost:9111/api/v1/oauth_callback" },
    allowedDomains: ["act3ai.com"],
    sessionSecret: "test-secret-0123456789-abcdefghij-strong",
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
    assert.ok(body.remediation.includes("createFederatedFrontend"), "generic remediation in body")
    assert.ok(!body.remediation.includes("app_internal_act3"), "body names no app-specific key")
    assert.ok(!body.remediation.includes(FAKE_SECRET), "body leaks no secret")
    ok("/sign_in/sso fails closed with 503 oauth_not_configured instead of redirecting to Google")
  } finally {
    server.close()
  }

  // And the happy path: with credentials passed in via the API, /sign_in/sso DOES 302 to Google
  // with a non-empty client_id.
  const mw2 = createAuthFrontend({
    google: {
      clientId: FAKE_ID,
      clientSecret: FAKE_SECRET,
      redirectUri: "http://localhost:9111/api/v1/oauth_callback",
    },
    allowedDomains: ["act3ai.com"],
    sessionSecret: "test-secret-0123456789-abcdefghij-strong",
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
    ok("with credentials passed in (legacy google{} alias), /sign_in/sso 302s to Google")
  } finally {
    server2.close()
  }

  // And the Federated-idiomatic shape: createFederatedFrontend with a connections[] array carrying the
  // oauth_google strategy must behave identically to the legacy google{} block.
  const mw3 = createFederatedFrontend({
    connections: [
      {
        strategy: "oauth_google",
        clientId: FAKE_ID,
        clientSecret: FAKE_SECRET,
        redirectUri: "http://localhost:9111/api/v1/oauth_callback",
      },
    ],
    allowedDomains: ["act3ai.com"],
    sessionSecret: "test-secret-0123456789-abcdefghij-strong",
    logger: () => {},
  })
  const server3 = http.createServer((req, res) => mw3(req, res))
  await new Promise((resolve) => server3.listen(0, resolve))
  const port3 = server3.address().port
  try {
    const res = await fetch(`http://localhost:${port3}/sign_in/sso?redirect_url=/cb`, {
      redirect: "manual",
    })
    assert.strictEqual(res.status, 302, "302 to Google from connections[] config")
    const u = new URL(res.headers.get("location"))
    assert.strictEqual(u.searchParams.get("client_id"), FAKE_ID, "client_id from connections[]")
    ok("connections: [{ strategy: 'oauth_google', ... }] 302s to Google with the configured client_id")
  } finally {
    server3.close()
  }
}

testGuard()
  .then(() => {
    console.log(`\nAll ${passed} credential tests passed.`)
  })
  .catch((err) => {
    console.error("\nTEST FAILED:", err)
    process.exit(1)
  })
