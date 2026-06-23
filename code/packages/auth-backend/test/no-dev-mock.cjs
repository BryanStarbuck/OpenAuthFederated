/**
 * "No dev mock" guarantee test (standalone Node — mirrors credentials.cjs / saml-roundtrip.cjs).
 *
 * Contract: OpenAuthFederated has NO dev auth mock of its own. It must NEVER accept a token signed
 * with a well-known/shared "dev" secret, and it reads NO environment variable (env must do nothing).
 * Embedded mode still works, but only with a strong sessionSecret supplied via the API — no default.
 *
 *   1. build:  pnpm --filter @auth/backend build   (or: npx tsc -p tsconfig.json)
 *   2. run:    node packages/auth-backend/test/no-dev-mock.cjs
 *
 * Exits non-zero on any failure.
 */
const assert = require("node:assert")
const { SignJWT } = require("jose")

const backend = require("../dist/index.js")
const { verifyToken } = backend
const STRONG = "a-genuinely-strong-operator-supplied-secret-32+chars"

let passed = 0
function ok(name) {
  passed++
  console.log(`  ✓ ${name}`)
}

function clearEnv() {
  delete process.env.AUTH_DEV_MODE
  delete process.env.AUTH_DEV_SHARED_SECRET
  delete process.env.AUTH_EMBEDDED
  delete process.env.AUTH_SESSION_SECRET
  delete process.env.AUTH_JWT_ISSUER
}

async function signHS256(secret, claims = {}) {
  return new SignJWT({ sub: "u_1", email: "dev@whitehatengineering.com", ...claims })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(new TextEncoder().encode(secret))
}

async function main() {
  // --- 1. The dev-mock API surface is gone --------------------------------------------------
  {
    for (const name of [
      "devModeActive",
      "evaluateDevMode",
      "isDevModeRequested",
      "DevModeForbiddenError",
      "isRunningLocalhost",
      "appCredentialsPresent",
    ]) {
      assert.strictEqual(backend[name], undefined, `${name} must not be exported`)
    }
    ok("no dev-mode/dev-guard API is exported from @auth/backend")
  }

  // --- 2. Env vars do nothing; a shared-secret token is never honoured via a dev path --------
  {
    clearEnv()
    // Set every legacy env var — the library must ignore ALL of them. With no embedded config
    // passed via the API and no opts.issuer, verification fails closed (it does not read env).
    process.env.AUTH_DEV_MODE = "true"
    process.env.AUTH_DEV_SHARED_SECRET = "dev-shared-secret"
    process.env.AUTH_EMBEDDED = "true"
    process.env.AUTH_SESSION_SECRET = "dev-shared-secret"
    process.env.AUTH_JWT_ISSUER = "http://localhost:9111"
    const token = await signHS256("dev-shared-secret")
    await assert.rejects(verifyToken(token), (err) => {
      assert.ok(!/dev mode/i.test(String(err && err.message)), "must not mention a dev-mode path")
      return true
    })
    ok("environment variables are ignored — a shared-secret token never verifies (no dev mock)")
  }

  // --- 3. Embedded mode requires a strong secret; the dev default fails closed ---------------
  {
    clearEnv()
    // Config is passed via the API (opts), never env. The weak default must be refused.
    await assert.rejects(
      verifyToken(await signHS256("dev-shared-secret"), {
        embedded: true,
        sessionSecret: "dev-shared-secret",
      }),
      /strong sessionSecret/,
      "embedded mode must reject the dev/default secret",
    )
    ok("embedded mode refuses the weak default secret (no silent fallback)")
  }

  // --- 4. Embedded mode works with a real secret; a wrong-secret token is rejected ----------
  {
    clearEnv()
    // (a) per-call opts.
    const good = await verifyToken(await signHS256(STRONG), { embedded: true, sessionSecret: STRONG })
    assert.strictEqual(good.email, "dev@whitehatengineering.com")
    await assert.rejects(
      verifyToken(await signHS256("some-other-secret"), { embedded: true, sessionSecret: STRONG }),
      "a token signed with the wrong secret must be rejected",
    )
    // (b) module-level config set once via the API (configureEmbeddedVerification), as
    // createFederatedFrontend does — verifyToken then needs no per-call secret.
    backend.configureEmbeddedVerification({ sessionSecret: STRONG })
    const good2 = await verifyToken(await signHS256(STRONG))
    assert.strictEqual(good2.email, "dev@whitehatengineering.com")
    ok("embedded mode verifies only tokens signed with the API-supplied sessionSecret")
  }

  clearEnv()
  console.log(`\nAll ${passed} no-dev-mock checks passed.`)
}

main().catch((err) => {
  console.error("\nFAIL:", err && err.stack ? err.stack : err)
  process.exit(1)
})
