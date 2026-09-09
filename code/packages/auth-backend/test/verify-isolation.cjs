/**
 * S1 — per-frontend token verification must not be process-global.
 *
 * `configureEmbeddedVerification()` writes one module-level variable, and
 * `createFederatedFrontend()` calls it on every construction. A host that mounts two frontends in
 * one process — which the library's own `cookiePrefix` documentation anticipates — therefore ends
 * up with last-write-wins: app A's `verifyToken()` starts validating against app B's secret,
 * issuer and audience. That silently destroys the per-app `aud` isolation the config docs promise.
 *
 * The contract asserted here:
 *   1. one frontend            → the global verifyToken() keeps working exactly as before;
 *   2. every frontend          → carries its OWN verifyToken(), unaffected by later constructions;
 *   3. a second, DIFFERENT     → the ambiguous global fails CLOSED and names the fix, rather than
 *      frontend                  silently verifying app A's tokens under app B's secret;
 *   4. a second, IDENTICAL     → is an idempotent bootstrap, not a conflict.
 *      frontend
 */
const assert = require("node:assert")
const { SignJWT } = require("jose")

const { createFederatedFrontend, verifyToken } = require("../dist/index.js")

const SECRET_A = "secret-for-app-a-must-be-at-least-32-chars"
const SECRET_B = "secret-for-app-b-entirely-different-32ch!!"

const conn = (port) => [
  {
    strategy: "oauth_google",
    clientId: "id",
    clientSecret: "sec",
    redirectUri: `http://localhost:${port}/api/v1/oauth_callback`,
  },
]

/** Mint an access token exactly the way the frontend's mintAccessToken() does (master secret). */
async function accessToken(secret, { issuer, audience, sub = "user_1" }) {
  let jwt = new SignJWT({ email: "bryan@act3ai.com", sid: "sess_1", roles: [], permissions: [] })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(sub)
    .setIssuedAt()
    .setIssuer(issuer)
    .setExpirationTime("5m")
  if (audience) jwt = jwt.setAudience(audience)
  return await jwt.sign(new TextEncoder().encode(secret))
}

async function main() {
  const quiet = () => {}

  // --- 1. A single frontend: the historical global path must keep working ---------------------
  const appA = createFederatedFrontend({
    sessionSecret: SECRET_A,
    issuer: "app-a",
    audience: "aud-a",
    allowedDomains: ["act3ai.com"],
    connections: conn(9111),
    logger: quiet,
  })
  const tokenA = await accessToken(SECRET_A, { issuer: "app-a", audience: "aud-a" })

  const viaGlobal = await verifyToken(tokenA)
  assert.strictEqual(viaGlobal.sub, "user_1", "one frontend: the global verifyToken must still work")
  console.log("  ✓ with a single frontend the global verifyToken() is unchanged (back-compat)")

  // --- 2. Every frontend carries its own verifier ---------------------------------------------
  assert.strictEqual(
    typeof appA.verifyToken,
    "function",
    "the frontend must expose its own verifyToken() so a host never depends on global state",
  )
  const viaA = await appA.verifyToken(tokenA)
  assert.strictEqual(viaA.sub, "user_1", "app A must verify its own token")
  console.log("  ✓ the frontend exposes an instance verifyToken() that validates its own tokens")

  // --- 4. An identical re-configuration is a no-op, not a conflict -----------------------------
  createFederatedFrontend({
    sessionSecret: SECRET_A,
    issuer: "app-a",
    audience: "aud-a",
    allowedDomains: ["act3ai.com"],
    connections: conn(9111),
    logger: quiet,
  })
  const stillGlobal = await verifyToken(tokenA)
  assert.strictEqual(
    stillGlobal.sub,
    "user_1",
    "re-constructing with identical config must not be treated as a conflict",
  )
  console.log("  ✓ constructing a second frontend with identical config stays a no-op")

  // --- 3. A second, DIFFERENT frontend ---------------------------------------------------------
  const appB = createFederatedFrontend({
    sessionSecret: SECRET_B,
    issuer: "app-b",
    audience: "aud-b",
    allowedDomains: ["whitehatengineering.com"],
    connections: conn(9112),
    logger: quiet,
  })

  // 3a. THE REGRESSION THIS TEST EXISTS FOR: app A's verifier must be untouched by app B.
  const stillA = await appA.verifyToken(tokenA)
  assert.strictEqual(
    stillA.sub,
    "user_1",
    "constructing app B must not repoint app A's verifier at app B's secret",
  )
  console.log("  ✓ constructing a second frontend does not clobber the first one's verifier")

  // 3b. Cross-app isolation: A's token is not valid at B.
  await assert.rejects(
    () => appB.verifyToken(tokenA),
    /signature|"iss"|"aud"/i,
    "app B must reject a token minted for app A",
  )
  console.log("  ✓ app B rejects a token minted for app A (per-app isolation holds)")

  const tokenB = await accessToken(SECRET_B, { issuer: "app-b", audience: "aud-b" })
  await assert.rejects(
    () => appA.verifyToken(tokenB),
    /signature|"iss"|"aud"/i,
    "app A must reject a token minted for app B",
  )
  console.log("  ✓ app A rejects a token minted for app B")

  // 3c. The now-ambiguous global must fail CLOSED and say what to do instead.
  await assert.rejects(
    () => verifyToken(tokenA),
    /ambiguous|more than one|multiple/i,
    "with two differently-configured frontends the global verifyToken must refuse, not guess",
  )
  console.log("  ✓ the ambiguous global verifyToken() fails closed instead of guessing an app")

  // 3d. An explicit per-call secret still works — the escape hatch is not blocked by the latch.
  const explicit = await verifyToken(tokenA, {
    embedded: true,
    sessionSecret: SECRET_A,
    issuer: "app-a",
    audience: "aud-a",
  })
  assert.strictEqual(explicit.sub, "user_1", "an explicit per-call config must still verify")
  console.log("  ✓ an explicit per-call sessionSecret still verifies (escape hatch intact)")

  // 3e. THE SHARED-SECRET CASE. An explicit `sessionSecret` with NO issuer/audience must still get
  // that app's claim checks — the latch must not turn "I know which secret" into "enforce nothing".
  // `authenticateRequest(req, { sessionSecret })` is a documented, supported shape, and two apps
  // sharing a secret while differing only by audience is exactly the configuration `aud` is
  // documented to protect.
  const SHARED = "one-secret-shared-by-two-sibling-apps-32ch"
  const appC = createFederatedFrontend({
    sessionSecret: SHARED,
    issuer: "iss-c",
    audience: "aud-c",
    allowedDomains: ["act3ai.com"],
    connections: conn(9113),
    logger: quiet,
  })
  const appD = createFederatedFrontend({
    sessionSecret: SHARED,
    issuer: "iss-d",
    audience: "aud-d",
    allowedDomains: ["act3ai.com"],
    connections: conn(9114),
    logger: quiet,
  })
  const tokenD = await accessToken(SHARED, { issuer: "iss-d", audience: "aud-d" })

  assert.strictEqual((await appD.verifyToken(tokenD)).sub, "user_1", "app D verifies its own token")
  await assert.rejects(
    () => appC.verifyToken(tokenD),
    /"iss"|"aud"|signature/i,
    "sharing a secret must not make app D's token valid at app C",
  )
  console.log("  ✓ two apps sharing a secret stay isolated by issuer/audience")

  await assert.rejects(
    () => verifyToken(tokenD, { embedded: true, sessionSecret: SHARED }),
    /more than one|ambiguous/i,
    "a secret two apps both registered does not identify an app, so a secret-only verify must " +
      "refuse rather than check the signature and enforce neither claim",
  )
  console.log("  ✓ a secret shared by two apps makes a secret-only verify refuse")

  // Naming the claims explicitly is still enough to proceed.
  const named = await verifyToken(tokenD, {
    embedded: true,
    sessionSecret: SHARED,
    issuer: "iss-d",
    audience: "aud-d",
  })
  assert.strictEqual(named.sub, "user_1", "an explicitly-described call must still verify")
  console.log("  ✓ naming issuer + audience explicitly still verifies")

  // And a secret only ONE app registered still gets that app's claims enforced for free.
  await assert.rejects(
    () => verifyToken(tokenA, { embedded: true, sessionSecret: SECRET_A, audience: "aud-b" }),
    /"aud"/i,
    "a wrong audience must be rejected even when the secret is right",
  )
  console.log("  ✓ a single-app secret still enforces that app's audience")

  console.log("\nAll verification-isolation checks passed.")
}

main().catch((e) => {
  console.error("FAILED:", e.message)
  process.exit(1)
})
