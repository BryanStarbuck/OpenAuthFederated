/**
 * The provider protocols on their own (src/oauth-providers.ts), against fake Google and X servers on
 * loopback: the authorize URLs, the code exchange, the id_token signature/claims/nonce checks, the
 * X profile read, and the error kinds a caller keys on (provider_busy, client_refused, rejected,
 * unreachable, identity_invalid) together with the stage they happened at.
 */
const assert = require("node:assert")
const http = require("node:http")

const { exportJWK, generateKeyPair, SignJWT } = require("jose")

const {
  createPkcePair,
  pkceChallenge,
  googleAuthorizeUrl,
  exchangeGoogleCode,
  xAuthorizeUrl,
  exchangeXCode,
  OAuthExchangeError,
} = require("../dist/index.js")

const CLIENT_ID = "test-client.apps.googleusercontent.com"

/** A loopback server whose routes are swapped per test. Returns { base, routes, requests, close }. */
async function fakeProvider() {
  const routes = {}
  const requests = []
  const server = http.createServer((req, res) => {
    let body = ""
    req.on("data", (c) => (body += c))
    req.on("end", () => {
      const path = new URL(req.url, "http://x").pathname
      requests.push({ path, method: req.method, headers: req.headers, body })
      const route = routes[path]
      if (!route) {
        res.statusCode = 404
        return res.end("{}")
      }
      const { status = 200, json } = route(req, body)
      res.statusCode = status
      res.setHeader("Content-Type", "application/json")
      res.end(JSON.stringify(json ?? {}))
    })
  })
  await new Promise((r) => server.listen(0, "127.0.0.1", r))
  const base = `http://127.0.0.1:${server.address().port}`
  return { base, routes, requests, close: () => new Promise((r) => server.close(r)) }
}

async function expectKind(promise, kind, stage) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof OAuthExchangeError, `expected OAuthExchangeError, got ${err}`)
    assert.strictEqual(err.kind, kind)
    if (stage) assert.strictEqual(err.stage, stage)
    return true
  })
}

async function main() {
  // --- PKCE and the authorize URLs ----------------------------------------------------------
  {
    const pkce = createPkcePair()
    assert.match(pkce.codeVerifier, /^[A-Za-z0-9_-]{43}$/)
    assert.strictEqual(pkce.codeChallenge, pkceChallenge(pkce.codeVerifier))
    // RFC 7636 appendix B test vector.
    assert.strictEqual(
      pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    )

    const g = new URL(
      googleAuthorizeUrl({
        clientId: CLIENT_ID,
        redirectUri: "https://tv.example/v1/auth/google/login/redirect",
        state: "st",
        nonce: "nn",
        codeChallenge: pkce.codeChallenge,
      }),
    )
    assert.strictEqual(g.origin + g.pathname, "https://accounts.google.com/o/oauth2/v2/auth")
    assert.strictEqual(g.searchParams.get("scope"), "openid email profile")
    assert.strictEqual(g.searchParams.get("code_challenge_method"), "S256")
    assert.strictEqual(g.searchParams.get("nonce"), "nn")
    assert.strictEqual(g.searchParams.get("prompt"), "select_account")
    assert.strictEqual(g.searchParams.get("hd"), null)

    const x = new URL(
      xAuthorizeUrl({
        clientId: "xid",
        redirectUri: "https://tv.example/v1/auth/x/login/redirect",
        state: "st",
        codeChallenge: pkce.codeChallenge,
      }),
    )
    assert.strictEqual(x.origin + x.pathname, "https://x.com/i/oauth2/authorize")
    assert.strictEqual(x.searchParams.get("scope"), "tweet.read users.read users.email")
    assert.strictEqual(x.searchParams.get("code_challenge"), pkce.codeChallenge)
    console.log("  ✓ PKCE matches RFC 7636 and both authorize URLs carry state, PKCE and scope")
  }

  // --- Google: exchange + id_token verification ----------------------------------------------
  const fake = await fakeProvider()
  try {
    const { publicKey, privateKey } = await generateKeyPair("RS256")
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" }
    fake.routes["/certs"] = () => ({ json: { keys: [jwk] } })
    const endpoints = { tokenUrl: `${fake.base}/token`, jwksUrl: `${fake.base}/certs` }

    const idToken = (claims = {}, key = privateKey) =>
      new SignJWT({
        email: "Viewer@Example.com",
        email_verified: true,
        given_name: "Ada",
        family_name: "Lovelace",
        nonce: "n-1",
        ...claims,
      })
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(claims.iss ?? "https://accounts.google.com")
        .setAudience(claims.aud ?? CLIENT_ID)
        .setSubject("1234567890")
        .setIssuedAt()
        .setExpirationTime(claims.exp ?? "5m")
        .sign(key)

    const opts = {
      clientId: CLIENT_ID,
      clientSecret: "secret",
      redirectUri: "https://tv.example/cb",
      code: "the-code",
      codeVerifier: "the-verifier",
      nonce: "n-1",
      endpoints,
    }

    const good = await idToken()
    fake.routes["/token"] = () => ({ json: { id_token: good } })
    const who = await exchangeGoogleCode(opts)
    assert.deepStrictEqual(
      { sub: who.sub, email: who.email, emailVerified: who.emailVerified, given: who.givenName, family: who.familyName },
      { sub: "1234567890", email: "Viewer@Example.com", emailVerified: true, given: "Ada", family: "Lovelace" },
    )
    const sent = new URLSearchParams(fake.requests.filter((r) => r.path === "/token").at(-1).body)
    assert.strictEqual(sent.get("code_verifier"), "the-verifier")
    assert.strictEqual(sent.get("client_secret"), "secret")
    console.log("  ✓ Google: the code is exchanged with PKCE and a signed id_token yields the identity")

    fake.routes["/token"] = () => ({ json: { id_token: good } })
    await expectKind(exchangeGoogleCode({ ...opts, nonce: "another-tab" }), "identity_invalid", "identity")
    const { privateKey: stranger } = await generateKeyPair("RS256")
    const forged = await idToken({}, stranger)
    fake.routes["/token"] = () => ({ json: { id_token: forged } })
    await expectKind(exchangeGoogleCode(opts), "identity_invalid", "identity")
    const wrongAud = await idToken({ aud: "someone-else" })
    fake.routes["/token"] = () => ({ json: { id_token: wrongAud } })
    await expectKind(exchangeGoogleCode(opts), "identity_invalid", "identity")
    const expired = await idToken({ exp: Math.floor(Date.now() / 1000) - 600 })
    fake.routes["/token"] = () => ({ json: { id_token: expired } })
    await expectKind(exchangeGoogleCode(opts), "identity_invalid", "identity")
    console.log("  ✓ Google: a wrong nonce, a foreign signature, a wrong audience and an expired token are refused")

    fake.routes["/token"] = () => ({ status: 429 })
    await expectKind(exchangeGoogleCode(opts), "provider_busy", "token")
    fake.routes["/token"] = () => ({ status: 401, json: { error: "invalid_client" } })
    await expectKind(exchangeGoogleCode(opts), "client_refused", "token")
    fake.routes["/token"] = () => ({ status: 400, json: { error: "invalid_grant" } })
    await expectKind(exchangeGoogleCode(opts), "rejected", "token")
    fake.routes["/token"] = () => ({ json: {} })
    await expectKind(exchangeGoogleCode(opts), "unreachable", "token")
    await expectKind(
      exchangeGoogleCode({ ...opts, endpoints: { ...endpoints, tokenUrl: "http://127.0.0.1:1/token" } }),
      "unreachable",
      "token",
    )
    console.log("  ✓ Google: 429, 401, 400, an id_token-less answer and a dead endpoint map to their kinds")

    // --- X: exchange + /2/users/me ----------------------------------------------------------
    const xEndpoints = { tokenUrl: `${fake.base}/x/token`, meUrl: `${fake.base}/x/me` }
    const xOpts = {
      clientId: "xid",
      clientSecret: "xsecret",
      redirectUri: "https://tv.example/x-cb",
      code: "x-code",
      codeVerifier: "x-verifier",
      endpoints: xEndpoints,
    }
    fake.routes["/x/token"] = () => ({ json: { access_token: "at", scope: "tweet.read users.read users.email" } })
    fake.routes["/x/me"] = (req) => {
      assert.strictEqual(req.headers.authorization, "Bearer at")
      return { json: { data: { id: "42", name: "Ada Lovelace", username: "ada", confirmed_email: "ada@example.com" } } }
    }
    const xr = await exchangeXCode(xOpts)
    assert.strictEqual(xr.identity.sub, "42")
    assert.strictEqual(xr.identity.email, "ada@example.com")
    assert.strictEqual(xr.identity.emailVerified, true)
    assert.strictEqual(xr.identity.provider, "x")
    assert.strictEqual(xr.grantedScopes, "tweet.read users.read users.email")
    const tokenReq = fake.requests.find((r) => r.path === "/x/token")
    assert.strictEqual(tokenReq.headers.authorization, `Basic ${Buffer.from("xid:xsecret").toString("base64")}`)
    assert.strictEqual(new URLSearchParams(tokenReq.body).get("client_secret"), null, "X takes the secret in Basic only")
    console.log("  ✓ X: HTTP Basic token exchange, then /2/users/me under the person's token")

    const logs = []
    fake.routes["/x/me"] = () => ({ json: { data: { id: "43", name: "No Mail" }, errors: [{ title: "Field Authorization Error" }] } })
    const noMail = await exchangeXCode({ ...xOpts, log: (l, m) => logs.push([l, m]) })
    assert.strictEqual(noMail.identity.email, "")
    assert.strictEqual(noMail.identity.emailVerified, false)
    assert.ok(logs.some(([l, m]) => l === "warn" && m.includes("Field Authorization Error")))
    console.log("  ✓ X: a missing confirmed_email is not an error, and the gap is logged with X's reason")

    fake.routes["/x/me"] = () => ({ json: { data: {} } })
    await expectKind(exchangeXCode(xOpts), "identity_invalid", "identity")
    fake.routes["/x/me"] = () => ({ status: 401 })
    await expectKind(exchangeXCode(xOpts), "rejected", "identity")
    fake.routes["/x/me"] = () => ({ status: 429 })
    await expectKind(exchangeXCode(xOpts), "provider_busy", "identity")
    fake.routes["/x/token"] = () => ({ status: 401 })
    await expectKind(exchangeXCode(xOpts), "client_refused", "token")
    fake.routes["/x/token"] = () => ({ status: 429 })
    await expectKind(exchangeXCode(xOpts), "provider_busy", "token")
    console.log("  ✓ X: a profile without an id, a refused profile read, and token 401/429 map to their kinds")
  } finally {
    await fake.close()
  }

  console.log("\nAll oauth-providers checks passed.")
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
