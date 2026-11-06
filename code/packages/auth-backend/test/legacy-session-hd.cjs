/**
 * A session's `hd` leaves the library only when it can be trusted.
 *
 * Before 2026-09-09 (3c961ca) a session's `hd` fell back to the presented EMAIL DOMAIN when the
 * upstream asserted none. That commit also began recording `provider` on every session. So a session
 * read back WITHOUT `provider` may carry an unverified `hd`, and it must not reach:
 *   * the access token's `hd` claim,
 *   * the identity handed to `revalidateGrants`,
 *   * `/client`'s user,
 *   * `readBrowserSession()`.
 * A modern session (with `provider`) keeps its `hd` everywhere. Stateless and stateful (store) modes.
 *
 *   npm run build && node test/legacy-session-hd.cjs
 */
const assert = require("node:assert")
const { hkdfSync } = require("node:crypto")
const { SignJWT } = require("jose")
const { createFederatedFrontend, InMemorySessionStore, trustedSessionHd } = require("../dist/index.js")
const { serve, call, cookieHeader, jwtPayload } = require("./helpers.cjs")

const SECRET = "a-strong-test-session-secret-of-32-plus-chars"
const sessionKey = new Uint8Array(
  hkdfSync("sha256", Buffer.from(SECRET, "utf8"), new Uint8Array(0), "oaf:session", 32),
)
let passed = 0
const ok = (msg) => {
  passed++
  console.log(`  ✓ ${msg}`)
}

async function cookieFor({ sid, email, hd, prv }) {
  const now = Math.floor(Date.now() / 1000)
  return await new SignJWT({
    sid,
    email,
    hd,
    roles: ["member"],
    permissions: [],
    org_id: null,
    memberships: [],
    lvc: now,
    gra: now - 3600, // grants are old, so the next mint re-validates
    ...(prv ? { prv, psub: "upstream_1", ev: true } : {}),
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(`user_${sid}`)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(sessionKey)
}

async function run(label, withStore) {
  const seen = []
  const store = withStore ? new InMemorySessionStore() : undefined
  let frontend = null
  const srv = await serve((req, res, next) => frontend(req, res, next))
  frontend = createFederatedFrontend({
    sessionSecret: SECRET,
    cookieSecure: false,
    logger: () => {},
    requirePolicy: true,
    signUpMode: "public",
    connections: [{ strategy: "oauth_google", clientId: "id", clientSecret: "sec", redirectUri: `${srv.base}/api/v1/oauth_callback` }],
    ...(store ? { sessionStore: store } : {}),
    reresolveGrantsEverySeconds: 1,
    revalidateGrants: (identity) => {
      seen.push(identity)
      return { roles: ["member"], permissions: [], orgId: null, memberships: [] }
    },
  })

  try {
    const cases = [
      { sid: "sess_legacy", email: "ann@corp.example", hd: "corp.example", prv: undefined, expectHd: undefined },
      { sid: "sess_modern", email: "bob@corp.example", hd: "corp.example", prv: "google", expectHd: "corp.example" },
    ]
    for (const c of cases) {
      if (store) {
        const now = Math.floor(Date.now() / 1000)
        await store.create({
          sid: c.sid,
          userId: `user_${c.sid}`,
          email: c.email,
          hd: c.hd,
          roles: ["member"],
          permissions: [],
          orgId: null,
          memberships: [],
          createdAt: now,
          lastActiveAt: now,
          lastVerifiedAt: now,
          grantsResolvedAt: now - 3600,
          expiresAt: now + 3600,
          ...(c.prv ? { provider: c.prv, providerSub: "upstream_1", emailVerified: true } : {}),
        })
      }
      const cookie = await cookieFor(c)
      const what = c.prv ? "a modern session" : "a legacy session (no provider)"

      const minted = await call(srv.base, `/client/sessions/${c.sid}/tokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookieHeader({ oaf_session: cookie }) },
        body: "{}",
      })
      assert.strictEqual(minted.status, 200, `${label}: ${what} mints (${minted.status})`)
      assert.strictEqual(jwtPayload(minted.json.jwt).hd, c.expectHd, `${label}: ${what} token hd`)
      const identity = seen.find((i) => i.email === c.email)
      assert.ok(identity, `${label}: revalidateGrants ran for ${what}`)
      assert.strictEqual(identity.hd, c.expectHd, `${label}: ${what} revalidation identity hd`)

      const client = (await call(srv.base, "/client", { headers: { Cookie: cookieHeader({ oaf_session: cookie }) } })).json
      const user = client?.response?.sessions?.[0]?.user ?? client?.sessions?.[0]?.user
      assert.ok(user, `${label}: /client returns the session for ${what}`)
      assert.strictEqual(user.hd, c.expectHd, `${label}: ${what} /client hd`)

      const browser = await frontend.readBrowserSession({
        headers: { cookie: `oaf_session=${cookie}` },
        url: "/",
        method: "GET",
      })
      assert.strictEqual(browser?.hd, c.expectHd, `${label}: ${what} readBrowserSession hd`)
      ok(`${label}: ${what} — hd ${c.expectHd ? "kept" : "dropped"} in token, revalidation, /client, readBrowserSession`)
    }
  } finally {
    srv.close()
  }
}

async function main() {
  assert.strictEqual(trustedSessionHd("corp.example", "google"), "corp.example")
  assert.strictEqual(trustedSessionHd("corp.example", undefined), undefined)
  assert.strictEqual(trustedSessionHd("corp.example", ""), undefined)
  assert.strictEqual(trustedSessionHd("", "google"), undefined)
  assert.strictEqual(trustedSessionHd(42, "google"), undefined)
  ok("trustedSessionHd: kept only with a recorded provider")

  await run("stateless", false)
  await run("stateful", true)
  console.log(`legacy-session-hd: ${passed} passed`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
