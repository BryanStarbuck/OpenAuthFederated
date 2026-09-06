// Smoke test: readBrowserSession() must resolve a real signed session cookie, reject a tampered
// one, and return null when there is no cookie at all.
const { hkdfSync } = require("node:crypto")
const { SignJWT } = require("jose")
const { createFederatedFrontend, FileSessionStore } = require("../dist/index.js")
const { mkdtempSync } = require("node:fs")
const { tmpdir } = require("node:os")
const { join } = require("node:path")

const SECRET = "a-very-strong-test-session-secret-value-32+"

async function main() {
  const frontend = createFederatedFrontend({
    sessionSecret: SECRET,
    allowedDomains: ["act3ai.com"],
    connections: [
      { strategy: "oauth_google", clientId: "id", clientSecret: "sec", redirectUri: "http://localhost:9112/api/v1/oauth_callback" },
    ],
  })

  if (typeof frontend.readBrowserSession !== "function") throw new Error("readBrowserSession missing")

  const key = new Uint8Array(hkdfSync("sha256", Buffer.from(SECRET, "utf8"), new Uint8Array(0), "oaf:session", 32))
  const token = await new SignJWT({
    sid: "sess_1",
    email: "bryan@act3ai.com",
    name: "Bryan Starbuck",
    roles: ["employee"],
    permissions: [],
    org_id: null,
    memberships: [],
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject("user_abc")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(key)

  const reqWith = (cookie) => ({ headers: cookie ? { cookie } : {}, url: "/", method: "GET" })

  const good = await frontend.readBrowserSession(reqWith(`oaf_session=${token}`))
  if (!good || good.email !== "bryan@act3ai.com" || good.name !== "Bryan Starbuck") {
    throw new Error("valid cookie did not resolve: " + JSON.stringify(good))
  }
  if ("grantsResolvedAt" in good) throw new Error("internal field leaked into the public contract")
  console.log("  ✓ a valid session cookie resolves to the signed-in human")

  const tampered = await frontend.readBrowserSession(reqWith(`oaf_session=${token.slice(0, -3)}xyz`))
  if (tampered !== null) throw new Error("tampered cookie resolved")
  console.log("  ✓ a tampered cookie reads as signed out")

  const none = await frontend.readBrowserSession(reqWith(null))
  if (none !== null) throw new Error("no cookie should be null")
  console.log("  ✓ no cookie reads as signed out")

  // Mutating what we were handed must not reach back into the library's session record.
  good.roles.push("admin")
  const again = await frontend.readBrowserSession(reqWith(`oaf_session=${token}`))
  if (again.roles.includes("admin")) throw new Error("caller mutation leaked into the session")
  console.log("  ✓ the returned session is a copy the caller cannot use to grant itself roles")

  // Stateful mode: the durable record is authoritative, so a revoked (signed-out / offboarded)
  // session must read as signed OUT here too — this is the property a server-rendered consent
  // screen depends on, and the whole reason the host app must not hand-roll its own cookie read.
  const store = new FileSessionStore(mkdtempSync(join(tmpdir(), "oaf-sess-")))
  const stateful = createFederatedFrontend({
    sessionSecret: SECRET,
    allowedDomains: ["act3ai.com"],
    sessionStore: store,
    connections: [
      { strategy: "oauth_google", clientId: "id", clientSecret: "sec", redirectUri: "http://localhost:9112/api/v1/oauth_callback" },
    ],
  })
  const now = Math.floor(Date.now() / 1000)
  await store.create({
    sid: "sess_1",
    userId: "user_abc",
    email: "bryan@act3ai.com",
    name: "Bryan Starbuck",
    roles: ["employee"],
    permissions: [],
    orgId: null,
    memberships: [],
    lastVerifiedAt: now,
    grantsResolvedAt: now,
    createdAt: now,
    lastActiveAt: now,
    expireAt: now + 3600,
    revoked: false,
  })
  const live = await stateful.readBrowserSession(reqWith(`oaf_session=${token}`))
  if (!live || live.email !== "bryan@act3ai.com") throw new Error("live stored session did not resolve")
  console.log("  ✓ with a session store, a live session resolves from the durable record")

  await store.remove("bryan@act3ai.com", "sess_1")
  const revoked = await stateful.readBrowserSession(reqWith(`oaf_session=${token}`))
  if (revoked !== null) throw new Error("revoked session still resolved — sign-out does not reach this reader")
  console.log("  ✓ a revoked session reads as signed out even though the cookie is still valid")

  console.log("\nAll readBrowserSession checks passed.")
}
main().catch((e) => { console.error("FAILED:", e.message); process.exit(1) })
