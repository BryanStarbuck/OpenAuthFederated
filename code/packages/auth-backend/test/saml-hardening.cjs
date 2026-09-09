/**
 * S2 + S3 — SAML admission and the fail-open replay/audience defenses.
 *
 * S2: the mapped SAML identity carries no `provider` and no `hd`, so `finishSignIn` reads it as a
 *     Google identity with no hosted-domain claim. Under `requireHostedDomain: true` — the
 *     recommended hardening for a Workspace-gated deployment — that rejects EVERY SAML assertion,
 *     and logs the refusal as a `google` one. The charter mandates SAML 2.0 as the go-forward
 *     default, so an operator meeting this turns the control off for OIDC too.
 *
 * S3: the assertion-id replay cache and the audience cross-check are both written as
 *     `if (fieldIsPresent) { check }`. When node-saml does not surface the field — a shape detail
 *     of a third-party library that a minor upgrade can change — one-time-use is not enforced at
 *     all, and nothing in the logs says so. The `inResponseTo` fallback is worse than nothing: it
 *     keys the cache on the REQUEST id, so two distinct assertions answering one AuthnRequest
 *     collide while genuine replays of different requests sail through.
 */
const assert = require("node:assert")

const { buildSamlClient, validateSamlAcs, InMemorySamlReplayStore } = require("../dist/index.js")
const { signedResponse, samlConfig, b64 } = require("./saml-fixture.cjs")

const ACS = "http://localhost:9111/api/v1/saml/acs"

/** A replay store that records exactly what it was asked to remember. */
function spyStore() {
  const recorded = []
  const ids = new Set()
  return {
    recorded,
    seen: (id) => ids.has(id),
    record: (id, notOnOrAfter) => {
      recorded.push({ id, notOnOrAfter })
      ids.add(id)
    },
  }
}

async function main() {
  const cfg = samlConfig(ACS)
  const client = buildSamlClient(cfg)

  // --- S2: the identity must name its own strategy -------------------------------------------
  const base = await validateSamlAcs(
    client,
    { SAMLResponse: b64(signedResponse({ acs: ACS })), RelayState: "x" },
    cfg,
  )
  assert.strictEqual(
    base.identity.provider,
    "saml",
    "a SAML identity must declare provider 'saml' — otherwise finishSignIn treats it as Google",
  )
  console.log("  ✓ a validated SAML identity declares provider: 'saml'")

  // --- S2: a hosted-domain attribute, when the IdP asserts one, must map onto `hd` ------------
  const withHd = await validateSamlAcs(
    client,
    {
      SAMLResponse: b64(signedResponse({ acs: ACS, attributes: { hd: "act3ai.com" } })),
      RelayState: "x",
    },
    cfg,
  )
  assert.strictEqual(
    withHd.identity.hd,
    "act3ai.com",
    "an asserted hosted-domain attribute must reach the identity as `hd`",
  )
  console.log("  ✓ an IdP-asserted hosted-domain attribute maps onto identity.hd")

  // An assertion that does NOT carry one must stay absent — never inferred from the email.
  assert.strictEqual(
    base.identity.hd,
    undefined,
    "hd must not be invented when the assertion does not assert one",
  )
  console.log("  ✓ hd stays undefined when the IdP asserted none (never inferred from the email)")

  // --- The asserted hd must CORROBORATE the address, never contradict it ----------------------
  // A Google `hd` is computed by Google from real Workspace membership. A SAML one is an attribute
  // whose value the IdP chose, so an assertion for one domain carrying a hosted domain of another
  // is saying two things that disagree — and the disagreeing value is the one that satisfies
  // `requireHostedDomain`. Dropped, so the identity simply has no hosted domain.
  const mismatched = await validateSamlAcs(
    client,
    {
      SAMLResponse: b64(
        signedResponse({
          acs: ACS,
          email: "mallory@contractors.example",
          attributes: { hd: "act3ai.com" },
        }),
      ),
      RelayState: "x",
    },
    cfg,
  )
  assert.strictEqual(
    mismatched.identity.hd,
    undefined,
    "an hd that does not match the asserted email domain must be dropped, not carried",
  )
  console.log("  ✓ an hd contradicting the email domain is dropped (corroborate, never substitute)")

  // --- Only `hd` is read implicitly ------------------------------------------------------------
  // `domain` is a name generic enough that an IdP may already emit it for something unrelated; if
  // it were read implicitly, that coincidence would satisfy the deployment's strongest control.
  const generic = await validateSamlAcs(
    client,
    {
      SAMLResponse: b64(signedResponse({ acs: ACS, attributes: { domain: "act3ai.com" } })),
      RelayState: "x",
    },
    cfg,
  )
  assert.strictEqual(
    generic.identity.hd,
    undefined,
    "a generic `domain` attribute must not be read as a hosted-domain claim unless named",
  )
  console.log("  ✓ a generic `domain` attribute is not implicitly a hosted-domain claim")

  // ...but an operator can name it, and then it is read (still subject to corroboration).
  const named = await validateSamlAcs(
    client,
    {
      SAMLResponse: b64(signedResponse({ acs: ACS, attributes: { department: "act3ai.com" } })),
      RelayState: "x",
    },
    samlConfig(ACS, { hostedDomainAttribute: "department" }),
  )
  assert.strictEqual(
    named.identity.hd,
    "act3ai.com",
    "an explicitly named hostedDomainAttribute must be read",
  )
  console.log("  ✓ hostedDomainAttribute lets the operator name the attribute explicitly")

  // --- S3: one-time use, on a real signed pair of identical assertions -------------------------
  const store = new InMemorySamlReplayStore()
  const once = b64(signedResponse({ acs: ACS, assertionId: "_fixed_replay_id" }))
  await validateSamlAcs(client, { SAMLResponse: once, RelayState: "x" }, cfg, store)
  await assert.rejects(
    () => validateSamlAcs(client, { SAMLResponse: once, RelayState: "x" }, cfg, store),
    /replay/i,
    "the same assertion id must not be consumable twice",
  )
  console.log("  ✓ replaying a consumed assertion id is rejected")

  // --- S3: a profile with NO assertion id must FAIL CLOSED ------------------------------------
  // Driven through a stub SAML client, because the failure is precisely "node-saml handed us a
  // profile shaped differently than we assumed" — which cannot be produced from valid XML.
  const stub = {
    validatePostResponseAsync: async () => ({
      profile: {
        nameID: "bryan@act3ai.com",
        email: "bryan@act3ai.com",
        attributes: {},
        // No `assertionId`, no `ID` — and deliberately an `inResponseTo`, because today's code
        // silently keys the replay cache on it.
        inResponseTo: "_request_id_not_an_assertion_id",
      },
    }),
  }
  const spy = spyStore()
  await assert.rejects(
    () => validateSamlAcs(stub, { SAMLResponse: "x", RelayState: "x" }, cfg, spy),
    /assertion id|one-time|replay/i,
    "an assertion with no id must be refused when a replay store is configured, not waved through",
  )
  assert.deepStrictEqual(
    spy.recorded,
    [],
    "the request id (inResponseTo) must never be recorded as if it were an assertion id",
  )
  console.log("  ✓ an assertion with no id fails closed instead of skipping replay protection")
  console.log("  ✓ inResponseTo is never used as the replay-cache key")

  // --- S3: a far-future NotOnOrAfter must not pin a cache entry forever ------------------------
  const spy2 = spyStore()
  const YEAR = 365 * 24 * 60 * 60 * 1000
  await validateSamlAcs(
    client,
    { SAMLResponse: b64(signedResponse({ acs: ACS, lifetimeMs: YEAR })), RelayState: "x" },
    cfg,
    spy2,
  )
  assert.strictEqual(spy2.recorded.length, 1, "the assertion should have been recorded once")
  const ceiling = Date.now() + 11 * 60 * 1000
  assert.ok(
    spy2.recorded[0].notOnOrAfter <= ceiling,
    `an IdP-supplied expiry must be capped (got ${new Date(spy2.recorded[0].notOnOrAfter).toISOString()}, ` +
      `cap ${new Date(ceiling).toISOString()}) — otherwise one assertion pins a cache entry for a year`,
  )
  console.log("  ✓ an IdP-supplied far-future expiry is capped before it reaches the replay store")

  console.log("\nAll SAML hardening checks passed.")
}

main().catch((e) => {
  console.error("FAILED:", e.message)
  process.exit(1)
})
