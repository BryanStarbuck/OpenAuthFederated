/**
 * SAML 2.0 SP round-trip integration test (gold path).
 *
 * jest's CJS VM cannot load `jose` via dynamic import(), so the signed-assertion validation +
 * profile→identity mapping is covered here as a standalone Node script instead. It mints a SAML
 * Response whose Assertion is signed by a throwaway test IdP key (test/fixtures), then runs it
 * through the library's `validateSamlAcs` and asserts the mapped identity. It also asserts that a
 * tampered assertion and a wrong audience are rejected.
 *
 *   1. build:  pnpm --filter @auth/backend build
 *   2. run:    node packages/auth-backend/test/saml-roundtrip.cjs
 *
 * Exits non-zero on any failure. The fixtures are disposable test-only keys (never used in prod).
 */
const fs = require("node:fs")
const path = require("node:path")
const assert = require("node:assert")

const { SignedXml } = require("xml-crypto")
const { buildSamlClient, validateSamlAcs } = require("../dist/index.js")

const FIX = path.join(__dirname, "fixtures")
const keyPem = fs.readFileSync(path.join(FIX, "test-idp-key.pem"), "utf8")
const certPem = fs.readFileSync(path.join(FIX, "test-idp-cert.pem"), "utf8")
const certDer = certPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")

const SP_ENTITY = "https://internal-app.whitehatengineering.com/saml"
const ACS = "http://localhost:9111/api/v1/saml/acs"
const IDP_ENTITY = "https://accounts.google.com/o/saml2?idpid=TESTIDP"

function signedResponse({ email = "bryan@act3ai.com" } = {}) {
  const now = Date.now()
  const iso = (t) => new Date(t).toISOString()
  const aid = "_a" + Math.random().toString(36).slice(2)
  const assertion =
    `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="${aid}" IssueInstant="${iso(now)}" Version="2.0">` +
    `<saml2:Issuer>${IDP_ENTITY}</saml2:Issuer>` +
    `<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml2:NameID>` +
    `<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="${iso(now + 3e5)}" Recipient="${ACS}"/></saml2:SubjectConfirmation></saml2:Subject>` +
    `<saml2:Conditions NotBefore="${iso(now - 3e5)}" NotOnOrAfter="${iso(now + 3e5)}"><saml2:AudienceRestriction><saml2:Audience>${SP_ENTITY}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>` +
    `<saml2:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="${aid}"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement>` +
    `<saml2:AttributeStatement><saml2:Attribute Name="firstName"><saml2:AttributeValue>Bryan</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="lastName"><saml2:AttributeValue>Starbuck</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement>` +
    `</saml2:Assertion>`

  const sig = new SignedXml({
    privateKey: keyPem,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    getKeyInfoContent: () => `<X509Data><X509Certificate>${certDer}</X509Certificate></X509Data>`,
  })
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  })
  sig.computeSignature(assertion, { location: { reference: "//*[local-name(.)='Issuer']", action: "after" } })
  const signed = sig.getSignedXml()
  return (
    `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" IssueInstant="${iso(now)}" Version="2.0" Destination="${ACS}">` +
    `<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">${IDP_ENTITY}</saml2:Issuer>` +
    `<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>${signed}</saml2p:Response>`
  )
}

const b64 = (xml) => Buffer.from(xml, "utf8").toString("base64")

;(async () => {
  const cfg = {
    enabled: true,
    idpEntityId: IDP_ENTITY,
    idpSsoUrl: "https://accounts.google.com/o/saml2/idp?idpid=TESTIDP",
    idpCert: certPem,
    spEntityId: SP_ENTITY,
    acsUrl: ACS,
    // The reference IdP (Google) signs the assertion; treat a valid signed assertion as a verified
    // email for this test (the new default is fail-closed unless opted in).
    trustAssertedEmailVerified: true,
  }
  const client = buildSamlClient(cfg)

  // 1. Valid signed assertion → mapped identity.
  const ok = await validateSamlAcs(client, { SAMLResponse: b64(signedResponse()), RelayState: "x" }, cfg)
  assert.strictEqual(ok.identity.email, "bryan@act3ai.com", "email maps from NameID")
  assert.strictEqual(ok.identity.givenName, "Bryan", "givenName maps from attribute")
  assert.strictEqual(ok.identity.familyName, "Starbuck", "familyName maps from attribute")
  assert.strictEqual(ok.identity.emailVerified, true)
  console.log("✅ valid signed assertion validated + mapped:", JSON.stringify(ok.identity))

  // 2. Tampered assertion (signature no longer matches) → rejected.
  const tampered = b64(signedResponse().replace("bryan@act3ai.com", "attacker@evil.com"))
  await assert.rejects(
    () => validateSamlAcs(client, { SAMLResponse: tampered, RelayState: "x" }, cfg),
    /signature/i,
    "tampered assertion must be rejected",
  )
  console.log("✅ tampered assertion rejected")

  // 3. Wrong audience (validator configured for a different SP) → rejected.
  const wrongCfg = {
    enabled: true,
    idpEntityId: IDP_ENTITY,
    idpSsoUrl: "x",
    idpCert: certPem,
    spEntityId: "https://some-other-sp.example/saml",
    acsUrl: ACS,
  }
  const wrongAud = buildSamlClient(wrongCfg)
  await assert.rejects(
    () => validateSamlAcs(wrongAud, { SAMLResponse: b64(signedResponse()), RelayState: "x" }, wrongCfg),
    /audience/i,
    "wrong audience must be rejected",
  )
  console.log("✅ wrong audience rejected")

  console.log("\nSAML round-trip integration test PASSED")
})().catch((err) => {
  console.error("SAML round-trip integration test FAILED:", err && err.message ? err.message : err)
  process.exit(1)
})
