/**
 * Mints real, real-signed SAML 2.0 Responses for the tests, using the disposable test IdP key in
 * `test/fixtures`. Extracted from saml-roundtrip.cjs so the hardening tests sign assertions the
 * same way the gold-path test does — one signer, so a test can never pass against a weaker
 * assertion than the one the round-trip test uses.
 */
const fs = require("node:fs")
const path = require("node:path")

const { SignedXml } = require("xml-crypto")

const FIX = path.join(__dirname, "fixtures")
const keyPem = fs.readFileSync(path.join(FIX, "test-idp-key.pem"), "utf8")
const certPem = fs.readFileSync(path.join(FIX, "test-idp-cert.pem"), "utf8")
const certDer = certPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")

const SP_ENTITY = "https://internal-app.whitehatengineering.com/saml"
const IDP_ENTITY = "https://accounts.google.com/o/saml2?idpid=TESTIDP"
const IDP_SSO = "https://accounts.google.com/o/saml2/idp?idpid=TESTIDP"

const escapeXml = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")

/**
 * Build a signed SAML Response.
 *
 * @param {object} o
 * @param {string} o.acs           ACS URL the Response is destined for (must match the SP config).
 * @param {string} [o.email]       NameID (Google issues the email address here).
 * @param {string} [o.assertionId] Force a specific assertion ID — replay tests reuse one.
 * @param {number} [o.lifetimeMs]  How far out Conditions/NotOnOrAfter sits. Default 5 minutes.
 * @param {object} [o.attributes]  Extra `Name -> value` attributes to assert (e.g. `hd`).
 */
function signedResponse(o) {
  const {
    acs,
    email = "bryan@act3ai.com",
    assertionId = "_a" + Math.random().toString(36).slice(2),
    lifetimeMs = 3e5,
    attributes = {},
  } = o
  const now = Date.now()
  const iso = (t) => new Date(t).toISOString()

  const attrs = Object.entries({ firstName: "Bryan", lastName: "Starbuck", ...attributes })
    .map(
      ([name, value]) =>
        `<saml2:Attribute Name="${escapeXml(name)}"><saml2:AttributeValue>${escapeXml(value)}</saml2:AttributeValue></saml2:Attribute>`,
    )
    .join("")

  const assertion =
    `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${iso(now)}" Version="2.0">` +
    `<saml2:Issuer>${IDP_ENTITY}</saml2:Issuer>` +
    `<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${escapeXml(email)}</saml2:NameID>` +
    `<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="${iso(now + lifetimeMs)}" Recipient="${acs}"/></saml2:SubjectConfirmation></saml2:Subject>` +
    `<saml2:Conditions NotBefore="${iso(now - 3e5)}" NotOnOrAfter="${iso(now + lifetimeMs)}"><saml2:AudienceRestriction><saml2:Audience>${SP_ENTITY}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>` +
    `<saml2:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="${assertionId}"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement>` +
    `<saml2:AttributeStatement>${attrs}</saml2:AttributeStatement>` +
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
  sig.computeSignature(assertion, {
    location: { reference: "//*[local-name(.)='Issuer']", action: "after" },
  })

  return (
    `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r${Math.random().toString(36).slice(2)}" IssueInstant="${iso(now)}" Version="2.0" Destination="${acs}">` +
    `<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">${IDP_ENTITY}</saml2:Issuer>` +
    `<saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>${sig.getSignedXml()}</saml2p:Response>`
  )
}

/** The SP config block matching the fixture IdP, for a given ACS URL. */
function samlConfig(acs, extra = {}) {
  return {
    enabled: true,
    idpEntityId: IDP_ENTITY,
    idpSsoUrl: IDP_SSO,
    idpCert: certPem,
    spEntityId: SP_ENTITY,
    acsUrl: acs,
    trustAssertedEmailVerified: true,
    ...extra,
  }
}

const b64 = (xml) => Buffer.from(xml, "utf8").toString("base64")

module.exports = { signedResponse, samlConfig, b64, certPem, SP_ENTITY, IDP_ENTITY, IDP_SSO }
