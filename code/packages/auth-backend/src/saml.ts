import { SAML, ValidateInResponseTo } from "@node-saml/node-saml"
import {
  generateServiceProviderMetadata as nodeSamlMetadata,
} from "@node-saml/node-saml"

import type { OidcIdentity } from "./frontend.js"

/**
 * SAML 2.0 Service Provider support for the embedded Frontend API.
 *
 * This module is the *only* place SAML XML is handled. It wraps `@node-saml/node-saml` (the
 * standalone core of passport-saml) so the host SP web app never implements SAML itself — it
 * only supplies config. The two protocol operations a Service Provider needs are exposed as
 * small async functions that `frontend.ts` calls from its router, then funnels the verified
 * identity into the *same* session model the Google-OIDC path uses. SAML and OIDC therefore
 * produce an identical `oaf_session` cookie, so `/client`, token minting and `<Protect>` behave
 * the same regardless of which path the user took.
 *
 * Reference IdP: a Google Workspace custom SAML app. Google's IdP gives you three values —
 * an SSO URL (`https://accounts.google.com/o/saml2/idp?idpid=…`), an Entity ID
 * (`https://accounts.google.com/o/saml2?idpid=…`) and an X.509 signing certificate — which map
 * onto `idpSsoUrl`, `idpEntityId` and `idpCert` below. On the Google side you register this
 * SP's ACS URL and Entity ID (see `samlSpMetadata`).
 */

/** SAML SP configuration. All XML/crypto specifics are derived from these few values. */
export interface SamlSpConfig {
  /** Turn the SAML path on. When false, the SAML routes 404 (OIDC stays available). */
  enabled: boolean
  /** IdP Entity ID (Google: `https://accounts.google.com/o/saml2?idpid=<IDPID>`). */
  idpEntityId: string
  /** IdP Single-Sign-On URL — the AuthnRequest destination (HTTP-Redirect binding). */
  idpSsoUrl: string
  /**
   * IdP signing certificate(s) used to verify the assertion signature. PEM or bare base64;
   * Google provides this in the downloaded IdP metadata / on the SAML app page. Multiple certs
   * (e.g. during rotation) are accepted.
   */
  idpCert: string | string[]
  /** This SP's Entity ID — must match the Entity ID registered in the Google SAML app. */
  spEntityId: string
  /** Absolute ACS URL the IdP POSTs the SAML Response to (must match the registered ACS URL). */
  acsUrl: string
  /** NameID format requested. Google issues email addresses. */
  identifierFormat?: string
  /** Require the assertion to be signed (default true — never accept an unsigned assertion). */
  wantAssertionsSigned?: boolean
  /** Require the whole SAML Response to be signed too. Google signs the assertion, not always
   *  the response, so this defaults to false. */
  wantAuthnResponseSigned?: boolean
  /** Clock-skew tolerance for the assertion's NotBefore / NotOnOrAfter (default 5000ms). */
  acceptedClockSkewMs?: number
  /** Optional SP private key (PEM) to sign the AuthnRequest. Google does not require it, so
   *  outbound requests are unsigned unless this is set. */
  spPrivateKey?: string
  /** Optional SP signing certificate (PEM) advertised in SP metadata when `spPrivateKey` is set. */
  spCertificate?: string
}

const DEFAULT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

/** Build a configured node-saml `SAML` instance for SP-initiated SSO against the IdP. */
export function buildSamlClient(cfg: SamlSpConfig): SAML {
  return new SAML({
    // --- IdP ---
    entryPoint: cfg.idpSsoUrl,
    idpCert: cfg.idpCert,
    // --- SP ---
    issuer: cfg.spEntityId,
    callbackUrl: cfg.acsUrl,
    audience: cfg.spEntityId,
    identifierFormat: cfg.identifierFormat ?? DEFAULT_NAMEID_FORMAT,
    // --- security posture ---
    // Always demand a signed assertion. Response-level signing is optional for Google.
    wantAssertionsSigned: cfg.wantAssertionsSigned ?? true,
    wantAuthnResponseSigned: cfg.wantAuthnResponseSigned ?? false,
    acceptedClockSkewMs: cfg.acceptedClockSkewMs ?? 5000,
    // CSRF/replay is handled by our own signed RelayState cookie (mirrors the OIDC `state`
    // cookie), so node-saml's InResponseTo cache — which would need cross-process shared
    // storage in the embedded model — is not relied upon.
    validateInResponseTo: ValidateInResponseTo.never,
    // Google does not require a signed AuthnRequest. Sign only if an SP key is supplied.
    ...(cfg.spPrivateKey
      ? { privateKey: cfg.spPrivateKey, signatureAlgorithm: "sha256" as const }
      : {}),
    // Google rejects a RequestedAuthnContext it doesn't recognise; omit it.
    disableRequestedAuthnContext: true,
  })
}

/**
 * Build the SP-initiated login redirect URL (HTTP-Redirect binding). `relayState` is our own
 * random CSRF token; the IdP echoes it back unchanged to the ACS, where we compare it to the
 * value stashed in a signed cookie.
 */
export async function samlLoginRedirectUrl(saml: SAML, relayState: string): Promise<string> {
  return await saml.getAuthorizeUrlAsync(relayState, undefined, {})
}

/** The result of validating a SAML Response at the ACS. */
export interface SamlAcsResult {
  identity: OidcIdentity
  sessionIndex?: string
  /** RelayState the IdP echoed back (compared against our signed cookie by the caller). */
  relayState?: string
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined
}

/**
 * Validate an incoming SAML Response (POST binding) and map the verified SAML profile onto the
 * same {@link OidcIdentity} shape the OIDC path produces, so the caller can run identical domain
 * enforcement, grant resolution and session creation. node-saml verifies the assertion
 * signature against `idpCert`, the audience, and the NotBefore/NotOnOrAfter conditions before
 * this resolves; a failure rejects.
 */
export async function validateSamlAcs(
  saml: SAML,
  body: { SAMLResponse?: string; RelayState?: string },
): Promise<SamlAcsResult> {
  const { profile } = await saml.validatePostResponseAsync({
    SAMLResponse: body.SAMLResponse ?? "",
    RelayState: body.RelayState ?? "",
  })
  if (!profile) throw new Error("SAML response contained no profile")

  // Google's NameID is the user's email. Fall back to common email attributes if a different
  // NameID format was configured on the IdP.
  const attrs = (profile.attributes as Record<string, unknown> | undefined) ?? {}
  const first = (k: string): string | undefined => {
    const v = (attrs as Record<string, unknown>)[k] ?? (profile as Record<string, unknown>)[k]
    if (Array.isArray(v)) return str(v[0])
    return str(v)
  }
  const email =
    str(profile.email) ??
    str(profile.mail) ??
    first("email") ??
    first("urn:oid:0.9.2342.19200300.100.1.3") ??
    (profile.nameID.includes("@") ? profile.nameID : undefined)

  if (!email) throw new Error("SAML assertion did not yield an email address")

  const identity: OidcIdentity = {
    sub: profile.nameID,
    email,
    // The assertion is signed by the IdP; a Workspace-issued email is authoritative, so we treat
    // a valid signed assertion as a verified email. Domain enforcement still applies downstream.
    emailVerified: true,
    name: first("displayName") ?? first("name"),
    givenName: first("firstName") ?? first("givenName") ?? first("urn:oid:2.5.4.42"),
    familyName: first("lastName") ?? first("surname") ?? first("urn:oid:2.5.4.4"),
  }

  return {
    identity,
    sessionIndex: str(profile.sessionIndex),
    relayState: str(body.RelayState),
  }
}

/** SP metadata XML to hand to the IdP operator (register its ACS URL + Entity ID with Google). */
export function samlSpMetadata(cfg: SamlSpConfig): string {
  return nodeSamlMetadata({
    issuer: cfg.spEntityId,
    callbackUrl: cfg.acsUrl,
    identifierFormat: cfg.identifierFormat ?? DEFAULT_NAMEID_FORMAT,
    wantAssertionsSigned: cfg.wantAssertionsSigned ?? true,
    ...(cfg.spCertificate ? { publicCerts: cfg.spCertificate } : {}),
  })
}
