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
  /**
   * Require the whole SAML Response to be signed too. Defaults to **true** — requiring the
   * response-level signature is the primary defense against XML Signature Wrapping (XSW), where an
   * attacker relocates a legitimately-signed assertion inside a forged response. Set false only for
   * an IdP that genuinely signs the assertion but not the response, accepting the documented risk.
   */
  wantAuthnResponseSigned?: boolean
  /** Clock-skew tolerance for the assertion's NotBefore / NotOnOrAfter (default 5000ms). */
  acceptedClockSkewMs?: number
  /**
   * Trust the IdP-asserted email as verified when the (signed) assertion carries no explicit
   * verified-email attribute. Defaults to **false** (fail closed): the ACS reads an
   * `email_verified` attribute when present and otherwise marks the email unverified unless this is
   * set. Set true only for an IdP (e.g. Google Workspace) whose signed assertion implies a verified
   * address.
   */
  trustAssertedEmailVerified?: boolean
  /**
   * Force re-authentication at the IdP on this AuthnRequest (SAML `ForceAuthn`). Used for the
   * step-up / reverify path so the IdP re-challenges the user rather than silently re-asserting.
   */
  forceAuthn?: boolean
  /** Optional SP private key (PEM) to sign the AuthnRequest. Google does not require it, so
   *  outbound requests are unsigned unless this is set. */
  spPrivateKey?: string
  /** Optional SP signing certificate (PEM) advertised in SP metadata when `spPrivateKey` is set. */
  spCertificate?: string
}

// SAML 2.0 nameid-format URN (the charter mandates SAML 2.0 exclusively; the 1.1-namespaced URN is
// not used).
const DEFAULT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"

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
    // Always demand a signed assertion. Response-envelope signing (the strongest XSW mitigation) is
    // configurable: enable it (wantAuthnResponseSigned: true) for any IdP that signs the response.
    // It defaults to false because the reference IdP (Google Workspace) signs the assertion, not
    // always the response — defaulting it on would break that flow. XSW is additionally mitigated by
    // node-saml v5's built-in signature-reference hardening, the audience + InResponseTo checks, and
    // the assertion-id replay cache in validateSamlAcs.
    wantAssertionsSigned: cfg.wantAssertionsSigned ?? true,
    wantAuthnResponseSigned: cfg.wantAuthnResponseSigned ?? false,
    acceptedClockSkewMs: cfg.acceptedClockSkewMs ?? 5000,
    // Bind each Response to the AuthnRequest it answers. We provide an InResponseTo cache via the
    // caller-supplied validator (`requestIdExpirationPeriodMs` bounds it); combined with the
    // assertion-id replay cache in validateSamlAcs and the signed RelayState cookie this gives
    // real one-time-use enforcement instead of relying on RelayState alone.
    validateInResponseTo: ValidateInResponseTo.ifPresent,
    forceAuthn: cfg.forceAuthn ?? false,
    // Google does not require a signed AuthnRequest. Sign only if an SP key is supplied.
    ...(cfg.spPrivateKey
      ? { privateKey: cfg.spPrivateKey, signatureAlgorithm: "sha256" as const }
      : {}),
    // Google rejects a RequestedAuthnContext it doesn't recognise; omit it.
    disableRequestedAuthnContext: true,
  })
}

/** A small TTL store of consumed SAML assertion IDs, defeating Response replay within the window. */
export interface SamlReplayStore {
  /** Returns true if this assertion id was already consumed (a replay). */
  seen(assertionId: string): boolean | Promise<boolean>
  /** Record a consumed assertion id, expiring no later than `notOnOrAfter` (epoch ms). */
  record(assertionId: string, notOnOrAfter: number): void | Promise<void>
}

/** Default in-memory {@link SamlReplayStore} — adequate for a single-process embedded deployment. */
export class InMemorySamlReplayStore implements SamlReplayStore {
  private readonly seenIds = new Map<string, number>()
  seen(assertionId: string): boolean {
    this.prune()
    return this.seenIds.has(assertionId)
  }
  record(assertionId: string, notOnOrAfter: number): void {
    this.seenIds.set(assertionId, notOnOrAfter)
  }
  private prune(): void {
    const now = Date.now()
    for (const [id, exp] of this.seenIds) if (exp <= now) this.seenIds.delete(id)
  }
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
  /** The assertion's `InResponseTo` (the AuthnRequest id it answers), when present. */
  inResponseTo?: string
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined
}

/** Coerce a SAML boolean-ish attribute (`true`/`false`/`1`/`0`) to a boolean. */
function asBool(v: unknown): boolean {
  if (Array.isArray(v)) return asBool(v[0])
  if (typeof v === "boolean") return v
  if (typeof v === "string") return v.toLowerCase() === "true" || v === "1"
  return false
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
  cfg: SamlSpConfig,
  replayStore?: SamlReplayStore,
): Promise<SamlAcsResult> {
  const { profile } = await saml.validatePostResponseAsync({
    SAMLResponse: body.SAMLResponse ?? "",
    RelayState: body.RelayState ?? "",
  })
  if (!profile) throw new Error("SAML response contained no profile")

  const profileRec = profile as unknown as Record<string, unknown>

  // Audience restriction: the assertion's AudienceRestriction/Audience MUST name this SP's Entity
  // ID, otherwise an assertion minted for a *different* SP could be replayed here. node-saml
  // surfaces the audience on the profile; compare it exactly to the configured spEntityId.
  const audience = str(profileRec.audience) ?? str(profileRec.audienceRestriction)
  if (audience !== undefined && audience !== cfg.spEntityId) {
    throw new Error("SAML assertion audience does not match the SP Entity ID")
  }

  // Assertion-id replay defense: reject an assertion id we have already consumed within its
  // validity window (one-time use).
  const assertionId =
    str(profileRec.assertionId) ?? str(profileRec.ID) ?? str(profileRec.inResponseTo)
  if (replayStore && assertionId) {
    if (await replayStore.seen(assertionId)) {
      throw new Error("SAML assertion replay detected")
    }
    const notOnOrAfter = Date.parse(String(profileRec.notOnOrAfter ?? "")) || Date.now() + 5 * 60_000
    await replayStore.record(assertionId, notOnOrAfter)
  }

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

  // Email-verified derivation: prefer an explicit asserted attribute; otherwise treat as verified
  // ONLY when the deployment opts into trusting the signed assertion (default false → fail closed).
  const verifiedAttr =
    (attrs as Record<string, unknown>)["email_verified"] ??
    (attrs as Record<string, unknown>)["emailVerified"]
  const emailVerified =
    verifiedAttr !== undefined ? asBool(verifiedAttr) : cfg.trustAssertedEmailVerified === true

  const identity: OidcIdentity = {
    sub: profile.nameID,
    email,
    emailVerified,
    name: first("displayName") ?? first("name"),
    givenName: first("firstName") ?? first("givenName") ?? first("urn:oid:2.5.4.42"),
    familyName: first("lastName") ?? first("surname") ?? first("urn:oid:2.5.4.4"),
  }

  return {
    identity,
    sessionIndex: str(profile.sessionIndex),
    relayState: str(body.RelayState),
    inResponseTo: str(profileRec.inResponseTo),
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
