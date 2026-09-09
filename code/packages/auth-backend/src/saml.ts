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
   * Require the whole SAML Response envelope to be signed too — not just the assertion. The
   * response-level signature is the single strongest defense against XML Signature Wrapping (XSW),
   * where an attacker relocates a legitimately-signed assertion inside a forged response.
   *
   * Defaults to **false**, because the reference IdP (Google Workspace) signs the *assertion* but
   * not always the *response*, and defaulting this on would break that flow. The residual XSW risk
   * is mitigated by node-saml v5's signature-reference hardening, the audience + InResponseTo
   * checks, and the assertion-id replay cache in {@link validateSamlAcs}.
   *
   * STRONGLY RECOMMENDED: any IdP that signs the response (most enterprise IdPs, and Google when
   * configured to sign the response) should set this to **true** for the strongest posture. Leave it
   * false only for an IdP that genuinely signs the assertion but not the response, accepting the
   * documented residual risk.
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
  /**
   * Name of the assertion attribute carrying this IdP's hosted/organization domain, when it is not
   * the default `hd`.
   *
   * Only `hd` is read implicitly, because this value is what satisfies `requireHostedDomain` and a
   * generically-named attribute (`domain`, say) may already be in use for something unrelated —
   * satisfying the deployment's strongest admission control by coincidence. Name yours here
   * instead.
   *
   * Whatever the source, the value must MATCH the email domain in the assertion or it is ignored:
   * a hosted-domain claim corroborates the address, it never substitutes for it.
   */
  hostedDomainAttribute?: string
}

// SAML 2.0 nameid-format URN (the charter mandates SAML 2.0 exclusively; the 1.1-namespaced URN is
// not used).
const DEFAULT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"

/**
 * Longest a consumed assertion id is retained for replay detection, regardless of what the
 * assertion's own `NotOnOrAfter` claims. The expiry is IdP-supplied; without a cap one assertion
 * can pin a cache entry indefinitely.
 */
const REPLAY_RETENTION_MAX_MS = 10 * 60_000

/**
 * Attribute names read, in order, as an IdP's hosted-domain assertion.
 *
 * DELIBERATELY NARROW. An earlier version of this list also accepted `hostedDomain`,
 * `hosted_domain` and `domain` — and `domain` in particular is a name generic enough that an IdP
 * may well already emit it for something else entirely (a directory column, a tenant label). Since
 * this value is what satisfies `requireHostedDomain`, a coincidental match would silently satisfy
 * the deployment's strongest admission control with an attribute nobody chose for that purpose.
 * `hd` is Google's own unambiguous name; anything else must be named explicitly by the operator via
 * {@link SamlSpConfig.hostedDomainAttribute}.
 */
const HOSTED_DOMAIN_ATTRIBUTES = ["hd"]

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

/**
 * Default in-memory {@link SamlReplayStore} — adequate for a SINGLE-process embedded deployment
 * only. A consumed assertion id recorded here is invisible to sibling processes/instances, so a
 * horizontally-scaled deployment (more than one process behind a load balancer) can still replay a
 * SAML assertion across the other instances within its validity window. Multi-instance deployments
 * MUST supply a shared, cross-process {@link SamlReplayStore} (Redis/DB-backed) via
 * `createFederatedFrontend({ samlReplayStore })`, and likewise a shared {@link SessionStore}.
 */
export class InMemorySamlReplayStore implements SamlReplayStore {
  private readonly seenIds = new Map<string, number>()
  /** Hard ceiling on retained ids. Beyond this the oldest are evicted (Map is insertion-ordered). */
  private static readonly MAX_ENTRIES = 20_000
  /** Sweep expired entries at most this often, instead of on every lookup. */
  private static readonly SWEEP_INTERVAL_MS = 30_000
  private lastSweep = 0

  /** How many consumed ids are currently retained. Diagnostics (and a bound the tests assert). */
  get size(): number {
    return this.seenIds.size
  }

  seen(assertionId: string): boolean {
    // Amortized: sweeping on EVERY lookup made this an O(n) scan per SAML login. A lookup is O(1)
    // and correctness does not depend on the sweep — an entry that outlives its window is only ever
    // stricter than required, never weaker.
    this.maybeSweep()
    return this.seenIds.has(assertionId)
  }

  record(assertionId: string, notOnOrAfter: number): void {
    this.seenIds.set(assertionId, notOnOrAfter)
    this.maybeSweep()
    // The expiry comes from the IdP, so a far-future value would otherwise pin an entry for as long
    // as the IdP says. Evict oldest-first once the ceiling is reached: bounded memory, and an
    // evicted id is one whose window has already been outlived by MAX_ENTRIES newer sign-ins.
    while (this.seenIds.size > InMemorySamlReplayStore.MAX_ENTRIES) {
      const oldest = this.seenIds.keys().next().value
      if (oldest === undefined) break
      this.seenIds.delete(oldest)
    }
  }

  private maybeSweep(): void {
    const now = Date.now()
    if (now - this.lastSweep < InMemorySamlReplayStore.SWEEP_INTERVAL_MS) return
    this.lastSweep = now
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

/** The domain half of an email address, lowercased. Empty when there is no `@`. */
function emailDomainOf(email: string): string {
  const at = email.lastIndexOf("@")
  return at < 0 ? "" : email.slice(at + 1).trim().toLowerCase()
}

/** The parsed shape node-saml hands back from `profile.getAssertion()` (xml2js output). */
interface ParsedAssertion {
  Assertion?: {
    $?: Record<string, string>
    Conditions?: Array<{
      $?: Record<string, string>
      AudienceRestriction?: Array<{ Audience?: Array<{ _?: string } | string> }>
    }>
  }
}

/**
 * Facts read from the assertion node that node-saml ITSELF selected and signature-validated.
 *
 * These do not appear on the flat `profile` at all — no `assertionId`, no `ID`, no `notOnOrAfter`,
 * no `audience` — which is why the checks that read them from there were dead code: for every real
 * assertion they were `undefined`, so the guards were skipped silently and one-time-use was never
 * actually enforced.
 *
 * Reading them from `getAssertion()` rather than re-parsing the raw SAMLResponse is deliberate: the
 * raw response may contain several Assertion elements, and picking one ourselves is precisely the
 * ambiguity XML Signature Wrapping exploits. This returns facts about the ONE assertion whose
 * signature was verified.
 */
function assertionFacts(profile: unknown): {
  id?: string
  notOnOrAfter?: number
  audiences: string[]
} {
  const getter = (profile as { getAssertion?: () => ParsedAssertion })?.getAssertion
  if (typeof getter !== "function") return { audiences: [] }
  let parsed: ParsedAssertion
  try {
    parsed = getter.call(profile)
  } catch {
    return { audiences: [] }
  }
  const node = parsed?.Assertion
  if (!node) return { audiences: [] }

  const conditions = node.Conditions?.[0]
  const rawNotOnOrAfter = conditions?.$?.NotOnOrAfter
  const parsedExpiry = rawNotOnOrAfter ? Date.parse(rawNotOnOrAfter) : Number.NaN

  const audiences: string[] = []
  for (const restriction of conditions?.AudienceRestriction ?? []) {
    for (const entry of restriction?.Audience ?? []) {
      const value = typeof entry === "string" ? entry : entry?._
      if (typeof value === "string" && value.length > 0) audiences.push(value)
    }
  }

  return {
    id: str(node.$?.ID),
    notOnOrAfter: Number.isFinite(parsedExpiry) ? parsedExpiry : undefined,
    audiences,
  }
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

  // Everything the one signature-validated assertion actually says about itself.
  const facts = assertionFacts(profile)

  // Audience restriction: the assertion's AudienceRestriction/Audience MUST name this SP's Entity
  // ID, otherwise an assertion minted for a *different* SP could be replayed here. node-saml
  // enforces this itself (it is configured with `audience: spEntityId`); this is the independent
  // second reading, taken straight off the validated assertion node.
  //
  // It used to read `profileRec.audience`, which node-saml never sets — so the check was skipped on
  // every real assertion.
  if (facts.audiences.length > 0 && !facts.audiences.includes(cfg.spEntityId)) {
    throw new Error("SAML assertion audience does not match the SP Entity ID")
  }

  // Assertion-id replay defense: reject an assertion id we have already consumed within its
  // validity window (one-time use).
  //
  // FAILS CLOSED. This used to read `if (replayStore && assertionId)`, so a profile that surfaced
  // no id simply skipped one-time-use enforcement, silently — and whether node-saml surfaces the id
  // is a shape detail of a third-party library that a minor upgrade can change. Every SAML 2.0
  // Assertion carries a required `ID` attribute, so an absent one means we are not reading what we
  // think we are reading; that is a reason to refuse, not to continue unprotected.
  //
  // `inResponseTo` is deliberately NOT a fallback: it is the AuthnRequest id, so keying the cache on
  // it collides distinct assertions answering one request while letting genuine replays of
  // different requests through — worse than no key at all.
  const assertionId = facts.id ?? str(profileRec.assertionId) ?? str(profileRec.ID)
  if (replayStore) {
    if (!assertionId) {
      throw new Error(
        "SAML assertion carried no assertion id, so one-time use cannot be enforced — refusing",
      )
    }
    if (await replayStore.seen(assertionId)) {
      throw new Error("SAML assertion replay detected")
    }
    // The expiry is IdP-supplied, so cap it: an assertion claiming a year-long window must not pin
    // a replay-cache entry for a year. The cap only ever shortens retention, and the assertion is
    // long dead by then anyway — node-saml has already enforced NotOnOrAfter above.
    const ceiling = Date.now() + REPLAY_RETENTION_MAX_MS
    const notOnOrAfter =
      facts.notOnOrAfter !== undefined ? Math.min(facts.notOnOrAfter, ceiling) : ceiling
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

  // The hosted domain, ONLY when the (signed) assertion actually asserts one. It is never derived
  // from the email address: `hd` means "the IdP vouches for this subject's membership of that
  // organization", and an address that merely ends in the right domain is not that fact.
  //
  // It must also CORROBORATE the address rather than replace it. A Google `hd` is computed by
  // Google from real Workspace membership; a SAML one is an attribute whose value the IdP chose, so
  // an assertion for `mallory@contractors.example` carrying `hd: company.com` says two things that
  // do not agree. Keeping the value in that case would let a tenant-wide attribute admit every
  // subject in a multi-domain directory. When the two disagree, the attribute is dropped: the
  // identity then simply has no hosted domain, and `requireHostedDomain` refuses it with the
  // ordinary message.
  const hostedDomainAttributes = cfg.hostedDomainAttribute
    ? [cfg.hostedDomainAttribute, ...HOSTED_DOMAIN_ATTRIBUTES]
    : HOSTED_DOMAIN_ATTRIBUTES
  let hd: string | undefined
  for (const attr of hostedDomainAttributes) {
    const v = first(attr)
    if (v) {
      hd = v.trim().toLowerCase()
      break
    }
  }
  if (hd && hd !== emailDomainOf(email)) hd = undefined

  const identity: OidcIdentity = {
    sub: profile.nameID,
    email,
    emailVerified,
    hd,
    name: first("displayName") ?? first("name"),
    givenName: first("firstName") ?? first("givenName") ?? first("urn:oid:2.5.4.42"),
    familyName: first("lastName") ?? first("surname") ?? first("urn:oid:2.5.4.4"),
    // WHICH STRATEGY VERIFIED THIS HUMAN. Without it `finishSignIn` reads a SAML identity as a
    // Google one (`identity.provider ?? "google"`), which both mislabels every SAML line in the
    // audit trail and puts SAML under a Google-only admission rule it can never satisfy.
    provider: "saml",
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
