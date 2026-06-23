import { SAML } from "@node-saml/node-saml";
import type { OidcIdentity } from "./frontend.js";
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
    enabled: boolean;
    /** IdP Entity ID (Google: `https://accounts.google.com/o/saml2?idpid=<IDPID>`). */
    idpEntityId: string;
    /** IdP Single-Sign-On URL — the AuthnRequest destination (HTTP-Redirect binding). */
    idpSsoUrl: string;
    /**
     * IdP signing certificate(s) used to verify the assertion signature. PEM or bare base64;
     * Google provides this in the downloaded IdP metadata / on the SAML app page. Multiple certs
     * (e.g. during rotation) are accepted.
     */
    idpCert: string | string[];
    /** This SP's Entity ID — must match the Entity ID registered in the Google SAML app. */
    spEntityId: string;
    /** Absolute ACS URL the IdP POSTs the SAML Response to (must match the registered ACS URL). */
    acsUrl: string;
    /** NameID format requested. Google issues email addresses. */
    identifierFormat?: string;
    /** Require the assertion to be signed (default true — never accept an unsigned assertion). */
    wantAssertionsSigned?: boolean;
    /**
     * Require the whole SAML Response to be signed too. Defaults to **true** — requiring the
     * response-level signature is the primary defense against XML Signature Wrapping (XSW), where an
     * attacker relocates a legitimately-signed assertion inside a forged response. Set false only for
     * an IdP that genuinely signs the assertion but not the response, accepting the documented risk.
     */
    wantAuthnResponseSigned?: boolean;
    /** Clock-skew tolerance for the assertion's NotBefore / NotOnOrAfter (default 5000ms). */
    acceptedClockSkewMs?: number;
    /**
     * Trust the IdP-asserted email as verified when the (signed) assertion carries no explicit
     * verified-email attribute. Defaults to **false** (fail closed): the ACS reads an
     * `email_verified` attribute when present and otherwise marks the email unverified unless this is
     * set. Set true only for an IdP (e.g. Google Workspace) whose signed assertion implies a verified
     * address.
     */
    trustAssertedEmailVerified?: boolean;
    /**
     * Force re-authentication at the IdP on this AuthnRequest (SAML `ForceAuthn`). Used for the
     * step-up / reverify path so the IdP re-challenges the user rather than silently re-asserting.
     */
    forceAuthn?: boolean;
    /** Optional SP private key (PEM) to sign the AuthnRequest. Google does not require it, so
     *  outbound requests are unsigned unless this is set. */
    spPrivateKey?: string;
    /** Optional SP signing certificate (PEM) advertised in SP metadata when `spPrivateKey` is set. */
    spCertificate?: string;
}
/** Build a configured node-saml `SAML` instance for SP-initiated SSO against the IdP. */
export declare function buildSamlClient(cfg: SamlSpConfig): SAML;
/** A small TTL store of consumed SAML assertion IDs, defeating Response replay within the window. */
export interface SamlReplayStore {
    /** Returns true if this assertion id was already consumed (a replay). */
    seen(assertionId: string): boolean | Promise<boolean>;
    /** Record a consumed assertion id, expiring no later than `notOnOrAfter` (epoch ms). */
    record(assertionId: string, notOnOrAfter: number): void | Promise<void>;
}
/** Default in-memory {@link SamlReplayStore} — adequate for a single-process embedded deployment. */
export declare class InMemorySamlReplayStore implements SamlReplayStore {
    private readonly seenIds;
    seen(assertionId: string): boolean;
    record(assertionId: string, notOnOrAfter: number): void;
    private prune;
}
/**
 * Build the SP-initiated login redirect URL (HTTP-Redirect binding). `relayState` is our own
 * random CSRF token; the IdP echoes it back unchanged to the ACS, where we compare it to the
 * value stashed in a signed cookie.
 */
export declare function samlLoginRedirectUrl(saml: SAML, relayState: string): Promise<string>;
/** The result of validating a SAML Response at the ACS. */
export interface SamlAcsResult {
    identity: OidcIdentity;
    sessionIndex?: string;
    /** RelayState the IdP echoed back (compared against our signed cookie by the caller). */
    relayState?: string;
    /** The assertion's `InResponseTo` (the AuthnRequest id it answers), when present. */
    inResponseTo?: string;
}
/**
 * Validate an incoming SAML Response (POST binding) and map the verified SAML profile onto the
 * same {@link OidcIdentity} shape the OIDC path produces, so the caller can run identical domain
 * enforcement, grant resolution and session creation. node-saml verifies the assertion
 * signature against `idpCert`, the audience, and the NotBefore/NotOnOrAfter conditions before
 * this resolves; a failure rejects.
 */
export declare function validateSamlAcs(saml: SAML, body: {
    SAMLResponse?: string;
    RelayState?: string;
}, cfg: SamlSpConfig, replayStore?: SamlReplayStore): Promise<SamlAcsResult>;
/** SP metadata XML to hand to the IdP operator (register its ACS URL + Entity ID with Google). */
export declare function samlSpMetadata(cfg: SamlSpConfig): string;
