"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InMemorySamlReplayStore = void 0;
exports.buildSamlClient = buildSamlClient;
exports.samlLoginRedirectUrl = samlLoginRedirectUrl;
exports.validateSamlAcs = validateSamlAcs;
exports.samlSpMetadata = samlSpMetadata;
const node_saml_1 = require("@node-saml/node-saml");
const node_saml_2 = require("@node-saml/node-saml");
// SAML 2.0 nameid-format URN (the charter mandates SAML 2.0 exclusively; the 1.1-namespaced URN is
// not used).
const DEFAULT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress";
/** Build a configured node-saml `SAML` instance for SP-initiated SSO against the IdP. */
function buildSamlClient(cfg) {
    return new node_saml_1.SAML({
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
        validateInResponseTo: node_saml_1.ValidateInResponseTo.ifPresent,
        forceAuthn: cfg.forceAuthn ?? false,
        // Google does not require a signed AuthnRequest. Sign only if an SP key is supplied.
        ...(cfg.spPrivateKey
            ? { privateKey: cfg.spPrivateKey, signatureAlgorithm: "sha256" }
            : {}),
        // Google rejects a RequestedAuthnContext it doesn't recognise; omit it.
        disableRequestedAuthnContext: true,
    });
}
/** Default in-memory {@link SamlReplayStore} — adequate for a single-process embedded deployment. */
class InMemorySamlReplayStore {
    seenIds = new Map();
    seen(assertionId) {
        this.prune();
        return this.seenIds.has(assertionId);
    }
    record(assertionId, notOnOrAfter) {
        this.seenIds.set(assertionId, notOnOrAfter);
    }
    prune() {
        const now = Date.now();
        for (const [id, exp] of this.seenIds)
            if (exp <= now)
                this.seenIds.delete(id);
    }
}
exports.InMemorySamlReplayStore = InMemorySamlReplayStore;
/**
 * Build the SP-initiated login redirect URL (HTTP-Redirect binding). `relayState` is our own
 * random CSRF token; the IdP echoes it back unchanged to the ACS, where we compare it to the
 * value stashed in a signed cookie.
 */
async function samlLoginRedirectUrl(saml, relayState) {
    return await saml.getAuthorizeUrlAsync(relayState, undefined, {});
}
function str(v) {
    return typeof v === "string" && v.length > 0 ? v : undefined;
}
/** Coerce a SAML boolean-ish attribute (`true`/`false`/`1`/`0`) to a boolean. */
function asBool(v) {
    if (Array.isArray(v))
        return asBool(v[0]);
    if (typeof v === "boolean")
        return v;
    if (typeof v === "string")
        return v.toLowerCase() === "true" || v === "1";
    return false;
}
/**
 * Validate an incoming SAML Response (POST binding) and map the verified SAML profile onto the
 * same {@link OidcIdentity} shape the OIDC path produces, so the caller can run identical domain
 * enforcement, grant resolution and session creation. node-saml verifies the assertion
 * signature against `idpCert`, the audience, and the NotBefore/NotOnOrAfter conditions before
 * this resolves; a failure rejects.
 */
async function validateSamlAcs(saml, body, cfg, replayStore) {
    const { profile } = await saml.validatePostResponseAsync({
        SAMLResponse: body.SAMLResponse ?? "",
        RelayState: body.RelayState ?? "",
    });
    if (!profile)
        throw new Error("SAML response contained no profile");
    const profileRec = profile;
    // Audience restriction: the assertion's AudienceRestriction/Audience MUST name this SP's Entity
    // ID, otherwise an assertion minted for a *different* SP could be replayed here. node-saml
    // surfaces the audience on the profile; compare it exactly to the configured spEntityId.
    const audience = str(profileRec.audience) ?? str(profileRec.audienceRestriction);
    if (audience !== undefined && audience !== cfg.spEntityId) {
        throw new Error("SAML assertion audience does not match the SP Entity ID");
    }
    // Assertion-id replay defense: reject an assertion id we have already consumed within its
    // validity window (one-time use).
    const assertionId = str(profileRec.assertionId) ?? str(profileRec.ID) ?? str(profileRec.inResponseTo);
    if (replayStore && assertionId) {
        if (await replayStore.seen(assertionId)) {
            throw new Error("SAML assertion replay detected");
        }
        const notOnOrAfter = Date.parse(String(profileRec.notOnOrAfter ?? "")) || Date.now() + 5 * 60_000;
        await replayStore.record(assertionId, notOnOrAfter);
    }
    // Google's NameID is the user's email. Fall back to common email attributes if a different
    // NameID format was configured on the IdP.
    const attrs = profile.attributes ?? {};
    const first = (k) => {
        const v = attrs[k] ?? profile[k];
        if (Array.isArray(v))
            return str(v[0]);
        return str(v);
    };
    const email = str(profile.email) ??
        str(profile.mail) ??
        first("email") ??
        first("urn:oid:0.9.2342.19200300.100.1.3") ??
        (profile.nameID.includes("@") ? profile.nameID : undefined);
    if (!email)
        throw new Error("SAML assertion did not yield an email address");
    // Email-verified derivation: prefer an explicit asserted attribute; otherwise treat as verified
    // ONLY when the deployment opts into trusting the signed assertion (default false → fail closed).
    const verifiedAttr = attrs["email_verified"] ??
        attrs["emailVerified"];
    const emailVerified = verifiedAttr !== undefined ? asBool(verifiedAttr) : cfg.trustAssertedEmailVerified === true;
    const identity = {
        sub: profile.nameID,
        email,
        emailVerified,
        name: first("displayName") ?? first("name"),
        givenName: first("firstName") ?? first("givenName") ?? first("urn:oid:2.5.4.42"),
        familyName: first("lastName") ?? first("surname") ?? first("urn:oid:2.5.4.4"),
    };
    return {
        identity,
        sessionIndex: str(profile.sessionIndex),
        relayState: str(body.RelayState),
        inResponseTo: str(profileRec.inResponseTo),
    };
}
/** SP metadata XML to hand to the IdP operator (register its ACS URL + Entity ID with Google). */
function samlSpMetadata(cfg) {
    return (0, node_saml_2.generateServiceProviderMetadata)({
        issuer: cfg.spEntityId,
        callbackUrl: cfg.acsUrl,
        identifierFormat: cfg.identifierFormat ?? DEFAULT_NAMEID_FORMAT,
        wantAssertionsSigned: cfg.wantAssertionsSigned ?? true,
        ...(cfg.spCertificate ? { publicCerts: cfg.spCertificate } : {}),
    });
}
//# sourceMappingURL=saml.js.map