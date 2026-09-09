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
/**
 * Longest a consumed assertion id is retained for replay detection, regardless of what the
 * assertion's own `NotOnOrAfter` claims. The expiry is IdP-supplied; without a cap one assertion
 * can pin a cache entry indefinitely.
 */
const REPLAY_RETENTION_MAX_MS = 10 * 60_000;
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
const HOSTED_DOMAIN_ATTRIBUTES = ["hd"];
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
/**
 * Default in-memory {@link SamlReplayStore} — adequate for a SINGLE-process embedded deployment
 * only. A consumed assertion id recorded here is invisible to sibling processes/instances, so a
 * horizontally-scaled deployment (more than one process behind a load balancer) can still replay a
 * SAML assertion across the other instances within its validity window. Multi-instance deployments
 * MUST supply a shared, cross-process {@link SamlReplayStore} (Redis/DB-backed) via
 * `createFederatedFrontend({ samlReplayStore })`, and likewise a shared {@link SessionStore}.
 */
class InMemorySamlReplayStore {
    seenIds = new Map();
    /** Hard ceiling on retained ids. Beyond this the oldest are evicted (Map is insertion-ordered). */
    static MAX_ENTRIES = 20_000;
    /** Sweep expired entries at most this often, instead of on every lookup. */
    static SWEEP_INTERVAL_MS = 30_000;
    lastSweep = 0;
    /** How many consumed ids are currently retained. Diagnostics (and a bound the tests assert). */
    get size() {
        return this.seenIds.size;
    }
    seen(assertionId) {
        // Amortized: sweeping on EVERY lookup made this an O(n) scan per SAML login. A lookup is O(1)
        // and correctness does not depend on the sweep — an entry that outlives its window is only ever
        // stricter than required, never weaker.
        this.maybeSweep();
        return this.seenIds.has(assertionId);
    }
    record(assertionId, notOnOrAfter) {
        this.seenIds.set(assertionId, notOnOrAfter);
        this.maybeSweep();
        // The expiry comes from the IdP, so a far-future value would otherwise pin an entry for as long
        // as the IdP says. Evict oldest-first once the ceiling is reached: bounded memory, and an
        // evicted id is one whose window has already been outlived by MAX_ENTRIES newer sign-ins.
        while (this.seenIds.size > InMemorySamlReplayStore.MAX_ENTRIES) {
            const oldest = this.seenIds.keys().next().value;
            if (oldest === undefined)
                break;
            this.seenIds.delete(oldest);
        }
    }
    maybeSweep() {
        const now = Date.now();
        if (now - this.lastSweep < InMemorySamlReplayStore.SWEEP_INTERVAL_MS)
            return;
        this.lastSweep = now;
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
/** The domain half of an email address, lowercased. Empty when there is no `@`. */
function emailDomainOf(email) {
    const at = email.lastIndexOf("@");
    return at < 0 ? "" : email.slice(at + 1).trim().toLowerCase();
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
function assertionFacts(profile) {
    const getter = profile?.getAssertion;
    if (typeof getter !== "function")
        return { audiences: [] };
    let parsed;
    try {
        parsed = getter.call(profile);
    }
    catch {
        return { audiences: [] };
    }
    const node = parsed?.Assertion;
    if (!node)
        return { audiences: [] };
    const conditions = node.Conditions?.[0];
    const rawNotOnOrAfter = conditions?.$?.NotOnOrAfter;
    const parsedExpiry = rawNotOnOrAfter ? Date.parse(rawNotOnOrAfter) : Number.NaN;
    const audiences = [];
    for (const restriction of conditions?.AudienceRestriction ?? []) {
        for (const entry of restriction?.Audience ?? []) {
            const value = typeof entry === "string" ? entry : entry?._;
            if (typeof value === "string" && value.length > 0)
                audiences.push(value);
        }
    }
    return {
        id: str(node.$?.ID),
        notOnOrAfter: Number.isFinite(parsedExpiry) ? parsedExpiry : undefined,
        audiences,
    };
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
    // Everything the one signature-validated assertion actually says about itself.
    const facts = assertionFacts(profile);
    // Audience restriction: the assertion's AudienceRestriction/Audience MUST name this SP's Entity
    // ID, otherwise an assertion minted for a *different* SP could be replayed here. node-saml
    // enforces this itself (it is configured with `audience: spEntityId`); this is the independent
    // second reading, taken straight off the validated assertion node.
    //
    // It used to read `profileRec.audience`, which node-saml never sets — so the check was skipped on
    // every real assertion.
    if (facts.audiences.length > 0 && !facts.audiences.includes(cfg.spEntityId)) {
        throw new Error("SAML assertion audience does not match the SP Entity ID");
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
    const assertionId = facts.id ?? str(profileRec.assertionId) ?? str(profileRec.ID);
    if (replayStore) {
        if (!assertionId) {
            throw new Error("SAML assertion carried no assertion id, so one-time use cannot be enforced — refusing");
        }
        if (await replayStore.seen(assertionId)) {
            throw new Error("SAML assertion replay detected");
        }
        // The expiry is IdP-supplied, so cap it: an assertion claiming a year-long window must not pin
        // a replay-cache entry for a year. The cap only ever shortens retention, and the assertion is
        // long dead by then anyway — node-saml has already enforced NotOnOrAfter above.
        const ceiling = Date.now() + REPLAY_RETENTION_MAX_MS;
        const notOnOrAfter = facts.notOnOrAfter !== undefined ? Math.min(facts.notOnOrAfter, ceiling) : ceiling;
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
        : HOSTED_DOMAIN_ATTRIBUTES;
    let hd;
    for (const attr of hostedDomainAttributes) {
        const v = first(attr);
        if (v) {
            hd = v.trim().toLowerCase();
            break;
        }
    }
    if (hd && hd !== emailDomainOf(email))
        hd = undefined;
    const identity = {
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