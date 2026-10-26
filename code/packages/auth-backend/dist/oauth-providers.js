"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuthExchangeError = exports.X_SCOPES = exports.X_ME_URL = exports.X_TOKEN_URL = exports.X_AUTH_URL = exports.GOOGLE_ISSUERS = exports.GOOGLE_JWKS_URL = exports.GOOGLE_TOKEN_URL = exports.GOOGLE_AUTH_URL = void 0;
exports.randomUrlToken = randomUrlToken;
exports.pkceChallenge = pkceChallenge;
exports.createPkcePair = createPkcePair;
exports.googleAuthorizeUrl = googleAuthorizeUrl;
exports.exchangeGoogleCode = exchangeGoogleCode;
exports.xAuthorizeUrl = xAuthorizeUrl;
exports.exchangeXCode = exchangeXCode;
const node_crypto_1 = require("node:crypto");
const jose_1 = require("jose");
/**
 * The provider half of social sign-in, as plain functions: build the authorize URL, exchange the
 * authorization code (PKCE), and return the verified identity. No cookies, no sessions, no domain
 * allowlist, no redirects — those are policy, and they belong to whoever calls these.
 *
 * `createFederatedFrontend()` is built on exactly these functions, so the embedded middleware and an
 * app that keeps its own session model (a consumer site with its own accounts service, say) run one
 * implementation of the Google and X protocols, not two copies that drift.
 *
 *   const pkce = createPkcePair()
 *   const state = randomUrlToken()
 *   const nonce = randomUrlToken()
 *   redirect(googleAuthorizeUrl({ clientId, redirectUri, state, nonce, codeChallenge: pkce.codeChallenge }))
 *   // ... callback, after the caller has checked `state` ...
 *   const identity = await exchangeGoogleCode({ clientId, clientSecret, redirectUri, code,
 *                                               codeVerifier: pkce.codeVerifier, nonce })
 *
 * Every failure is an {@link OAuthExchangeError} whose `kind` says what went wrong, so the caller
 * can choose its own words for the human and its own reaction (turn the provider off on
 * `client_refused`, say "busy" on `provider_busy`). Messages never carry a code, a token or a body.
 */
exports.GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
exports.GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
exports.GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
exports.GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
// --- X (Twitter) OAuth 2.0 -----------------------------------------------------------------------
//
// X IS NOT AN OIDC PROVIDER. There is no id_token, no JWKS and no signature to verify, so the
// identity cannot be read out of the token response the way Google's is. It is read from the API
// under the freshly minted access token instead (`exchangeXCode` → GET /2/users/me), which is why
// the X path has one more network hop than the Google path and why that hop is not optional.
exports.X_AUTH_URL = "https://x.com/i/oauth2/authorize";
exports.X_TOKEN_URL = "https://api.x.com/2/oauth2/token";
exports.X_ME_URL = "https://api.x.com/2/users/me";
// `users.email` is what makes `confirmed_email` come back from /2/users/me. X refuses the scope
// unless the application has "Request email from users" enabled in the developer portal, and an
// account with no confirmed email address still answers without the field — so a missing email is a
// NORMAL outcome here, not an error, and the caller is what decides whether it is admissible.
exports.X_SCOPES = "tweet.read users.read users.email";
const DEFAULT_UPSTREAM_TIMEOUT_MS = 20_000;
class OAuthExchangeError extends Error {
    kind;
    provider;
    /**
     * Which step failed: `token` (the code exchange) or `identity` (verifying the id_token, or reading
     * X's /2/users/me). A caller can word "could not complete" and "could not verify" differently.
     */
    stage;
    /** The provider's HTTP status, when it answered one. */
    status;
    constructor(provider, kind, message, opts = {}) {
        super(message);
        this.name = "OAuthExchangeError";
        this.provider = provider;
        this.kind = kind;
        this.stage = opts.stage ?? (kind === "identity_invalid" ? "identity" : "token");
        this.status = opts.status;
    }
}
exports.OAuthExchangeError = OAuthExchangeError;
// --- small helpers -------------------------------------------------------------------------------
function base64url(buf) {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/** `bytes` random bytes as base64url. 24 bytes (32 characters) for `state` and `nonce` by default. */
function randomUrlToken(bytes = 24) {
    return base64url((0, node_crypto_1.randomBytes)(bytes));
}
/** The S256 challenge for a PKCE verifier. */
function pkceChallenge(codeVerifier) {
    return base64url((0, node_crypto_1.createHash)("sha256").update(codeVerifier).digest());
}
/** A fresh PKCE verifier (32 random bytes) and its S256 challenge. Keep the verifier secret. */
function createPkcePair() {
    const codeVerifier = randomUrlToken(32);
    return { codeVerifier, codeChallenge: pkceChallenge(codeVerifier) };
}
// Cached per JWKS URL: `createRemoteJWKSet` keeps its own key cache, and re-creating it per sign-in
// would refetch Google's keys every time.
const jwksByUrl = new Map();
function keySet(url) {
    let set = jwksByUrl.get(url);
    if (!set) {
        set = (0, jose_1.createRemoteJWKSet)(new URL(url), {
            // A hung key server must not hold a sign-in open either.
            timeoutDuration: 5_000,
            cooldownDuration: 30_000,
        });
        jwksByUrl.set(url, set);
    }
    return set;
}
/** Google's authorize URL: code flow, `openid email profile`, PKCE S256, online access. */
function googleAuthorizeUrl(opts) {
    const url = new URL(exports.GOOGLE_AUTH_URL);
    url.searchParams.set("client_id", opts.clientId);
    url.searchParams.set("redirect_uri", opts.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("state", opts.state);
    if (opts.nonce)
        url.searchParams.set("nonce", opts.nonce);
    url.searchParams.set("code_challenge", opts.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("prompt", opts.prompt ?? "select_account");
    if (opts.maxAge != null)
        url.searchParams.set("max_age", String(opts.maxAge));
    url.searchParams.set("access_type", "online");
    if (opts.hostedDomain)
        url.searchParams.set("hd", opts.hostedDomain);
    return url.toString();
}
/**
 * Exchange Google's authorization code (PKCE) for an id_token, verify the token's signature against
 * Google's JWKS (RS256 only) together with `iss`, `aud`, `exp` and the nonce, and return who signed
 * in. The id_token is not returned, stored or logged.
 */
async function exchangeGoogleCode(opts) {
    const tokenUrl = opts.endpoints?.tokenUrl ?? exports.GOOGLE_TOKEN_URL;
    let idToken;
    let tokenRes;
    try {
        tokenRes = await fetch(tokenUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code: opts.code,
                client_id: opts.clientId,
                client_secret: opts.clientSecret,
                redirect_uri: opts.redirectUri,
                code_verifier: opts.codeVerifier,
            }),
            // Without this a hung connection to Google holds the request, its socket and the caller
            // until Node's default socket timeout, and the human just watches a spinner.
            signal: AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS),
        });
    }
    catch (err) {
        throw new OAuthExchangeError("google", "unreachable", `Google token request failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    // Do NOT put the raw provider error body in a message: it can carry sensitive request detail.
    // The status code alone is enough to diagnose.
    if (!tokenRes.ok)
        throw statusError("google", tokenRes.status);
    try {
        const tokenJson = (await tokenRes.json());
        if (typeof tokenJson.id_token !== "string" || !tokenJson.id_token) {
            throw new Error("no id_token in token response");
        }
        idToken = tokenJson.id_token;
    }
    catch (err) {
        throw new OAuthExchangeError("google", "unreachable", `Google token response unusable: ${err instanceof Error ? err.message : String(err)}`);
    }
    try {
        const { payload } = await (0, jose_1.jwtVerify)(idToken, keySet(opts.endpoints?.jwksUrl ?? exports.GOOGLE_JWKS_URL), {
            issuer: exports.GOOGLE_ISSUERS,
            audience: opts.clientId,
            // Pin RS256 (Google signs id_tokens with RSA) — consistent with every other verify path in
            // the library and closes any RS/HS algorithm-confusion agility on this call.
            algorithms: ["RS256"],
        });
        if (opts.nonce && payload.nonce !== opts.nonce)
            throw new Error("nonce mismatch");
        const sub = typeof payload.sub === "string" ? payload.sub : "";
        if (!sub)
            throw new Error("id_token has no sub");
        return {
            sub,
            email: typeof payload.email === "string" ? payload.email : "",
            emailVerified: payload.email_verified === true || payload.email_verified === "true",
            hd: typeof payload.hd === "string" ? payload.hd : undefined,
            name: typeof payload.name === "string" ? payload.name : undefined,
            givenName: typeof payload.given_name === "string" ? payload.given_name : undefined,
            familyName: typeof payload.family_name === "string" ? payload.family_name : undefined,
            picture: typeof payload.picture === "string" ? payload.picture : undefined,
        };
    }
    catch (err) {
        throw new OAuthExchangeError("google", "identity_invalid", `id_token verification failed: ${err instanceof Error ? err.message : String(err)}`);
    }
}
/** X's authorize URL: code flow, PKCE S256. */
function xAuthorizeUrl(opts) {
    const url = new URL(exports.X_AUTH_URL);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", opts.clientId);
    url.searchParams.set("redirect_uri", opts.redirectUri);
    url.searchParams.set("scope", opts.scope ?? exports.X_SCOPES);
    url.searchParams.set("state", opts.state);
    url.searchParams.set("code_challenge", opts.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    return url.toString();
}
/**
 * Exchange X's authorization code (PKCE; the client authenticates with HTTP Basic, as X's
 * confidential clients must) for an access token, then read who signed in from GET /2/users/me.
 * The access token is used for that one call and is not returned, stored or logged.
 *
 * A missing `confirmed_email` is NOT an error: the identity comes back with `email: ""` and
 * `emailVerified: false`, and the caller decides (a linked identity may still sign in).
 */
async function exchangeXCode(opts) {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS;
    let tokenRes;
    try {
        // A confidential client authenticates with HTTP Basic. `client_id` also rides in the body,
        // which X accepts and which keeps the request valid if the app is ever re-registered public.
        const basic = Buffer.from(`${opts.clientId}:${opts.clientSecret}`).toString("base64");
        tokenRes = await fetch(opts.endpoints?.tokenUrl ?? exports.X_TOKEN_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json",
                Authorization: `Basic ${basic}`,
            },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code: opts.code,
                client_id: opts.clientId,
                redirect_uri: opts.redirectUri,
                code_verifier: opts.codeVerifier,
            }),
            signal: AbortSignal.timeout(timeoutMs),
        });
    }
    catch (err) {
        throw new OAuthExchangeError("x", "unreachable", `X token request failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    // Never put the body in a message: a token error response can quote the code, or the token.
    if (!tokenRes.ok)
        throw statusError("x", tokenRes.status);
    let accessToken;
    // X returns the scopes it ACTUALLY granted, which is not always what we asked for. That string is
    // the difference between "this person has no confirmed email" and "this app was never allowed to
    // ask", and nothing else distinguishes them.
    let grantedScopes = "";
    try {
        const tokenJson = (await tokenRes.json());
        if (typeof tokenJson.access_token !== "string" || !tokenJson.access_token) {
            throw new Error("no access_token in token response");
        }
        accessToken = tokenJson.access_token;
        grantedScopes = typeof tokenJson.scope === "string" ? tokenJson.scope : "";
    }
    catch (err) {
        throw new OAuthExchangeError("x", "unreachable", `X token response unusable: ${err instanceof Error ? err.message : String(err)}`);
    }
    const identity = await fetchXIdentity(accessToken, grantedScopes, timeoutMs, opts);
    return { identity, grantedScopes };
}
/**
 * GET /2/users/me under the person's own access token — the whole of what X tells us about them.
 *
 * `confirmed_email` comes back only when the application has "Request email from users" enabled
 * AND the account has a confirmed address, so its ABSENCE IS ORDINARY and is not treated as a
 * failure here.
 */
async function fetchXIdentity(accessToken, grantedScopes, timeoutMs, opts) {
    const url = new URL(opts.endpoints?.meUrl ?? exports.X_ME_URL);
    url.searchParams.set("user.fields", "confirmed_email,profile_image_url,username");
    let res;
    try {
        res = await fetch(url.toString(), {
            headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
            signal: AbortSignal.timeout(timeoutMs),
        });
    }
    catch (err) {
        throw new OAuthExchangeError("x", "unreachable", `X profile request failed: ${err instanceof Error ? err.message : String(err)}`, { stage: "identity" });
    }
    if (!res.ok) {
        // A 401 here is about the PERSON's fresh token, not our client: never "client_refused".
        throw new OAuthExchangeError("x", res.status === 429 ? "provider_busy" : "rejected", `X answered HTTP ${res.status} for /2/users/me`, { stage: "identity", status: res.status });
    }
    let body;
    try {
        body = (await res.json());
    }
    catch {
        throw new OAuthExchangeError("x", "unreachable", "X answered /2/users/me with something that is not JSON", { stage: "identity" });
    }
    const sub = typeof body.data?.id === "string" ? body.data.id.trim() : "";
    if (!sub)
        throw new OAuthExchangeError("x", "identity_invalid", "X answered without an account id");
    const email = typeof body.data?.confirmed_email === "string" ? body.data.confirmed_email.trim() : "";
    if (!email && opts.log) {
        // THE NAMED GAP. Never the address itself — only whether one arrived, what X was willing to
        // grant, and X's own words about the field it withheld.
        const said = (body.errors ?? [])
            .map((e) => [e.title, e.parameter, e.detail].filter((v) => typeof v === "string").join(": "))
            .filter(Boolean)
            .join(" | ");
        opts.log("warn", "X returned no confirmed_email, so this sign-in cannot be admitted. " +
            `Scopes X actually granted: "${grantedScopes || "(none reported)"}". ` +
            (said ? `X said: ${said}. ` : "X reported no error on the field. ") +
            "If `users.email` is missing from the granted scopes, enable \"Request email from users\" " +
            "in the X developer portal (it needs the app's privacy-policy and terms URLs) and have the " +
            "person re-authorize. If it IS granted, the account has no confirmed email address on X.");
    }
    return {
        sub,
        email,
        // X's own word for the field is "confirmed". There is no separate verification flag to read,
        // so the presence of the address IS the assertion — and an absent one stays unverified.
        emailVerified: Boolean(email),
        name: typeof body.data?.name === "string" ? body.data.name : undefined,
        username: typeof body.data?.username === "string" ? body.data.username : undefined,
        picture: typeof body.data?.profile_image_url === "string" ? body.data.profile_image_url : undefined,
        provider: "x",
    };
}
function statusError(provider, status) {
    const who = provider === "google" ? "Google" : "X";
    if (status === 429) {
        return new OAuthExchangeError(provider, "provider_busy", `${who} token endpoint answered 429`, {
            status,
        });
    }
    if (status === 401) {
        return new OAuthExchangeError(provider, "client_refused", `${who} token endpoint refused our client credentials (401)`, { status });
    }
    return new OAuthExchangeError(provider, "rejected", `${who} token exchange failed (${status})`, {
        status,
    });
}
//# sourceMappingURL=oauth-providers.js.map