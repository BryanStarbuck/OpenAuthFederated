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
export declare const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export declare const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export declare const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
export declare const GOOGLE_ISSUERS: string[];
export declare const X_AUTH_URL = "https://x.com/i/oauth2/authorize";
export declare const X_TOKEN_URL = "https://api.x.com/2/oauth2/token";
export declare const X_ME_URL = "https://api.x.com/2/users/me";
export declare const X_SCOPES = "tweet.read users.read users.email";
/**
 * A verified upstream identity. Named for its first producer (Google's OIDC id_token); it is now
 * also what the SAML ACS and the X sign-in path produce, so that every strategy hands its caller
 * one identical shape.
 */
export interface OidcIdentity {
    /** The provider's stable subject identifier (Google `sub`, SAML nameID, X numeric user id). */
    sub: string;
    email: string;
    emailVerified: boolean;
    /** Hosted-domain claim (Google Workspace). Absent for consumer gmail.com accounts. */
    hd?: string;
    name?: string;
    givenName?: string;
    familyName?: string;
    picture?: string;
    /**
     * WHICH STRATEGY VERIFIED THIS HUMAN. Admission rules are not the same for all three:
     * `requireHostedDomain` asks for a Google Workspace `hd` claim, which is a thing only Google has.
     * Optional, and absent means `google` — so every existing call site keeps its exact behaviour.
     */
    provider?: "google" | "saml" | "x";
    /** The X handle, without the `@`. Set on the X path only; nothing else populates it. */
    username?: string;
}
/**
 * Why a code exchange or identity read failed.
 *   - `provider_busy`        the provider answered 429. Give up for now; never retry in a loop.
 *   - `client_refused`       the token endpoint rejected OUR client credentials (401). X bans apps
 *                            for repeated bad traffic, so a caller should stop sending people there
 *                            until the credentials are fixed.
 *   - `rejected`             any other non-2xx from the provider (an expired or reused code, ...).
 *   - `unreachable`          the request threw (DNS, TLS, timeout) or the answer was unusable.
 *   - `identity_invalid`     the id_token failed verification (signature, iss, aud, exp, nonce) or
 *                            the profile carried no account id.
 */
export type OAuthExchangeErrorKind = "provider_busy" | "client_refused" | "rejected" | "unreachable" | "identity_invalid";
export declare class OAuthExchangeError extends Error {
    readonly kind: OAuthExchangeErrorKind;
    readonly provider: "google" | "x";
    /**
     * Which step failed: `token` (the code exchange) or `identity` (verifying the id_token, or reading
     * X's /2/users/me). A caller can word "could not complete" and "could not verify" differently.
     */
    readonly stage: "token" | "identity";
    /** The provider's HTTP status, when it answered one. */
    readonly status?: number;
    constructor(provider: "google" | "x", kind: OAuthExchangeErrorKind, message: string, opts?: {
        stage?: "token" | "identity";
        status?: number;
    });
}
/** Where the provider lives. Only tests override these; production uses the constants above. */
export interface GoogleEndpoints {
    tokenUrl?: string;
    jwksUrl?: string;
}
export interface XEndpoints {
    tokenUrl?: string;
    meUrl?: string;
}
type Log = (level: "info" | "warn" | "error", message: string, meta?: unknown) => void;
/** `bytes` random bytes as base64url. 24 bytes (32 characters) for `state` and `nonce` by default. */
export declare function randomUrlToken(bytes?: number): string;
/** The S256 challenge for a PKCE verifier. */
export declare function pkceChallenge(codeVerifier: string): string;
export interface PkcePair {
    codeVerifier: string;
    codeChallenge: string;
}
/** A fresh PKCE verifier (32 random bytes) and its S256 challenge. Keep the verifier secret. */
export declare function createPkcePair(): PkcePair;
export interface GoogleAuthorizeOptions {
    clientId: string;
    /** Must exactly match an Authorized redirect URI in the Google Cloud OAuth client. */
    redirectUri: string;
    state: string;
    codeChallenge: string;
    /** OIDC nonce; checked against the id_token by {@link exchangeGoogleCode}. Recommended. */
    nonce?: string;
    /** Defaults to `select_account`. `login` forces a fresh authentication (step-up). */
    prompt?: "select_account" | "login" | "consent" | "none";
    /** `max_age` in seconds; `0` together with `prompt: "login"` makes re-authentication real. */
    maxAge?: number;
    /** Google Workspace hosted domain to hint (`hd`). A hint only: enforce it on the identity. */
    hostedDomain?: string;
}
/** Google's authorize URL: code flow, `openid email profile`, PKCE S256, online access. */
export declare function googleAuthorizeUrl(opts: GoogleAuthorizeOptions): string;
export interface GoogleExchangeOptions {
    clientId: string;
    clientSecret: string;
    /** The same redirect URI the authorize URL carried. */
    redirectUri: string;
    code: string;
    codeVerifier: string;
    /** The nonce the authorize URL carried. When set, the id_token must carry the same one. */
    nonce?: string;
    /** Bound on the token request. Defaults to 20 s. */
    timeoutMs?: number;
    endpoints?: GoogleEndpoints;
}
/**
 * Exchange Google's authorization code (PKCE) for an id_token, verify the token's signature against
 * Google's JWKS (RS256 only) together with `iss`, `aud`, `exp` and the nonce, and return who signed
 * in. The id_token is not returned, stored or logged.
 */
export declare function exchangeGoogleCode(opts: GoogleExchangeOptions): Promise<OidcIdentity>;
export interface XAuthorizeOptions {
    clientId: string;
    /** Must exactly match a Callback URI registered in the X app's *User authentication settings*. */
    redirectUri: string;
    state: string;
    codeChallenge: string;
    /** Defaults to {@link X_SCOPES}. */
    scope?: string;
}
/** X's authorize URL: code flow, PKCE S256. */
export declare function xAuthorizeUrl(opts: XAuthorizeOptions): string;
export interface XExchangeOptions {
    clientId: string;
    clientSecret: string;
    /** The same redirect URI the authorize URL carried. */
    redirectUri: string;
    code: string;
    codeVerifier: string;
    /** Bound on each of the two requests (token, /2/users/me). Defaults to 20 s. */
    timeoutMs?: number;
    /** Told why an identity came back without an email (never the address, never a token). */
    log?: Log;
    endpoints?: XEndpoints;
}
export interface XExchangeResult {
    identity: OidcIdentity;
    /** The scopes X ACTUALLY granted (a person can clear a checkbox; `users.email` may be missing). */
    grantedScopes: string;
}
/**
 * Exchange X's authorization code (PKCE; the client authenticates with HTTP Basic, as X's
 * confidential clients must) for an access token, then read who signed in from GET /2/users/me.
 * The access token is used for that one call and is not returned, stored or logged.
 *
 * A missing `confirmed_email` is NOT an error: the identity comes back with `email: ""` and
 * `emailVerified: false`, and the caller decides (a linked identity may still sign in).
 */
export declare function exchangeXCode(opts: XExchangeOptions): Promise<XExchangeResult>;
export {};
