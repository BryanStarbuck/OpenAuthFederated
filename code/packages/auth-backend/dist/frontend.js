"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthFrontend = createAuthFrontend;
const node_crypto_1 = require("node:crypto");
/**
 * In-process Frontend API — the embedded counterpart to a deployed OpenAuthFederated server.
 *
 * `createAuthFrontend()` returns an Express/Node-compatible middleware that the host app mounts
 * (e.g. `app.use('/api/v1', createAuthFrontend(cfg))`). It implements exactly the endpoints the
 * `@auth/react` `RealAuthCore` calls, so a SPA gets a *real* Google Workspace sign-in with no
 * separate auth server process:
 *
 *   GET  /sign_in/sso                         → 302 to Google's OAuth 2.0 / OIDC authorize URL
 *   GET  /oauth_callback                      → code→token exchange, id_token + hd verification,
 *                                               establishes the session cookie, 302 back to the SPA
 *   GET  /client                              → rehydrate the current session (signed-out = empty)
 *   POST /client/sessions/:id/tokens          → mint a short-lived access JWT for API calls
 *   POST /client/sessions/:id/tokens/:tmpl    → templated token mint (same path, tagged)
 *   POST /client/sessions/:id/touch           → set the session's active organization
 *   GET  /client/sessions/:id/reverify        → step-up: refresh the session's verified-at time
 *   POST /client/sessions/:id/remove          → sign out (clear the session cookie)
 *
 * Everything runs in the host's own process. The human is authenticated by Google (real OIDC
 * round-trip, real id_token signature check against Google's JWKS, real `hd`/`email_verified`
 * enforcement). The app *session* and the short-lived access tokens are signed with a single
 * in-process HS256 secret (`sessionSecret`) — the same secret `verifyToken()` checks in embedded
 * mode — so there is no JWKS endpoint and no second service to run.
 */
const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
let josePromise = null;
function jose() {
    if (!josePromise)
        josePromise = import("jose");
    return josePromise;
}
let googleJwks = null;
async function googleKeySet() {
    if (!googleJwks) {
        const { createRemoteJWKSet } = await jose();
        googleJwks = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));
    }
    return googleJwks;
}
const STATE_COOKIE = "oaf_oauth_state";
const STATE_TTL_SECONDS = 600;
// --- small Node http helpers (no express dependency) ---------------------------------------
function base64url(buf) {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function pathOf(req) {
    const raw = req.url ?? "/";
    try {
        return new URL(raw, "http://internal").pathname;
    }
    catch {
        return raw.split("?")[0] ?? raw;
    }
}
function queryOf(req) {
    const raw = req.url ?? "/";
    try {
        return new URL(raw, "http://internal").searchParams;
    }
    catch {
        return new URLSearchParams();
    }
}
function parseCookies(req) {
    const header = req.headers.cookie;
    if (!header)
        return {};
    const out = {};
    for (const part of header.split(";")) {
        const eq = part.indexOf("=");
        if (eq < 0)
            continue;
        const k = part.slice(0, eq).trim();
        const v = part.slice(eq + 1).trim();
        if (k)
            out[k] = decodeURIComponent(v);
    }
    return out;
}
function appendSetCookie(res, cookie) {
    const prev = res.getHeader("Set-Cookie");
    if (!prev)
        res.setHeader("Set-Cookie", [cookie]);
    else if (Array.isArray(prev))
        res.setHeader("Set-Cookie", [...prev, cookie]);
    else
        res.setHeader("Set-Cookie", [String(prev), cookie]);
}
function setCookie(res, name, value, opts = {}) {
    const parts = [
        `${name}=${encodeURIComponent(value)}`,
        "Path=/",
        "HttpOnly",
        `SameSite=${opts.sameSite ?? "Lax"}`,
    ];
    if (opts.maxAgeSeconds != null)
        parts.push(`Max-Age=${opts.maxAgeSeconds}`);
    if (opts.secure)
        parts.push("Secure");
    appendSetCookie(res, parts.join("; "));
}
function clearCookie(res, name, secure) {
    appendSetCookie(res, `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`);
}
function sendJson(res, status, body) {
    const payload = JSON.stringify(body);
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(payload);
}
function redirect(res, location) {
    res.statusCode = 302;
    res.setHeader("Location", location);
    res.setHeader("Cache-Control", "no-store");
    res.end();
}
async function readJsonBody(req) {
    // The host (NestJS) may have already parsed the body; prefer it to avoid a consumed stream.
    const pre = req.body;
    if (pre && typeof pre === "object")
        return pre;
    return await new Promise((resolve) => {
        let data = "";
        let done = false;
        const finish = (v) => {
            if (!done) {
                done = true;
                resolve(v);
            }
        };
        req.on("data", (c) => {
            data += c;
            if (data.length > 1_000_000)
                finish({}); // guard against oversized bodies
        });
        req.on("end", () => {
            try {
                finish(data ? JSON.parse(data) : {});
            }
            catch {
                finish({});
            }
        });
        req.on("error", () => finish({}));
    });
}
function emailDomain(email) {
    const at = email.lastIndexOf("@");
    return at < 0 ? "" : email.slice(at + 1).trim().toLowerCase();
}
function constantTimeEqual(a, b) {
    const ab = Buffer.from(a);
    const bb = Buffer.from(b);
    if (ab.length !== bb.length)
        return false;
    return (0, node_crypto_1.timingSafeEqual)(ab, bb);
}
// --- default RBAC mapping ------------------------------------------------------------------
/**
 * Default grant: an internal employee who is an admin of the single "internal" org. Read
 * everything, write everything within the org — mirrors the prior dev-mock behavior so the
 * app's `<Protect …:write>` controls keep working. Replace via `config.resolveGrants` to map
 * Google Workspace groups to finer-grained roles.
 */
function defaultResolveGrants(identity) {
    const domain = identity.hd || emailDomain(identity.email) || "company";
    const membership = {
        id: "orgmem_internal",
        organization: { id: "org_internal", name: `${domain} (Internal)`, slug: "internal" },
        role: "org:admin",
        permissions: ["*:read", "*:write", "org:sys_memberships:manage"],
    };
    return {
        roles: ["employee"],
        permissions: ["*:read"],
        orgId: "org_internal",
        memberships: [membership],
    };
}
function normalizeConfig(config) {
    return {
        google: config.google,
        allowedDomains: config.allowedDomains.map((d) => d.trim().toLowerCase()).filter(Boolean),
        sessionSecret: config.sessionSecret,
        issuer: config.issuer,
        sessionCookieName: config.sessionCookieName ?? "oaf_session",
        sessionTtlSeconds: config.sessionTtlSeconds ?? 8 * 60 * 60,
        accessTokenTtlSeconds: config.accessTokenTtlSeconds ?? 60,
        cookieSecure: config.cookieSecure ?? false,
        resolveGrants: config.resolveGrants ?? defaultResolveGrants,
        log: config.logger ??
            ((level, message, meta) => {
                // Default: quiet on info, surface problems.
                if (level !== "info")
                    console[level](`[auth-frontend] ${message}`, meta ?? "");
            }),
    };
}
/**
 * Create the embedded Frontend API middleware. Mount it where the SDK's `frontendApi` + `/v1`
 * resolves to — e.g. `app.use('/api/v1', createAuthFrontend(cfg))` with `frontendApi: '/api'`.
 */
function createAuthFrontend(config) {
    const cfg = normalizeConfig(config);
    const secretKey = new TextEncoder().encode(cfg.sessionSecret);
    if (!cfg.google.clientId || !cfg.google.clientSecret) {
        cfg.log("warn", "Google OAuth client is not configured (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET). " +
            "Sign-in will fail until real credentials are set.");
    }
    if (!cfg.sessionSecret || cfg.sessionSecret === "dev-shared-secret") {
        cfg.log("warn", "AUTH_SESSION_SECRET is unset or default — set a strong secret before production.");
    }
    async function signSession(record) {
        const { SignJWT } = await jose();
        return await new SignJWT({
            email: record.email,
            name: record.name,
            first_name: record.firstName,
            last_name: record.lastName,
            hd: record.hd,
            sid: record.sid,
            roles: record.roles,
            permissions: record.permissions,
            org_id: record.orgId,
            memberships: record.memberships,
            lvc: record.lastVerifiedAt,
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(record.userId)
            .setIssuedAt()
            .setIssuer(cfg.issuer ?? "openauthfederated")
            .setExpirationTime(`${cfg.sessionTtlSeconds}s`)
            .sign(secretKey);
    }
    async function readSession(req) {
        const raw = parseCookies(req)[cfg.sessionCookieName];
        if (!raw)
            return null;
        try {
            const { jwtVerify } = await jose();
            const { payload } = await jwtVerify(raw, secretKey);
            const m = payload.memberships ?? [];
            return {
                sid: payload.sid ?? "",
                userId: payload.sub ?? "",
                email: payload.email ?? "",
                name: payload.name,
                firstName: payload.first_name,
                lastName: payload.last_name,
                hd: payload.hd,
                roles: Array.isArray(payload.roles) ? payload.roles : [],
                permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
                orgId: payload.org_id ?? null,
                memberships: Array.isArray(m) ? m : [],
                lastVerifiedAt: payload.lvc ?? Math.floor(Date.now() / 1000),
            };
        }
        catch {
            return null;
        }
    }
    /** The Client snapshot shape RealAuthCore.applyClient() consumes. */
    function clientSnapshot(session) {
        return {
            object: "client",
            last_active_session_id: session.sid,
            org_id: session.orgId,
            organization_memberships: session.memberships.map((m) => ({
                id: m.id,
                organization: { id: m.organization.id, name: m.organization.name, slug: m.organization.slug },
                role: m.role,
                permissions: m.permissions,
            })),
            sessions: [
                {
                    id: session.sid,
                    status: "active",
                    user_id: session.userId,
                    last_verified_at: session.lastVerifiedAt * 1000, // applyClient divides by 1000
                    user: {
                        id: session.userId,
                        first_name: session.firstName,
                        last_name: session.lastName,
                        primary_email_address: session.email,
                        roles: session.roles,
                        permissions: session.permissions,
                        hd: session.hd,
                    },
                },
            ],
        };
    }
    /** Grants for the requested active org (falls back to the session's base grants). */
    function grantsForOrg(session, orgId) {
        const active = session.memberships.find((m) => m.organization.id === orgId);
        if (active)
            return { roles: [active.role], permissions: active.permissions, orgId };
        return { roles: session.roles, permissions: session.permissions, orgId: session.orgId };
    }
    async function mintAccessToken(session, orgId) {
        const { SignJWT } = await jose();
        const g = grantsForOrg(session, orgId);
        return await new SignJWT({
            email: session.email,
            sid: session.sid,
            org_id: g.orgId,
            roles: g.roles,
            permissions: g.permissions,
            hd: session.hd,
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(session.userId)
            .setIssuedAt()
            .setIssuer(cfg.issuer ?? "openauthfederated")
            .setExpirationTime(`${cfg.accessTokenTtlSeconds}s`)
            .sign(secretKey);
    }
    // --- OAuth state (CSRF + PKCE + return targets) carried in a short-lived signed cookie ----
    async function signState(state) {
        const { SignJWT } = await jose();
        return await new SignJWT(state)
            .setProtectedHeader({ alg: "HS256" })
            .setIssuedAt()
            .setExpirationTime(`${STATE_TTL_SECONDS}s`)
            .sign(secretKey);
    }
    async function readState(req) {
        const raw = parseCookies(req)[STATE_COOKIE];
        if (!raw)
            return null;
        try {
            const { jwtVerify } = await jose();
            const { payload } = await jwtVerify(raw, secretKey);
            return payload;
        }
        catch {
            return null;
        }
    }
    // --- endpoint handlers ---------------------------------------------------------------------
    async function handleSsoStart(req, res) {
        const q = queryOf(req);
        const redirectUrl = q.get("redirect_url") || "/sso-callback";
        const redirectUrlComplete = q.get("redirect_url_complete") || "/";
        // The SDK passes connection=conn_<domain_slug>; the explicit hostedDomain config wins.
        const connection = q.get("connection") ?? "";
        const domainFromConn = connection.startsWith("conn_")
            ? connection.slice("conn_".length).replace(/_/g, ".")
            : undefined;
        const hostedDomain = cfg.google.hostedDomain ??
            (domainFromConn && cfg.allowedDomains.includes(domainFromConn) ? domainFromConn : undefined);
        const state = base64url((0, node_crypto_1.randomBytes)(24));
        const nonce = base64url((0, node_crypto_1.randomBytes)(24));
        const codeVerifier = base64url((0, node_crypto_1.randomBytes)(32));
        const codeChallenge = base64url((0, node_crypto_1.createHash)("sha256").update(codeVerifier).digest());
        const stateJwt = await signState({
            state,
            nonce,
            codeVerifier,
            redirectUrl,
            redirectUrlComplete,
            domain: hostedDomain,
        });
        setCookie(res, STATE_COOKIE, stateJwt, {
            maxAgeSeconds: STATE_TTL_SECONDS,
            secure: cfg.cookieSecure,
        });
        const authUrl = new URL(GOOGLE_AUTH_URL);
        authUrl.searchParams.set("client_id", cfg.google.clientId);
        authUrl.searchParams.set("redirect_uri", cfg.google.redirectUri);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("scope", "openid email profile");
        authUrl.searchParams.set("state", state);
        authUrl.searchParams.set("nonce", nonce);
        authUrl.searchParams.set("code_challenge", codeChallenge);
        authUrl.searchParams.set("code_challenge_method", "S256");
        authUrl.searchParams.set("prompt", "select_account");
        authUrl.searchParams.set("access_type", "online");
        if (hostedDomain)
            authUrl.searchParams.set("hd", hostedDomain);
        redirect(res, authUrl.toString());
    }
    /** Bounce back to the SPA callback page, carrying either success or a rejection. */
    function backToApp(res, redirectUrl, params) {
        let url;
        try {
            url = new URL(redirectUrl);
        }
        catch {
            url = new URL(redirectUrl, "http://localhost");
        }
        for (const [k, v] of Object.entries(params))
            url.searchParams.set(k, v);
        // Preserve a relative target if the SDK passed one.
        const isAbsolute = /^https?:\/\//i.test(redirectUrl);
        redirect(res, isAbsolute ? url.toString() : `${url.pathname}${url.search}`);
    }
    async function handleCallback(req, res) {
        const q = queryOf(req);
        const saved = await readState(req);
        clearCookie(res, STATE_COOKIE, cfg.cookieSecure);
        const fallbackRedirect = saved?.redirectUrl ?? "/sso-callback";
        const redirectUrlComplete = saved?.redirectUrlComplete ?? "/";
        // Google-reported error (e.g. user cancelled consent).
        const googleError = q.get("error");
        if (googleError) {
            cfg.log("warn", `OAuth callback returned error: ${googleError}`);
            return backToApp(res, fallbackRedirect, {
                error: "sign_in_not_completed",
                error_message: "Sign-in was not completed.",
                redirect_url_complete: redirectUrlComplete,
            });
        }
        const code = q.get("code");
        const returnedState = q.get("state");
        if (!saved || !code || !returnedState || !constantTimeEqual(returnedState, saved.state)) {
            cfg.log("warn", "OAuth callback failed state/PKCE validation");
            return backToApp(res, fallbackRedirect, {
                error: "sign_in_not_completed",
                error_message: "Sign-in could not be verified. Please try again.",
                redirect_url_complete: redirectUrlComplete,
            });
        }
        // Exchange the authorization code for tokens (PKCE).
        let idToken;
        try {
            const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    code,
                    client_id: cfg.google.clientId,
                    client_secret: cfg.google.clientSecret,
                    redirect_uri: cfg.google.redirectUri,
                    code_verifier: saved.codeVerifier,
                }),
            });
            if (!tokenRes.ok) {
                const detail = await tokenRes.text();
                cfg.log("error", `Google token exchange failed (${tokenRes.status})`, detail.slice(0, 500));
                return backToApp(res, fallbackRedirect, {
                    error: "sign_in_not_completed",
                    error_message: "Could not complete sign-in with Google.",
                    redirect_url_complete: redirectUrlComplete,
                });
            }
            const tokenJson = (await tokenRes.json());
            if (!tokenJson.id_token)
                throw new Error("no id_token in token response");
            idToken = tokenJson.id_token;
        }
        catch (err) {
            cfg.log("error", "Google token exchange threw", err instanceof Error ? err.message : err);
            return backToApp(res, fallbackRedirect, {
                error: "sign_in_not_completed",
                error_message: "Could not reach Google to complete sign-in.",
                redirect_url_complete: redirectUrlComplete,
            });
        }
        // Verify the id_token signature against Google's JWKS and check the standard claims.
        let identity;
        try {
            const { jwtVerify } = await jose();
            const jwks = await googleKeySet();
            const { payload } = await jwtVerify(idToken, jwks, {
                issuer: GOOGLE_ISSUERS,
                audience: cfg.google.clientId,
            });
            if (saved.nonce && payload.nonce !== saved.nonce) {
                throw new Error("nonce mismatch");
            }
            identity = {
                sub: String(payload.sub ?? ""),
                email: String(payload.email ?? ""),
                emailVerified: payload.email_verified === true || payload.email_verified === "true",
                hd: typeof payload.hd === "string" ? payload.hd : undefined,
                name: typeof payload.name === "string" ? payload.name : undefined,
                givenName: typeof payload.given_name === "string" ? payload.given_name : undefined,
                familyName: typeof payload.family_name === "string" ? payload.family_name : undefined,
                picture: typeof payload.picture === "string" ? payload.picture : undefined,
            };
        }
        catch (err) {
            cfg.log("error", "id_token verification failed", err instanceof Error ? err.message : err);
            return backToApp(res, fallbackRedirect, {
                error: "sign_in_not_completed",
                error_message: "Could not verify your Google identity.",
                redirect_url_complete: redirectUrlComplete,
            });
        }
        // Domain enforcement (authentication.mdx §3): require a verified email on an allowed domain.
        const presentedDomain = (identity.hd || emailDomain(identity.email)).toLowerCase();
        if (!identity.email || !identity.emailVerified) {
            return backToApp(res, fallbackRedirect, {
                error: "identity_domain_not_allowed",
                error_message: "A verified company email is required.",
                presented_domain: presentedDomain,
                redirect_url_complete: redirectUrlComplete,
            });
        }
        if (!presentedDomain || !cfg.allowedDomains.includes(presentedDomain)) {
            cfg.log("warn", `Rejecting sign-in from non-allowed domain: ${presentedDomain || "unknown"}`);
            return backToApp(res, fallbackRedirect, {
                error: "identity_domain_not_allowed",
                error_message: "This app is restricted to company accounts. Your domain is not on the allowlist.",
                presented_domain: presentedDomain,
                redirect_url_complete: redirectUrlComplete,
            });
        }
        // Establish the session.
        const grants = cfg.resolveGrants(identity);
        const now = Math.floor(Date.now() / 1000);
        const session = {
            sid: `sess_${base64url((0, node_crypto_1.randomBytes)(12))}`,
            userId: `user_${identity.sub}`,
            email: identity.email,
            name: identity.name,
            firstName: identity.givenName,
            lastName: identity.familyName,
            hd: identity.hd ?? presentedDomain,
            roles: grants.roles,
            permissions: grants.permissions,
            orgId: grants.orgId,
            memberships: grants.memberships,
            lastVerifiedAt: now,
        };
        const sessionJwt = await signSession(session);
        setCookie(res, cfg.sessionCookieName, sessionJwt, {
            maxAgeSeconds: cfg.sessionTtlSeconds,
            secure: cfg.cookieSecure,
        });
        cfg.log("info", `Sign-in established for ${identity.email}`);
        backToApp(res, fallbackRedirect, { redirect_url_complete: redirectUrlComplete });
    }
    async function handleClient(req, res) {
        const session = await readSession(req);
        if (!session || !session.sid) {
            // Signed out — RealAuthCore treats an empty client as EMPTY_SNAPSHOT.
            return sendJson(res, 200, {
                object: "client",
                last_active_session_id: null,
                sessions: [],
            });
        }
        sendJson(res, 200, clientSnapshot(session));
    }
    async function handleMintToken(req, res) {
        const session = await readSession(req);
        if (!session)
            return sendJson(res, 401, { error: "not_authenticated" });
        const body = await readJsonBody(req);
        const orgId = body.org_id ?? session.orgId;
        const jwt = await mintAccessToken(session, orgId);
        sendJson(res, 200, { jwt, object: "token" });
    }
    async function handleTouch(req, res) {
        const session = await readSession(req);
        if (!session)
            return sendJson(res, 401, { error: "not_authenticated" });
        const body = await readJsonBody(req);
        const next = body.active_organization_id ?? null;
        if (next && !session.memberships.some((m) => m.organization.id === next)) {
            return sendJson(res, 400, { error: "not_a_member" });
        }
        session.orgId = next;
        const sessionJwt = await signSession(session);
        setCookie(res, cfg.sessionCookieName, sessionJwt, {
            maxAgeSeconds: cfg.sessionTtlSeconds,
            secure: cfg.cookieSecure,
        });
        sendJson(res, 200, { object: "session", id: session.sid, org_id: session.orgId });
    }
    async function handleReverify(req, res) {
        const session = await readSession(req);
        const q = queryOf(req);
        const back = q.get("redirect_url") || "/";
        if (!session)
            return redirect(res, back);
        // Step-up in embedded mode: refresh the verified-at stamp and return. (A full IdP
        // re-prompt would route back through /sign_in/sso with prompt=login.)
        session.lastVerifiedAt = Math.floor(Date.now() / 1000);
        const sessionJwt = await signSession(session);
        setCookie(res, cfg.sessionCookieName, sessionJwt, {
            maxAgeSeconds: cfg.sessionTtlSeconds,
            secure: cfg.cookieSecure,
        });
        redirect(res, back);
    }
    async function handleRemove(_req, res) {
        clearCookie(res, cfg.sessionCookieName, cfg.cookieSecure);
        sendJson(res, 200, { object: "session", deleted: true });
    }
    // --- router --------------------------------------------------------------------------------
    return (req, res, next) => {
        const path = pathOf(req);
        const method = (req.method ?? "GET").toUpperCase();
        const route = async () => {
            if (method === "GET" && path === "/sign_in/sso") {
                await handleSsoStart(req, res);
                return true;
            }
            if (method === "GET" && path === "/oauth_callback") {
                await handleCallback(req, res);
                return true;
            }
            if (method === "GET" && path === "/client") {
                await handleClient(req, res);
                return true;
            }
            // /client/sessions/:id/...
            const m = /^\/client\/sessions\/([^/]+)\/(tokens|touch|reverify|remove)(?:\/[^/]+)?$/.exec(path);
            if (m) {
                const action = m[2];
                if (action === "tokens" && method === "POST") {
                    await handleMintToken(req, res);
                    return true;
                }
                if (action === "touch" && method === "POST") {
                    await handleTouch(req, res);
                    return true;
                }
                if (action === "reverify" && method === "GET") {
                    await handleReverify(req, res);
                    return true;
                }
                if (action === "remove" && method === "POST") {
                    await handleRemove(req, res);
                    return true;
                }
            }
            return false;
        };
        route()
            .then((handled) => {
            if (!handled) {
                if (next)
                    next();
                else
                    sendJson(res, 404, { error: "not_found" });
            }
        })
            .catch((err) => {
            cfg.log("error", "auth-frontend handler threw", err instanceof Error ? err.message : err);
            if (!res.headersSent)
                sendJson(res, 500, { error: "internal_error" });
        });
    };
}
//# sourceMappingURL=frontend.js.map