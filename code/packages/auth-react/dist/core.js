import { domainSlug, EMPTY_SNAPSHOT, hasPermission, hasRole, } from "./types.js";
// Active-org is per-tab (sessionStorage), so two tabs can hold different active orgs — the
// "tab-aware active organization context" the spec calls out (§14).
const SS_ACTIVE_ORG = "openauthfed_active_org_v1";
/** Small promise delay used by the load() retry backoff. */
function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
 * Shared subscribe/emit plumbing for the external store. Exported so a consuming app can build its
 * OWN {@link AuthCore} (e.g. a localhost-only dev core) on top of it and inject it via
 * `<FederatedProvider core={...}>`. OpenAuthFederated itself ships only {@link RealAuthCore} — it
 * provides no dev/mock core of its own.
 */
export class BaseCore {
    snapshot = EMPTY_SNAPSHOT;
    state = "loading";
    listeners = new Set();
    getSnapshot() {
        return this.snapshot;
    }
    loadState() {
        return this.state;
    }
    setState(next) {
        if (this.state === next)
            return;
        this.state = next;
        for (const listener of this.listeners)
            listener();
    }
    subscribe(listener) {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }
    setSnapshot(next) {
        this.snapshot = next;
        for (const listener of this.listeners)
            listener();
    }
    /** The permissions/roles that apply *right now*, given the active organization. */
    activeGrants() {
        const user = this.snapshot.user;
        if (!user)
            return { roles: [], permissions: [] };
        const active = this.snapshot.memberships.find((m) => m.organization.id === this.snapshot.orgId);
        if (active)
            return { roles: [active.role], permissions: active.permissions };
        // No active org (personal workspace) → fall back to the user's base grants.
        return { roles: user.roles, permissions: user.permissions };
    }
    has(check = {}) {
        if (!this.snapshot.user)
            return false;
        const { roles, permissions } = this.activeGrants();
        if (check.role && !hasRole(roles, check.role))
            return false;
        if (check.permission && !hasPermission(permissions, check.permission))
            return false;
        return true;
    }
    isRecentlyVerified(maxAgeSeconds) {
        const at = this.snapshot.lastVerifiedAt;
        if (at == null)
            return false;
        return Math.floor(Date.now() / 1000) - at <= maxAgeSeconds;
    }
    readActiveOrg() {
        try {
            return sessionStorage.getItem(SS_ACTIVE_ORG);
        }
        catch {
            return null;
        }
    }
    writeActiveOrg(orgId) {
        try {
            if (orgId)
                sessionStorage.setItem(SS_ACTIVE_ORG, orgId);
            else
                sessionStorage.removeItem(SS_ACTIVE_ORG);
        }
        catch {
            // sessionStorage unavailable (SSR / privacy mode) — active org stays in-memory only.
        }
    }
    async setActiveOrg(orgId) {
        if (!this.snapshot.isSignedIn)
            return;
        if (orgId && !this.snapshot.memberships.some((m) => m.organization.id === orgId)) {
            throw new Error(`setActiveOrg: not a member of ${orgId}`);
        }
        this.writeActiveOrg(orgId);
        this.setSnapshot({ ...this.snapshot, orgId });
    }
}
/**
 * Map the documented callback rejection codes (`docs/apis/frontend/errors.mdx`) to a friendly
 * fallback message — used only when the platform did not send its own `error_message`. Covers
 * every rejection the federated, domain-gated flow can produce so the user always sees a
 * specific reason rather than a generic "try again."
 */
function rejectionMessage(code, presentedDomain) {
    const who = presentedDomain ? ` ('${presentedDomain}')` : "";
    switch (code) {
        case "identity_domain_not_allowed":
        case "domain_not_allowed":
            return `This app is restricted to company accounts. The identity${who} is not part of an allowed company domain.`;
        case "identity_email_unverified":
            return `That Google account's email is not verified, so sign-in can't continue. Use your company Google Workspace account.`;
        case "identity_blocked":
            return `This account${who} has been blocked from accessing the app. Contact your administrator.`;
        case "attempt_expired":
        case "session_expired":
            return "Your sign-in attempt expired before it completed. Please try again.";
        case "sign_in_not_completed":
            return "Sign-in could not be completed. Please try again.";
        default:
            return "Sign-in could not be completed. Please try again.";
    }
}
/**
 * Build the rich {@link AuthRejection} the SDK hands back to the app from the error query
 * parameters the platform appends to the callback URL on a refused identity. Mirrors the
 * platform error envelope so the frontend rejection carries the same detail as the API error:
 * `error`/`error_code`, `error_message`, `error_long_message`, `presented_domain`,
 * `allowed_domains` (comma-separated), `email_verified`, and `trace_id`. Returns `null` when no
 * error param is present (i.e. the handshake did not fail at the callback). See
 * `docs/apis/frontend/errors.mdx#redirect-callback-parameters`.
 */
function rejectionFromParams(params) {
    const code = params.get("error") ?? params.get("error_code");
    if (!code)
        return null;
    const presentedDomain = params.get("presented_domain") ?? undefined;
    const allowedRaw = params.get("allowed_domains");
    const allowedDomains = allowedRaw
        ? allowedRaw.split(",").map((d) => d.trim()).filter(Boolean)
        : undefined;
    const emailVerifiedRaw = params.get("email_verified");
    const emailVerified = emailVerifiedRaw == null ? undefined : emailVerifiedRaw === "true";
    const meta = {};
    if (allowedDomains?.length)
        meta.allowedDomains = allowedDomains;
    if (presentedDomain)
        meta.presentedDomain = presentedDomain;
    if (emailVerified !== undefined)
        meta.emailVerified = emailVerified;
    return {
        code,
        message: params.get("error_message") ?? rejectionMessage(code, presentedDomain),
        longMessage: params.get("error_long_message") ?? undefined,
        presentedDomain,
        meta: Object.keys(meta).length ? meta : undefined,
        traceId: params.get("trace_id") ?? undefined,
    };
}
/**
 * Read the `exp` (epoch seconds) claim from a JWT *without* verifying it — used only to time the
 * client-side access-token cache, never for a trust decision. Returns null if it can't be parsed.
 */
function readJwtExp(jwt) {
    try {
        const payload = jwt.split(".")[1];
        if (!payload)
            return null;
        const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
        const exp = JSON.parse(json).exp;
        return typeof exp === "number" ? exp : null;
    }
    catch {
        return null;
    }
}
/**
 * Real client against the Frontend API: rehydrates the Client, mints short-lived JWTs, and
 * runs the SSO redirect handshake. Authorized with the publishable key + rotating session
 * cookie (`credentials: 'include'`). Requires a deployed OpenAuthFederated server.
 */
export class RealAuthCore extends BaseCore {
    frontendApi;
    publishableKey;
    allowedDomains;
    activeSessionId = null;
    // Cached access token + its `exp` (epoch seconds), and a single in-flight mint so a page-load
    // fan-out of queries triggers one network mint, not one per request. Without this the SDK
    // would POST /tokens on every API call (60s TTL), so any transient mint failure would surface
    // as a 401 and sign the user out — the "times out too often" symptom.
    token = null;
    tokenExp = 0;
    inflight = null;
    constructor(frontendApi, publishableKey, allowedDomains) {
        super();
        this.frontendApi = frontendApi;
        this.publishableKey = publishableKey;
        this.allowedDomains = allowedDomains;
    }
    base() {
        return `${this.frontendApi.replace(/\/+$/, "")}/v1`;
    }
    headers() {
        return { Authorization: `Bearer ${this.publishableKey}` };
    }
    connections() {
        return this.allowedDomains.map((domain) => ({
            id: `conn_${domainSlug(domain)}`,
            domain,
            label: domain,
        }));
    }
    // Backoff schedule (ms) for retrying a transient /client failure. Tuned so a page load that
    // races a backend RESTART keeps trying for ~15s instead of giving up on the first miss and
    // bouncing the user to /sign-in. A clean 200 (signed in OR signed out) is authoritative and
    // never retried — only "couldn't reach the API" / 5xx is.
    static LOAD_BACKOFF_MS = [400, 800, 1500, 2500, 4000, 5000];
    async load() {
        await this.loadWithRetry(0);
    }
    async loadWithRetry(attempt) {
        const schedule = RealAuthCore.LOAD_BACKOFF_MS;
        try {
            const res = await fetch(`${this.base()}/client`, {
                headers: this.headers(),
                credentials: "include",
            });
            if (res.ok) {
                // Authoritative answer (the body says signed-in or signed-out). Trust it; never retry.
                this.applyClient(await res.json());
                this.setState("loaded");
                return;
            }
            // 5xx = API up but erroring → transient, keep retrying. 4xx = authoritative (e.g. bad
            // publishable key) → stop. A signed-OUT user gets 200 + empty sessions, never a 4xx here.
            if (res.status >= 500 && attempt < schedule.length) {
                this.setState("degraded");
                await delay(schedule[attempt] ?? 5000);
                return this.loadWithRetry(attempt + 1);
            }
            this.setState(res.status >= 500 ? "degraded" : "loaded");
        }
        catch {
            // Frontend API unreachable (server restarting / briefly offline). Do NOT conclude
            // "signed out" — that is what forces a needless re-login. Retry on a backoff so a reload
            // during a backend restart rehydrates from the still-valid session cookie. The route guard
            // shows a "reconnecting" state (not the sign-in page) while loadState is "failed".
            if (attempt < schedule.length) {
                this.setState("failed");
                await delay(schedule[attempt] ?? 5000);
                return this.loadWithRetry(attempt + 1);
            }
            this.setState("failed");
        }
    }
    parseMemberships(raw) {
        if (!Array.isArray(raw))
            return [];
        return raw.map((m) => {
            const rec = m;
            const org = (rec.organization ?? {});
            return {
                id: rec.id ?? "",
                organization: {
                    id: org.id,
                    name: org.name ?? "",
                    slug: org.slug,
                    membersCount: org.members_count,
                    publicMetadata: org.public_metadata,
                },
                role: rec.role ?? "org:member",
                permissions: rec.permissions ?? [],
            };
        });
    }
    applyClient(client) {
        // Session identity may have changed — never serve a token cached against a prior session.
        this.clearTokenCache();
        const activeId = client.last_active_session_id;
        const session = (client.sessions ?? []).find((s) => s.id === activeId && s.status === "active");
        if (!session) {
            this.activeSessionId = null;
            this.setSnapshot(EMPTY_SNAPSHOT);
            return;
        }
        const user = (session.user ?? {});
        this.activeSessionId = session.id;
        const memberships = this.parseMemberships(client.organization_memberships);
        // Prefer a per-tab active org if it is still valid; otherwise the server's org_id.
        const serverOrg = client.org_id ?? null;
        const storedOrg = this.readActiveOrg();
        const orgId = storedOrg && memberships.some((m) => m.organization.id === storedOrg)
            ? storedOrg
            : serverOrg;
        const verifiedAt = (session.last_verified_at ?? session.last_active_at);
        this.setSnapshot({
            isSignedIn: true,
            userId: session.user_id,
            sessionId: session.id,
            orgId,
            user: {
                id: session.user_id,
                firstName: user.first_name,
                lastName: user.last_name,
                primaryEmailAddress: user.primary_email_address,
                roles: user.roles ?? [],
                permissions: user.permissions ?? [],
                hd: user.hd,
            },
            memberships,
            lastVerifiedAt: verifiedAt != null ? Math.floor(verifiedAt / 1000) : null,
        });
    }
    async authenticateWithRedirect(params) {
        const conn = this.connections().find((c) => c.id === params.connectionId) ?? this.connections()[0];
        const query = new URLSearchParams({
            strategy: params.strategy ?? "oauth_google_workspace",
            connection: conn?.id ?? "",
            redirect_url: new URL(params.redirectUrl, window.location.origin).toString(),
            redirect_url_complete: new URL(params.redirectUrlComplete, window.location.origin).toString(),
        });
        window.location.assign(`${this.base()}/sign_in/sso?${query.toString()}`);
    }
    async completeRedirectCallback() {
        const params = new URLSearchParams(window.location.search);
        // Domain enforcement rejection (§7.3): the platform redirects back to the callback with an
        // error envelope (in query params) rather than a session when the verified identity fails
        // domain enforcement. No session was created — surface the rich rejection (code, message,
        // long message, allowed/presented domains, trace id) instead of forwarding the user on, so
        // the app can show a specific reason. See `docs/apis/frontend/errors.mdx`.
        const rejection = rejectionFromParams(params);
        if (rejection) {
            this.activeSessionId = null;
            this.setSnapshot(EMPTY_SNAPSHOT);
            return { error: rejection };
        }
        await this.load();
        // A reachable Frontend API that nonetheless yields no active session here means the attempt
        // did not establish one (e.g. a rejected identity that produced no error query param).
        if (!this.snapshot.isSignedIn) {
            return {
                error: {
                    code: "sign_in_not_completed",
                    message: rejectionMessage("sign_in_not_completed"),
                    longMessage: "The sign-in handshake returned, but no active session was established. The attempt " +
                        "may have expired or been refused upstream. Please try signing in again.",
                },
            };
        }
        return { redirectTo: params.get("redirect_url_complete") ?? "/" };
    }
    async getToken(opts = {}) {
        if (!this.activeSessionId)
            return null;
        // A templated token is minted fresh each call (its claim shape may differ) and never cached.
        if (opts.template)
            return this.mintToken(opts.template);
        const now = Math.floor(Date.now() / 1000);
        // Reuse the cached access token until ~10s before expiry. Org switches / sign-out invalidate
        // the cache (clearTokenCache below), so a stale-grant token is never served.
        if (this.token && this.tokenExp - now > 10)
            return this.token;
        // Single-flight: concurrent callers share one in-flight mint instead of each hitting /tokens.
        if (this.inflight)
            return this.inflight;
        this.inflight = this.mintToken().finally(() => {
            this.inflight = null;
        });
        return this.inflight;
    }
    /** POST to the Frontend API to mint an access JWT. Caches the default (non-templated) token. */
    async mintToken(template) {
        if (!this.activeSessionId)
            return null;
        // A named JWT template mints against a different Frontend-API path (spec §15).
        const path = template
            ? `${this.base()}/client/sessions/${this.activeSessionId}/tokens/${template}`
            : `${this.base()}/client/sessions/${this.activeSessionId}/tokens`;
        const res = await fetch(path, {
            method: "POST",
            headers: { ...this.headers(), "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify(this.snapshot.orgId ? { org_id: this.snapshot.orgId } : {}),
        });
        if (!res.ok)
            return null;
        const data = (await res.json());
        const jwt = data.jwt ?? null;
        if (jwt && !template) {
            this.token = jwt;
            // Time the cache off the token's own `exp`; fall back to the 60s default TTL if unreadable.
            this.tokenExp = readJwtExp(jwt) ?? Math.floor(Date.now() / 1000) + 60;
        }
        return jwt;
    }
    /** Drop the cached access token so the next getToken() re-mints with current grants. */
    clearTokenCache() {
        this.token = null;
        this.tokenExp = 0;
    }
    async setActiveOrg(orgId) {
        if (!this.activeSessionId)
            return;
        if (orgId && !this.snapshot.memberships.some((m) => m.organization.id === orgId)) {
            throw new Error(`setActiveOrg: not a member of ${orgId}`);
        }
        // Tell the Frontend API to set this session's active org, then rehydrate.
        try {
            await fetch(`${this.base()}/client/sessions/${this.activeSessionId}/touch`, {
                method: "POST",
                headers: { ...this.headers(), "Content-Type": "application/json" },
                credentials: "include",
                body: JSON.stringify({ active_organization_id: orgId }),
            });
        }
        catch {
            // best-effort; local active-org write below still applies for this tab
        }
        this.writeActiveOrg(orgId);
        // The cached token carries the prior org's grants — drop it so the next mint re-scopes.
        this.clearTokenCache();
        this.setSnapshot({ ...this.snapshot, orgId });
    }
    async reverify() {
        if (!this.activeSessionId)
            return;
        // Step-up: bounce through the IdP to re-verify, then return here and rehydrate.
        const url = new URL(`${this.base()}/client/sessions/${this.activeSessionId}/reverify`);
        url.searchParams.set("redirect_url", window.location.href);
        window.location.assign(url.toString());
    }
    async signOut(opts = {}) {
        try {
            if (this.activeSessionId) {
                await fetch(`${this.base()}/client/sessions/${this.activeSessionId}/remove`, {
                    method: "POST",
                    headers: this.headers(),
                    credentials: "include",
                });
            }
        }
        catch {
            // best-effort; clear local state regardless
        }
        this.activeSessionId = null;
        this.clearTokenCache();
        this.writeActiveOrg(null);
        this.setSnapshot(EMPTY_SNAPSHOT);
        if (opts.redirectUrl)
            window.location.assign(opts.redirectUrl);
    }
}
//# sourceMappingURL=core.js.map