import { SignJWT } from "jose";
import { domainSlug, EMPTY_SNAPSHOT, hasPermission, } from "./types.js";
const LS_SESSION = "openauthfed_dev_session_v1";
const LS_PENDING = "openauthfed_dev_pending_v1";
/** Shared subscribe/emit plumbing for the external store. */
class BaseCore {
    snapshot = EMPTY_SNAPSHOT;
    listeners = new Set();
    getSnapshot() {
        return this.snapshot;
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
    has(check = {}) {
        const user = this.snapshot.user;
        if (!user)
            return false;
        if (check.role && !user.roles.includes(check.role))
            return false;
        if (check.permission && !hasPermission(user.permissions, check.permission))
            return false;
        return true;
    }
}
/**
 * Local dev mock: no Google round-trip, no running server. Sign-in establishes a session
 * in localStorage and `getToken()` mints a short-lived HS256 JWT with the shared dev secret
 * that `@auth/backend` verifies in dev mode.
 */
export class DevAuthCore extends BaseCore {
    allowedDomains;
    devSharedSecret;
    issuer;
    token = null;
    tokenExp = 0;
    constructor(allowedDomains, devSharedSecret, issuer) {
        super();
        this.allowedDomains = allowedDomains;
        this.devSharedSecret = devSharedSecret;
        this.issuer = issuer;
    }
    connections() {
        return this.allowedDomains.map((domain) => ({
            id: `conn_${domainSlug(domain)}`,
            domain,
            label: domain,
        }));
    }
    async load() {
        const raw = localStorage.getItem(LS_SESSION);
        if (!raw)
            return;
        try {
            this.setSnapshot(JSON.parse(raw));
        }
        catch {
            localStorage.removeItem(LS_SESSION);
        }
    }
    async authenticateWithRedirect(params) {
        const conn = this.connections().find((c) => c.id === params.connectionId) ?? this.connections()[0];
        localStorage.setItem(LS_PENDING, JSON.stringify({ domain: conn?.domain, redirectUrlComplete: params.redirectUrlComplete }));
        window.location.assign(params.redirectUrl);
    }
    async completeRedirectCallback() {
        const raw = localStorage.getItem(LS_PENDING);
        localStorage.removeItem(LS_PENDING);
        const pending = raw ? JSON.parse(raw) : null;
        const domain = pending?.domain ?? this.allowedDomains[0];
        const snapshot = this.buildSession(domain);
        localStorage.setItem(LS_SESSION, JSON.stringify(snapshot));
        this.token = null;
        this.setSnapshot(snapshot);
        return { redirectTo: pending?.redirectUrlComplete ?? "/" };
    }
    buildSession(domain) {
        const slug = domainSlug(domain);
        const user = {
            id: `user_dev_${slug}`,
            firstName: "Dev",
            lastName: "Employee",
            primaryEmailAddress: `dev@${domain}`,
            // Demo RBAC: read everything, write a subset — enough to exercise <Protect> both ways.
            roles: ["employee"],
            permissions: ["*:read", "film:write", "movies:write", "tools:write"],
            hd: domain,
        };
        return {
            isSignedIn: true,
            userId: user.id,
            sessionId: `sess_dev_${slug}`,
            orgId: "org_dev_internal",
            user,
        };
    }
    async getToken() {
        const snap = this.snapshot;
        if (!snap.isSignedIn || !snap.user)
            return null;
        const now = Math.floor(Date.now() / 1000);
        if (this.token && this.tokenExp - now > 10)
            return this.token;
        const key = new TextEncoder().encode(this.devSharedSecret);
        const jwt = await new SignJWT({
            email: snap.user.primaryEmailAddress,
            org_id: snap.orgId,
            roles: snap.user.roles,
            permissions: snap.user.permissions,
            hd: snap.user.hd,
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(snap.userId ?? "")
            .setIssuedAt(now)
            .setIssuer(this.issuer)
            .setExpirationTime(now + 60)
            .sign(key);
        this.token = jwt;
        this.tokenExp = now + 60;
        return jwt;
    }
    async signOut(opts = {}) {
        localStorage.removeItem(LS_SESSION);
        this.token = null;
        this.setSnapshot(EMPTY_SNAPSHOT);
        if (opts.redirectUrl)
            window.location.assign(opts.redirectUrl);
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
    async load() {
        try {
            const res = await fetch(`${this.base()}/client`, {
                headers: this.headers(),
                credentials: "include",
            });
            if (!res.ok)
                return;
            this.applyClient(await res.json());
        }
        catch {
            // Frontend API unreachable — stay signed out.
        }
    }
    applyClient(client) {
        const activeId = client.last_active_session_id;
        const session = (client.sessions ?? []).find((s) => s.id === activeId && s.status === "active");
        if (!session) {
            this.activeSessionId = null;
            this.setSnapshot(EMPTY_SNAPSHOT);
            return;
        }
        const user = (session.user ?? {});
        this.activeSessionId = session.id;
        this.setSnapshot({
            isSignedIn: true,
            userId: session.user_id,
            sessionId: session.id,
            orgId: client.org_id ?? null,
            user: {
                id: session.user_id,
                firstName: user.first_name,
                lastName: user.last_name,
                primaryEmailAddress: user.primary_email_address,
                roles: user.roles ?? [],
                permissions: user.permissions ?? [],
                hd: user.hd,
            },
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
        await this.load();
        const params = new URLSearchParams(window.location.search);
        return { redirectTo: params.get("redirect_url_complete") ?? "/" };
    }
    async getToken() {
        if (!this.activeSessionId)
            return null;
        const res = await fetch(`${this.base()}/client/sessions/${this.activeSessionId}/tokens`, {
            method: "POST",
            headers: { ...this.headers(), "Content-Type": "application/json" },
            credentials: "include",
            body: "{}",
        });
        if (!res.ok)
            return null;
        const data = (await res.json());
        return data.jwt ?? null;
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
        this.setSnapshot(EMPTY_SNAPSHOT);
        if (opts.redirectUrl)
            window.location.assign(opts.redirectUrl);
    }
}
//# sourceMappingURL=core.js.map