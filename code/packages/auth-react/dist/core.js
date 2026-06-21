import { SignJWT } from "jose";
import { domainSlug, EMPTY_SNAPSHOT, hasPermission, hasRole, } from "./types.js";
const LS_SESSION = "openauthfed_dev_session_v1";
const LS_PENDING = "openauthfed_dev_pending_v1";
// Active-org is per-tab (sessionStorage), so two tabs can hold different active orgs — the
// "tab-aware active organization context" the spec calls out (§14).
const SS_ACTIVE_ORG = "openauthfed_active_org_v1";
/** Shared subscribe/emit plumbing for the external store. */
class BaseCore {
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
    /** Safe localStorage access — returns null when storage is unavailable (SSR / privacy mode). */
    readLocal(key) {
        try {
            return localStorage.getItem(key);
        }
        catch {
            return null;
        }
    }
    writeLocal(key, value) {
        try {
            localStorage.setItem(key, value);
        }
        catch {
            // storage unavailable — the dev mock keeps its session in-memory for this page only.
        }
    }
    removeLocal(key) {
        try {
            localStorage.removeItem(key);
        }
        catch {
            // storage unavailable — nothing to remove.
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
 * Map the documented callback rejection codes
 * (`docs/apis/frontend/sign-up.mdx#domain-enforcement`) to a friendly message. Defaults to the
 * domain-enforcement copy since that is the only rejection the two-global-login flow produces.
 */
function rejectionMessage(code, presentedDomain) {
    const who = presentedDomain ? ` ('${presentedDomain}')` : "";
    switch (code) {
        case "identity_domain_not_allowed":
        case "domain_not_allowed":
            return `This app is restricted to company accounts. The identity${who} is not part of an allowed company domain.`;
        default:
            return "Sign-in could not be completed. Please try again.";
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
        const raw = this.readLocal(LS_SESSION);
        if (!raw) {
            this.setState("loaded");
            return;
        }
        try {
            const stored = JSON.parse(raw);
            // Honor a per-tab active org if one was chosen and is still a valid membership.
            const activeOrg = this.readActiveOrg();
            const orgId = activeOrg && stored.memberships?.some((m) => m.organization.id === activeOrg)
                ? activeOrg
                : stored.orgId;
            this.setSnapshot({ ...stored, orgId });
        }
        catch {
            this.removeLocal(LS_SESSION);
        }
        finally {
            this.setState("loaded");
        }
    }
    async authenticateWithRedirect(params) {
        const conn = this.connections().find((c) => c.id === params.connectionId) ?? this.connections()[0];
        this.writeLocal(LS_PENDING, JSON.stringify({ domain: conn?.domain, redirectUrlComplete: params.redirectUrlComplete }));
        window.location.assign(params.redirectUrl);
    }
    async completeRedirectCallback() {
        const raw = this.readLocal(LS_PENDING);
        this.removeLocal(LS_PENDING);
        const pending = raw ? JSON.parse(raw) : null;
        const domain = pending?.domain ?? this.allowedDomains[0];
        // Domain enforcement (the rejection path of §7.3): even though the dev mock has no real
        // Google round-trip, model the platform's domain gate so the rejection is exercisable.
        // An explicit `?auth_reject=<domain>` on the callback URL simulates an outsider returning
        // from the IdP; a pending domain outside the allowlist is likewise refused. No session is
        // created — mirrors `identity_domain_not_allowed`.
        let presentedDomain = domain;
        try {
            const simulated = new URLSearchParams(window.location.search).get("auth_reject");
            if (simulated)
                presentedDomain = simulated;
        }
        catch {
            // window.location unavailable (SSR) — fall back to the pending domain.
        }
        if (!presentedDomain || !this.allowedDomains.includes(presentedDomain)) {
            this.setSnapshot(EMPTY_SNAPSHOT);
            return {
                error: {
                    code: "identity_domain_not_allowed",
                    message: rejectionMessage("identity_domain_not_allowed", presentedDomain),
                    presentedDomain,
                },
            };
        }
        const snapshot = this.buildSession(presentedDomain);
        this.writeLocal(LS_SESSION, JSON.stringify(snapshot));
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
        // Two demo orgs so <OrganizationSwitcher> has something to switch between, and so the
        // active-org RBAC scoping is exercisable: admin in one, viewer in the other.
        const memberships = [
            {
                id: `orgmem_dev_${slug}_internal`,
                organization: { id: "org_dev_internal", name: `${domain} (Internal)`, slug: "internal" },
                role: "org:admin",
                permissions: ["*:read", "*:write", "org:sys_memberships:manage"],
            },
            {
                id: `orgmem_dev_${slug}_client`,
                organization: { id: "org_dev_client", name: "Client Workspace", slug: "client" },
                role: "org:viewer",
                permissions: ["*:read"],
            },
        ];
        const activeOrg = this.readActiveOrg();
        const orgId = activeOrg && memberships.some((m) => m.organization.id === activeOrg)
            ? activeOrg
            : "org_dev_internal";
        return {
            isSignedIn: true,
            userId: user.id,
            sessionId: `sess_dev_${slug}`,
            orgId,
            user,
            memberships,
            lastVerifiedAt: Math.floor(Date.now() / 1000),
        };
    }
    async getToken(opts = {}) {
        const snap = this.snapshot;
        if (!snap.isSignedIn || !snap.user)
            return null;
        const now = Math.floor(Date.now() / 1000);
        // A templated token is minted fresh each call (its claim shape may differ); the default
        // token is cached until ~10s before expiry. Org switches invalidate the cache below.
        if (!opts.template && this.token && this.tokenExp - now > 10)
            return this.token;
        // Scope the token claims to the active organization's grants (tab-aware RBAC).
        const { roles, permissions } = this.activeGrants();
        const key = new TextEncoder().encode(this.devSharedSecret);
        const jwt = await new SignJWT({
            email: snap.user.primaryEmailAddress,
            org_id: snap.orgId,
            // `sid` (session id) lets a backend verify/revoke the server-side session record for
            // sensitive actions and sign-out, matching the production token shape.
            sid: snap.sessionId,
            roles,
            permissions,
            hd: snap.user.hd,
            ...(opts.template ? { template: opts.template } : {}),
        })
            .setProtectedHeader({ alg: "HS256" })
            .setSubject(snap.userId ?? "")
            .setIssuedAt(now)
            .setIssuer(this.issuer)
            .setExpirationTime(now + 60)
            .sign(key);
        if (!opts.template) {
            this.token = jwt;
            this.tokenExp = now + 60;
        }
        return jwt;
    }
    async setActiveOrg(orgId) {
        await super.setActiveOrg(orgId);
        // Drop the cached token so the next getToken() reflects the new org's grants.
        this.token = null;
    }
    async reverify() {
        // Dev mock: no real IdP round-trip — just stamp a fresh verification time.
        if (!this.snapshot.isSignedIn)
            return;
        const next = { ...this.snapshot, lastVerifiedAt: Math.floor(Date.now() / 1000) };
        this.writeLocal(LS_SESSION, JSON.stringify(next));
        this.setSnapshot(next);
    }
    async signOut(opts = {}) {
        this.removeLocal(LS_SESSION);
        this.writeActiveOrg(null);
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
            if (!res.ok) {
                // Reachable but not OK (e.g. 5xx) → degraded; signed-out but the API is up.
                this.setState(res.status >= 500 ? "degraded" : "loaded");
                return;
            }
            this.applyClient(await res.json());
            this.setState("loaded");
        }
        catch {
            // Frontend API unreachable — auth cannot initialize at all.
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
        // error code rather than a session when the verified identity fails domain enforcement.
        // No session was created — surface the rejection instead of forwarding the user on. See
        // `docs/apis/frontend/sign-up.mdx#domain-enforcement`.
        const errorCode = params.get("error") ?? params.get("error_code");
        if (errorCode) {
            const presentedDomain = params.get("presented_domain") ?? undefined;
            this.activeSessionId = null;
            this.setSnapshot(EMPTY_SNAPSHOT);
            return {
                error: {
                    code: errorCode,
                    message: params.get("error_message") ?? rejectionMessage(errorCode, presentedDomain),
                    presentedDomain,
                },
            };
        }
        await this.load();
        // A reachable Frontend API that nonetheless yields no active session here means the attempt
        // did not establish one (e.g. a rejected identity that produced no error query param).
        if (!this.snapshot.isSignedIn) {
            return {
                error: {
                    code: "sign_in_not_completed",
                    message: rejectionMessage("sign_in_not_completed"),
                },
            };
        }
        return { redirectTo: params.get("redirect_url_complete") ?? "/" };
    }
    async getToken(opts = {}) {
        if (!this.activeSessionId)
            return null;
        // A named JWT template mints against a different Frontend-API path (spec §15).
        const path = opts.template
            ? `${this.base()}/client/sessions/${this.activeSessionId}/tokens/${opts.template}`
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
        return data.jwt ?? null;
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
        this.writeActiveOrg(null);
        this.setSnapshot(EMPTY_SNAPSHOT);
        if (opts.redirectUrl)
            window.location.assign(opts.redirectUrl);
    }
}
//# sourceMappingURL=core.js.map