"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthClient = void 0;
const permissions_js_1 = require("./permissions.js");
const verify_js_1 = require("./verify.js");
/** `authClient.users` — read and deprovision users via the Backend API. */
class UsersResource {
    client;
    constructor(client) {
        this.client = client;
    }
    getUser(userId) {
        return this.client.request(`/users/${userId}`);
    }
    getUserList(params = {}) {
        const q = new URLSearchParams();
        if (params.limit != null)
            q.set("limit", String(params.limit));
        if (params.offset != null)
            q.set("offset", String(params.offset));
        if (params.orderBy)
            q.set("order_by", params.orderBy);
        for (const email of params.emailAddress ?? [])
            q.append("email_address", email);
        const qs = q.toString();
        return this.client.request(`/users${qs ? `?${qs}` : ""}`);
    }
    updateUserMetadata(userId, body) {
        return this.client.request(`/users/${userId}/metadata`, {
            method: "PATCH",
            body: JSON.stringify(body),
        });
    }
    deleteUser(userId) {
        return this.client.request(`/users/${userId}`, { method: "DELETE" });
    }
}
/** `authClient.sessions` — inspect, verify, and immediately revoke server-side sessions. */
class SessionsResource {
    client;
    constructor(client) {
        this.client = client;
    }
    getSessionList(params = {}) {
        const q = new URLSearchParams();
        if (params.userId)
            q.set("user_id", params.userId);
        if (params.status)
            q.set("status", params.status);
        const qs = q.toString();
        return this.client.request(`/sessions${qs ? `?${qs}` : ""}`);
    }
    revokeSession(sessionId) {
        return this.client.request(`/sessions/${sessionId}/revoke`, { method: "POST" });
    }
    /** Stateful re-check for sensitive actions — a just-offboarded user fails here. */
    verifySession(sessionId) {
        return this.client.request(`/sessions/${sessionId}/verify`, { method: "POST" });
    }
}
/** `authClient.organizations` — orgs/tenants and their memberships. */
class OrganizationsResource {
    client;
    constructor(client) {
        this.client = client;
    }
    getOrganization(params) {
        return this.client.request(`/organizations/${params.organizationId}`);
    }
    getOrganizationMembershipList(params) {
        return this.client.request(`/organizations/${params.organizationId}/memberships`);
    }
    createOrganization(body) {
        return this.client.request(`/organizations`, {
            method: "POST",
            body: JSON.stringify(body),
        });
    }
    updateOrganization(organizationId, body) {
        return this.client.request(`/organizations/${organizationId}`, {
            method: "PATCH",
            body: JSON.stringify(body),
        });
    }
    deleteOrganization(organizationId) {
        return this.client.request(`/organizations/${organizationId}`, { method: "DELETE" });
    }
    /** Add a member with a role — the RBAC join used by JIT/SCIM provisioning. */
    createOrganizationMembership(params) {
        return this.client.request(`/organizations/${params.organizationId}/memberships`, {
            method: "POST",
            body: JSON.stringify({ user_id: params.userId, role: params.role }),
        });
    }
    /** Update a member's role — e.g. when their upstream group membership changes. */
    updateOrganizationMembership(params) {
        return this.client.request(`/organizations/${params.organizationId}/memberships/${params.userId}`, { method: "PATCH", body: JSON.stringify({ role: params.role }) });
    }
    /** Remove a member — e.g. SCIM deprovisioning or losing the gating group. */
    deleteOrganizationMembership(params) {
        return this.client.request(`/organizations/${params.organizationId}/memberships/${params.userId}`, { method: "DELETE" });
    }
}
/** `authClient.invitations` — proactively grant access before first sign-in (spec §8/§12). */
class InvitationsResource {
    client;
    constructor(client) {
        this.client = client;
    }
    getInvitationList(params = {}) {
        const q = new URLSearchParams();
        if (params.status)
            q.set("status", params.status);
        if (params.limit != null)
            q.set("limit", String(params.limit));
        if (params.offset != null)
            q.set("offset", String(params.offset));
        const qs = q.toString();
        return this.client.request(`/invitations${qs ? `?${qs}` : ""}`);
    }
    createInvitation(body) {
        return this.client.request(`/invitations`, {
            method: "POST",
            body: JSON.stringify({
                email_address: body.emailAddress,
                organization_id: body.organizationId,
                role: body.role,
                public_metadata: body.publicMetadata,
            }),
        });
    }
    revokeInvitation(invitationId) {
        return this.client.request(`/invitations/${invitationId}/revoke`, { method: "POST" });
    }
}
/** `authClient.jwtTemplates` — named custom-claim templates for downstream tokens (spec §15). */
class JwtTemplatesResource {
    client;
    constructor(client) {
        this.client = client;
    }
    getJwtTemplateList() {
        return this.client.request(`/jwt_templates`);
    }
    createJwtTemplate(body) {
        return this.client.request(`/jwt_templates`, {
            method: "POST",
            body: JSON.stringify(body),
        });
    }
    updateJwtTemplate(templateId, body) {
        return this.client.request(`/jwt_templates/${templateId}`, {
            method: "PATCH",
            body: JSON.stringify(body),
        });
    }
    deleteJwtTemplate(templateId) {
        return this.client.request(`/jwt_templates/${templateId}`, { method: "DELETE" });
    }
    /** Mint a session token shaped by a template, server-side (spec §15 / jwt-templates.mdx). */
    mintToken(params) {
        return this.client.request(`/tokens`, {
            method: "POST",
            body: JSON.stringify({ session_id: params.sessionId, template: params.template }),
        });
    }
}
/**
 * Typed wrapper over the Backend REST API, authorized with the secret key. Use it from
 * trusted server code only (NestJS services, jobs, webhook/SCIM handlers).
 */
class AuthClient {
    users = new UsersResource(this);
    sessions = new SessionsResource(this);
    organizations = new OrganizationsResource(this);
    invitations = new InvitationsResource(this);
    jwtTemplates = new JwtTemplatesResource(this);
    secretKey;
    apiUrl;
    issuer;
    constructor(opts = {}) {
        this.secretKey = opts.secretKey ?? process.env.AUTH_SECRET_KEY ?? "";
        this.apiUrl = opts.apiUrl ?? process.env.AUTH_BACKEND_API ?? "https://api.localhost/v1";
        this.issuer = opts.issuer ?? process.env.AUTH_JWT_ISSUER;
    }
    get isDevMode() {
        return process.env.AUTH_DEV_MODE === "true";
    }
    /** Networkless JWT verification (JWKS in prod, HS256 dev secret in dev mode). */
    verifyToken(token) {
        return (0, verify_js_1.verifyToken)(token, { issuer: this.issuer });
    }
    /** Verify a token and assert a `<feature>:<action>` permission; throws `Forbidden`. */
    requirePermission(token, permission) {
        return (0, permissions_js_1.requirePermission)(token, permission);
    }
    /** Verify a token and assert a role (e.g. `org:admin`); throws `Forbidden`. */
    requireRole(token, role) {
        return (0, permissions_js_1.requireRole)(token, role);
    }
    /** Verify a machine (M2M / API-key) token for server-to-server calls (spec §15). */
    verifyMachineToken(token) {
        return (0, verify_js_1.verifyMachineToken)(token, { issuer: this.issuer });
    }
    /** Low-level authorized request to the Backend API. */
    async request(path, init = {}) {
        if (this.isDevMode) {
            throw new Error(`@auth/backend: ${init.method ?? "GET"} ${path} is unavailable in dev mode ` +
                `(no live OpenAuthFederated server). Only verifyToken() is supported in dev.`);
        }
        const res = await fetch(`${this.apiUrl.replace(/\/+$/, "")}${path}`, {
            ...init,
            headers: {
                Authorization: `Bearer ${this.secretKey}`,
                "Content-Type": "application/json",
                ...(init.headers ?? {}),
            },
        });
        if (!res.ok) {
            throw new Error(`@auth/backend: ${init.method ?? "GET"} ${path} → ${res.status}`);
        }
        return (await res.json());
    }
}
exports.AuthClient = AuthClient;
//# sourceMappingURL=client.js.map