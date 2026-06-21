import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useState } from "react";
import { useAuthContext } from "./context.js";
import { useAuth, useOrganization, useOrganizationList, useSignIn, useSignUp, useUser, } from "./hooks.js";
// Where a callback rejection (e.g. domain enforcement) is stashed so the sign-in screen can
// show a clear message after we bounce the user back. Read+cleared by <SignIn> / useAuthError.
const SS_AUTH_ERROR = "openauthfed_auth_error_v1";
/** Persist a callback rejection so the sign-in screen can surface it after the redirect. */
function stashAuthError(error) {
    try {
        sessionStorage.setItem(SS_AUTH_ERROR, JSON.stringify(error));
    }
    catch {
        // sessionStorage unavailable — the rejection still routes back; just without the message.
    }
}
/** Read and clear any stashed callback rejection (one-shot). */
export function readAuthError() {
    try {
        const raw = sessionStorage.getItem(SS_AUTH_ERROR);
        if (!raw)
            return null;
        sessionStorage.removeItem(SS_AUTH_ERROR);
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
/**
 * Read the most recent sign-in rejection once, on mount. For apps that render their **own**
 * sign-in screen (instead of the drop-in `<SignIn>`) and still want to show why the last
 * attempt was refused — e.g. a wrong/unauthorized Google account. One-shot: the rejection is
 * cleared as it is read, so a refresh won't re-show a stale message.
 */
export function useAuthError() {
    const [rejection, setRejection] = useState(null);
    useEffect(() => {
        setRejection(readAuthError());
    }, []);
    return rejection;
}
const DEFAULT_PRIMARY = "#0f766e";
const card = {
    width: "100%",
    maxWidth: 360,
    margin: "0 auto",
    padding: 24,
    borderRadius: 12,
    border: "1px solid #e5e7eb",
    background: "#fff",
    boxShadow: "0 1px 2px rgba(0,0,0,0.05)",
    fontFamily: "system-ui, sans-serif",
};
function bigButton(color) {
    return {
        display: "flex",
        width: "100%",
        alignItems: "center",
        justifyContent: "center",
        gap: 8,
        padding: "10px 14px",
        marginTop: 10,
        borderRadius: 8,
        border: "1px solid #d1d5db",
        background: color,
        color: "#fff",
        fontSize: 14,
        fontWeight: 600,
        cursor: "pointer",
    };
}
function primaryColor(appearance, fallback) {
    return (appearance?.variables?.colorPrimary ??
        fallback?.variables?.colorPrimary ??
        DEFAULT_PRIMARY);
}
const rejectionBanner = {
    marginTop: 12,
    padding: "8px 10px",
    borderRadius: 8,
    border: "1px solid #fca5a5",
    background: "#fef2f2",
    color: "#991b1b",
    fontSize: 12,
};
/** Internal: the federated, password-free sign-in/up surface — one button per company domain. */
function FederatedAuth(props) {
    const { connections, config } = useAuthContext();
    const { signIn } = useSignIn();
    const { signUp } = useSignUp();
    const complete = props.forceRedirectUrl ?? props.fallbackRedirectUrl ?? "/";
    const color = primaryColor(props.appearance, config.appearance);
    // Surface a rejection from a prior callback bounce (e.g. domain enforcement, §7.3). One-shot,
    // cleared on read, so a refresh doesn't re-show a stale message.
    const rejection = useAuthError();
    const start = (connectionId) => {
        const authenticate = props.mode === "sign-up"
            ? signUp.authenticateWithRedirect
            : signIn.authenticateWithRedirect;
        authenticate({
            strategy: "oauth_google_workspace",
            connectionId,
            redirectUrl: "/sso-callback",
            redirectUrlComplete: complete,
        });
    };
    return (_jsxs("div", { style: card, children: [_jsx("h1", { style: { fontSize: 18, fontWeight: 700, margin: 0 }, children: "Internal App" }), _jsx("p", { style: { fontSize: 13, color: "#6b7280", marginTop: 4 }, children: "Employees only. Continue with your company Google Workspace." }), rejection && (_jsxs("div", { role: "alert", style: rejectionBanner, children: [_jsx("strong", { style: { display: "block" }, children: rejection.message }), rejection.longMessage && (_jsx("span", { style: { display: "block", marginTop: 4 }, children: rejection.longMessage })), rejection.meta?.allowedDomains?.length ? (_jsxs("span", { style: { display: "block", marginTop: 4 }, children: ["Allowed company ", rejection.meta.allowedDomains.length > 1 ? "domains" : "domain", ":", " ", rejection.meta.allowedDomains.join(", "), "."] })) : null] })), connections.map((conn) => (_jsxs("button", { type: "button", onClick: () => start(conn.id), style: bigButton(color), children: ["Continue with ", conn.domain] }, conn.id))), _jsx(GoogleOneTap, { fallbackRedirectUrl: complete, signInForceRedirectUrl: complete }), _jsx("p", { style: { fontSize: 11, color: "#9ca3af", marginTop: 14 }, children: "No passwords. Access is restricted to company accounts." })] }));
}
/** Complete federated sign-in experience (no password field). */
export function SignIn(props) {
    return (_jsx(FederatedAuth, { mode: "sign-in", forceRedirectUrl: props.forceRedirectUrl, fallbackRedirectUrl: props.fallbackRedirectUrl, appearance: props.appearance }));
}
/** Sign-up surface — funnels into the same federated flow (JIT provisioning). */
export function SignUp(props) {
    return (_jsx(FederatedAuth, { mode: "sign-up", forceRedirectUrl: props.forceRedirectUrl, fallbackRedirectUrl: props.fallbackRedirectUrl, appearance: props.appearance }));
}
/** Lightweight trigger that starts the federated sign-in flow. */
export function SignInButton(props) {
    const { connections } = useAuthContext();
    const { signIn } = useSignIn();
    const onClick = () => signIn.authenticateWithRedirect({
        strategy: "oauth_google_workspace",
        connectionId: connections[0]?.id,
        redirectUrl: "/sso-callback",
        redirectUrlComplete: props.forceRedirectUrl ?? props.fallbackRedirectUrl ?? "/",
    });
    if (props.children) {
        return (_jsx("span", { onClick: onClick, style: { cursor: "pointer" }, children: props.children }));
    }
    return (_jsx("button", { type: "button", onClick: onClick, children: "Sign in" }));
}
/** Sign-up counterpart of <SignInButton>. */
export function SignUpButton(props) {
    const { connections } = useAuthContext();
    const { signUp } = useSignUp();
    const onClick = () => signUp.authenticateWithRedirect({
        strategy: "oauth_google_workspace",
        connectionId: connections[0]?.id,
        redirectUrl: "/sso-callback",
        redirectUrlComplete: props.forceRedirectUrl ?? props.fallbackRedirectUrl ?? "/",
    });
    if (props.children) {
        return (_jsx("span", { onClick: onClick, style: { cursor: "pointer" }, children: props.children }));
    }
    return (_jsx("button", { type: "button", onClick: onClick, children: "Create account" }));
}
/** Ends the session and revokes its server-side record immediately. */
export function SignOutButton(props) {
    const { signOut } = useAuth();
    const onClick = () => signOut({ redirectUrl: props.redirectUrl ?? "/sign-in" });
    if (props.children) {
        return (_jsx("span", { onClick: onClick, style: { cursor: "pointer" }, children: props.children }));
    }
    return (_jsx("button", { type: "button", onClick: onClick, children: "Sign out" }));
}
/** Minimal account control: shows the signed-in email and a sign-out action. */
export function UserButton(props) {
    const { user } = useUser();
    const { signOut } = useAuth();
    if (!user)
        return null;
    return (_jsxs("span", { style: { display: "inline-flex", alignItems: "center", gap: 8 }, children: [_jsx("span", { style: { fontSize: 13, color: "#374151" }, children: user.primaryEmailAddress }), _jsx("button", { type: "button", onClick: () => signOut({ redirectUrl: props.afterSignOutUrl ?? "/sign-in" }), children: "Sign out" })] }));
}
/** Google One Tap prompt. In the dev mock there is no real prompt, so it renders nothing. */
export function GoogleOneTap(_props) {
    return null;
}
/**
 * Completes the SSO redirect handshake on the callback route. On success it forwards the user
 * on; on a rejection (e.g. domain enforcement — `identity_domain_not_allowed`) it stashes the
 * error and bounces back to the sign-in screen so the user sees a clear "restricted to company
 * accounts" message (§7.3). No session is created for a rejected identity.
 */
export function AuthenticateWithRedirectCallback(props) {
    const { core, config } = useAuthContext();
    const { onError } = props;
    useEffect(() => {
        let active = true;
        core.completeRedirectCallback().then((result) => {
            if (!active)
                return;
            if (result.error) {
                stashAuthError(result.error);
                onError?.(result.error);
                window.location.assign(props.signInUrl ?? config.signInUrl);
                return;
            }
            const target = props.signInForceRedirectUrl ?? props.signUpForceRedirectUrl ?? result.redirectTo ?? "/";
            window.location.assign(target);
        });
        return () => {
            active = false;
        };
    }, [
        core,
        config.signInUrl,
        onError,
        props.signInUrl,
        props.signInForceRedirectUrl,
        props.signUpForceRedirectUrl,
    ]);
    return _jsx("div", { style: { padding: 24, fontFamily: "system-ui, sans-serif" }, children: "Completing sign-in\u2026" });
}
/** Gates children behind a role / `<feature>:<action>` permission (UX gating; backend is authoritative). */
export function Protect(props) {
    const { has } = useAuth();
    const allowed = props.condition
        ? props.condition(has)
        : has({ permission: props.permission, role: props.role });
    return _jsx(_Fragment, { children: allowed ? props.children : (props.fallback ?? null) });
}
/** Conditionally render children by sign-in state. */
export function Show(props) {
    const { isSignedIn } = useAuth();
    const match = props.when === "signed-in" ? isSignedIn : !isSignedIn;
    return _jsx(_Fragment, { children: match ? props.children : (props.fallback ?? null) });
}
export function SignedIn(props) {
    return _jsx(Show, { when: "signed-in", children: props.children });
}
export function SignedOut(props) {
    return _jsx(Show, { when: "signed-out", children: props.children });
}
/** Immediately redirect to the federated sign-in flow. */
export function RedirectToSignIn(_props) {
    const { config } = useAuthContext();
    useEffect(() => {
        window.location.assign(config.signInUrl);
    }, [config.signInUrl]);
    return null;
}
/** Immediately redirect to the federated sign-up flow (JIT provisioning). */
export function RedirectToSignUp(_props) {
    const { config } = useAuthContext();
    useEffect(() => {
        window.location.assign(config.signUpUrl);
    }, [config.signUpUrl]);
    return null;
}
/** Renders children only after the SDK has fully initialized. */
export function AuthLoaded(props) {
    const { loadState } = useAuthContext();
    return _jsx(_Fragment, { children: loadState === "loaded" || loadState === "degraded" ? props.children : null });
}
/** Renders children while the SDK is still initializing (spinner/skeleton slot). */
export function AuthLoading(props) {
    const { loadState } = useAuthContext();
    return _jsx(_Fragment, { children: loadState === "loading" ? props.children : null });
}
/** Renders children when the SDK is reachable but degraded (soft warning slot). */
export function AuthDegraded(props) {
    const { loadState } = useAuthContext();
    return _jsx(_Fragment, { children: loadState === "degraded" ? props.children : null });
}
/** Renders children when the SDK failed to initialize (hard error / retry slot). */
export function AuthFailed(props) {
    const { loadState } = useAuthContext();
    return _jsx(_Fragment, { children: loadState === "failed" ? props.children : null });
}
/**
 * Dropdown for switching the active organization. Setting the active org updates `orgId`
 * (and the permissions that apply) throughout the SDK — tab-scoped, so two tabs can hold
 * different active orgs simultaneously (spec §14).
 */
export function OrganizationSwitcher(props) {
    const { isLoaded, userMemberships, setActive } = useOrganizationList();
    const { organization } = useOrganization();
    if (!isLoaded || userMemberships.data.length === 0)
        return null;
    const onChange = async (value) => {
        await setActive({ organization: value === "__personal__" ? null : value });
        if (props.afterSelectOrganizationUrl) {
            window.location.assign(props.afterSelectOrganizationUrl);
        }
    };
    return (_jsxs("select", { "aria-label": "Switch organization", value: organization?.id ?? "__personal__", onChange: (e) => void onChange(e.target.value), style: {
            padding: "6px 10px",
            borderRadius: 8,
            border: "1px solid #d1d5db",
            fontSize: 13,
            fontFamily: "system-ui, sans-serif",
        }, children: [!props.hidePersonal && _jsx("option", { value: "__personal__", children: "Personal" }), userMemberships.data.map((m) => (_jsx("option", { value: m.organization.id, children: m.organization.name }, m.organization.id)))] }));
}
/** Lists the user's organizations so they can select one — a post-sign-in landing page. */
export function OrganizationList(props) {
    const { isLoaded, userMemberships, setActive } = useOrganizationList();
    if (!isLoaded)
        return null;
    const select = async (orgId) => {
        await setActive({ organization: orgId });
        if (props.afterSelectOrganizationUrl) {
            window.location.assign(props.afterSelectOrganizationUrl);
        }
    };
    return (_jsxs("div", { style: card, children: [_jsx("h2", { style: { fontSize: 16, fontWeight: 700, margin: "0 0 8px" }, children: "Choose an organization" }), !props.hidePersonal && (_jsx("button", { type: "button", style: bigButton(DEFAULT_PRIMARY), onClick: () => void select(null), children: "Personal workspace" })), userMemberships.data.map((m) => (_jsx("button", { type: "button", style: bigButton(DEFAULT_PRIMARY), onClick: () => void select(m.organization.id), children: m.organization.name }, m.organization.id)))] }));
}
/**
 * A standalone create-organization form. Multi-tenancy onboarding actually provisions the
 * org through the Backend API; this drop-in captures the name and hands off via the callback.
 */
export function CreateOrganization(props) {
    return (_jsxs("form", { style: card, onSubmit: (e) => {
            e.preventDefault();
            const name = String(new FormData(e.currentTarget).get("name") ?? "").trim();
            if (!name)
                return;
            void Promise.resolve(props.onCreate?.(name)).then(() => {
                if (props.afterCreateOrganizationUrl) {
                    window.location.assign(props.afterCreateOrganizationUrl);
                }
            });
        }, children: [_jsx("h2", { style: { fontSize: 16, fontWeight: 700, margin: "0 0 8px" }, children: "Create organization" }), _jsx("input", { name: "name", placeholder: "Organization name", style: {
                    width: "100%",
                    padding: "8px 10px",
                    borderRadius: 8,
                    border: "1px solid #d1d5db",
                    fontSize: 14,
                } }), _jsx("button", { type: "submit", style: bigButton(DEFAULT_PRIMARY), children: "Create" })] }));
}
/** A read-only management surface for the active org: name, your role, and member count. */
export function OrganizationProfile(_props) {
    const { isLoaded, organization, membership } = useOrganization();
    if (!isLoaded || !organization)
        return null;
    return (_jsxs("div", { style: card, children: [_jsx("h2", { style: { fontSize: 16, fontWeight: 700, margin: 0 }, children: organization.name }), _jsxs("p", { style: { fontSize: 13, color: "#6b7280", marginTop: 6 }, children: ["Your role: ", _jsx("strong", { children: membership?.role ?? "—" })] }), organization.membersCount != null && (_jsxs("p", { style: { fontSize: 13, color: "#6b7280", margin: 0 }, children: ["Members: ", organization.membersCount] }))] }));
}
//# sourceMappingURL=components.js.map