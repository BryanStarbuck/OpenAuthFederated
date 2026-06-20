import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect } from "react";
import { useAuthContext } from "./context.js";
import { useAuth, useSignIn, useSignUp, useUser } from "./hooks.js";
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
/** Internal: the federated, password-free sign-in/up surface — one button per company domain. */
function FederatedAuth(props) {
    const { connections, config } = useAuthContext();
    const { signIn } = useSignIn();
    const { signUp } = useSignUp();
    const complete = props.forceRedirectUrl ?? props.fallbackRedirectUrl ?? "/";
    const color = primaryColor(props.appearance, config.appearance);
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
    return (_jsxs("div", { style: card, children: [_jsx("h1", { style: { fontSize: 18, fontWeight: 700, margin: 0 }, children: "Internal App" }), _jsx("p", { style: { fontSize: 13, color: "#6b7280", marginTop: 4 }, children: "Employees only. Continue with your company Google Workspace." }), connections.map((conn) => (_jsxs("button", { type: "button", onClick: () => start(conn.id), style: bigButton(color), children: ["Continue with ", conn.domain] }, conn.id))), _jsx("p", { style: { fontSize: 11, color: "#9ca3af", marginTop: 14 }, children: "No passwords. Access is restricted to company accounts." })] }));
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
/** Completes the SSO redirect handshake on the callback route, then forwards the user on. */
export function AuthenticateWithRedirectCallback(props) {
    const { core } = useAuthContext();
    useEffect(() => {
        let active = true;
        core.completeRedirectCallback().then(({ redirectTo }) => {
            if (!active)
                return;
            const target = props.signInForceRedirectUrl ?? props.signUpForceRedirectUrl ?? redirectTo;
            window.location.assign(target);
        });
        return () => {
            active = false;
        };
    }, [core, props.signInForceRedirectUrl, props.signUpForceRedirectUrl]);
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
//# sourceMappingURL=components.js.map