import { type ReactNode } from "react";
import type { Appearance, AuthRejection, PermissionCheck } from "./types.js";
/** Read and clear any stashed callback rejection (one-shot). */
export declare function readAuthError(): AuthRejection | null;
/**
 * Read the most recent sign-in rejection once, on mount. For apps that render their **own**
 * sign-in screen (instead of the drop-in `<SignIn>`) and still want to show why the last
 * attempt was refused — e.g. a wrong/unauthorized Google account. One-shot: the rejection is
 * cleared as it is read, so a refresh won't re-show a stale message.
 */
export declare function useAuthError(): AuthRejection | null;
interface SignInProps {
    routing?: "hash" | "path" | "virtual";
    path?: string;
    signInUrl?: string;
    signUpUrl?: string;
    forceRedirectUrl?: string;
    fallbackRedirectUrl?: string;
    appearance?: Appearance;
}
/** Complete federated sign-in experience (no password field). */
export declare function SignIn(props: SignInProps): ReactNode;
/** Sign-up surface — funnels into the same federated flow (JIT provisioning). */
export declare function SignUp(props: SignInProps): ReactNode;
interface TriggerButtonProps {
    children?: ReactNode;
    mode?: "modal" | "redirect";
    forceRedirectUrl?: string;
    fallbackRedirectUrl?: string;
}
/** Lightweight trigger that starts the federated sign-in flow. */
export declare function SignInButton(props: TriggerButtonProps): ReactNode;
/** Sign-up counterpart of <SignInButton>. */
export declare function SignUpButton(props: TriggerButtonProps): ReactNode;
interface SignOutButtonProps {
    children?: ReactNode;
    redirectUrl?: string;
}
/** Ends the session and revokes its server-side record immediately. */
export declare function SignOutButton(props: SignOutButtonProps): ReactNode;
/** Minimal account control: shows the signed-in email and a sign-out action. */
export declare function UserButton(props: {
    afterSignOutUrl?: string;
}): ReactNode;
/** Google One Tap prompt. Renders nothing until the One Tap UI is wired to the real client. */
export declare function GoogleOneTap(_props: {
    cancelOnTapOutside?: boolean;
    fallbackRedirectUrl?: string;
    signInForceRedirectUrl?: string;
}): ReactNode;
/**
 * Completes the SSO redirect handshake on the callback route. On success it forwards the user
 * on; on a rejection (e.g. domain enforcement — `identity_domain_not_allowed`) it stashes the
 * error and bounces back to the sign-in screen so the user sees a clear "restricted to company
 * accounts" message (§7.3). No session is created for a rejected identity.
 */
export declare function AuthenticateWithRedirectCallback(props: {
    signInForceRedirectUrl?: string;
    signUpForceRedirectUrl?: string;
    continueSignUpUrl?: string;
    /** Where to return on a rejection (defaults to the configured sign-in URL). */
    signInUrl?: string;
    /** Observe the rejection (e.g. to fire an audit/telemetry event) before the bounce. */
    onError?: (error: AuthRejection) => void;
}): ReactNode;
interface ProtectProps {
    permission?: string;
    role?: string;
    condition?: (has: (check?: PermissionCheck) => boolean) => boolean;
    fallback?: ReactNode;
    children?: ReactNode;
}
/** Gates children behind a role / `<feature>:<action>` permission (UX gating; backend is authoritative). */
export declare function Protect(props: ProtectProps): ReactNode;
/** Conditionally render children by sign-in state. */
export declare function Show(props: {
    when: "signed-in" | "signed-out";
    fallback?: ReactNode;
    children?: ReactNode;
}): ReactNode;
export declare function SignedIn(props: {
    children?: ReactNode;
}): ReactNode;
export declare function SignedOut(props: {
    children?: ReactNode;
}): ReactNode;
/** Immediately redirect to the federated sign-in flow. */
export declare function RedirectToSignIn(_props: {
    redirectUrl?: string;
}): ReactNode;
/** Immediately redirect to the federated sign-up flow (JIT provisioning). */
export declare function RedirectToSignUp(_props: {
    redirectUrl?: string;
}): ReactNode;
/** Renders children only after the SDK has fully initialized. */
export declare function AuthLoaded(props: {
    children?: ReactNode;
}): ReactNode;
/** Renders children while the SDK is still initializing (spinner/skeleton slot). */
export declare function AuthLoading(props: {
    children?: ReactNode;
}): ReactNode;
/** Renders children when the SDK is reachable but degraded (soft warning slot). */
export declare function AuthDegraded(props: {
    children?: ReactNode;
}): ReactNode;
/** Renders children when the SDK failed to initialize (hard error / retry slot). */
export declare function AuthFailed(props: {
    children?: ReactNode;
}): ReactNode;
interface OrganizationSwitcherProps {
    hidePersonal?: boolean;
    afterSelectOrganizationUrl?: string;
    appearance?: Appearance;
}
/**
 * Dropdown for switching the active organization. Setting the active org updates `orgId`
 * (and the permissions that apply) throughout the SDK — tab-scoped, so two tabs can hold
 * different active orgs simultaneously (spec §14).
 */
export declare function OrganizationSwitcher(props: OrganizationSwitcherProps): ReactNode;
interface OrganizationListProps {
    hidePersonal?: boolean;
    afterSelectOrganizationUrl?: string;
    appearance?: Appearance;
}
/** Lists the user's organizations so they can select one — a post-sign-in landing page. */
export declare function OrganizationList(props: OrganizationListProps): ReactNode;
/**
 * A standalone create-organization form. Multi-tenancy onboarding actually provisions the
 * org through the Backend API; this drop-in captures the name and hands off via the callback.
 */
export declare function CreateOrganization(props: {
    afterCreateOrganizationUrl?: string;
    onCreate?: (name: string) => void | Promise<void>;
    appearance?: Appearance;
}): ReactNode;
/** A read-only management surface for the active org: name, your role, and member count. */
export declare function OrganizationProfile(_props: {
    routing?: "hash" | "path" | "virtual";
    path?: string;
    appearance?: Appearance;
}): ReactNode;
export {};
