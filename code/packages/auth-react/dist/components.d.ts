import { type ReactNode } from "react";
import type { Appearance, PermissionCheck } from "./types.js";
interface SignInProps {
    routing?: "hash" | "path" | "virtual";
    path?: string;
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
/** Google One Tap prompt. In the dev mock there is no real prompt, so it renders nothing. */
export declare function GoogleOneTap(_props: {
    cancelOnTapOutside?: boolean;
    fallbackRedirectUrl?: string;
    signInForceRedirectUrl?: string;
}): ReactNode;
/** Completes the SSO redirect handshake on the callback route, then forwards the user on. */
export declare function AuthenticateWithRedirectCallback(props: {
    signInForceRedirectUrl?: string;
    signUpForceRedirectUrl?: string;
    continueSignUpUrl?: string;
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
export {};
