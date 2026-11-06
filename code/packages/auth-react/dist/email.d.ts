/**
 * The email connection, browser side: three calls against the Frontend API's JSON routes
 * (auth-backend `connections: [{ strategy: "email", ... }]`, docs/apis/frontend/sign-in-email.mdx).
 *
 *   requestEmailCode   POST {base}/email/code      a six-digit code is emailed
 *   verifyEmailCode    POST {base}/email/verify    the code (and optionally a new password) signs in
 *   signInWithPassword POST {base}/email/password  email + password signs in
 *
 * On `{ ok: true, status: "complete" }` the session cookie is already set. Finish the way every
 * other connection finishes: send the browser to the app's sso-callback page (with
 * `redirect_url_complete`), which reloads the client and forwards on — so nothing downstream has to
 * know which connection was used.
 *
 * Every call is same-origin with `Content-Type: application/json`; the server refuses anything else
 * (that is what stops a cross-site form from signing a visitor into someone else's account).
 */
export type EmailCodePurpose = "sign_up" | "sign_in" | "reset_password";
export interface EmailAuthError {
    ok: false;
    /** Stable code (Clerk spellings where one exists): form_identifier_invalid, too_many_requests,
     *  email_not_delivered, verification_expired, verification_failed, form_code_incorrect,
     *  form_password_invalid, form_password_incorrect, user_locked, password_disabled, or an
     *  admission code (identity_blocked, identity_not_allowlisted, sign_up_restricted, ...). */
    code: string;
    /** Written to be shown to the person as-is. */
    message: string;
    longMessage?: string;
    retryAfterSeconds?: number;
    attemptsRemaining?: number;
    traceId?: string;
    status: number;
}
export type EmailCodeResult = {
    ok: true;
    status: "code_sent";
    email: string;
    expiresInSeconds: number;
    passwordEnabled: boolean;
} | EmailAuthError;
export type EmailSignInResult = {
    ok: true;
    status: "complete";
    redirectUrlComplete: string;
} | EmailAuthError;
/** Ask for a code. The answer is the same whether or not an account exists. */
export declare function requestEmailCode(base: string, params: {
    email: string;
    purpose?: EmailCodePurpose;
}): Promise<EmailCodeResult>;
/** Type the code back. A `password` here is stored only because the code just proved the mailbox. */
export declare function verifyEmailCode(base: string, params: {
    email: string;
    code: string;
    password?: string;
    redirectUrlComplete?: string;
}): Promise<EmailSignInResult>;
/** Sign in with an email and password. */
export declare function signInWithPassword(base: string, params: {
    email: string;
    password: string;
    redirectUrlComplete?: string;
}): Promise<EmailSignInResult>;
