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

export type EmailCodePurpose = "sign_up" | "sign_in" | "reset_password"

export interface EmailAuthError {
  ok: false
  /** Stable code (Clerk spellings where one exists): form_identifier_invalid, too_many_requests,
   *  email_not_delivered, verification_expired, verification_failed, form_code_incorrect,
   *  form_password_invalid, form_password_incorrect, user_locked, password_disabled, or an
   *  admission code (identity_blocked, identity_not_allowlisted, sign_up_restricted, ...). */
  code: string
  /** Written to be shown to the person as-is. */
  message: string
  longMessage?: string
  retryAfterSeconds?: number
  attemptsRemaining?: number
  traceId?: string
  status: number
}

export type EmailCodeResult =
  | { ok: true; status: "code_sent"; email: string; expiresInSeconds: number; passwordEnabled: boolean }
  | EmailAuthError

export type EmailSignInResult = { ok: true; status: "complete"; redirectUrlComplete: string } | EmailAuthError

async function post(base: string, path: string, body: Record<string, unknown>): Promise<{ status: number; json: Record<string, unknown> }> {
  let res: Response
  try {
    res = await fetch(`${base.replace(/\/$/, "")}${path}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    })
  } catch {
    return { status: 0, json: { error: "network_error", error_message: "Could not reach the server. Check your connection and try again." } }
  }
  let json: Record<string, unknown> = {}
  try {
    json = (await res.json()) as Record<string, unknown>
  } catch {
    json = {}
  }
  return { status: res.status, json }
}

function toError(status: number, j: Record<string, unknown>): EmailAuthError {
  return {
    ok: false,
    status,
    code: typeof j.error === "string" ? j.error : status === 404 ? "not_enabled" : "sign_in_not_completed",
    message: typeof j.error_message === "string" ? j.error_message : "Sign-in could not be completed. Please try again.",
    ...(typeof j.error_long_message === "string" ? { longMessage: j.error_long_message } : {}),
    ...(typeof j.retry_after_seconds === "number" ? { retryAfterSeconds: j.retry_after_seconds } : {}),
    ...(typeof j.attempts_remaining === "number" ? { attemptsRemaining: j.attempts_remaining } : {}),
    ...(typeof j.trace_id === "string" ? { traceId: j.trace_id } : {}),
  }
}

/** Ask for a code. The answer is the same whether or not an account exists. */
export async function requestEmailCode(
  base: string,
  params: { email: string; purpose?: EmailCodePurpose },
): Promise<EmailCodeResult> {
  const { status, json } = await post(base, "/email/code", { email: params.email, purpose: params.purpose ?? "sign_in" })
  if (status === 200 && json.status === "code_sent") {
    return {
      ok: true,
      status: "code_sent",
      email: String(json.email ?? params.email),
      expiresInSeconds: Number(json.expires_in_seconds ?? 600),
      passwordEnabled: json.password_enabled === true,
    }
  }
  return toError(status, json)
}

function complete(status: number, json: Record<string, unknown>): EmailSignInResult {
  if (status === 200 && json.status === "complete") {
    return { ok: true, status: "complete", redirectUrlComplete: String(json.redirect_url_complete ?? "/") }
  }
  return toError(status, json)
}

/** Type the code back. A `password` here is stored only because the code just proved the mailbox. */
export async function verifyEmailCode(
  base: string,
  params: { email: string; code: string; password?: string; redirectUrlComplete?: string },
): Promise<EmailSignInResult> {
  const { status, json } = await post(base, "/email/verify", {
    email: params.email,
    code: params.code,
    ...(params.password ? { password: params.password } : {}),
    ...(params.redirectUrlComplete ? { redirect_url_complete: params.redirectUrlComplete } : {}),
  })
  return complete(status, json)
}

/** Sign in with an email and password. */
export async function signInWithPassword(
  base: string,
  params: { email: string; password: string; redirectUrlComplete?: string },
): Promise<EmailSignInResult> {
  const { status, json } = await post(base, "/email/password", {
    email: params.email,
    password: params.password,
    ...(params.redirectUrlComplete ? { redirect_url_complete: params.redirectUrlComplete } : {}),
  })
  return complete(status, json)
}
