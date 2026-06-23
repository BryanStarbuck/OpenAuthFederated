Look for security problems in OpenAuthFederated and in the two web apps that
consume it. Produce three plain-text security audit reports. Read every
relevant source file in the library and in each caller, then write up every
security bug, missing control, and risky situation you can find.


====================================================================
VARIABLES
====================================================================

ROOT_DIR dir is ~/BGit/Bryan_git/OpenAuthFederated
* The OpenAuthFederated authentication/identity LIBRARY. This is the thing the
  web apps embed as their SAML/OIDC Service-Provider library. It is NOT a web
  app itself.

AUTH_CODE_DIR dir is {ROOT_DIR}/code
* The library source. Two packages live under {AUTH_CODE_DIR}/packages :
    * auth-backend  -- server-side NestJS/Node auth, SAML/OIDC, sessions, RBAC.
    * auth-react    -- React UI components, hooks, client token/session handling.

OUTPUT_DIR dir is {ROOT_DIR}/audit_security
* Where the three output .txt reports get written. This prompt file lives here.

APP_1_DIR dir is ~/BGit/all/app
* Web app #1. Name = "Internal Web App". Internal employees-only hub. Consumes
  OpenAuthFederated as its auth layer. Code under {APP_1_DIR}/code .

APP_2_DIR dir is ~/BGit/all/marketing/ai
* Web app #2. Name = "Marketing AI" (Social Media AI Marketing Engine).
  Consumes OpenAuthFederated as its auth layer. Code under {APP_2_DIR}/code .

OUT_APP_1_FILE is file {OUTPUT_DIR}/Internal_Web_App.txt
OUT_APP_2_FILE is file {OUTPUT_DIR}/Marketing_AI.txt
OUT_LIB_FILE   is file {OUTPUT_DIR}/OpenAuthFederated.txt
* Output is plain text (.txt), NOT markdown. Each file name matches the name of
  the web app it covers (underscores, no spaces). The library report is named
  after the library.


====================================================================
WHAT THIS PROMPT DOES
====================================================================

* OpenAuthFederated is an open-source identity/auth library (an open-source
  equivalent of hosted identity providers). The two web apps above EMBED it and
  call into it to authenticate users and authorize actions.
* This audit hunts for SECURITY problems in three scopes and writes one report
  per scope:
    1. Internal Web App  -- how APP_1 uses the library, plus app-side auth code.
    2. Marketing AI      -- how APP_2 uses the library, plus app-side auth code.
    3. OpenAuthFederated -- the library on its own, ignoring all callers.
* Run the three stages in order. Each stage reads code and writes exactly one
  .txt report in the format defined below.
* Goal is COVERAGE: output as many real problems as can be found. Do not stop at
  a handful. Prefer more findings over fewer. Each finding must be concrete and
  tied to specific source files and call counts -- no generic advice.


====================================================================
SECURITY THINGS TO LOOK FOR (apply in every stage)
====================================================================

* Authentication: SAML 2.0 assertion validation (signature, issuer, audience,
  recipient, NotBefore/NotOnOrAfter, InResponseTo, replay), OIDC ID-token
  validation (signature, iss, aud, exp, nonce), hosted-domain (hd) and
  email_verified checks. SAML 1.x must be rejected.
* Domain enforcement: sign-in restricted to the allowed verified domain(s);
  unverified emails and out-of-org accounts rejected.
* Session model: short-lived JWT access tokens, rotating HttpOnly refresh
  cookie, server-side session records, immediate revocation, logout, idle and
  absolute timeouts, fixation, rotation on privilege change.
* Token handling: secret strength and storage, algorithm pinning (no alg=none,
  no HS/RS confusion), expiry, audience, no long-lived secrets in localStorage.
* Cookies / CSRF: SameSite, HttpOnly, Secure, CSRF tokens or double-submit,
  state parameter on OIDC, RelayState handling on SAML.
* Authorization / RBAC: group-to-role mapping, role-to-permission checks,
  authoritative server-side enforcement, IDOR, missing guards on routes,
  privilege escalation, default-allow.
* Provisioning: JIT account creation safety, SCIM endpoint auth, deprovision
  promptness, webhook signature verification.
* Transport / headers: HTTPS enforcement, HSTS, CSP, CORS misconfiguration,
  open redirect (ACS / redirect_uri / RelayState / returnTo).
* Input handling: injection (SQL/NoSQL/command/LDAP), XXE in SAML XML parsing,
  XML signature wrapping, deserialization, SSRF on metadata/JWKS fetch.
* Secrets: hardcoded keys/passwords, secrets in logs, secrets in repo.
* Crypto: weak/MD5/SHA1, predictable randomness for tokens/state/nonce,
  missing constant-time compare.
* Logging / audit: missing audit of sign-in/out/refresh/permission-denied/admin
  actions; sensitive data in logs.
* Error handling: leaking stack traces, user enumeration, verbose errors.
* Dependencies: known-vulnerable or unpinned auth-critical packages.
* For the two app stages additionally look at: misuse of the library API,
  trusting client-supplied identity, bypassing guards, missing auth on routes,
  storing tokens insecurely, duplicating/forking the library's checks wrongly.


====================================================================
OUTPUT FILE FORMAT (identical for all three .txt files)
====================================================================

Plain text only. No markdown. Use these sections.

* Header block:
    * Title line: report name (web app name or "OpenAuthFederated").
    * Scope line: which directories were analyzed (absolute paths).
    * One-line summary: total count of findings.

* TABLE OF CONTENTS:
    * A numbered list. One line per finding:  N. <short title>  [SEVERITY]
    * SEVERITY is one of: CRITICAL, HIGH, MEDIUM, LOW.
    * Order findings highest severity first.

* DETAILS:
    * One numbered entry per finding, matching the TOC numbers. Separate each
      entry with a line of ==== characters. Each entry is an extensive write-up
      with these labeled fields:

        N. <short title>  [SEVERITY]

        SITUATION / PROBLEM:
            What is the security situation that will be a problem. Plain,
            concrete description of what is wrong.

        ROOT CAUSE:
            The underlying cause -- what in the code/design makes this possible.

        SCENARIO:
            The concrete scenario / attack story where it goes wrong.

        RISK:
            What an attacker gains or what breaks. Impact and likelihood.

        REPRO STEPS:
            Numbered steps to reproduce or demonstrate the problem.

        SOURCE FILES INVOLVED:
            Every file path that participates, with line ranges where known.
            Include BOTH the auth library files under {AUTH_CODE_DIR} AND the
            calling app files under {APP_x_DIR} where relevant. List file paths.
            Do NOT name classes or methods -- refer to files and locations.

        CALL COUNT:
            The number of call sites that trigger the problem (how many places
            in the code make the call that causes it). Give the count and list
            the files where those calls live.

        FIX:
            * Root cause being fixed: which underlying cause this addresses.
            * How: the approach.
            * Structure of the fix: how the fix is organized.
            * Files changed and how: each file that gets edited and what the
              edit is. Cover both the library and the app side when both move.

* End each file with a footer line of ==== and "END OF REPORT".


====================================================================
STAGE 1 -- Internal Web App  ->  OUT_APP_1_FILE
====================================================================

* Read the library so you understand its public surface and its security
  guarantees: walk {AUTH_CODE_DIR}/packages/auth-backend and
  {AUTH_CODE_DIR}/packages/auth-react .
* Read the consuming app: walk {APP_1_DIR}/code (and {APP_1_DIR}/cli if it
  touches auth). Find every place the app calls into OpenAuthFederated, every
  auth/session/RBAC decision the app makes, and every route or action gated by
  auth.
* Find every security problem in HOW THIS APP USES THE LIBRARY and in the app's
  own auth-adjacent code: misuse of the API, trusting client identity, missing
  guards, insecure token/cookie storage, missing domain checks, etc. Library
  bugs that this app's usage actually triggers belong here too (and again in
  Stage 3 from the library's own point of view).
* Write OUT_APP_1_FILE in the format above. Title = "Internal Web App".


====================================================================
STAGE 2 -- Marketing AI  ->  OUT_APP_2_FILE
====================================================================

* Same procedure as Stage 1, for {APP_2_DIR}. Read {APP_2_DIR}/code (and
  {APP_2_DIR}/cli if it touches auth). Find every call into OpenAuthFederated
  and every auth/session/RBAC decision the app makes.
* Find every security problem in how THIS app uses the library and in its own
  auth-adjacent code.
* Write OUT_APP_2_FILE in the format above. Title = "Marketing AI".


====================================================================
STAGE 3 -- OpenAuthFederated library alone  ->  OUT_LIB_FILE
====================================================================

* Ignore the callers. Analyze ONLY {AUTH_CODE_DIR} (both packages auth-backend
  and auth-react) as a standalone library.
* Find every security bug and missing control that exists in the library itself
  right now, independent of how anyone calls it: SAML/OIDC validation gaps,
  session/token weaknesses, RBAC holes, CSRF/cookie issues, XML parsing
  (XXE / signature wrapping), open redirect, crypto/randomness, secret handling,
  audit gaps, header/transport defaults, injection, SSRF on JWKS/metadata fetch,
  dependency risks.
* Source files involved and call counts refer to library-internal files only.
* Write OUT_LIB_FILE in the format above. Title = "OpenAuthFederated".


====================================================================
RUN ORDER
====================================================================

* Run STAGE 1, then STAGE 2, then STAGE 3. Each stage writes its own .txt file.
* Each report stands alone and is complete. Maximize the number of real,
  concrete, file-anchored findings in each.
* Output to stdout when each file is written:
    --------------------------------------------------------------
    WROTE <path>  --  <N> findings
    --------------------------------------------------------------
