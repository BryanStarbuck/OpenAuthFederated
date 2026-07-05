Look for security problems in OpenAuthFederated (the library) and in every web
app that consumes it. Produce (1) one plain-text report per scope, and (2) two
aggregate roll-up files. Read every relevant source file in the library and in
each caller, then write up every security bug, missing control, risky default,
and every place a caller uses the library incorrectly.

This is a RE-RUNNABLE audit. Run it whenever the library or a caller changes.


====================================================================
RULE 0 -- AUDIT THE CURRENT CODE, NOT AN OLD REPORT
====================================================================

* The library is under active hardening. Earlier runs of this audit produced
  reports that are now STALE -- many findings they list have since been fixed in
  the code (algorithm pinning, SAML audience check, InResponseTo + assertion
  replay, HKDF-derived per-cookie subkeys, fail-closed weak-secret guard, open
  redirect allowlist, security headers, PII log redaction, etc.).
* Therefore: NEVER copy a finding from a prior report. Open the file and the exact
  line range and PROVE the weakness still exists in the code as it is right now.
  If the code already defends against it, do not report it.
* Conversely, do not assume a control exists because a comment or a doc says so --
  confirm the code actually does it (a config comment can over-promise a guarantee
  the code only half-enforces; that gap is itself a finding).


====================================================================
VARIABLES
====================================================================

ROOT_DIR dir is ~/BGit/Bryan_git/OpenAuthFederated
* The OpenAuthFederated authentication/identity LIBRARY. The web apps embed it as
  their SAML 2.0 / OIDC Service-Provider library. It is NOT a web app itself.

AUTH_CODE_DIR dir is {ROOT_DIR}/code
* The library source. Two packages under {AUTH_CODE_DIR}/packages :
    * auth-backend  (npm name @auth/backend)  -- server-side Node auth: embedded
      Frontend API, Google OIDC, SAML 2.0 SP, sessions, session store, RBAC,
      token verify, backend REST client, webhook verify.
    * auth-react    (npm name @auth/react)    -- React UI components, hooks,
      client token/session handling.

OUTPUT_DIR dir is {ROOT_DIR}/audit_security
* Where every output file is written. This prompt file lives here.

CALLERS -- the web apps that consume the library. Detect them, do not assume the
list is fixed. A caller is any repo with a non-node_modules, non-dist reference to
`@auth/backend`, `@auth/react`, `createFederatedFrontend`, `createAuthFrontend`,
or `OpenAuthFederated`. As of the last run the consumers were:

    APP  Internal Web App     dir ~/BGit/all/app
    APP  Marketing AI         dir ~/BGit/all/marketing/ai
    APP  Large File Bridge    dir ~/BGit/Bryan_git/LargeFileBridge
    APP  Email Delivery Hero  dir ~/BGit/Bryan_git/EmailDeliveryHero
    APP  Philosophers Stone   dir ~/BGit/Bryan_git/Philosophers_Stone
    APP  The Starbucks        dir ~/BGit/Bryan_git/the_starbucks

Checked and NOT consuming the library at the last run (exclude unless a rescan
finds a new reference): ~/BGit/act3/Front_AI_Coding (React UI, talks to a Go
backend), ~/BGit/all/tools/voice_improve, ~/BGit/all/jfk/code/simulator,
~/BGit/all/film/platform. The JFK Social backend (~/BGit/act3/AI_Coding) is Go and
does not embed this Node library.

Re-detect the caller list at the start of every run:
    rg -l --glob '!**/node_modules/**' --glob '!**/dist/**' \
       -e '@auth/backend' -e '@auth/react' -e 'createFederatedFrontend' \
       -e 'createAuthFrontend' -e 'OpenAuthFederated' <candidate-dir>


====================================================================
OUTPUT FILES
====================================================================

Per-scope reports (plain text .txt, format defined below):
    {OUTPUT_DIR}/OpenAuthFederated.txt   -- the library alone, ignoring callers.
    {OUTPUT_DIR}/Internal_Web_App.txt    -- one file per caller. File name = the
    {OUTPUT_DIR}/Marketing_AI.txt           app name in Underscore_Case, matching
    {OUTPUT_DIR}/Large_File_Bridge.txt      the CALLERS list above. Create a new
    {OUTPUT_DIR}/Email_Delivery_Hero.txt    .txt for every newly-detected caller.
    {OUTPUT_DIR}/Philosophers_Stone.txt
    {OUTPUT_DIR}/The_Starbucks.txt

Aggregate roll-ups (Markdown .md, format defined below):
    {OUTPUT_DIR}/security_bugs_to_fix.md
    * Every SECURITY bug we should fix, pulled from ALL reports above -- both the
      library's own bugs and each app's app-side bugs. Deduplicated, ranked most
      severe first, each row pointing back to the per-scope report and the source
      file. This is the master fix list.
    {OUTPUT_DIR}/web_apps_calling_us_incorrectly.md
    * Every place a web app calls the library INCORRECTLY (misuse of the API,
      missing/lax config, bypassing a guarantee). Grouped by app, each row naming
      the app, the wrong call, the correct call, and the risk. This is what we send
      back to each app team.

Output to stdout after writing each file:
    --------------------------------------------------------------
    WROTE <path>  --  <N> findings
    --------------------------------------------------------------


====================================================================
THE LIBRARY USAGE CONTRACT (what "calling us correctly" means)
====================================================================

A caller is using OpenAuthFederated correctly only if ALL of these hold. Each is a
place to look for a "calling us incorrectly" finding.

Configuration of createFederatedFrontend / createAuthFrontend:
* sessionSecret is >=32 chars, non-placeholder, and sourced from OUT of the repo
  (env or loadOrCreateSecret) -- never hardcoded or committed. (The constructor
  throws on a weak/short/placeholder secret, so a caller that fails to start is a
  smell; a caller that hardcodes a long constant is a bug.)
* allowedDomains names the real company domain(s). Empty, "gmail.com", a wildcard,
  or a domain the app does not own = anyone can sign in.
* requireHostedDomain is true for any Workspace-gated app. Default is FALSE: with it
  false, a consumer Google account whose email domain happens to be on
  allowedDomains passes WITHOUT being a Workspace member (no hd claim).
* cookiePrefix is DISTINCT per app. Cookies are not port-scoped, so two apps on the
  same host both using the default "oaf" prefix clobber each other's session cookie
  (logout churn, and cross-app session confusion when secrets/prefixes collide).
* audience: if the app relies on audience to isolate its tokens from a sibling app,
  it MUST pass `audience` on BOTH the mint side (createFederatedFrontend) AND the
  verify side (the verify/authenticate options). The library stamps `aud` on the
  token but embedded verifyToken does NOT enforce it unless the caller passes it,
  because configureEmbeddedVerification is not given the audience. Configuring
  audience on mint only is a false sense of isolation.
* cookieSecure is true in production (default true). Setting false outside local
  http dev ships a non-Secure session cookie.
* sessionStore is provided whenever the app needs revocation, "sign out
  everywhere", or an inactivity timeout. Without a store, sign-out only clears the
  local cookie -- a copied/stolen cookie stays valid until its exp, and the
  inactivity timeout is not enforced.
* sessionTtlSeconds is reasonable (default 7d). Years-long values keep a captured
  session valid far too long.
* resolveGrants maps real upstream groups to roles. The default is a least-privilege
  read-only employee. Hardcoding admin, trusting a client-supplied role, or mapping
  every user to elevated permissions is a bug.
* allowedRedirectOrigins lists the app's own origins if it ever passes an absolute
  post-sign-in redirect target (absolute targets are otherwise refused -- safe).

Backend enforcement:
* Every protected route/controller actually calls the library's enforcement --
  getRequestAuth(req).protect({permission}) / requireAuth() / authMiddleware() /
  a guard that verifies the Bearer token. UI gating (<Protect>) is NOT authoritative.
* The app never trusts client-supplied identity: not a header, not a request-body
  field, not an unverified JWT. It never forks the library's verification (no
  decode-without-verify, no alg:none, no accepting a token the library would reject).
* AuthClient / createFederatedClient uses an https apiUrl (loopback http only in
  dev) and an out-of-repo secretKey.
* Any webhook / SCIM receiver verifies the signature with verifyWebhook over the
  RAW request bytes (a re-serialized body will not match).

Frontend:
* The access token stays in memory + the HttpOnly rotating cookie. The app does NOT
  copy tokens or session data into localStorage / sessionStorage.
* The app does not make trust decisions from client state; the backend re-checks.


====================================================================
SECURITY THINGS TO LOOK FOR (apply in every scope)
====================================================================

* Authentication: SAML 2.0 assertion validation (signature, issuer, audience,
  recipient, NotBefore/NotOnOrAfter, InResponseTo, assertion-id replay), OIDC
  id-token validation (signature, iss, aud, nonce, exp), hosted-domain (hd) and
  email_verified enforcement. SAML 1.x must be rejected.
* Domain enforcement: sign-in restricted to the allowed verified domain(s);
  unverified emails and out-of-org accounts rejected.
* Session model: short-lived access tokens, rotating HttpOnly cookie, server-side
  records, revocation, logout, idle + absolute timeouts, fixation, rotation on
  privilege change; grants re-resolved vs staleness after deprovision.
* Token handling: secret strength/storage, algorithm pinning (no alg=none, no
  HS/RS confusion), expiry, audience binding actually enforced, no long-lived
  secrets in localStorage.
* Cookies / CSRF: SameSite, HttpOnly, Secure, state on OIDC, RelayState on SAML,
  double-submit / token on state-changing non-bearer routes.
* Authorization / RBAC: group-to-role mapping, role-to-permission checks,
  authoritative server-side enforcement, IDOR, missing guards, privilege
  escalation, default-allow.
* Provisioning: JIT safety, SCIM endpoint auth, deprovision promptness, webhook
  signature verification.
* Transport / headers: HTTPS enforcement, HSTS, CSP, CORS misconfiguration, open
  redirect (ACS / redirect_uri / RelayState / returnTo).
* Input handling: injection (SQL/NoSQL/command/LDAP/path traversal), XXE in SAML
  XML, XML signature wrapping, deserialization, SSRF on metadata/JWKS/any
  user-driven fetch.
* Secrets: hardcoded keys/passwords, secrets in logs, secrets committed to the repo.
* Crypto: weak hashing, predictable randomness for tokens/state/nonce, missing
  constant-time compare.
* Logging / audit: missing audit of sign-in/out/refresh/permission-denied/admin;
  sensitive data (raw PII, tokens) in logs.
* Error handling: leaked stack traces, user enumeration, verbose errors.
* Dependencies: known-vulnerable or unpinned auth-critical packages.
* CHARTER NAMING RULE: the word "Clerk" / "clerk" / "clark" must not appear in any
  code, comment, doc, or product copy in {ROOT_DIR} or in a caller. Flag every
  occurrence as a finding (LOW severity, category naming-rule) with the file+line.
* App scopes additionally: misuse of the library API (see the usage contract),
  trusting client identity, bypassing guards, missing auth on routes, storing
  tokens insecurely, duplicating/forking the library's checks wrongly.


====================================================================
PER-SCOPE REPORT FORMAT (the .txt files)
====================================================================

Plain text only. No markdown. Sections:

* Header block:
    * Title line: the scope name (an app name, or "OpenAuthFederated").
    * Scope line: which directories were analyzed (absolute paths).
    * One-line summary: total finding count + severity breakdown.

* TABLE OF CONTENTS:
    * Numbered, one line per finding:  N. <short title>  [SEVERITY]
    * SEVERITY in {CRITICAL, HIGH, MEDIUM, LOW}. Highest severity first.
    * For an APP scope, also tag each line [MISUSE] (calling the library wrong) or
      [APP-BUG] (the app's own security bug). The library scope needs no such tag.

* DETAILS: one numbered entry per finding, matching the TOC, each separated by a
  line of ==== characters, with these labeled fields:

        N. <short title>  [SEVERITY]  (+ [MISUSE]/[APP-BUG] for app scopes)

        SITUATION / PROBLEM:  concrete description of what is wrong.
        ROOT CAUSE:           what in the code/design makes it possible.
        SCENARIO:             the concrete attack / failure story.
        RISK:                 what an attacker gains or what breaks; impact + likelihood.
        REPRO STEPS:          numbered steps to reproduce or demonstrate.
        SOURCE FILES INVOLVED: every file path that participates, with line ranges.
                              For app scopes include BOTH the library files under
                              {AUTH_CODE_DIR} AND the app files. Refer to files and
                              locations (line ranges), not class/method names.
        CALL COUNT:           how many call sites trigger it; list the files.
        FIX:
            * Root cause being fixed.
            * How: the approach.
            * Structure of the fix.
            * Files changed and how -- each edited file and the edit, covering both
              library and app side when both move.

* Footer line of ==== then "END OF REPORT".


====================================================================
AGGREGATE ROLL-UP FORMAT (the .md files)
====================================================================

security_bugs_to_fix.md (Markdown):
* H1 title + a one-line summary (total bugs, how many CRITICAL/HIGH/MEDIUM/LOW,
  how many are library vs app-side).
* A "Fix order" table, most severe first, columns:
    | # | Severity | Scope (library / app name) | Bug (short) | Source file(s) + lines | Fix (one line) | Report file |
* Then one H2 section per CRITICAL and HIGH bug with a short paragraph: what, why
  it matters, and the concrete fix. MEDIUM/LOW may stay table-only.
* Deduplicate: a single library bug triggered by several apps is ONE row (scope =
  "library"), with the triggering apps listed in the Bug cell.

web_apps_calling_us_incorrectly.md (Markdown):
* H1 title + one-line summary (how many apps, how many misuse findings total).
* One H2 per app. Under each, a table, most severe first, columns:
    | Severity | What they do wrong | Correct usage | Risk | Source file(s) + lines |
* A final H2 "Patterns across apps" listing the misuse types that recur (e.g.
  audience-not-enforced, no sessionStore, no distinct cookiePrefix) with the count
  of apps hitting each -- so the library team can decide whether to change a default
  or make a footgun impossible.


====================================================================
RUN ORDER
====================================================================

* STAGE 0 -- Detect callers (the rg command above). Confirm / update the CALLERS
  list. Read the library public surface so you know its guarantees and footguns
  ({AUTH_CODE_DIR}/packages/auth-backend/src and .../auth-react/src).
* STAGE 1 -- One per-caller .txt report per app in the CALLERS list. For each app:
  read the app's code (and its cli/ if it touches auth), find every call into the
  library, check it against the usage contract, and find the app's own auth-adjacent
  security bugs. A library bug the app actually triggers is reported here too (and
  again in the library report from the library's point of view).
* STAGE 2 -- The library .txt report ({OUTPUT_DIR}/OpenAuthFederated.txt). Ignore
  callers; analyze {AUTH_CODE_DIR} alone. Source files + call counts are
  library-internal only.
* STAGE 3 -- The two aggregate .md roll-ups, built from every .txt report written
  in Stages 1-2.
* Each report stands alone and is complete. Maximize the number of real, concrete,
  file-anchored findings. Every finding ties to specific source files and line
  ranges -- no generic advice. Prefer more real findings over fewer, but never
  invent one the code does not actually exhibit (Rule 0).
