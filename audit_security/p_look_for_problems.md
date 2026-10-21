Audit OpenAuthFederated (the library) and every web app that consumes it for security problems. Write one plain-text report per scope plus two aggregate roll-ups. Read every relevant source file in the library and each caller; report every security bug, missing control, risky default, and every place a caller uses the library incorrectly.
Re-runnable: run whenever the library or a caller changes.


====================================================================
RULE 0 -- AUDIT THE CURRENT CODE, NOT AN OLD REPORT
====================================================================

* The library is under active hardening; earlier reports are STALE (many findings since fixed: algorithm pinning, SAML audience check, InResponseTo + assertion replay, HKDF per-cookie subkeys, fail-closed weak-secret guard, open-redirect allowlist, security headers, PII log redaction, etc.).
* NEVER copy a finding from a prior report. Open the file and exact line range and PROVE the weakness exists now. If the code defends against it, don't report it.
* Don't assume a control exists because a comment or doc says so; confirm the code does it (a comment over-promising what the code half-enforces is itself a finding).


====================================================================
VARIABLES
====================================================================

ROOT_DIR dir is ~/BGit/Bryan_git/OpenAuthFederated
* The SAML 2.0 / OIDC Service-Provider LIBRARY the web apps embed. Not a web app.

AUTH_CODE_DIR dir is {ROOT_DIR}/code
* Two packages under {AUTH_CODE_DIR}/packages :
    * auth-backend (@auth/backend) -- server Node auth: embedded Frontend API, Google OIDC, SAML 2.0 SP, sessions, session store, RBAC, token verify, backend REST client, webhook verify.
    * auth-react (@auth/react) -- React UI components, hooks, client token/session handling.

OUTPUT_DIR dir is {ROOT_DIR}/audit_security   (this prompt lives here)

CALLERS -- detect, don't assume. A caller is any repo with a non-node_modules, non-dist reference to `@auth/backend`, `@auth/react`, `createFederatedFrontend`, `createAuthFrontend`, or `OpenAuthFederated`. Last run:

    APP  Internal Web App     dir ~/BGit/all/app
    APP  Marketing AI         dir ~/BGit/all/marketing/ai
    APP  Large File Bridge    dir ~/BGit/Bryan_git/LargeFileBridge
    APP  Email Delivery Hero  dir ~/BGit/Bryan_git/EmailDeliveryHero
    APP  Uplift   dir ~/BGit/Bryan_git/uplift
    APP  The Starbucks        dir ~/BGit/Bryan_git/the_starbucks

NOT consuming at last run (exclude unless a rescan finds a reference): ~/BGit/act3/Front_AI_Coding, ~/BGit/all/tools/voice_improve, ~/BGit/all/jfk/code/simulator, ~/BGit/all/film/platform, ~/BGit/act3/AI_Coding (Go).

Re-detect every run:
    rg -l --glob '!**/node_modules/**' --glob '!**/dist/**' \
       -e '@auth/backend' -e '@auth/react' -e 'createFederatedFrontend' \
       -e 'createAuthFrontend' -e 'OpenAuthFederated' <candidate-dir>


====================================================================
OUTPUT FILES
====================================================================

Per-scope reports (plain text .txt):
    {OUTPUT_DIR}/OpenAuthFederated.txt   -- the library alone.
    {OUTPUT_DIR}/Internal_Web_App.txt    -- one per caller, app name in
    {OUTPUT_DIR}/Marketing_AI.txt           Underscore_Case per CALLERS. New
    {OUTPUT_DIR}/Large_File_Bridge.txt      .txt for every newly-detected caller.
    {OUTPUT_DIR}/Email_Delivery_Hero.txt
    {OUTPUT_DIR}/uplift.txt
    {OUTPUT_DIR}/The_Starbucks.txt

Aggregate roll-ups (Markdown):
    {OUTPUT_DIR}/security_bugs_to_fix.md -- master fix list: every SECURITY bug from ALL reports (library + app-side), deduplicated, most severe first, each row pointing to its per-scope report and source file.
    {OUTPUT_DIR}/web_apps_calling_us_incorrectly.md -- every incorrect library call (API misuse, missing/lax config, bypassed guarantee), grouped by app: app, wrong call, correct call, risk. Sent to each app team.

Output to stdout after writing each file:
    --------------------------------------------------------------
    WROTE <path>  --  <N> findings
    --------------------------------------------------------------


====================================================================
THE LIBRARY USAGE CONTRACT (what "calling us correctly" means)
====================================================================

A caller is correct only if ALL hold; each is a place to look for a misuse finding.

createFederatedFrontend / createAuthFrontend config:
* sessionSecret >=32 chars, non-placeholder, sourced OUT of the repo (env or loadOrCreateSecret). Constructor throws on weak secrets, so a caller failing to start is a smell; a hardcoded long constant is a bug.
* allowedDomains = the real company domain(s). Empty, "gmail.com", wildcard, or an unowned domain = anyone signs in.
* requireHostedDomain true for any Workspace-gated app. Default FALSE: then a consumer Google account whose email domain is on allowedDomains passes without Workspace membership (no hd claim).
* cookiePrefix DISTINCT per app. Cookies aren't port-scoped; two apps on one host with the default "oaf" clobber each other (logout churn, cross-app session confusion).
* audience: to isolate tokens from a sibling app, pass `audience` on BOTH mint (createFederatedFrontend) AND verify (verify/authenticate options). Embedded verifyToken doesn't enforce `aud` unless the caller passes it (configureEmbeddedVerification isn't given it). Mint-only = false isolation.
* cookieSecure true in production (default true). false outside local http dev = non-Secure session cookie.
* sessionStore provided whenever the app needs revocation, "sign out everywhere", or inactivity timeout. Without it sign-out only clears the local cookie (a stolen cookie stays valid to exp) and inactivity timeout isn't enforced.
* sessionTtlSeconds reasonable (default 7d); years-long is a bug.
* resolveGrants maps real upstream groups to roles. Default is least-privilege read-only employee. Hardcoded admin, client-supplied roles, or elevating everyone is a bug.
* allowedRedirectOrigins lists the app's own origins if it passes absolute post-sign-in redirects (absolute targets are otherwise refused -- safe).

Backend enforcement:
* Every protected route calls library enforcement -- getRequestAuth(req).protect({permission}) / requireAuth() / authMiddleware() / a Bearer-verifying guard. UI gating (<Protect>) is NOT authoritative.
* Never trusts client-supplied identity (header, body field, unverified JWT); never forks verification (no decode-without-verify, no alg:none, no accepting what the library rejects).
* AuthClient / createFederatedClient uses https apiUrl (loopback http only in dev) and an out-of-repo secretKey.
* Webhook / SCIM receivers verify with verifyWebhook over the RAW request bytes (a re-serialized body won't match).

Frontend:
* Access token stays in memory + HttpOnly rotating cookie; never copied to localStorage / sessionStorage.
* No trust decisions from client state; backend re-checks.


====================================================================
SECURITY THINGS TO LOOK FOR (every scope)
====================================================================

* Authentication: SAML 2.0 assertion validation (signature, issuer, audience, recipient, NotBefore/NotOnOrAfter, InResponseTo, assertion-id replay); OIDC id-token validation (signature, iss, aud, nonce, exp); hd and email_verified enforcement. SAML 1.x rejected.
* Domain enforcement: only allowed verified domain(s); unverified and out-of-org rejected.
* Sessions: short-lived access tokens, rotating HttpOnly cookie, server-side records, revocation, logout, idle + absolute timeouts, fixation, rotation on privilege change, grants re-resolved after deprovision.
* Tokens: secret strength/storage, algorithm pinning (no alg=none, no HS/RS confusion), expiry, audience actually enforced, no long-lived secrets in localStorage.
* Cookies / CSRF: SameSite, HttpOnly, Secure, OIDC state, SAML RelayState, double-submit/token on state-changing non-bearer routes.
* Authorization / RBAC: group-to-role and role-to-permission mapping, server-side enforcement, IDOR, missing guards, privilege escalation, default-allow.
* Provisioning: JIT safety, SCIM auth, prompt deprovision, webhook signature verification.
* Transport / headers: HTTPS, HSTS, CSP, CORS, open redirect (ACS / redirect_uri / RelayState / returnTo).
* Input: injection (SQL/NoSQL/command/LDAP/path traversal), SAML XXE, XML signature wrapping, deserialization, SSRF on metadata/JWKS/user-driven fetch.
* Secrets: hardcoded keys/passwords, secrets in logs or committed.
* Crypto: weak hashing, predictable randomness for tokens/state/nonce, missing constant-time compare.
* Logging / audit: missing audit of sign-in/out/refresh/permission-denied/admin; raw PII or tokens in logs.
* Errors: leaked stack traces, user enumeration, verbose errors.
* Dependencies: known-vulnerable or unpinned auth-critical packages.
* CHARTER NAMING RULE: "Clerk" / "clerk" / "clark" must not appear in any code, comment, doc, or copy in {ROOT_DIR} or a caller. Flag each occurrence (LOW, category naming-rule) with file+line.
* App scopes also: library API misuse (usage contract), trusting client identity, bypassed guards, unauthenticated routes, insecure token storage, wrongly duplicated/forked library checks.


====================================================================
PER-SCOPE REPORT FORMAT (the .txt files)
====================================================================

Plain text, no markdown.

* Header: title line (app name or "OpenAuthFederated"); Scope line (absolute dirs analyzed); one-line summary (total findings + severity breakdown).

* TABLE OF CONTENTS: numbered, one line per finding:  N. <short title>  [SEVERITY]
  * SEVERITY in {CRITICAL, HIGH, MEDIUM, LOW}, highest first.
  * App scopes also tag [MISUSE] (calling the library wrong) or [APP-BUG] (app's own bug).

* DETAILS: one numbered entry per finding matching the TOC, separated by ==== lines:

        N. <short title>  [SEVERITY]  (+ [MISUSE]/[APP-BUG] for app scopes)

        SITUATION / PROBLEM:  concrete description of what is wrong.
        ROOT CAUSE:           what in the code/design makes it possible.
        SCENARIO:             the concrete attack / failure story.
        RISK:                 what an attacker gains or what breaks; impact + likelihood.
        REPRO STEPS:          numbered steps to reproduce or demonstrate.
        SOURCE FILES INVOLVED: every participating file path with line ranges.
                              App scopes: BOTH library files under {AUTH_CODE_DIR}
                              AND app files. Files and line ranges, not class/method names.
        CALL COUNT:           how many call sites trigger it; list the files.
        FIX:
            * Root cause being fixed.
            * How: the approach.
            * Structure of the fix.
            * Files changed and how -- each edited file and edit, library and app side.

* Footer: a ==== line then "END OF REPORT".


====================================================================
AGGREGATE ROLL-UP FORMAT (the .md files)
====================================================================

security_bugs_to_fix.md:
* H1 + one-line summary (total; CRITICAL/HIGH/MEDIUM/LOW counts; library vs app-side).
* "Fix order" table, most severe first:
    | # | Severity | Scope (library / app name) | Bug (short) | Source file(s) + lines | Fix (one line) | Report file |
* One H2 per CRITICAL and HIGH bug: what, why it matters, concrete fix. MEDIUM/LOW table-only is fine.
* Dedupe: one library bug triggered by several apps = ONE row (scope "library"), triggering apps listed in the Bug cell.

web_apps_calling_us_incorrectly.md:
* H1 + one-line summary (app count, total misuse findings).
* One H2 per app with a table, most severe first:
    | Severity | What they do wrong | Correct usage | Risk | Source file(s) + lines |
* Final H2 "Patterns across apps": recurring misuse types (e.g. audience-not-enforced, no sessionStore, no distinct cookiePrefix) with app counts, so the library team can change a default or remove a footgun.


====================================================================
RUN ORDER
====================================================================

* STAGE 0 -- Detect callers (rg above); update CALLERS. Read the library public surface ({AUTH_CODE_DIR}/packages/auth-backend/src and .../auth-react/src) to learn its guarantees and footguns.
* STAGE 1 -- One .txt per caller: read the app's code (and cli/ if it touches auth), check every library call against the usage contract, find the app's own auth-adjacent bugs. A library bug the app triggers is reported here too.
* STAGE 2 -- {OUTPUT_DIR}/OpenAuthFederated.txt: {AUTH_CODE_DIR} alone; source files and call counts library-internal only.
* STAGE 3 -- The two .md roll-ups from every .txt written in Stages 1-2.
* Each report stands alone. Maximize real, concrete, file-and-line-anchored findings; no generic advice; never invent one the code doesn't exhibit (Rule 0).
