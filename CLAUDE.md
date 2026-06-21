# OpenAuthFederated

OpenAuthFederated is our **open-source authentication and identity platform** — a self-hosted,
open-source equivalent of the commercial SaaS identity providers (Auth0, AWS Cognita, and
similar hosted identity platforms). It provides the authentication/identity layer that gates
access to our applications: federated sign-in, provisioning, role-based authorization, sessions,
and the security around them.

* **Repo (local):** `~/BGit/Bryan_git/OpenAuthFederated/`
* **Repo (remote):** https://github.com/BryanStarbuck/OpenAuthFederated.git
* **Use:** we use OpenAuthFederated to carry out authentication security, deployed and operated
  much like a hosted commercial identity provider — but open-source and under our own control.

## Naming Rule (MANDATORY)

* **NEVER use the name of the commercial SaaS identity provider we are modeling after in any
  public documentation, code, comments, marketing, READMEs, or product copy.** Describe the
  value generically instead: "an open-source identity platform," "an open-source equivalent of
  hosted identity providers," or compare against Auth0 / Cognita when a concrete reference is
  needed.
* Our own product name in all public material is **OpenAuthFederated**.
* This rule applies everywhere this project is referenced.

## Charter

OpenAuthFederated delivers a complete, self-hostable identity layer that an application can sit
behind for **all** authentication and authorization. The platform's value — the thing we are
building an open-source equivalent of — is:

* **Authentication methods** — federated SSO via **SAML 2.0** and **OIDC**, social logins, and
  enterprise IdP connections. (For our internal apps the go-forward default is federation to
  **Google Workspace** as the identity provider; see "Reference deployment" below.)
* **Identity federation** — act as the Service-Provider-side identity/auth layer between an app
  and an upstream Identity Provider; the app trusts the platform's asserted identity and never
  handles the user's upstream password.
* **Domain enforcement** — restrict sign-in to one or more verified company domains; reject any
  identity outside the allowed domain(s), including unverified emails and out-of-org accounts.
  On the OIDC path, verify the hosted-domain (`hd`) claim and `email_verified`.
* **Provisioning** — **Just-In-Time (JIT)** user creation on first valid sign-in, plus
  **SCIM 2.0** directory sync for full lifecycle (provision / update / deprovision) with
  webhooks (`user.created`, `user.updated`, `user.deleted`, group/membership changes).
* **Organizations / multi-tenancy** — model orgs/tenants so the platform can gate more than one
  app or customer.
* **RBAC (role-based access control)** — map upstream groups to roles, and roles to
  `<feature>:<action>` permissions (e.g. `code:read`, `jfk:write`, `*:read`). Treat the IdP's
  groups/roles as **inputs**, but keep the **authoritative authorization model in our own
  backend/DB** to avoid lock-in.
* **Hybrid session model** — short-lived **JWT access tokens** (Bearer) refreshed by a
  longer-lived, rotating, **HttpOnly** cookie, backed by server-side session records that allow
  **immediate revocation** despite short token lifetimes. Stateless verification + stateful
  revocation.
* **Security** — MFA inherited from the upstream IdP (with optional step-up reverification for
  sensitive actions), HTTPS only, `SameSite` + `HttpOnly` cookies (CSRF defense), CSP headers,
  no long-lived secrets in `localStorage`, and full auditing of sign-in / sign-out / refresh /
  permission-denied / admin actions.
* **No password surface** — when federating to an upstream IdP, the platform stores **no end-user
  passwords**, eliminating that entire class of attack.
* **UI components** — drop-in sign-in / sign-up / account-management UI so apps don't rebuild
  auth screens.

## SAML version requirement (MANDATORY): SAML 2.0

* We **must** be compatible with **SAML 2.0** — and **not** any earlier version of SAML.
* Any SAML integration, assertion handling, metadata, or binding we implement targets **SAML
  2.0 exclusively**. Reject or do not support SAML 1.x.
* We will at times **also** support **Google authentication** (OIDC / Google Workspace sign-in)
  as an alternative path. But whenever we do **SAML**, it **must be SAML version 2.0**.

## Service Provider (SP) role

* **Service Provider (SP):** the application or service that the user wants to access. It does
  **not** authenticate the user itself. Instead, it **trusts and consumes the SAML assertion
  from the Identity Provider (IdP)** to establish a session and make authorization decisions.
* **OpenAuthFederated is NOT the Service Provider, and is NOT a web app.** The Service Providers
  are the separate web apps (our internal app, and any other consumer app) that the user wants
  to access. We are the **library that those SP web apps embed.**
* We want **OpenAuthFederated** to be the **library that plugs into SAML Service Provider web
  apps** so that, on their behalf, it communicates with the SAML **Identity Provider**.
  OpenAuthFederated runs on the SP side as a dependency of the SP app: it speaks SAML 2.0 to the
  IdP, validates the returned assertion, and hands the host SP app a trusted, established
  identity/session. The SP app is the consumer; OpenAuthFederated is the library it consumes.

## Reference deployment: gating an internal app to Google Workspace

The first real consumer of OpenAuthFederated is an internal company web app. Its rule is the
canonical example of how the platform is used:

> **Access requirement:** a person must have an active account in our company **Google Workspace
> (G Suite)** on the `whitehatengineering.com` domain to log in. Google Workspace is the single
> source of truth for who is an employee — no app-specific passwords, no other social logins, no
> anonymous access.

* **IdP:** Google Workspace (`whitehatengineering.com`) authenticates the human.
* **SP:** the app, with **OpenAuthFederated** as the identity/auth layer between the app and
  Google.
* **Flow (SP-initiated):** App → OpenAuthFederated → Google Workspace → signed SAML assertion /
  OIDC ID token → validate → resolve/JIT-create user → map groups → establish session → app
  receives a short-lived JWT and the user is in. **SAML 2.0 via a Google Workspace custom app**
  is the go-forward default (domain-scoped enforcement + attribute/group mapping); OIDC is an
  acceptable equivalent with the same domain restriction.
* **Authorization:** Google Workspace groups map to app roles; read-only vs read/write is
  enforced on **both** front-end (UX) and backend (authoritative).
* **Offboarding:** suspend/delete the Google account → SCIM deprovision + short token lifetimes
  → access is revoked promptly; admins can force-revoke sessions.

## Engineering stack

OpenAuthFederated follows our standard Node + TypeScript stack (derived from the ACT3 and
JFKSocial codebases):

* **Language/runtime:** TypeScript (`strict: true`) on Node ≥ 20; **pnpm**; **Biome 2**; husky +
  lint-staged.
* **Backend:** **NestJS** (REST + **Swagger**), **TypeORM + PostgreSQL** (soft-delete,
  migrations — never `synchronize`), **class-validator** DTOs, **Passport + JWT** auth + RBAC
  guards (`@UseGuards(JwtAuthGuard)`, `@CurrentUser()`), Redis + BullMQ as needed, Sentry,
  Jest + supertest.
* **Front-end (UI components / admin):** React 19 + Vite 7, Zustand (client state), TanStack
  Query + axios + OpenAPI-generated client (server state), Tailwind + shadcn/ui + Radix + CVA,
  react-hook-form + Zod, TanStack Router, Vitest + Playwright, Sentry.
* **Contract:** backend Swagger → front-end typed TanStack-Query client via OpenAPI codegen.
* **axios interceptors** are the single place for auth + error policy: request injects the
  Bearer token from the auth store; response handles `401` (single-flight refresh + queued
  retry, then logout) and `403` (insufficient permission → toast).

We don't want to use the word "Clerk" or "clark" in any of our code, comments, documentation or anything else. We don't want to talk about that product.  Only talk about us as "OpenAuthFederated".  Don't talk about "Clerk".  Output warnings if you find anything in this directory or lower that does that.

## Project structure

```
OpenAuthFederated/
├── code/    # Application code (Node + TypeScript: NestJS backend + React UI)
├── pm/      # Product management — MDX specs and charter docs
├── README.md
└── CLAUDE.md  # this file
```

## Source specifications

The product specs this charter is distilled from live in `~/BGit/all/app/pm/`:

* `overview.mdx` — internal-app charter, divisions, table of contents.
* `authentication.mdx` — the federated-auth spec (Google Workspace IdP, SAML/OIDC, domain
  enforcement, JIT/SCIM, group-based RBAC, sessions, security, acceptance criteria).
* `engineering.mdx` — the full Node/TypeScript engineering standards.

Note: `~/BGit/all/app/pm/identity_platform.mdx` is currently an empty stub (a TOC placeholder for the
identity-platform capability reference). The capabilities above are captured here as the
OpenAuthFederated charter; expand the spec doc as the platform grows — and keep the naming rule:
never use the modeled provider's name in public material.

## Consumer apps (Service Providers that embed this library)

These are the internal web apps that consume OpenAuthFederated as their SAML Service Provider
library. They are the SP web apps; OpenAuthFederated is the library they embed.

* **Primary internal web app** — the main app we use internally that will use this library:
  * `~/BGit/all/app/`
* **Other internal applications** — additional apps to our product that we'll bring onto this
  library over time:
  * `~/BGit/all/tools/voice_improve/`
  * `~/BGit/all/marketing/ai/`
  * `~/BGit/all/jfk/code/simulator/`
  * `~/BGit/all/film/platform/`
