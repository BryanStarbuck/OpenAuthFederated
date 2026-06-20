# OpenAuthFederated

**An open-source, self-hosted authentication and identity platform.**

OpenAuthFederated is a free, open-source equivalent of the hosted commercial identity
providers (Auth0, AWS Cognito, and similar SaaS identity services). It delivers a complete
identity layer that any application can sit behind for **all** of its authentication and
authorization — federated sign-in, provisioning, role-based authorization, sessions, and the
security around them — without depending on, paying for, or being locked into a proprietary
vendor.

You own the code. You own the data. You own the authorization model. It runs on your
infrastructure, under your keys and your policies.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#license)

---

## Why OpenAuthFederated

Hosted identity providers solve a real problem — but they do it as a closed, metered SaaS you
rent. OpenAuthFederated gives you the same value as software you **own and control**:

* **Open source.** The entire platform is open and inspectable. No closed components, no
  per-seat billing, no usage metering. Anyone can run it, audit it, and extend it.
* **Self-hosted.** Runs on your own infrastructure, under your own keys and policies. Identity
  data and authorization decisions stay in your hands.
* **No vendor lock-in.** Upstream identity providers supply groups and roles as *inputs*, but
  the authoritative authorization model lives in your own backend and database. Swap upstream
  IdPs without rebuilding your application's permission model.
* **A drop-in identity layer.** An application sits behind OpenAuthFederated for *all* of its
  authentication and authorization instead of rebuilding auth screens, session handling, and
  RBAC from scratch.

---

## Charter

OpenAuthFederated delivers a complete, self-hostable identity layer that an application can sit
behind for all authentication and authorization. The platform provides:

* **Authentication methods** — federated SSO via **SAML 2.0** and **OIDC**, social logins, and
  enterprise IdP connections.
* **Identity federation** — acts as the Service-Provider-side identity/auth layer between an app
  and an upstream Identity Provider. The app trusts the platform's asserted identity and never
  handles the user's upstream password.
* **Domain enforcement** — restrict sign-in to one or more verified company domains; reject any
  identity outside the allowed domain(s), including unverified emails and out-of-org accounts.
  On the OIDC path, verify the hosted-domain (`hd`) claim and `email_verified`.
* **Provisioning** — **Just-In-Time (JIT)** user creation on first valid sign-in, plus
  **SCIM 2.0** directory sync for full lifecycle management (provision / update / deprovision)
  with webhooks (`user.created`, `user.updated`, `user.deleted`, group/membership changes).
* **Organizations / multi-tenancy** — model orgs and tenants so the platform can gate more than
  one app or customer.
* **RBAC (role-based access control)** — map upstream groups to roles, and roles to
  `<feature>:<action>` permissions (e.g. `code:read`, `*:read`). Treat the IdP's groups/roles
  as inputs, but keep the authoritative authorization model in your own backend/DB.
* **Hybrid session model** — short-lived **JWT access tokens** (Bearer) refreshed by a
  longer-lived, rotating, **HttpOnly** cookie, backed by server-side session records that allow
  **immediate revocation** despite short token lifetimes. Stateless verification plus stateful
  revocation.
* **Security** — MFA inherited from the upstream IdP (with optional step-up reverification for
  sensitive actions), HTTPS only, `SameSite` + `HttpOnly` cookies (CSRF defense), CSP headers,
  no long-lived secrets in `localStorage`, and full auditing of sign-in / sign-out / refresh /
  permission-denied / admin actions.
* **No password surface** — when federating to an upstream IdP, the platform stores **no
  end-user passwords**, eliminating that entire class of attack.
* **UI components** — drop-in sign-in / sign-up / account-management UI so apps don't rebuild
  auth screens.

---

## How it works

OpenAuthFederated sits between your application (the Service Provider) and an upstream Identity
Provider (the source of truth for who your users are). A typical SP-initiated flow:

```
App  →  OpenAuthFederated  →  Upstream IdP  →  signed SAML assertion / OIDC ID token
                                                          │
                          validate ─ resolve/JIT-create user ─ map groups to roles
                                                          │
                          establish session  →  App receives a short-lived JWT
```

1. A user hits a protected app and is redirected to OpenAuthFederated.
2. OpenAuthFederated redirects to the upstream IdP, which authenticates the human (including
   MFA).
3. The IdP returns a signed SAML assertion or OIDC ID token.
4. OpenAuthFederated validates the assertion, enforces domain restrictions, and JIT-creates or
   resolves the user.
5. Upstream groups are mapped to roles, roles to permissions — the authoritative model lives in
   your database.
6. A session is established: the app receives a short-lived JWT, refreshed by a rotating
   HttpOnly cookie, and sessions can be revoked immediately server-side.

### Reference deployment: gating an app to a Google Workspace domain

The canonical example consumer is an internal web app that only employees may access:

> **Access requirement:** a person must have an active account in the company **Google
> Workspace** on the allowed domain to log in. Google Workspace is the single source of truth
> for who is an employee — no app-specific passwords, no other social logins, no anonymous
> access.

* **IdP:** Google Workspace authenticates the human.
* **SP:** the app, with OpenAuthFederated as the identity/auth layer between the app and Google.
* **Default integration:** SAML 2.0 via a Google Workspace custom app (domain-scoped
  enforcement + attribute/group mapping). OIDC is an acceptable equivalent with the same domain
  restriction.
* **Authorization:** Google Workspace groups map to app roles; read-only vs read/write is
  enforced on **both** the front-end (UX) and backend (authoritative).
* **Offboarding:** suspend/delete the Google account → SCIM deprovision + short token lifetimes
  → access is revoked promptly; admins can force-revoke sessions.

---

## Engineering stack

OpenAuthFederated is built on a standard, modern Node + TypeScript stack:

* **Language/runtime:** TypeScript (`strict: true`) on Node ≥ 20; **pnpm**; **Biome 2**;
  husky + lint-staged.
* **Backend:** **NestJS** (REST + **Swagger**), **TypeORM + PostgreSQL** (soft-delete,
  migrations — never `synchronize`), **class-validator** DTOs, **Passport + JWT** auth + RBAC
  guards, Redis + BullMQ as needed, Sentry, Jest + supertest.
* **Front-end (UI components / admin):** React 19 + Vite 7, Zustand (client state), TanStack
  Query + axios + OpenAPI-generated client (server state), Tailwind + shadcn/ui + Radix + CVA,
  react-hook-form + Zod, TanStack Router, Vitest + Playwright, Sentry.
* **Contract:** backend Swagger → front-end typed TanStack-Query client via OpenAPI codegen.
* **axios interceptors** are the single place for auth + error policy: request injects the
  Bearer token; response handles `401` (single-flight refresh + queued retry, then logout) and
  `403` (insufficient permission → toast).

---

## Project structure

```
OpenAuthFederated/
├── code/      # Application code (NestJS backend + React UI)
├── pm/        # Product management — MDX specs and charter docs
├── README.md  # this file
└── CLAUDE.md  # repository working notes
```

---

## Getting started

> **Status:** early development. The charter and specs are stable; application code under
> `code/` is in progress. The steps below describe the intended setup.

### Prerequisites

* **Node ≥ 20** and **pnpm**
* **PostgreSQL** (and **Redis** if you enable background jobs)
* An upstream Identity Provider you can federate to (e.g. a Google Workspace domain) with a
  SAML 2.0 or OIDC application configured

### Install

```bash
# 1. Clone
git clone https://github.com/BryanStarbuck/OpenAuthFederated.git
cd OpenAuthFederated

# 2. Install dependencies
pnpm install

# 3. Configure environment
cp .env.example .env
#   then edit .env — set DATABASE_URL, the IdP (SAML/OIDC) settings,
#   the allowed sign-in domain(s), JWT/cookie secrets, and session lifetimes

# 4. Run database migrations
pnpm migration:run

# 5. Start the backend (and the UI in a second terminal)
pnpm dev
```

### Configure an upstream IdP

1. In your Identity Provider (e.g. Google Workspace), create a SAML 2.0 application (or an OIDC
   client) for OpenAuthFederated.
2. Set the ACS / redirect URL to your OpenAuthFederated instance.
3. Map the IdP's group attributes through to OpenAuthFederated so groups can be mapped to roles.
4. In `.env`, set the allowed domain(s) so only verified company identities can sign in.

### Point your application at it

Put your app behind OpenAuthFederated and let the platform handle sign-in, sessions, and RBAC.
Your app verifies the short-lived JWT on each request and enforces the permissions returned by
the platform; the rotating HttpOnly refresh cookie and server-side session records handle
renewal and immediate revocation.

---

## Contributing

Contributions are welcome. Please open an issue to discuss substantial changes before sending a
pull request. Match the existing TypeScript / NestJS / React conventions and the engineering
stack described above (strict typing, DTO validation, migrations over `synchronize`, auth
enforced on both front-end and backend).

---

## License

OpenAuthFederated is released under the **MIT License** — free to use, copy, modify, and
distribute. See below for the full text.

```
MIT License

Copyright (c) 2026 Bryan Starbuck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

**Repo:** https://github.com/BryanStarbuck/OpenAuthFederated.git
