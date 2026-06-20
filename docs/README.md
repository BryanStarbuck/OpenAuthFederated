# OpenAuthFederated Documentation

**OpenAuthFederated** is an open-source, self-hosted authentication and identity
platform — an open-source equivalent of hosted identity providers. It gives your
applications a complete identity layer to sit behind: federated single sign-on
(SAML 2.0 / OIDC), domain enforcement, Just-In-Time provisioning and SCIM 2.0
directory sync, organizations and multi-tenancy, role-based access control, a
hybrid session model with immediate revocation, and drop-in UI components — all
under your own control, with no end-user passwords to store.

These docs are written for developers integrating OpenAuthFederated into an
application. If you have used a hosted identity provider before, the developer
experience will feel familiar: install an SDK, wrap your app, protect your
routes, and call the APIs.

---

## Start here

| Guide | What it covers |
| --- | --- |
| [Overview](./getting_started/overview.mdx) | The mental model — Frontend API, Backend API, Platform API, SDKs, and how federation to an upstream IdP works |
| [Next.js quickstart](./getting_started/quickstart-nextjs.mdx) | Install `@auth/nextjs`, wrap your app in `<AuthProvider>`, add `authMiddleware()`, and read the user — in minutes |
| [Environment variables](./getting_started/environment-variables.mdx) | Every key and URL you need, public vs. secret |
| [Protect routes](./getting_started/protect-routes.mdx) | `createRouteMatcher`, `auth.protect()`, and role/permission checks |
| [Read the current user](./getting_started/read-the-user.mdx) | Server (`auth()`, `currentUser()`) and client (`useUser`, `useAuth`) |
| [Deploy to production](./getting_started/deploy.mdx) | Custom domains, the Google Workspace SSO connection, domain enforcement, and offboarding |

---

## SDKs and UI components

The SDKs are the fastest way to integrate. They wrap the APIs below and ship
ready-made sign-in, sign-up, and account-management UI.

- [SDK overview](./sdk/overview.mdx) — `@auth/nextjs`, `@auth/react`, `@auth/backend`, and when to use each
- [Next.js SDK reference](./sdk/nextjs.mdx) — `authMiddleware()`, `auth()`, `currentUser()`, `getAuth()`
- [React hooks](./sdk/hooks.mdx) — `useUser`, `useAuth`, `useSession`, `useSignIn`, `useOrganization`, and more
- [Backend SDK](./sdk/backend-sdk.mdx) — `createAuthClient()` / `authClient` for server-side resource access
- [UI components](./sdk/components/overview.mdx) — catalog of all drop-in components
  - [Authentication](./sdk/components/authentication.mdx) · [User](./sdk/components/user.mdx) · [Organization](./sdk/components/organization.mdx) · [Control](./sdk/components/control.mdx)

---

## APIs

OpenAuthFederated exposes three APIs across two planes. Pick the one that matches
where your code runs.

| API | Plane | Who calls it | Authorized with |
| --- | --- | --- | --- |
| [**Frontend API**](./apis/frontend/overview.mdx) | Data | The browser / native client (via the SDKs) | Publishable key + short-lived session token |
| [**Backend API**](./apis/backend/overview.mdx) | Data | Your servers | Secret key (`Bearer sk_live_…`) |
| [**Platform API**](./apis/platform/overview.mdx) | Control | Your servers / admin tooling | Secret key (`Bearer sk_live_…`) |

### Frontend API
The public, browser-facing API your client SDKs use to run sign-in, sign-up, and
session flows.
[Overview](./apis/frontend/overview.mdx) ·
[Client & sessions](./apis/frontend/client-and-sessions.mdx) ·
[Sign-in](./apis/frontend/sign-in.mdx) ·
[Sign-up](./apis/frontend/sign-up.mdx) ·
[Current user](./apis/frontend/user.mdx)

### Backend API
The server-to-server REST API for managing users, sessions, organizations, and
invitations.
[Overview](./apis/backend/overview.mdx) ·
[Users](./apis/backend/users.mdx) ·
[Sessions](./apis/backend/sessions.mdx) ·
[Organizations](./apis/backend/organizations.mdx) ·
[Invitations](./apis/backend/invitations.mdx) ·
[JWT templates](./apis/backend/jwt-templates.mdx)

### Platform API
The administrative control plane: tenants, SSO connections, verified domains,
SCIM provisioning, webhooks, RBAC, audit logs, and API keys.
[Overview](./apis/platform/overview.mdx) ·
[Organizations / tenants](./apis/platform/organizations.mdx) ·
[SSO connections](./apis/platform/sso-connections.mdx) ·
[Domains](./apis/platform/domains.mdx) ·
[SCIM](./apis/platform/scim.mdx) ·
[Webhooks](./apis/platform/webhooks.mdx) ·
[RBAC](./apis/platform/rbac.mdx) ·
[Audit logs](./apis/platform/audit-logs.mdx) ·
[API keys](./apis/platform/api-keys.mdx)

---

## How the pieces fit together

OpenAuthFederated sits between your application and an upstream identity provider
(the reference deployment federates to **Google Workspace**). Your app never
handles the user's upstream password.

```
                            ┌───────────────────────────────────────────┐
   Browser / Client         │              OpenAuthFederated             │      Upstream IdP
   (@auth/react,            │                                            │   (Google Workspace,
    @auth/nextjs)           │  Frontend API ── Backend API ── Platform   │    SAML 2.0 / OIDC)
        │                   │       │              │           API       │          │
        │  sign-in ───────► │  sign-in flow ──────────────────────────────────────►│
        │                   │       │              │            │        │          │
        │ ◄──── session ─── │  short-lived JWT  +  rotating HttpOnly refresh cookie │
        │                   │       │              │            │        │
   Your Server              │   verify JWT    manage users   manage tenants,
   (@auth/backend)  ──────► │                 & sessions     SSO, SCIM, RBAC
                            └───────────────────────────────────────────┘
```

**Sign-in flow (SP-initiated):** your app → OpenAuthFederated → the upstream IdP →
signed SAML assertion / OIDC ID token → validated (domain enforcement on `hd` +
`email_verified`) → user resolved or JIT-created → groups mapped to roles →
session established → your app receives a short-lived JWT and the user is in.

For the full walkthrough, start with the [Overview](./getting_started/overview.mdx)
and the [Next.js quickstart](./getting_started/quickstart-nextjs.mdx).
