# OpenAuthFederated SDKs

The official client and server SDKs for integrating an application with
**OpenAuthFederated** — our self-hosted, open-source identity layer. These packages are the
typed surface an application programs against, exactly as documented under
[`../docs/sdk/`](../docs/sdk/overview.mdx).

| Package | Name | Layer | Consumer |
|---------|------|-------|----------|
| `packages/auth-react` | `@auth/react` | Client (browser) | React SPA (Vite, React Router) — ESM |
| `packages/auth-backend` | `@auth/backend` | Server (secret key) | NestJS / Node — CommonJS |

> `@auth/ui` (component theming) is folded into `@auth/react` via the `appearance` prop; it is
> not a separately installed package.

## Build

```sh
pnpm install
pnpm build      # emits dist/ in each package
```

Both packages emit `dist/` (types + JS). Downstream apps consume them with pnpm `file:`
dependencies — **build here first**, then install the app.

## Local dev mode (no running server)

Both SDKs support a **dev mock** so an app can run and "sign in" locally without a deployed
OpenAuthFederated server:

* `@auth/react` — pass `devMode`, `allowedDomains`, and `devSharedSecret` to `<AuthProvider>`.
  Sign-in mints a short-lived **HS256** dev JWT (no real Google round-trip), carrying the chosen
  company domain, demo roles, and `<feature>:<action>` permissions.
* `@auth/backend` — set `AUTH_DEV_MODE=true` and `AUTH_DEV_SHARED_SECRET` (the same secret the
  front end mints with). `verifyToken()` then verifies the HS256 dev JWT instead of fetching the
  issuer JWKS.

In production both switch to the real path: the Frontend API session/token mint and networkless
JWKS verification. Naming rule: never name the modeled commercial provider in code or docs.
