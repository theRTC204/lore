# Authenticate with Microsoft Entra ID (OIDC)

By default, `lore auth login` authenticates against Epic's UCS Auth service. If you
self-host `loreserver` and want your team to sign in with their **Microsoft Entra ID
(Azure AD)** accounts instead, Lore can run a standard OpenID Connect
authorization-code + PKCE flow directly against Entra.

In this flow:

- the **client** opens a browser to Microsoft, completes sign-in, and stores the
  resulting **ID token**;
- the **server** validates that ID token against Entra's published keys (JWKS) and
  authorizes it.

> **Authorization model.** This guide uses `authorization_mode = "trust_authenticated"`:
> any token that passes signature, issuer, and audience verification is authorized
> for all repositories on the server. This suits a single-tenant, self-hosted
> deployment. It does **not** do per-repository or group-based authorization.

## Prerequisites

- A self-hosted `loreserver` you control. See
  [Deploy a local Lore Server](deploy-local-lore-server.md).
- Permission to create an **app registration** in your Entra tenant.
- Your Entra **tenant ID**.

## 1. Register an application in Entra

1. In the [Entra admin center](https://entra.microsoft.com) → **App registrations**
   → **New registration**.
2. Name it (e.g. `Lore CLI`). Leave the redirect URI blank for now and register.
3. Open the app → **Authentication** → **Add a platform** →
   **Mobile and desktop applications**.
   - Add the redirect URI `http://localhost` (the CLI uses a loopback redirect on a
     dynamic port, which Entra permits for this platform type).
   - Under **Advanced settings**, set **Allow public client flows** to **Yes**.
     (PKCE is used; no client secret is required.)
4. **API permissions** → ensure the delegated `openid` and `profile` permissions are
   present (add `offline_access` too if you want refresh tokens).
5. Note the **Application (client) ID** — referred to below as `<client-id>`.

## 2. Configure the server

The `[server.auth]` block tells the server how to validate tokens; the
`[environment.endpoint]` block advertises the OIDC login URL to clients. Put these
in your active config override file (the one selected by `LORE_ENV`, e.g.
`local.toml` or `docker.toml`) — not the compiled-in `default.toml`.

```toml
[server.auth]
jwt_issuer  = "https://login.microsoftonline.com/<tenant-id>/v2.0"
jwt_audience = ["<client-id>"]               # an Entra ID token's `aud` is the client_id
authorization_mode = "trust_authenticated"

[server.auth.jwk]
endpoint = "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys"

[environment.endpoint]
auth_url = "oidc://login.microsoftonline.com/<tenant-id>/v2.0?client_id=<client-id>&scope=openid%20profile%20offline_access"
```

Notes:

- The `auth_url` **scheme is `oidc`** — this is what tells the client to run the
  OIDC flow instead of the UCS protocol. The issuer is the same URL over `https`
  with the query string removed.
- `client_id` and `scope` are read from the `auth_url` query string; no client-side
  configuration is needed.
- Entra signs tokens with **RS256** but omits the `alg` field from its JWKS; the
  server infers it. (You also need a server build that includes this fix.)

Restart the server after editing the config.

## 3. Sign in from the client

```bash
lore auth login lore://<your-server-host>:41337
```

A browser opens to the Microsoft sign-in page. After you authenticate, the browser
redirects to a local page ("Sign-in complete") and the terminal prints
`Authentication successful`. Verify with:

```bash
lore auth list
```

For a headless machine, add `--no-browser` to print the URL instead of opening it:

```bash
lore auth login --no-browser lore://<your-server-host>:41337
```

## How it works

- The client fetches the server's environment config, sees the `oidc://` `auth_url`,
  and runs authorization-code + PKCE: it discovers Entra's endpoints via
  `/.well-known/openid-configuration`, opens the browser, captures the redirect on a
  loopback listener, and exchanges the code for an ID token at Entra's token
  endpoint.
- The ID token is stored bound to your Lore server's domain (the token's own
  audience references Entra, not your server, so the binding is explicit).
- On each request the client presents the Entra ID token directly. The server
  validates it against Entra's JWKS (issuer + audience + expiry) and — under
  `trust_authenticated` — authorizes it.

## Troubleshooting

- **`No authentication configured on server`** — `[environment.endpoint].auth_url`
  is unset or in the wrong config file. Confirm with `lore --log-level trace auth
  login …`; it logs `Server environment config: …`.
- **Browser opens but login fails with `AADSTS…` redirect errors** — the redirect
  URI isn't registered. Ensure `http://localhost` is added under the
  **Mobile and desktop applications** platform and public client flows are enabled.
- **`Not allowed` / `permission_denied` on requests** — the server rejected the
  token. Check that `jwt_issuer` ends in `/v2.0`, `jwt_audience` equals the
  `<client-id>`, and the server log doesn't show a missing-key (`kid`) error from
  the JWKS endpoint.
- **`Unauthorized`** — `authorization_mode` is not `trust_authenticated`, so the
  server is requiring a Lore `resources` claim the Entra token doesn't carry.
