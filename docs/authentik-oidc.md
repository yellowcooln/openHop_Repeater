# Authentik OIDC Setup

openHop OIDC is optional. Existing installations keep local password login when
`web.auth` is absent or `web.auth.mode` is `local`.

## Authentik

In Authentik, create an OAuth2/OpenID provider and application for openHop:

- Flow: Authorization Code with PKCE.
- Redirect URI: `https://repeater.example.com/auth/oidc/callback`.
- Issuer: use the per-provider issuer, for example
  `https://auth.example.com/application/o/openhop/`.
- Scopes: `openid`, `profile`, and `email`.
- Signing key: choose an asymmetric signing key so openHop can validate tokens
  through JWKS.

Create an Authentik group such as `openhop-admins` and add only openHop web
administrators to it. Use Authentik's token preview or a temporary test login to
verify the ID token includes the configured claim shape, for example:

```json
{"groups": ["openhop-admins"]}
```

If `groups` is missing or has a different shape, create and assign an Authentik
OAuth2 scope mapping that emits the required claim.

## openHop Configuration

Start in mixed mode so local password recovery remains available while testing:

```yaml
web:
  auth:
    mode: local_and_oidc
    oidc:
      issuer: "https://auth.example.com/application/o/openhop/"
      client_id: "openhop"
      client_secret: "replace-with-client-secret"
      provider_name: "Authentik"
      external_url: "https://repeater.example.com"
      scopes:
        - openid
        - profile
        - email
      authorization:
        rules:
          - claim: groups
            any_of:
              - openhop-admins
```

Test one Authentik user in `openhop-admins` and one user outside the group. The
member should enter the dashboard; the non-member should be denied. After that,
you may change `mode` to `oidc` to disable local web password login.

To recover from a bad OIDC configuration, edit the config file on the device,
restore `web.auth.mode: local`, and restart the service.

## Reverse Proxy

The externally visible URL must be HTTPS and must match `external_url`. openHop
builds its callback URL from this configured value, not from `Host` or forwarded
headers. Preserve HTTPS at the public edge and do not expose the backend as an
alternate route that bypasses the identity provider.

## CLI And API Tokens

API tokens remain separate from OIDC and are recommended before switching to
OIDC-only mode. The local CLI sends tokens with `X-API-Key`:

```bash
export OPENHOP_API_TOKEN="replace-with-api-token"
pymc-cli --host 127.0.0.1 --port 8000
```

Or store the token in a protected file:

```bash
install -m 600 /dev/null ~/.config/openhop/api-token
printf '%s\n' 'replace-with-api-token' > ~/.config/openhop/api-token
pymc-cli --api-token-file ~/.config/openhop/api-token
```

Do not put API tokens in command arguments. Do not paste real tokens into shell
history or shared logs.

## Secrets And Backups

Normal config exports redact OIDC `client_secret`, passwords, JWT secrets, API
tokens, and identity keys. Authenticated full-secret backups requested with
`include_secrets=true` intentionally include OIDC client secrets and other
credentials so they can restore a device. Store full backups like any other
secret material.

## Scope

OIDC changes web authentication only. MeshCore admin and guest passwords under
`repeater.security` remain protocol credentials. LDAP, local user management,
local RBAC roles, invitations, and group synchronization are not included.
