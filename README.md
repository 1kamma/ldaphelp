# LDAP Help

A self hosted tool to manage, change, add, edit and modify your ldap.

## Build

Build for the current platform:

```bash
go build -o ldaphelp .
```

Build a static Linux aarch64/arm64 binary:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ldaphelp-linux-arm64 .
```

The project uses the pure-Go `modernc.org/sqlite` driver, so cross-compilation does not require a C toolchain when `CGO_ENABLED=0`.

## Test

Run the full test suite:

```bash
./scripts/run_tests.sh
```

Run with package coverage:

```bash
./scripts/run_tests.sh -cover
```

Tests are stored in `_test/`. There are no root-level test symlinks. The runner temporarily copies tests into the package directory because Go does not discover underscore-prefixed directories with `go test ./...`, and these tests need the root `package main` compile context to cover unexported helpers.

## LDAP search API

`GET /api/search` searches across all LDAP naming contexts by default.

There is also a browser-side LDAP Search panel in the `/browse` sidebar. It supports a quick text query and an advanced parameterized LDAP filter/base/scope/attribute search.

Backward-compatible DN-only search:

```text
/api/search?filter=(objectClass=posixAccount)
```

Parameterized search with attributes:

```text
/api/search?format=entries&q=alice&attrs=cn,uid,mail,objectClass&limit=100
```

Useful parameters:

- `filter`: raw LDAP filter. If omitted, `(objectClass=*)` is used.
- `q`: text search across `cn`, `uid`, `mail`, `sn`, `givenName`, `displayName`, and `description`.
- `search_attr`: repeatable attribute list used by `q`.
- `objectClass` / `object_class`: restrict search to one object class.
- `base`: repeatable base DN override. If omitted, all Root DSE `namingContexts` are searched.
- `scope`: `subtree`, `one`, or `base`.
- `attrs`: comma-separated returned attributes.
- `attr`: repeatable returned attribute.
- `limit`: maximum result count. `0` means no application-side limit.
- `full=true`: disables the application-side result limit.
- `format=entries`: returns structured entries instead of a DN array.

Structured response shape:

```json
{
  "results": [
    {
      "dn": "uid=alice,ou=users,dc=example,dc=com",
      "attributes": {
        "cn": ["Alice"],
        "uid": ["alice"],
        "mail": ["alice@example.com"]
      }
    }
  ],
  "count": 1,
  "searched_bases": ["dc=example,dc=com"],
  "truncated": false
}
```

## SSO and LDAP permissions

Password logins bind to LDAP as the authenticated LDAP user. LDAP ACLs therefore apply directly to that user.

SAML/OIDC sessions do not provide the user's LDAP password. For those sessions, LDAP access uses the configured service bind credentials:

```yaml
external_api:
  bind_dn: "cn=ldaphelp-service,ou=services,dc=example,dc=com"
  bind_password: "change-me"
```

LDAP permissions for SSO users are therefore controlled by:

1. The SSO handler/session deciding who is allowed into the application.
2. LDAP ACLs granted to the configured service bind DN.

The repository also contains ignored OpenLDAP SASL EXTERNAL templates under `openldap-sasl-external-config/`. That directory is intentionally ignored because real certificate keys and deployment-specific LDAP config should not be committed.
