# LDAP Help

A self hosted tool to manage, change, add, edit and modify your ldap.

## LDAP search API

`GET /api/search` searches across all LDAP naming contexts by default.

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
