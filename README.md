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

## Servers & Backups user guide

Sign in and open **Servers & Backups** in the `/browse` header. This dialog manages attached LDAP servers and backup destinations. Saved connections and destinations are **owner-scoped to your login identity**: another login cannot list, edit, remove, or use your saved resources. This ownership does not grant LDAP permissions; the LDAP bind identity's ACLs still decide what can be read or changed.

### Attach an LDAP server

1. Select **New connection or destination** and choose **LDAP server**.
2. Enter a descriptive **Name**, a **Server URI** such as `ldaps://ldap.example.com:636`, the full **Bind user DN** such as `cn=backup-reader,ou=services,dc=example,dc=com`, and its **Password**.
3. Select **Save**. Use **Edit connection** to update the saved details later. Leave the password empty when editing to preserve it; saved passwords are never returned to the browser.

LDAP URIs accept `ldap://` or `ldaps://` with an optional port, but no embedded credentials, search/base-DN path, query, or fragment. Prefer LDAPS: plain `ldap://` does not encrypt bind credentials in transit, and attached connections do not automatically upgrade with StartTLS. Saving a connection is not a connectivity or permissions test; schema access and backup operations open and bind the connection when used.

**Remove** deletes the saved resource, not LDAP data or existing backup files. Removing an LDAP attachment excludes it from future backups under this login.

### Saved passwords and `encryption_key`

Saved LDAP and WebDAV passwords are encrypted in the application database with **AES-GCM**, using the existing top-level `encryption_key` in the application configuration. Connection names, URIs, bind DNs/usernames, and paths are not encrypted by this feature. Encryption at rest does not replace filesystem permissions, HTTPS for the application, or TLS to remote services.

Keep the existing `encryption_key` safe and recoverable, with access restricted to the application and trusted administrators. Keep a protected copy **separate from database exports**; a database copy and its key together can expose stored passwords. Losing or changing the key makes existing encrypted passwords unreadable. **Key rotation and re-encryption are not automatic**: do not simply replace the key and expect existing credentials to continue working. Plan a controlled migration or credential re-entry and account for other encrypted application data before changing it.

### Edit an attached server's OpenLDAP schema

1. On a saved LDAP connection, select **Object classes** or **Attribute types**.
2. Inspect the definitions. **Use definition in editor** copies a definition's DN and raw value into the editor; open the editor if needed.
3. Check the attached-server target, target DN, attribute, and raw definition. Targets must be `cn=schema,cn=config` or a descendant; the supported attributes are `olcObjectClasses` and `olcAttributeTypes`.
4. Choose the **Schema operation**, submit the editor form, and confirm the change.

The saved bind DN needs LDAP read access to inspect schema and appropriate write access to modify it. Application login or ownership of the saved connection does not bypass OpenLDAP ACLs. This editor modifies an existing schema entry; it is not a general-purpose schema-entry creation tool.

- **Add definition** adds the supplied definition value.
- **Delete this definition** removes the supplied definition value.
- **Replace all definitions of this attribute** replaces the entire selected attribute on the target entry with the supplied value, removing its other definitions—not merely editing the selected definition.

**Delete and replace are destructive.** Schema changes can fail because of ACLs, dependencies, or server validation, and can affect existing directory data and applications. Take an independently verified backup and plan recovery before modifying production schema. LDAP Help has no automatic rollback or restore workflow.

### What a backup contains

**Back up all servers now** produces one gzip-compressed tar archive (`ldap-backup-<UTC timestamp>-<random suffix>.tar.gz`) containing:

```text
manifest.json
servers/000/schema.ldif
servers/000/entries.ldif
servers/001/schema.ldif
servers/001/entries.ldif
...
```

`servers/000` is the configured primary LDAP server. Subsequent directories are **every LDAP attachment saved by the current user**, not attachments belonging to other logins. The manifest maps directories to saved server names/IDs and records the format version, UTC creation time, naming contexts, advertised subschema DNs, and an export warning.

For each server, the export includes:

- All readable entries beneath the naming contexts advertised by Root DSE, including **all readable users** and other objects. This is a superset of a users-only export, not a backup restricted to the currently displayed search or selected user.
- Readable OpenLDAP schema under `cn=schema,cn=config`, when present, and advertised subschema entries discovered from Root DSE and exported entries.
- Readable attributes, subject to the server's ACLs and search behavior. An ACL may silently hide data even when the operation succeeds.

The primary server uses the current session's normal LDAP connection: the signed-in user's bind for password login, or the configured service bind for SSO (see [SSO and LDAP permissions](#sso-and-ldap-permissions)). Each attachment uses its own saved bind credentials. Ensure these identities can read the intended naming contexts and schema. Any connection/export error stops publication of the combined archive; success does not prove ACL-hidden data was included.

The manifest does not include connection URIs, bind identities, saved passwords, or destination credentials. **This is an LDAP data export, not an application database/configuration export.** Credentials present in LDAP itself, such as readable password hashes or secret attributes, can still appear in the LDIF.

### Configure a backup destination

Choose **New connection or destination**, enter a name, select one of the destination types below, complete its fields, and select **Save**. Directories and WebDAV collections must already exist; LDAP Help does not create them. Saving a destination does not prove that a backup can be published there.

#### Local backup directory

Choose **Local backup directory** and enter an existing absolute path as seen by the running application, for example `/var/lib/ldaphelp/backups`.

Example Linux host setup, assuming an existing service account named `ldaphelp` (adapt the account and paths to your deployment):

```bash
sudo install -d -o ldaphelp -g ldaphelp -m 0700 /var/lib/ldaphelp/backups
```

The application needs directory traversal/write permissions and enough free space. The destination filesystem must support **hard links**: publication copies the complete archive to a private temporary file in that directory, then hard-links it to a unique final filename without overwriting an existing archive. Local archive files are created with mode `0600`; check effective access on your filesystem as well.

#### WebDAV over HTTPS

Choose **WebDAV over HTTPS**, then set, for example:

| Field | Example / requirement |
| --- | --- |
| Server URI | `https://storage.example.com/backups/` — an existing collection |
| Existing subdirectory | `ldaphelp/daily` — optional, relative, and already created |
| WebDAV username | Optional; enter the account used by your storage service |
| Password | Optional; enter through the UI, never in the URI |

With those example paths, archives are published beneath `https://storage.example.com/backups/ldaphelp/daily/`. The name `daily` is only a directory name; it does not schedule backups. Omit the subdirectory to use the collection directly. Do not use leading/trailing slashes, empty path segments, `.`/`..`, backslashes, or percent-encoded path tricks in the relative subdirectory. The URI must not contain credentials, a query, or a fragment.

Authentication, when supplied, uses HTTP Basic authentication over HTTPS; the saved password is encrypted using `encryption_key`. TLS certificate verification remains enabled. Install any required private CA trust in the application's runtime environment rather than disabling verification. **Redirects are not followed**; use the final HTTPS collection URL, not a redirecting web login or share link.

The WebDAV service must permit **PUT** to create a temporary object and **MOVE** to publish it within the collection without overwriting an existing object. Both operations must return `201 Created`. Allow **DELETE** for best-effort cleanup of a staged object after failure. Provision the collection/subdirectory and its access controls on the WebDAV server before using the UI. Failed cleanup can leave a hidden `.partial` object to remove administratively.

#### Mounted CIFS/SMB or NFS directory

Choose **Mounted CIFS/SMB directory** or **Mounted NFS directory** only after the operating system has mounted the share. Enter an existing absolute backup directory inside that mount, not an `smb://` URI, UNC share, or `server:/export` string.

LDAP Help **does not mount shares, request mount privileges, or store SMB/NFS mount credentials**. Host configuration handles credentials, Kerberos, mount options, and reconnects. As with local destinations, the effective application account must be able to write to the directory and the share/filesystem must support hard links. CIFS servers and mount options vary; verify hard-link support before relying on a share.

Example Linux CIFS setup (requires host administration, CIFS tooling, and an existing `ldaphelp` service account):

```bash
sudo install -d -m 0750 /mnt/ldaphelp-cifs
sudo install -m 0600 /dev/null /root/ldaphelp-smb.credentials
sudoedit /root/ldaphelp-smb.credentials
sudo mount -t cifs //files.example.com/ldap-backups /mnt/ldaphelp-cifs -o credentials=/root/ldaphelp-smb.credentials,vers=3.1.1,uid=ldaphelp,gid=ldaphelp,file_mode=0600,dir_mode=0700
sudo -u ldaphelp mkdir -m 0700 /mnt/ldaphelp-cifs/ldaphelp
```

Populate the root-only credentials file with the `username` and `password` fields required by your host's `mount.cifs` tooling (and `domain` if needed), or use a host-managed Kerberos setup. Do not put passwords on command lines, in this README, or in LDAP Help destination fields. In the UI, select the CIFS type and enter `/mnt/ldaphelp-cifs/ldaphelp`.

Example Linux NFS setup (requires host administration and NFS client tooling):

```bash
sudo install -d -m 0750 /mnt/ldaphelp-nfs
sudo mount -t nfs -o vers=4,rw nfs.example.com:/exports/ldap-backups /mnt/ldaphelp-nfs
sudo -u ldaphelp mkdir -m 0700 /mnt/ldaphelp-nfs/ldaphelp
```

Configure the NFS export's ownership, UID/GID mapping, ACLs, and any Kerberos requirements on the host/server so that the application account can create that directory and its files. Root squashing can prevent root from fixing permissions through the client mount. In the UI, select the NFS type and enter `/mnt/ldaphelp-nfs/ldaphelp`.

For persistent mounts, use your host's mount/service configuration and ensure the application starts only after the required mount is available. LDAP Help treats these destinations as directories; it does not verify that the intended remote share is still mounted. Prevent fallback writes to an unmounted local mountpoint.

**Containers:** mount CIFS/NFS on the host first, then expose the existing backup directory as a writable bind mount/volume to the application. For example, a Compose service can include:

```yaml
volumes:
  - /mnt/ldaphelp-nfs/ldaphelp:/backups:rw
```

Enter `/backups` in the UI, because paths are resolved inside the container. Match the container process's effective UID/GID and security policy to host/share permissions. Do not grant the application container privileged mode or mount capabilities merely for this feature; mounting and mount secrets belong to the host. Local destinations likewise require a persistent writable volume if backups must survive container replacement.

### Run a backup and protect it

1. Save any LDAP attachments to include and at least one backup destination.
2. Under **Generate backup**, select the destination in **Save to**.
3. Select **Back up all servers now** and confirm the unencrypted export warning.
4. Keep the page open while the export and publication run. On success, the dialog reports the number of servers and the destination location. Check that the archive exists and inspect its manifest/LDIF securely before relying on it.

Backups are **manual and on demand only**. There are no schedules, automatic retention policies, or application restore/import workflows. Arrange retention and any recovery procedure separately; removing a destination does not delete archives.

**Security and consistency limits:**

- Archives are **unencrypted**. Gzip compression and LDIF base64 values are not encryption. Readable password hashes, personal data, and other LDAP secrets may be included. Restrict destination permissions/ACLs, remote storage access, and access to downloaded or extracted copies; use separately managed encryption where required.
- Export staging uses a private temporary directory on the application host. Protect the host's temporary storage and allow space for LDIF, the compressed archive, and the destination copy where applicable.
- Exports are **online and non-atomic**, including across servers. Concurrent changes can yield inconsistent entries or schema/data combinations. Atomic publication of a completed file does not make its LDAP contents an atomic snapshot.
- LDAP ACLs can hide entries and attributes; server limits or unsupported searches can fail an export. This is **not `slapcat`**, a complete OpenLDAP configuration/database snapshot, or a guarantee of disaster recovery. Use a separate server-native backup/recovery strategy when those guarantees are needed.
- Keep application database exports, configuration secrets, and `encryption_key` protected separately. LDAP archives do not back up saved connection credentials or the key, and stored-password encryption does not encrypt the LDAP archives.

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
