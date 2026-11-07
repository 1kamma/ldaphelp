package main

// Backups are online LDAP exports, NOT atomic snapshots. ACLs can silently hide
// entries or attributes even when a search succeeds; use a suitably privileged
// backup identity and test restores. Archives are unencrypted and may contain
// password hashes and other secrets. Protect destinations and retention copies.
// A missing cn=schema,cn=config is allowed for non-OpenLDAP servers; all other
// schema/search failures abort publication. Mounted CIFS/NFS paths must already
// exist; this backend never mounts shares or creates WebDAV collections.
// Mounted staging files must report private permissions before data is copied.
// Server-side share ACLs remain the operator's responsibility: POSIX mode checks
// cannot establish which remote identities can access a CIFS/NFS backup.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const backupLDAPTimeout = 30 * time.Second
const backupWarning = "Online LDAP export, not an atomic snapshot; ACLs may hide data. Unencrypted archive includes password hashes and other secrets."

type backupServerManifest struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Directory      string   `json:"directory"`
	NamingContexts []string `json:"naming_contexts"`
	Subschema      []string `json:"subschema"`
}

type backupManifest struct {
	Version int                    `json:"version"`
	Created time.Time              `json:"created"`
	Warning string                 `json:"warning"`
	Servers []backupServerManifest `json:"servers"`
}

func (a *App) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	owner, ok := a.managedOwner(w, r)
	if !ok {
		return
	}
	var input struct {
		DestinationID int64 `json:"destination_id"`
	}
	if !managedJSONRequest(w, r, &input) {
		return
	}
	if input.DestinationID <= 0 {
		http.Error(w, "invalid backup request", http.StatusBadRequest)
		return
	}
	destination, err := getManagedResource(owner, input.DestinationID, a.cfg.EncryptionKey)
	if err != nil {
		http.Error(w, "backup destination unavailable", http.StatusBadRequest)
		return
	}
	if err := backupValidateDestination(destination); err != nil {
		http.Error(w, "invalid backup destination", http.StatusBadRequest)
		return
	}
	resources, err := listManagedResources(owner)
	if err != nil {
		http.Error(w, "cannot list backup servers", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "ldaphelp-backup-*")
	if err != nil {
		http.Error(w, "cannot stage backup", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(dir)
	manifest := backupManifest{Version: 1, Created: time.Now().UTC(), Warning: backupWarning}
	// Do not include URIs, bind identities, passwords, or destination credentials
	// in either the manifest or errors returned to the browser.
	primary, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, "primary LDAP connection failed", http.StatusBadGateway)
		return
	}
	info, err := backupExportConnection(ctx, primary, dir, 0, "Primary LDAP", 0)
	if err != nil {
		http.Error(w, "primary LDAP export failed; no backup published", http.StatusBadGateway)
		return
	}
	manifest.Servers = append(manifest.Servers, info)
	for _, resource := range resources {
		if resource.Kind != "ldap" {
			continue
		}
		if ctx.Err() != nil {
			http.Error(w, "backup canceled", http.StatusRequestTimeout)
			return
		}
		item, err := getManagedResource(owner, resource.ID, a.cfg.EncryptionKey)
		if err != nil {
			http.Error(w, "saved LDAP credentials unavailable", http.StatusInternalServerError)
			return
		}
		conn, err := connectManagedLDAP(item)
		if err != nil {
			http.Error(w, "saved LDAP connection failed; no backup published", http.StatusBadGateway)
			return
		}
		info, err := backupExportConnection(ctx, conn, dir, item.ID, item.Name, len(manifest.Servers))
		if err != nil {
			http.Error(w, "saved LDAP export failed; no backup published", http.StatusBadGateway)
			return
		}
		manifest.Servers = append(manifest.Servers, info)
	}
	archive, err := backupMakeArchive(ctx, dir, manifest)
	if err != nil {
		http.Error(w, "cannot create backup archive", http.StatusInternalServerError)
		return
	}
	filename, err := backupFilename()
	if err != nil {
		http.Error(w, "cannot name backup", http.StatusInternalServerError)
		return
	}
	location, err := backupPublish(ctx, destination, archive, filename, nil)
	if err != nil {
		http.Error(w, "backup publication failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"filename": filename, "location": location, "servers": len(manifest.Servers)})
}

func backupExportConnection(ctx context.Context, conn *ldap.Conn, dir string, id int64, name string, index int) (backupServerManifest, error) {
	defer conn.Close()
	conn.SetTimeout(backupLDAPTimeout)
	// Shared helpers own dialing/binding; the primary getLDAPConn helper must
	// bound its own bind, since no connection is exposed until it completes.
	// Closing the dedicated connection interrupts an in-flight Search on cancel.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	info := backupServerManifest{ID: id, Name: name, Directory: fmt.Sprintf("servers/%03d", index)}
	serverDir := filepath.Join(dir, filepath.FromSlash(info.Directory))
	if err := os.MkdirAll(serverDir, 0700); err != nil {
		return info, err
	}
	entries, err := os.OpenFile(filepath.Join(serverDir, "entries.ldif"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return info, err
	}
	defer entries.Close()
	schema, err := os.OpenFile(filepath.Join(serverDir, "schema.ldif"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return info, err
	}
	defer schema.Close()
	info, err = backupExportLDAP(ctx, conn, entries, schema, info)
	if err != nil {
		return info, err
	}
	if err := entries.Close(); err != nil {
		return info, err
	}
	return info, schema.Close()
}

// backupWalk processes one bounded page at a time rather than SearchWithPaging,
// which accumulates the entire directory in memory. A critical paging control
// and required response cookie prevent silently accepting an unpaged truncation.
func backupWalk(ctx context.Context, conn ldapSearcher, base string, scope int, visit func(*ldap.Entry) error) error {
	var cookie []byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var controls []ldap.Control
		if scope != ldap.ScopeBaseObject {
			page := ldap.NewControlPaging(500)
			page.SetCookie(cookie)
			// ControlPaging's encoder does not expose criticality. Wrap its BER packet.
			controls = []ldap.Control{backupCriticalPaging{page}}
		}
		req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, int(backupLDAPTimeout/time.Second), false, "(objectClass=*)", []string{"*", "+"}, controls)
		result, err := conn.Search(req)
		if err != nil {
			return err
		} // Never use partial entries returned with errors.
		if err := ctx.Err(); err != nil {
			return err
		}
		if result == nil || len(result.Referrals) != 0 {
			return errors.New("incomplete LDAP search (nil result or referrals)")
		}
		for _, entry := range result.Entries {
			if entry == nil {
				return errors.New("nil LDAP entry")
			}
			if err := visit(entry); err != nil {
				return err
			}
		}
		if scope == ldap.ScopeBaseObject {
			if len(result.Entries) != 1 {
				return errors.New("base search did not return exactly one entry")
			}
			return nil
		}
		control := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		page, ok := control.(*ldap.ControlPaging)
		if !ok {
			return errors.New("LDAP server did not acknowledge paging")
		}
		cookie = page.Cookie
		if len(cookie) == 0 {
			return nil
		}
		// Cookies are opaque and may legitimately be reused by the server.
		// The overall request deadline bounds a server that never finishes.
	}
}

// The library's paging control is noncritical by default. Retain its wire value
// while requiring servers to reject unsupported paging rather than ignore it.
type backupCriticalPaging struct{ *ldap.ControlPaging }

func (p backupCriticalPaging) Encode() *ber.Packet {
	packet := p.ControlPaging.Encode()
	critical := ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality")
	packet.Children = append(packet.Children[:1], append([]*ber.Packet{critical}, packet.Children[1:]...)...)
	// Rebuild Data, since Children mutations alone do not update BER wire bytes.
	rebuilt := ber.Encode(packet.ClassType, packet.TagType, packet.Tag, nil, packet.Description)
	for _, child := range packet.Children {
		rebuilt.AppendChild(child)
	}
	return rebuilt
}

func backupExportLDAP(ctx context.Context, conn ldapSearcher, entries, schema io.Writer, info backupServerManifest) (backupServerManifest, error) {
	var contexts, subschema []string
	subschemaSeen := make(map[string]bool)
	addSubschema := func(values []string) {
		for _, value := range values {
			if !subschemaSeen[value] {
				subschemaSeen[value] = true
				subschema = append(subschema, value)
			}
		}
	}
	err := backupWalk(ctx, conn, "", ldap.ScopeBaseObject, func(e *ldap.Entry) error {
		contexts = e.GetAttributeValues("namingContexts")
		addSubschema(e.GetAttributeValues("subschemaSubentry"))
		return nil
	})
	if err != nil {
		return info, err
	}
	bases, err := backupDistinctContexts(contexts)
	if err != nil {
		return info, err
	}
	if len(bases) == 0 {
		return info, errors.New("RootDSE advertises no naming contexts")
	}
	info.NamingContexts = bases
	if _, err := io.WriteString(entries, "version: 1\n\n"); err != nil {
		return info, err
	}
	if _, err := io.WriteString(schema, "version: 1\n\n"); err != nil {
		return info, err
	}
	entryDNs := make(map[string]bool)
	for _, base := range bases {
		count := 0
		err = backupWalk(ctx, conn, base, ldap.ScopeWholeSubtree, func(e *ldap.Entry) error {
			count++
			addSubschema(e.GetAttributeValues("subschemaSubentry"))
			key, err := backupDNKey(e.DN)
			if err != nil {
				return err
			}
			if entryDNs[key] {
				return nil
			}
			entryDNs[key] = true
			return backupWriteEntry(entries, e)
		})
		if err != nil {
			return info, err
		}
		if count == 0 {
			return info, errors.New("empty naming context export")
		}
	}
	var schemaDNs []*ldap.DN
	writeSchema := func(e *ldap.Entry) error {
		dn, err := ldap.ParseDN(e.DN)
		if err != nil {
			return err
		}
		for _, previous := range schemaDNs {
			if previous.EqualFold(dn) {
				return nil
			}
		}
		schemaDNs = append(schemaDNs, dn)
		return backupWriteEntry(schema, e)
	}
	schemaCount := 0
	err = backupWalk(ctx, conn, "cn=schema,cn=config", ldap.ScopeWholeSubtree, func(e *ldap.Entry) error {
		schemaCount++
		return writeSchema(e)
	})
	if err != nil && !(schemaCount == 0 && ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject)) {
		return info, err
	}
	if err == nil && schemaCount == 0 {
		return info, errors.New("empty OpenLDAP schema export")
	}
	var advertised []*ldap.DN
	for _, base := range subschema {
		dn, err := ldap.ParseDN(base)
		if err != nil || base == "" {
			return info, errors.New("invalid subschema DN")
		}
		duplicate := false
		for _, previous := range advertised {
			if previous.EqualFold(dn) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		advertised = append(advertised, dn)
		info.Subschema = append(info.Subschema, base)
		if err := backupWalk(ctx, conn, base, ldap.ScopeBaseObject, writeSchema); err != nil {
			return info, err
		}
	}
	if schemaCount == 0 && len(advertised) == 0 {
		return info, errors.New("no schema discoverable")
	}
	return info, nil
}

// Nested naming contexts can be separate databases not traversed by a search
// of their parent, so only equivalent DNs may be removed from the search list.
func backupDistinctContexts(contexts []string) ([]string, error) {
	var parsed []*ldap.DN
	var names []string
	for _, name := range contexts {
		dn, err := ldap.ParseDN(name)
		if err != nil || strings.TrimSpace(name) == "" {
			return nil, errors.New("invalid naming context")
		}
		duplicate := false
		for _, previous := range parsed {
			if previous.EqualFold(dn) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			parsed = append(parsed, dn)
			names = append(names, name)
		}
	}
	return names, nil
}

// Parse escapes before folding and let DN.String sort multivalued RDNs. Fold
// Unicode simple-fold cycles consistently with ldap.DN.EqualFold, not merely
// strings.ToLower (which treats e.g. final sigma differently).
func backupDNKey(name string) (string, error) {
	dn, err := ldap.ParseDN(name)
	if err != nil {
		return "", err
	}
	fold := func(value string) string {
		return strings.Map(func(r rune) rune {
			minimum := r
			for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
				if next < minimum {
					minimum = next
				}
			}
			return minimum
		}, value)
	}
	for _, rdn := range dn.RDNs {
		for _, attr := range rdn.Attributes {
			attr.Type = fold(attr.Type)
			attr.Value = fold(attr.Value)
		}
	}
	return dn.String(), nil
}

var backupAttributeName = regexp.MustCompile(`^(?:[a-zA-Z][a-zA-Z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[a-zA-Z0-9-]+)*$`)

func backupWriteEntry(w io.Writer, entry *ldap.Entry) error {
	if err := backupWriteValue(w, "dn", []byte(entry.DN)); err != nil {
		return err
	}
	for _, attr := range entry.Attributes {
		if attr == nil || !backupAttributeName.MatchString(attr.Name) {
			return errors.New("invalid LDAP attribute description")
		}
		// ByteValues is authoritative: converting through text can corrupt binary
		// values or hashes. Fall back only for synthetic entries without ByteValues.
		values := attr.ByteValues
		if values == nil {
			for _, value := range attr.Values {
				values = append(values, []byte(value))
			}
		}
		for _, value := range values {
			if err := backupWriteValue(w, attr.Name, value); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func backupWriteValue(w io.Writer, name string, value []byte) error {
	unsafe := len(value) > 0 && (value[0] == ' ' || value[0] == ':' || value[0] == '<' || value[len(value)-1] == ' ')
	for _, b := range value {
		if b < 0x20 || b >= 0x7f {
			unsafe = true
			break
		}
	}
	line := name + ":"
	if len(value) > 0 {
		if unsafe {
			line += ": " + base64.StdEncoding.EncodeToString(value)
		} else {
			line += " " + string(value)
		}
	}
	// LDIF continuation lines start with one space; fold on ASCII wire bytes.
	for len(line) > 76 {
		if _, err := io.WriteString(w, line[:76]+"\n"); err != nil {
			return err
		}
		line = " " + line[76:]
	}
	_, err := io.WriteString(w, line+"\n")
	return err
}

func backupMakeArchive(ctx context.Context, dir string, manifest backupManifest) (string, error) {
	name := filepath.Join(dir, "archive.tar.gz")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gz := gzip.NewWriter(file)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	add := func(name string, size int64, reader io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: size, ModTime: manifest.Created}); err != nil {
			return err
		}
		_, err := io.Copy(tw, backupContextReader{ctx, reader})
		return err
	}
	if err := add("manifest.json", int64(len(data)), bytes.NewReader(data)); err != nil {
		return "", err
	}
	for _, server := range manifest.Servers {
		for _, leaf := range []string{"schema.ldif", "entries.ldif"} {
			member := server.Directory + "/" + leaf
			f, err := os.Open(filepath.Join(dir, filepath.FromSlash(member)))
			if err != nil {
				return "", err
			}
			st, err := f.Stat()
			if err == nil {
				err = add(member, st.Size(), f)
			}
			closeErr := f.Close()
			if err != nil {
				return "", err
			}
			if closeErr != nil {
				return "", closeErr
			}
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return name, nil
}

type backupContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r backupContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func backupFilename() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "ldap-backup-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random[:]) + ".tar.gz", nil
}

func backupValidateDestination(item ManagedResource) error {
	switch item.Kind {
	case "local", "cifs", "nfs":
		if !filepath.IsAbs(item.Path) {
			return errors.New("backup path must be absolute")
		}
		info, err := os.Stat(item.Path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("backup path must be an existing directory")
		}
		return nil
	case "webdav":
		_, err := backupDAVCollection(item)
		return err
	default:
		return errors.New("unsupported backup destination")
	}
}

func backupDAVCollection(item ManagedResource) (*url.URL, error) {
	u, err := url.Parse(item.URI)
	if err != nil {
		return nil, errors.New("invalid WebDAV URI")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("WebDAV requires an HTTPS collection without credentials, query, or fragment")
	}
	validate := func(path string, relative bool) error {
		if strings.ContainsAny(path, "\\\x00\r\n") || (relative && strings.HasPrefix(path, "/")) {
			return errors.New("invalid WebDAV path")
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == "." || segment == ".." || (relative && segment == "") {
				return errors.New("invalid WebDAV segment")
			}
			// Reject escaped separators and double-encoded traversal as well.
			if strings.Contains(segment, "%") {
				return errors.New("escaped WebDAV path segment")
			}
		}
		return nil
	}
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return nil, errors.New("escaped WebDAV separator")
	}
	if err := validate(u.Path, false); err != nil {
		return nil, err
	}
	if item.Path != "" {
		if err := validate(item.Path, true); err != nil {
			return nil, err
		}
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	if item.Path != "" {
		u.Path += item.Path + "/"
	}
	u.RawPath = ""
	return u, nil
}

func backupPublish(ctx context.Context, item ManagedResource, archive, filename string, client *http.Client) (string, error) {
	if filename == "" || filepath.Base(filename) != filename || strings.ContainsAny(filename, "/\\\x00") || filename == "." || filename == ".." {
		return "", errors.New("invalid backup filename")
	}
	if err := backupValidateDestination(item); err != nil {
		return "", err
	}
	if item.Kind == "webdav" {
		return backupPublishDAV(ctx, item, archive, filename, client)
	}
	// Copy to the destination filesystem first. Linking publishes a fully-written
	// private inode atomically and fails if the final name already exists. Unlike
	// Rename, Link cannot silently overwrite an existing archive.
	staged, err := os.CreateTemp(item.Path, ".ldaphelp-backup-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	if err := backupSecureStaging(staged); err != nil {
		return "", err
	}
	source, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer source.Close()
	if _, err := io.Copy(staged, backupContextReader{ctx, source}); err != nil {
		return "", err
	}
	if err := staged.Sync(); err != nil {
		return "", err
	}
	if err := staged.Close(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	destination := filepath.Join(item.Path, filename)
	if err := os.Link(staged.Name(), destination); err != nil {
		return "", err
	}
	return destination, nil
}

// Some mounted shares silently ignore chmod. Check the effective mode before
// opening/copying the sensitive archive, not merely after publication.
func backupSecureStaging(file interface {
	Chmod(os.FileMode) error
	Stat() (os.FileInfo, error)
}) error {
	if err := file.Chmod(0600); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("backup filesystem does not enforce private staging permissions")
	}
	return nil
}

func backupPublishDAV(ctx context.Context, item ManagedResource, archive, filename string, supplied *http.Client) (string, error) {
	collection, err := backupDAVCollection(item)
	if err != nil {
		return "", err
	}
	// Copy the injected client so redirects are rejected even in tests, without
	// mutating a shared client. Never include URLs or HTTP bodies in error output.
	client := http.Client{Timeout: 5 * time.Minute}
	if supplied != nil {
		client = *supplied
		client.Timeout = 5 * time.Minute
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	final := *collection
	final.Path += filename
	stage := *collection
	random, err := backupFilename()
	if err != nil {
		return "", err
	}
	stage.Path += "." + random + ".partial"
	request := func(ctx context.Context, method string, target *url.URL, body io.Reader, headers map[string]string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
		if err != nil {
			return 0, errors.New("WebDAV request failed")
		}
		if item.Username != "" || item.Password != "" {
			req.SetBasicAuth(item.Username, item.Password)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, errors.New("WebDAV transport failed")
		}
		defer resp.Body.Close()
		// Bound discarded error bodies; a malicious peer must not prolong cleanup.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return resp.StatusCode, nil
	}
	cleanup := true
	defer func() {
		if cleanup {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = request(cleanupCtx, http.MethodDelete, &stage, nil, nil)
		}
	}()
	source, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer source.Close()
	status, err := request(ctx, http.MethodPut, &stage, source, map[string]string{"Content-Type": "application/gzip", "If-None-Match": "*"})
	if err != nil {
		return "", err
	}
	// A fresh staging resource must be created, never replaced (204).
	if status != http.StatusCreated {
		return "", fmt.Errorf("WebDAV PUT returned status %d", status)
	}
	status, err = request(ctx, "MOVE", &stage, nil, map[string]string{"Destination": final.String(), "Overwrite": "F"})
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("WebDAV MOVE returned status %d", status)
	}
	cleanup = false
	return final.String(), nil
}
