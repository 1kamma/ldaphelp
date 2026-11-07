package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type backupTestSearcher func(*ldap.SearchRequest) (*ldap.SearchResult, error)

func (f backupTestSearcher) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) { return f(r) }

func TestBackupLDIFRawBytes(t *testing.T) {
	values := [][]byte{nil, []byte("plain"), {0, 255, 128, 10, 13}, []byte(" leading"), []byte("trailing "), []byte(":colon"), []byte("<url"), []byte("café"), []byte("{SSHA}secret"), []byte(strings.Repeat("x", 180))}
	entry := &ldap.Entry{DN: "cn=café,dc=example", Attributes: []*ldap.EntryAttribute{{Name: "userPassword;binary", ByteValues: values, Values: []string{"WRONG"}}}}
	var out bytes.Buffer
	if err := backupWriteEntry(&out, entry); err != nil {
		t.Fatal(err)
	}
	unfolded := strings.ReplaceAll(out.String(), "\n ", "")
	lines := strings.Split(strings.TrimSpace(unfolded), "\n")
	if lines[0] != "dn:: "+base64.StdEncoding.EncodeToString([]byte(entry.DN)) {
		t.Fatalf("DN not encoded: %s", lines[0])
	}
	for i, value := range values {
		line := strings.TrimPrefix(lines[i+1], "userPassword;binary:")
		var got []byte
		if strings.HasPrefix(line, ": ") {
			var err error
			got, err = base64.StdEncoding.DecodeString(line[2:])
			if err != nil {
				t.Fatal(err)
			}
		} else {
			got = []byte(strings.TrimPrefix(line, " "))
		}
		if !bytes.Equal(got, value) {
			t.Fatalf("value %d: %x != %x", i, got, value)
		}
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if len(line) > 76 {
			t.Fatal("unfolded long LDIF line")
		}
	}
	if err := backupWriteEntry(io.Discard, &ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "x\ninjected"}}}); err == nil {
		t.Fatal("accepted attribute injection")
	}
}

func TestBackupPagedSearch(t *testing.T) {
	for _, mode := range []string{"success", "partial error", "missing control", "referral", "repeated cookie", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			calls, visits := 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn := backupTestSearcher(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				calls++
				if req.SizeLimit != 0 || req.TimeLimit == 0 || !reflect.DeepEqual(req.Attributes, []string{"*", "+"}) {
					t.Fatalf("incorrect search: %+v", req)
				}
				control := req.Controls[0].Encode()
				if len(control.Children) != 3 || control.Children[1].Value != true {
					t.Fatal("paging must be critical")
				}
				page := ldap.NewControlPaging(500)
				if calls == 1 || (mode == "repeated cookie" && calls < 3) {
					page.SetCookie([]byte("next"))
				}
				result := &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "dc=example"}}, Controls: []ldap.Control{page}}
				switch mode {
				case "partial error":
					return result, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("truncated"))
				case "missing control":
					result.Controls = nil
				case "referral":
					result.Referrals = []string{"ldap://elsewhere"}
				case "canceled":
					cancel()
				}
				return result, nil
			})
			err := backupWalk(ctx, conn, "dc=example", ldap.ScopeWholeSubtree, func(*ldap.Entry) error { visits++; return nil })
			if mode == "success" || mode == "repeated cookie" {
				want := 2
				if mode == "repeated cookie" {
					want = 3
				}
				if err != nil || calls != want || visits != want {
					t.Fatalf("calls=%d visits=%d err=%v", calls, visits, err)
				}
			} else if err == nil {
				t.Fatal("accepted incomplete result")
			}
			if (mode == "partial error" || mode == "referral" || mode == "canceled") && visits != 0 {
				t.Fatal("used incomplete entries")
			}
		})
	}
}

func TestBackupExportSchemaAndContexts(t *testing.T) {
	var searched []string
	conn := backupTestSearcher(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		searched = append(searched, req.BaseDN)
		var entries []*ldap.Entry
		switch req.BaseDN {
		case "":
			entries = []*ldap.Entry{ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=example", "DC=example", "ou=people,dc=example"}, "subschemaSubentry": {"cn=Subschema"}})}
		case "dc=example":
			entries = []*ldap.Entry{ldap.NewEntry("dc=example", map[string][]string{"objectClass": {"domain"}, "userPassword": {"{SSHA}hash"}}), ldap.NewEntry("uid=user,dc=example", map[string][]string{"description": {"all entries"}})}
		case "ou=people,dc=example":
			// This separate database is not traversed by the parent search.
			entries = []*ldap.Entry{ldap.NewEntry(req.BaseDN, map[string][]string{"objectClass": {"organizationalUnit"}}), ldap.NewEntry("uid=child,ou=people,dc=example", map[string][]string{"description": {"nested database entry"}})}
		case "cn=schema,cn=config":
			entries = []*ldap.Entry{ldap.NewEntry(req.BaseDN, map[string][]string{"objectClass": {"olcSchemaConfig"}}), ldap.NewEntry("cn={0}core,"+req.BaseDN, map[string][]string{"olcAttributeTypes": {"schema definition"}})}
		case "cn=Subschema":
			entries = []*ldap.Entry{ldap.NewEntry(req.BaseDN, map[string][]string{"objectClasses": {"class definition"}, "attributeTypes": {"attribute definition"}, "ldapSyntaxes": {"syntax"}, "matchingRules": {"rule"}})}
		default:
			t.Fatalf("unexpected base %q", req.BaseDN)
		}
		result := &ldap.SearchResult{Entries: entries}
		if req.Scope != ldap.ScopeBaseObject {
			result.Controls = []ldap.Control{ldap.NewControlPaging(500)}
		}
		return result, nil
	})
	var entries, schema bytes.Buffer
	info, err := backupExportLDAP(context.Background(), conn, &entries, &schema, backupServerManifest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.SchemaOnly {
		t.Fatal("legacy export unexpectedly schema-only")
	}
	if !reflect.DeepEqual(info.NamingContexts, []string{"dc=example", "ou=people,dc=example"}) {
		t.Fatalf("contexts: %v", info.NamingContexts)
	}
	if !reflect.DeepEqual(searched, []string{"", "dc=example", "ou=people,dc=example", "cn=schema,cn=config", "cn=Subschema"}) {
		t.Fatalf("searches: %v", searched)
	}
	for _, text := range []string{"dn: cn=schema,cn=config", "olcAttributeTypes:", "objectClasses:", "attributeTypes:", "ldapSyntaxes:", "matchingRules:"} {
		if !strings.Contains(schema.String(), text) {
			t.Errorf("missing %s", text)
		}
	}
	if !strings.Contains(entries.String(), "dn: uid=child,ou=people,dc=example\n") {
		t.Fatal("nested database entry omitted")
	}
	if !strings.Contains(entries.String(), "userPassword: {SSHA}hash") {
		t.Fatal("password omitted")
	}
}

// Any data search fails immediately, including discovery of per-entry subschema.
func backupSchemaOnlyTestSearcher(t *testing.T, contexts []string, openLDAP bool) backupTestSearcher {
	t.Helper()
	return backupTestSearcher(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		var entries []*ldap.Entry
		switch req.BaseDN {
		case "":
			if req.Scope != ldap.ScopeBaseObject {
				t.Fatal("RootDSE search must be base-only")
			}
			entries = []*ldap.Entry{ldap.NewEntry("", map[string][]string{
				"namingContexts":    contexts,
				"subschemaSubentry": {"cn=Subschema", "CN=subschema", "cn=OtherSchema"},
			})}
		case "cn=schema,cn=config":
			if !openLDAP {
				return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("not OpenLDAP"))
			}
			entries = []*ldap.Entry{
				ldap.NewEntry(req.BaseDN, map[string][]string{"objectClass": {"olcSchemaConfig"}}),
				ldap.NewEntry("cn={0}core,"+req.BaseDN, map[string][]string{"olcAttributeTypes": {"OpenLDAP definition"}}),
			}
		case "cn=Subschema", "cn=OtherSchema":
			if req.Scope != ldap.ScopeBaseObject {
				t.Fatal("subschema search must be base-only")
			}
			entries = []*ldap.Entry{ldap.NewEntry(req.BaseDN, map[string][]string{
				"objectClasses": {"class definition"}, "attributeTypes": {"attribute definition"},
				"ldapSyntaxes": {"syntax"}, "matchingRules": {"rule"},
			})}
		default:
			t.Fatalf("schema-only export issued a data search: %+v", req)
		}
		return &ldap.SearchResult{Entries: entries, Controls: []ldap.Control{ldap.NewControlPaging(500)}}, nil
	})
}

func TestBackupSchemaOnlyExport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contexts []string
	}{
		{"no naming contexts", nil},
		{"advertised data", []string{"dc=example", "ou=people,dc=example"}},
		{"invalid unused context", []string{"not a DN"}},
	} {
		for _, openLDAP := range []bool{false, true} {
			t.Run(tc.name+"/OpenLDAP="+strconv.FormatBool(openLDAP), func(t *testing.T) {
				var entries, schema bytes.Buffer
				info, err := backupExportLDAPWithScope(context.Background(), backupSchemaOnlyTestSearcher(t, tc.contexts, openLDAP), &entries, &schema, backupServerManifest{}, true)
				if err != nil {
					t.Fatal(err)
				}
				if !info.SchemaOnly || len(info.NamingContexts) != 0 || entries.Len() != 0 {
					t.Fatalf("schema-only export included data: info=%+v entries=%q", info, entries.String())
				}
				if !reflect.DeepEqual(info.Subschema, []string{"cn=Subschema", "cn=OtherSchema"}) {
					t.Fatalf("subschema: %v", info.Subschema)
				}
				for _, text := range []string{"version: 1", "dn: cn=Subschema", "dn: cn=OtherSchema", "objectClasses:", "attributeTypes:", "ldapSyntaxes:", "matchingRules:"} {
					if !strings.Contains(schema.String(), text) {
						t.Errorf("missing %s", text)
					}
				}
				if strings.Contains(schema.String(), "olcAttributeTypes:") != openLDAP {
					t.Fatalf("unexpected OpenLDAP schema: %s", schema.String())
				}
			})
		}
	}
}

func TestBackupSchemaOnlyFailureClosed(t *testing.T) {
	for _, mode := range []string{"root failure", "OpenLDAP failure", "subschema failure", "no schema"} {
		t.Run(mode, func(t *testing.T) {
			conn := backupTestSearcher(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				switch req.BaseDN {
				case "":
					if mode == "root failure" {
						return nil, errors.New("root unavailable")
					}
					attrs := map[string][]string{}
					if mode != "no schema" {
						attrs["subschemaSubentry"] = []string{"cn=subschema"}
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", attrs)}}, nil
				case "cn=schema,cn=config":
					if mode == "OpenLDAP failure" {
						return nil, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
					}
					return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("absent"))
				case "cn=subschema":
					return nil, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
				default:
					t.Fatalf("unexpected data search: %+v", req)
					return nil, errors.New("unexpected search")
				}
			})
			if _, err := backupExportLDAPWithScope(context.Background(), conn, nil, io.Discard, backupServerManifest{}, true); err == nil {
				t.Fatal("accepted incomplete schema export")
			}
		})
	}
}

func TestBackupFullExportRequiresNamingContexts(t *testing.T) {
	_, err := backupExportLDAP(context.Background(), backupSchemaOnlyTestSearcher(t, nil, true), io.Discard, io.Discard, backupServerManifest{})
	if err == nil || !strings.Contains(err.Error(), "no naming contexts") {
		t.Fatalf("full export must require naming contexts: %v", err)
	}
}

func TestBackupOverlappingContextDeduplication(t *testing.T) {
	firstDN := `CN=Smith\, Jane+UID=7,ou=nested,dc=example`
	duplicateDN := `uid=7+cn=smith\2c jane,OU=NESTED,DC=EXAMPLE`
	conn := backupTestSearcher(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		var entries []*ldap.Entry
		switch req.BaseDN {
		case "":
			entries = []*ldap.Entry{ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=example", "ou=nested,dc=example"}})}
		case "dc=example":
			entries = []*ldap.Entry{ldap.NewEntry(req.BaseDN, nil), ldap.NewEntry(firstDN, map[string][]string{"description": {"first copy"}})}
		case "ou=nested,dc=example":
			entries = []*ldap.Entry{ldap.NewEntry(req.BaseDN, nil), ldap.NewEntry(duplicateDN, map[string][]string{"description": {"duplicate copy"}}), ldap.NewEntry("uid=only-child,"+req.BaseDN, nil)}
		case "cn=schema,cn=config":
			entries = []*ldap.Entry{ldap.NewEntry(req.BaseDN, nil)}
		default:
			t.Fatalf("unexpected search %q", req.BaseDN)
		}
		return &ldap.SearchResult{Entries: entries, Controls: []ldap.Control{ldap.NewControlPaging(500)}}, nil
	})
	var entries bytes.Buffer
	_, err := backupExportLDAP(context.Background(), conn, &entries, io.Discard, backupServerManifest{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(entries.String(), "\ndn: ") != 4 || strings.Contains(entries.String(), "duplicate copy") {
		t.Fatalf("overlapping entries not deduplicated: %s", entries.String())
	}
	if !strings.Contains(entries.String(), "uid=only-child,") {
		t.Fatal("unique nested entry omitted")
	}
	for _, pair := range [][2]string{
		{firstDN, duplicateDN},
		{"cn=σ,dc=example", "CN=ς,DC=EXAMPLE"},
	} {
		left, err := backupDNKey(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		right, err := backupDNKey(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if left != right {
			t.Fatalf("equivalent DN keys differ: %q != %q", left, right)
		}
	}
}

func TestBackupSchemaFailureClosed(t *testing.T) {
	for _, code := range []uint16{ldap.LDAPResultInsufficientAccessRights, ldap.LDAPResultTimeLimitExceeded, ldap.LDAPResultNoSuchObject} {
		t.Run(ldap.LDAPResultCodeMap[code], func(t *testing.T) {
			conn := backupTestSearcher(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.BaseDN == "" {
					return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=x"}, "subschemaSubentry": {"cn=subschema"}})}}, nil
				}
				if req.BaseDN == "cn=schema,cn=config" {
					return nil, ldap.NewError(code, errors.New("schema failure"))
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(req.BaseDN, map[string][]string{"objectClass": {"top"}})}, Controls: []ldap.Control{ldap.NewControlPaging(500)}}, nil
			})
			_, err := backupExportLDAP(context.Background(), conn, io.Discard, io.Discard, backupServerManifest{})
			if (err == nil) != (code == ldap.LDAPResultNoSuchObject) {
				t.Fatalf("code %d: %v", code, err)
			}
		})
	}
}

type backupTestFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i backupTestFileInfo) Mode() os.FileMode { return i.mode }

type backupTestStagingFile struct {
	info              os.FileInfo
	chmodErr, statErr error
	chmodCalled       bool
}

func (f *backupTestStagingFile) Chmod(mode os.FileMode) error {
	f.chmodCalled = mode == 0600
	// Simulate a mounted filesystem reporting success without applying chmod.
	return f.chmodErr
}
func (f *backupTestStagingFile) Stat() (os.FileInfo, error) {
	if !f.chmodCalled {
		return nil, errors.New("stat before chmod")
	}
	return f.info, f.statErr
}

func TestBackupSecureStaging(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0400, 0644, 0604, 0620, 0610, 0601, 0660, 0777} {
		t.Run(mode.String(), func(t *testing.T) {
			file := &backupTestStagingFile{info: backupTestFileInfo{mode: mode}}
			err := backupSecureStaging(file)
			if (err != nil) != (mode.Perm()&0077 != 0) {
				t.Fatalf("effective mode %v: %v", mode, err)
			}
			if !file.chmodCalled {
				t.Fatal("chmod 0600 was not attempted")
			}
		})
	}
	failure := errors.New("filesystem failure")
	for _, file := range []*backupTestStagingFile{{chmodErr: failure}, {statErr: failure}} {
		if err := backupSecureStaging(file); !errors.Is(err, failure) {
			t.Fatalf("lost filesystem error: %v", err)
		}
	}
}

func TestBackupLocalPrivateExclusivePublication(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	item := ManagedResource{Kind: "local", Path: dir}
	names := make(map[string]bool)
	for i := 0; i < 5; i++ {
		name, err := backupFilename()
		if err != nil {
			t.Fatal(err)
		}
		if names[name] {
			t.Fatal("duplicate name")
		}
		names[name] = true
		location, err := backupPublish(context.Background(), item, source, name, nil)
		if err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(location)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("mode %v", st.Mode())
		}
		if _, err := backupPublish(context.Background(), item, source, name, nil); err == nil {
			t.Fatal("overwrote backup")
		}
		data, _ := os.ReadFile(location)
		if string(data) != "archive" {
			t.Fatal("corrupt publication")
		}
	}
	for _, name := range []string{"../escape", "/absolute", "back\\slash", ".."} {
		if _, err := backupPublish(context.Background(), item, source, name, nil); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := backupPublish(ctx, item, source, "canceled", nil); err == nil {
		t.Fatal("ignored cancel")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 5 {
		t.Fatalf("staging files leaked: %v", files)
	}
}

func TestBackupDAVPublication(t *testing.T) {
	for _, mode := range []string{"success", "put failure", "put overwrite", "move failure", "redirect", "move redirect"} {
		t.Run(mode, func(t *testing.T) {
			var methods []string
			leaked := false
			trap := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; w.WriteHeader(http.StatusCreated) }))
			defer trap.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				methods = append(methods, r.Method)
				user, pass, ok := r.BasicAuth()
				if !ok || user != "backup" || pass != "secret" {
					t.Error("missing basic authentication")
				}
				if !strings.HasPrefix(r.URL.Path, "/collection/subdir/.") {
					t.Errorf("invalid staging path %q", r.URL.Path)
				}
				switch r.Method {
				case http.MethodPut:
					if r.Header.Get("If-None-Match") != "*" {
						t.Error("PUT lacks exclusivity")
					}
					data, _ := io.ReadAll(r.Body)
					if string(data) != "archive" {
						t.Error("wrong PUT body")
					}
					switch mode {
					case "put failure":
						w.WriteHeader(http.StatusForbidden)
					case "put overwrite":
						w.WriteHeader(http.StatusNoContent)
					case "redirect":
						w.Header().Set("Location", trap.URL)
						w.WriteHeader(http.StatusTemporaryRedirect)
					default:
						w.WriteHeader(http.StatusCreated)
					}
				case "MOVE":
					if r.Header.Get("Overwrite") != "F" || !strings.HasSuffix(r.Header.Get("Destination"), "/collection/subdir/backup.tar.gz") {
						t.Error("unsafe MOVE")
					}
					if mode == "move failure" {
						w.WriteHeader(http.StatusPreconditionFailed)
					} else if mode == "move redirect" {
						w.Header().Set("Location", trap.URL)
						w.WriteHeader(http.StatusTemporaryRedirect)
					} else {
						w.WriteHeader(http.StatusCreated)
					}
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected method %s", r.Method)
				}
			}))
			defer server.Close()
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("archive"), 0600); err != nil {
				t.Fatal(err)
			}
			item := ManagedResource{Kind: "webdav", URI: server.URL + "/collection", Path: "subdir", Username: "backup", Password: "secret"}
			location, err := backupPublish(context.Background(), item, source, "backup.tar.gz", server.Client())
			if mode == "success" {
				if err != nil || location != server.URL+"/collection/subdir/backup.tar.gz" {
					t.Fatalf("location=%q err=%v", location, err)
				}
				if !reflect.DeepEqual(methods, []string{"PUT", "MOVE"}) {
					t.Fatalf("methods %v", methods)
				}
			} else {
				if err == nil {
					t.Fatal("accepted failed publication")
				}
				if methods[len(methods)-1] != "DELETE" {
					t.Fatalf("no cleanup: %v", methods)
				}
			}
			if leaked {
				t.Fatal("followed redirect")
			}
		})
	}
}

func TestBackupDAVValidation(t *testing.T) {
	for _, item := range []ManagedResource{
		{URI: "http://example.com/"}, {URI: "https://user:pass@example.com/"}, {URI: "https://example.com/?secret=x"},
		{URI: "https://example.com/?"}, {URI: "https://example.com/a%2fb/"}, {URI: "https://example.com/#frag"}, {URI: "https://example.com/%2e%2e/"}, {URI: "https://example.com/%252e%252e/"},
		{URI: "https://example.com/", Path: "../escape"}, {URI: "https://example.com/", Path: "/absolute"},
		{URI: "https://example.com/", Path: "a//b"}, {URI: "https://example.com/", Path: "a\\b"}, {URI: "https://example.com/", Path: "a/%2f"},
	} {
		if _, err := backupDAVCollection(item); err == nil {
			t.Errorf("accepted %+v", item)
		}
	}
	if u, err := backupDAVCollection(ManagedResource{URI: "https://example.com/a%20b/", Path: "child dir"}); err != nil || u.String() != "https://example.com/a%20b/child%20dir/" {
		t.Fatalf("url %v err %v", u, err)
	}
}

func TestBackupArchive(t *testing.T) {
	dir := t.TempDir()
	serverDir := filepath.Join(dir, "servers", "000")
	if err := os.MkdirAll(serverDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, leaf := range []string{"entries.ldif", "schema.ldif"} {
		if err := os.WriteFile(filepath.Join(serverDir, leaf), []byte(leaf), 0600); err != nil {
			t.Fatal(err)
		}
	}
	attachment, err := backupExportServer(context.Background(), backupSchemaOnlyTestSearcher(t, nil, true), dir, 7, "Schema attachment", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "servers", "001", "entries.ldif")); !os.IsNotExist(err) {
		t.Fatalf("schema-only export created entries.ldif: %v", err)
	}
	manifest := backupManifest{Version: 2, Created: time.Now().UTC(), Warning: backupWarning, Servers: []backupServerManifest{{Name: "Primary", Directory: "servers/000"}, attachment}}
	archive, err := backupMakeArchive(context.Background(), dir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	st, _ := file.Stat()
	if st.Mode().Perm() != 0600 {
		t.Fatal("archive not private")
	}
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		if header.Mode != 0600 {
			t.Fatal("tar member not private")
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == "manifest.json" {
			var got backupManifest
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got.Version != 2 || got.Warning != backupWarning || len(got.Servers) != 2 {
				t.Fatal("bad manifest")
			}
			if got.Servers[0].SchemaOnly || !got.Servers[1].SchemaOnly || got.Servers[1].ID != 7 {
				t.Fatalf("incorrect server scope: %+v", got.Servers)
			}
			if !bytes.Contains(data, []byte(`"schema_only": false`)) || !bytes.Contains(data, []byte(`"schema_only": true`)) {
				t.Fatalf("missing explicit manifest scope: %s", data)
			}
		}
	}
	if !reflect.DeepEqual(names, []string{"manifest.json", "servers/000/schema.ldif", "servers/000/entries.ldif", "servers/001/schema.ldif"}) {
		t.Fatalf("members %v", names)
	}
}

func TestBackupHandlerMutationValidation(t *testing.T) {
	app := &App{cfg: Config{Settings: Settings{Session: SessionSettings{TTLMinutes: 60, IdleMinutes: 10}}}}
	seed := httptest.NewRequest(http.MethodGet, "/", nil)
	session, err := store.New(seed, "ldap-session")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	session.Values["dn"] = "backup-owner"
	session.Values["created"] = now
	session.Values["last_active"] = now
	cookieWriter := httptest.NewRecorder()
	if err := session.Save(seed, cookieWriter); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, contentType, origin, site string
		status                                int
	}{
		{"cross site", `{"destination_id":1}`, "application/json", "https://attacker.invalid", "", http.StatusForbidden},
		{"fetch metadata", `{"destination_id":1}`, "application/json", "", "cross-site", http.StatusForbidden},
		{"form", `{"destination_id":1}`, "text/plain", "", "", http.StatusUnsupportedMediaType},
		{"malformed", `{`, "application/json", "", "", http.StatusBadRequest},
		{"trailing", `{"destination_id":1}{}`, "application/json", "", "", http.StatusBadRequest},
		{"unknown field", `{"destination_id":1,"password":"bad"}`, "application/json", "", "", http.StatusBadRequest},
		{"invalid ID", `{"destination_id":0}`, "application/json", "", "", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/backup", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			for _, cookie := range cookieWriter.Result().Cookies() {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			app.handleBackup(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

func TestBackupConnectionCancellation(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := ldap.NewConn(client, false)
	conn.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := backupExportConnection(ctx, conn, t.TempDir(), 0, "test", 0)
	if err == nil {
		t.Fatal("accepted canceled LDAP search")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("cancellation did not interrupt LDAP search")
	}
	if !conn.IsClosing() {
		t.Fatal("LDAP connection leaked")
	}
}

func TestBackupHandlerRejectsUnauthenticated(t *testing.T) {
	app := &App{}
	rec := httptest.NewRecorder()
	app.handleBackup(rec, httptest.NewRequest(http.MethodPost, "/api/backup", strings.NewReader(`{"destination_id":1}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	app.handleBackup(rec, httptest.NewRequest(http.MethodGet, "/api/backup", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}
