package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func managedTestDB(t *testing.T) {
	t.Helper()
	previous := db
	var err error
	db, err = sql.Open("sqlite", filepath.Join(t.TempDir(), "managed.db"))
	if err != nil {
		t.Fatal(err)
	}
	current := db
	t.Cleanup(func() { current.Close(); db = previous })
}

func managedTestLDAP() ManagedResource {
	return ManagedResource{Name: "Attached LDAP", Kind: "ldap", URI: "ldaps://ldap.example.test", Username: "cn=admin,dc=example,dc=test"}
}

func TestManagedResourcesBackupDestinations(t *testing.T) {
	managedTestDB(t)
	key, password := generateEncryptionKey(), "dav-secret"
	dir := t.TempDir()
	for _, kind := range []string{"local", "cifs", "nfs", "webdav"} {
		item := ManagedResource{Name: kind, Kind: kind, Path: dir}
		var secret *string
		if kind == "webdav" {
			item.Path = ""
			item.URI = "https://backup.example.test/archive"
			item.Username = "backup-user"
			secret = &password
		}
		id, err := saveManagedResource("alice", item, secret, key)
		if err != nil {
			t.Fatalf("save %s: %v", kind, err)
		}
		got, err := getManagedResource("alice", id, key)
		if err != nil {
			t.Fatal(err)
		}
		if kind == "webdav" {
			if got.Password != password || !got.HasPassword || got.URI != "https://backup.example.test/archive/" {
				t.Fatalf("DAV round trip: %#v", got)
			}
		} else if got.Path != dir || got.Password != "" || got.HasPassword {
			t.Fatalf("mounted directory round trip: %#v", got)
		}
	}
}

func TestManagedResourcesEncryptedOwnership(t *testing.T) {
	managedTestDB(t)
	key := generateEncryptionKey()
	password := "very-private-password"
	item := managedTestLDAP()
	id, err := saveManagedResource("alice", item, &password, key)
	if err != nil {
		t.Fatal(err)
	}
	item.ID = id
	got, err := getManagedResource("alice", id, key)
	if err != nil || got.Password != password || !got.HasPassword {
		t.Fatalf("round trip: %#v, %v", got, err)
	}
	var ciphertext string
	if err := db.QueryRow("SELECT encrypted_password FROM managed_resources WHERE id=?", id).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, password) || ciphertext == "" {
		t.Fatal("password stored unencrypted")
	}
	listed, err := listManagedResources("alice")
	if err != nil || len(listed) != 1 || listed[0].Password != "" || !listed[0].HasPassword {
		t.Fatalf("list: %#v, %v", listed, err)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), password) || strings.Contains(string(encoded), `"password"`) {
		t.Fatalf("secret in JSON: %s", encoded)
	}
	listed, err = listManagedResources("bob")
	if err != nil || len(listed) != 0 {
		t.Fatalf("cross-owner list: %#v %v", listed, err)
	}
	if _, err := getManagedResource("bob", id, key); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-owner read: %v", err)
	}
	if _, err := saveManagedResource("bob", item, &password, key); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-owner update: %v", err)
	}
	if err := deleteManagedResource("bob", id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-owner delete: %v", err)
	}
	if _, err := getManagedResource("alice", id, generateEncryptionKey()); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, p := range []*string{nil, new(string)} {
		item.Name = "Renamed"
		if _, err := saveManagedResource("alice", item, p, key); err != nil {
			t.Fatal(err)
		}
		got, err = getManagedResource("alice", id, key)
		if err != nil || got.Password != password {
			t.Fatalf("password not preserved: %v", err)
		}
	}
	replacement := "replacement-secret"
	if _, err := saveManagedResource("alice", item, &replacement, key); err != nil {
		t.Fatal(err)
	}
	got, err = getManagedResource("alice", id, key)
	if err != nil || got.Password != replacement {
		t.Fatalf("replacement failed: %v", err)
	}
	if err := deleteManagedResource("alice", id); err != nil {
		t.Fatal(err)
	}
	if _, err := getManagedResource("alice", id, key); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted resource remains: %v", err)
	}
}

func TestManagedResourcesCiphertextBinding(t *testing.T) {
	managedTestDB(t)
	key, password := generateEncryptionKey(), "secret"
	first, err := saveManagedResource("alice", managedTestLDAP(), &password, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"alice", "bob"} {
		second, err := saveManagedResource(owner, managedTestLDAP(), &password, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec("UPDATE managed_resources SET encrypted_password=(SELECT encrypted_password FROM managed_resources WHERE id=?) WHERE id=?", first, second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := getManagedResource(owner, second, key); err == nil {
			t.Fatal("transplanted ciphertext accepted")
		}
	}
	// Even moving the entire row to another owner must invalidate its secret.
	if _, err := db.Exec("UPDATE managed_resources SET owner='bob' WHERE id=?", first); err != nil {
		t.Fatal(err)
	}
	if _, err := getManagedResource("bob", first, key); err == nil {
		t.Fatal("owner transplant accepted")
	}
}

func TestManagedResourcesValidation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		item     ManagedResource
		password bool
		valid    bool
	}{
		{"ldap", managedTestLDAP(), true, true},
		{"ldap no password", managedTestLDAP(), false, false},
		{"webdav", ManagedResource{Name: "DAV", Kind: "webdav", URI: "https://example.test/backups"}, true, true},
		{"webdav plain HTTP", ManagedResource{Name: "DAV", Kind: "webdav", URI: "http://example.test/"}, false, false},
		{"webdav traversal", ManagedResource{Name: "DAV", Kind: "webdav", URI: "https://example.test/", Path: "../private"}, false, false},
		{"webdav absolute subdirectory", ManagedResource{Name: "DAV", Kind: "webdav", URI: "https://example.test/", Path: "/private"}, false, false},
		{"local", ManagedResource{Name: "disk", Kind: "local", Path: dir}, false, true},
		{"nfs", ManagedResource{Name: "mounted", Kind: "nfs", Path: dir}, false, true},
		{"cifs", ManagedResource{Name: "mounted", Kind: "cifs", Path: dir}, false, true},
		{"cifs password", ManagedResource{Name: "mounted", Kind: "cifs", Path: dir}, true, false},
		{"local password", ManagedResource{Name: "disk", Kind: "local", Path: dir}, true, false},
		{"nfs username", ManagedResource{Name: "mounted", Kind: "nfs", Path: dir, Username: "user"}, false, false},
		{"cifs username", ManagedResource{Name: "mounted", Kind: "cifs", Path: dir, Username: "user"}, false, false},
		{"unmounted share", ManagedResource{Name: "share", Kind: "cifs", URI: "smb://example.test/share", Path: dir}, false, false},
		{"relative", ManagedResource{Name: "disk", Kind: "local", Path: "relative"}, false, false},
		{"missing", ManagedResource{Name: "disk", Kind: "local", Path: filepath.Join(dir, "missing")}, false, false},
		{"file", ManagedResource{Name: "disk", Kind: "local", Path: file}, false, false},
		{"unknown", ManagedResource{Name: "bad", Kind: "ftp"}, false, false},
	}
	for _, uri := range []string{"ldap://", "http://example.test", "ldap://user:secret@example.test", "ldap://example.test/?x", "ldap://example.test/#x", "ldap://example.test/?", "ldap://example.test/#", "ldap://example.test/dc=test", "ldap://example.test:99999"} {
		item := managedTestLDAP()
		item.URI = uri
		cases = append(cases, struct {
			name     string
			item     ManagedResource
			password bool
			valid    bool
		}{uri, item, true, false})
	}
	for _, dn := range []string{"", "not a DN"} {
		item := managedTestLDAP()
		item.Username = dn
		cases = append(cases, struct {
			name     string
			item     ManagedResource
			password bool
			valid    bool
		}{"bad DN " + dn, item, true, false})
	}
	for _, uri := range []string{"https://u:p@example.test/", "https://example.test/?q=x", "https://example.test/#frag"} {
		cases = append(cases, struct {
			name     string
			item     ManagedResource
			password bool
			valid    bool
		}{uri, ManagedResource{Name: "DAV", Kind: "webdav", URI: uri}, false, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateManagedResource(&tc.item, tc.password)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
			if err == nil && tc.item.Kind == "webdav" && !strings.HasSuffix(tc.item.URI, "/") {
				t.Fatal("DAV URI not a directory")
			}
		})
	}
}

func TestManagedResourcesCreationIsAtomic(t *testing.T) {
	managedTestDB(t)
	password := "secret"
	if _, err := saveManagedResource("alice", managedTestLDAP(), nil, generateEncryptionKey()); !errors.Is(err, errManagedInvalid) {
		t.Fatalf("missing creation password: %v", err)
	}
	if _, err := saveManagedResource("alice", managedTestLDAP(), &password, "bad key"); err == nil {
		t.Fatal("bad key accepted")
	}
	items, err := listManagedResources("alice")
	if err != nil || len(items) != 0 {
		t.Fatalf("failed insert left a row: %#v %v", items, err)
	}
}

func managedTestRequest(t *testing.T, method, path, body string, values map[interface{}]interface{}) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if values == nil {
		return req
	}
	seed := httptest.NewRequest(http.MethodGet, "/", nil)
	session, err := store.New(seed, "ldap-session")
	if err != nil {
		t.Fatal(err)
	}
	session.Values = values
	recorder := httptest.NewRecorder()
	if err := session.Save(seed, recorder); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range recorder.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func managedTestSession() map[interface{}]interface{} {
	now := time.Now().Unix()
	return map[interface{}]interface{}{"dn": "alice", "created": now - 10, "last_active": now - 5}
}

func managedTestApp() *App {
	return &App{cfg: Config{EncryptionKey: generateEncryptionKey(), Settings: Settings{Session: SessionSettings{TTLMinutes: 60, IdleMinutes: 10}}}}
}

func TestManagedOwnerAuthentication(t *testing.T) {
	app := managedTestApp()
	for _, name := range []string{"valid", "missing cookie", "invalid signature", "missing created", "missing active", "expired TTL", "expired idle", "future", "blank owner"} {
		t.Run(name, func(t *testing.T) {
			values := managedTestSession()
			switch name {
			case "missing cookie":
				values = nil
			case "missing created":
				delete(values, "created")
			case "missing active":
				delete(values, "last_active")
			case "expired TTL":
				values["created"] = time.Now().Unix() - 3601
			case "expired idle":
				values["created"] = time.Now().Unix() - 1000
				values["last_active"] = time.Now().Unix() - 601
			case "future":
				values["last_active"] = time.Now().Unix() + 100
			case "blank owner":
				values["dn"] = " "
			}
			req := managedTestRequest(t, http.MethodGet, "/api/managed_resources", "", values)
			if name == "invalid signature" {
				req.Header.Set("Cookie", "ldap-session=invalid-signature")
			}
			rr := httptest.NewRecorder()
			owner, ok := app.managedOwner(rr, req)
			if name != "valid" {
				if ok || rr.Code != http.StatusUnauthorized {
					t.Fatalf("unauthenticated: ok=%v status=%d", ok, rr.Code)
				}
				return
			}
			if !ok || owner != "alice" {
				t.Fatalf("valid auth denied: %s", rr.Body.String())
			}
			follow := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range rr.Result().Cookies() {
				follow.AddCookie(cookie)
			}
			session, err := store.Get(follow, "ldap-session")
			if err != nil || session.Values["last_active"].(int64) < time.Now().Unix()-1 {
				t.Fatalf("activity not refreshed: %v", err)
			}
		})
	}
}

func TestManagedResourcesAPISecurityAndRoundTrip(t *testing.T) {
	managedTestDB(t)
	app := managedTestApp()
	payload := `{"name":"LDAP","kind":"ldap","uri":"ldaps://example.test","username":"cn=admin","password":"private-secret"}`
	tests := []struct {
		name, method, body, content, origin, site string
		status                                    int
	}{
		{"foreign origin", "POST", payload, "application/json", "http://evil.test", "", 403},
		{"cross-site", "POST", payload, "application/json", "", "cross-site", 403},
		{"same-site is not same-origin", "POST", payload, "application/json", "", "same-site", 403},
		{"text JSON", "POST", payload, "text/plain", "", "", 415},
		{"missing content type", "POST", payload, "", "", "", 415},
		{"trailing JSON", "POST", payload + ` {}`, "application/json", "", "", 400},
		{"unknown fields", "POST", `{"unexpected":true}`, "application/json", "", "", 400},
		{"oversize", "POST", `{"name":"` + strings.Repeat("x", (1<<20)+1) + `"}`, "application/json", "", "", 400},
		{"delete csrf", "DELETE", `{"id":1}`, "application/json", "http://evil.test", "", 403},
		{"unsupported", "PATCH", "", "application/json", "", "", 405},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := managedTestRequest(t, tc.method, "/api/managed_resources", tc.body, managedTestSession())
			req.Header.Set("Content-Type", tc.content)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Sec-Fetch-Site", tc.site)
			rr := httptest.NewRecorder()
			app.handleManagedResources(rr, req)
			if rr.Code != tc.status {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
	rr := httptest.NewRecorder()
	req := managedTestRequest(t, "POST", "/api/managed_resources", payload, managedTestSession())
	// Public HTTPS origin with a cleartext proxy-to-application connection.
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	app.handleManagedResources(rr, req)
	if rr.Code != 200 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil || result.ID <= 0 {
		t.Fatalf("create result: %v", err)
	}
	rr = httptest.NewRecorder()
	app.handleManagedResources(rr, managedTestRequest(t, "GET", "/api/managed_resources", "", managedTestSession()))
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "private-secret") || !strings.Contains(rr.Body.String(), `"has_password":true`) {
		t.Fatalf("list: %s", rr.Body.String())
	}
	bob := managedTestSession()
	bob["dn"] = "bob"
	rr = httptest.NewRecorder()
	app.handleManagedResources(rr, managedTestRequest(t, "DELETE", "/api/managed_resources", `{"id":`+strconv.FormatInt(result.ID, 10)+`}`, bob))
	if rr.Code != 404 {
		t.Fatalf("cross-owner delete: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	app.handleManagedResources(rr, managedTestRequest(t, "DELETE", "/api/managed_resources", `{"id":`+strconv.FormatInt(result.ID, 10)+`}`, managedTestSession()))
	if rr.Code != 200 {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
}

func TestManagedSchemaValidationAndSecurity(t *testing.T) {
	valid := managedSchemaChange{ID: 1, DN: "cn={1}custom,cn=schema,cn=config", Attribute: "olcObjectClasses", Values: []string{"( 1.2.3 NAME 'custom' SUP top AUXILIARY )"}, Operation: "add"}
	for _, name := range []string{"valid", "base", "case insensitive DN", "outside", "suffix trick", "malformed", "wrong attr", "wrong operation", "empty add", "empty value"} {
		t.Run(name, func(t *testing.T) {
			req := valid
			switch name {
			case "base":
				req.DN = "cn=schema,cn=config"
			case "case insensitive DN":
				req.DN = "cn=Custom,CN=SCHEMA,CN=CONFIG"
			case "outside":
				req.DN = "cn=config"
			case "suffix trick":
				req.DN = "cn=evilcn=schema,cn=config"
			case "malformed":
				req.DN = "invalid"
			case "wrong attr":
				req.Attribute = "olcRootPW"
			case "wrong operation":
				req.Operation = "increment"
			case "empty add":
				req.Values = nil
			case "empty value":
				req.Values = []string{" "}
			}
			err := validateManagedSchemaChange(req)
			expected := name == "valid" || name == "base" || name == "case insensitive DN"
			if (err == nil) != expected {
				t.Fatalf("expected valid=%v, got %v", expected, err)
			}
		})
	}
	managedTestDB(t)
	app := managedTestApp()
	for _, test := range []struct {
		method, body, origin string
		auth                 bool
		status               int
	}{
		{"GET", "", "", false, 401},
		{"POST", `{"id":1}`, "http://evil.test", true, 403},
		{"POST", `{"id":1,"dn":"cn=config","attribute":"olcRootPW","operation":"replace","values":["private-secret"]}`, "", true, 400},
		{"GET", "", "", true, 404},
	} {
		var values map[interface{}]interface{}
		if test.auth {
			values = managedTestSession()
		}
		req := managedTestRequest(t, test.method, "/api/attached_schema?id=1", test.body, values)
		req.Header.Set("Origin", test.origin)
		rr := httptest.NewRecorder()
		app.handleAttachedSchema(rr, req)
		if rr.Code != test.status {
			t.Fatalf("schema status=%d want %d: %s", rr.Code, test.status, rr.Body.String())
		}
		body, _ := io.ReadAll(rr.Result().Body)
		if strings.Contains(string(body), "private-secret") {
			t.Fatal("request secret leaked in error")
		}
	}
}
