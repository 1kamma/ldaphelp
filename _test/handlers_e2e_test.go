package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestHandleApiRootsE2E(t *testing.T) {
	fake := &fakeLDAPSearchConn{search: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.BaseDN != "" {
			t.Fatalf("BaseDN = %q, want Root DSE", req.BaseDN)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("", map[string][]string{
				"namingContexts":    {"dc=example,dc=com"},
				"subschemaSubentry": {"cn=Subschema"},
				"monitorContext":    {"cn=Monitor"},
				"configContext":     {"cn=config"},
			}),
		}}, nil
	}}

	app := &App{
		cfg: Config{Base: "ou=users,dc=example,dc=com"},
		ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) {
			return fake, nil
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/roots", nil)
	app.handleApiRoots(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var roots []TreeNode
	if err := json.Unmarshal(rec.Body.Bytes(), &roots); err != nil {
		t.Fatalf("unmarshal roots: %v", err)
	}
	if len(roots) != 5 {
		t.Fatalf("roots = %#v", roots)
	}
	if roots[0].DN != "ou=users,dc=example,dc=com" {
		t.Fatalf("configured base root missing first: %#v", roots)
	}
}

func TestHandleApiSettingsE2E(t *testing.T) {
	initTestDB(t)

	app := &App{cfg: Config{Settings: Settings{UI: UISettings{Theme: "dark"}}}}

	getRec := httptest.NewRecorder()
	app.handleApiSettingsGet(getRec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d", getRec.Code)
	}

	body := bytes.NewBufferString(`{"ui":{"theme":"light"},"objects":{"person":{"default_location":"ou=people,dc=example,dc=com","dn_parameter":"uid","pin_quick_create":true}}}`)
	postRec := httptest.NewRecorder()
	app.handleApiSettingsPost(postRec, httptest.NewRequest(http.MethodPost, "/api/settings", body))
	if postRec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, body = %s", postRec.Code, postRec.Body.String())
	}
	if app.cfg.Settings.UI.Theme != "light" {
		t.Fatalf("app settings not updated: %#v", app.cfg.Settings)
	}

	persisted, err := LoadSettingsFromDB()
	if err != nil {
		t.Fatalf("LoadSettingsFromDB() error = %v", err)
	}
	if persisted.UI.Theme != "light" || !persisted.Objects["person"].PinQuickCreate {
		t.Fatalf("persisted settings = %#v", persisted)
	}
}

func TestHandleApiSettingsPostRejectsInvalidJSON(t *testing.T) {
	app := &App{}
	rec := httptest.NewRecorder()
	app.handleApiSettingsPost(rec, httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRecoverE2E(t *testing.T) {
	app := &App{}

	methodRec := httptest.NewRecorder()
	app.handleRecover(methodRec, httptest.NewRequest(http.MethodGet, "/recover", nil))
	if methodRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", methodRec.Code)
	}

	postRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/recover", strings.NewReader("username=alice"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.handleRecover(postRec, req)
	if postRec.Code != http.StatusOK {
		t.Fatalf("POST status = %d", postRec.Code)
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"status": "ok"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
