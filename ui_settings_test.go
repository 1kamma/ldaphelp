package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func initUISettingsTestDB(t *testing.T) {
	t.Helper()
	if db != nil {
		_ = db.Close()
	}
	if err := initDB(filepath.Join(t.TempDir(), "ldaphelp-test.db")); err != nil {
		t.Fatalf("initDB() error = %v", err)
	}
}

func TestHandleUISettingsRendersFragment(t *testing.T) {
	app := &App{cfg: Config{Settings: Settings{DefaultGIDNumber: "1000", UI: UISettings{Theme: "dark"}}}}
	req := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	rec := httptest.NewRecorder()
	app.handleUISettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"settings-modal-content", "hx-post=\"/ui/settings\"", "settings-ui-json", "settings-type-actions-json"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in body: %s", want, body)
		}
	}
}

func TestHandleUISaveSettingsPersistsAndRefreshes(t *testing.T) {
	initUISettingsTestDB(t)
	app := &App{cfg: Config{Settings: Settings{UI: UISettings{Theme: "dark"}, DefaultGIDNumber: "1000"}}}
	form := strings.NewReader("ui_json=%7B%22theme%22%3A%22light%22%2C%22context_menu%22%3A%5B%5D%7D&objects_json=%7B%7D&type_actions_json=%7B%7D&default_gid_number=2000&default_group=cn%3Dusers%2Cdc%3Dexample%2Cdc%3Dcom&assets_logo=&assets_favicon=&logo_source_file=&favicon_source_file=&session_ttl=30&session_idle=15&saml_idp=&saml_entity=&saml_cert=&oidc_issuer=&oidc_clientid=&oidc_clientsecret=")
	req := httptest.NewRequest(http.MethodPost, "/ui/settings", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	app.handleUISaveSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("HX-Refresh") != "true" {
		t.Fatalf("expected HX-Refresh header, got %#v", rec.Header())
	}
	got, err := LoadSettingsFromDB()
	if err != nil {
		t.Fatalf("LoadSettingsFromDB() error = %v", err)
	}
	if got.UI.Theme != "light" || got.DefaultGIDNumber != "2000" || got.Session.TTLMinutes != 30 || got.Session.IdleMinutes != 15 {
		t.Fatalf("unexpected saved settings: %#v", got)
	}
}
