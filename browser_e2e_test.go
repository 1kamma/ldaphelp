package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newAuthenticatedRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	session, err := store.Get(req, "ldap-session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	now := time.Now().Unix()
	session.Values["dn"] = "uid=test,dc=example,dc=com"
	session.Values["password"] = "secret"
	session.Values["created"] = now
	session.Values["last_active"] = now
	if err := session.Save(req, rr); err != nil {
		t.Fatalf("save session: %v", err)
	}

	authedReq := httptest.NewRequest(method, path, nil)
	for _, cookie := range rr.Result().Cookies() {
		authedReq.AddCookie(cookie)
	}
	return authedReq
}

func TestHandleBrowseRendersUpdatedSettingsAndGroupModal(t *testing.T) {
	app := &App{cfg: Config{Settings: Settings{
		DefaultGIDNumber: "1000",
		Session:          SessionSettings{TTLMinutes: 60, IdleMinutes: 60},
		UI:               UISettings{Theme: "dark"},
	}}}

	req := newAuthenticatedRequest(t, http.MethodGet, "/browse")
	rr := httptest.NewRecorder()

	app.handleBrowse(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	body := rr.Body.String()
	checks := []string{
		"settings-type-actions-json",
		"settings-default-gid-number",
		"modal-scroll-shell",
		"Remove from group",
		"Binary value (base64)",
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Fatalf("expected browse HTML to contain %q", check)
		}
	}
}
