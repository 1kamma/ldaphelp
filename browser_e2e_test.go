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

func renderBrowseBody(t *testing.T) string {
	t.Helper()

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
	return rr.Body.String()
}

func TestHandleBrowseRendersUpdatedSettingsAndGroupModal(t *testing.T) {
	body := renderBrowseBody(t)
	checks := []string{
		"name=\"viewport\"",
		"entry-toolbar-actions",
		"table-wrap",
		"settings-modal-content",
		"/ui/settings",
		"/ui/groups/select",
		"/ui/quick-create",
		"modal-scroll-shell",
		"modal-footer-fixed",
		"attachLongPressContextMenu",
		"consumeLongPressClick",
		"Remove from group",
		"Binary value (base64)",
		"const syncExpander = (state) => {",
		"childrenUl.innerHTML = '';",
		"loaded = false;",
		"Replication Peers",
		"/api/schema_replicas",
		"/api/schema_replica",
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Fatalf("expected browse HTML to contain %q", check)
		}
	}
}

func TestHandleBrowseRendersMobileLayoutAndEditors(t *testing.T) {
	body := renderBrowseBody(t)
	checks := []string{
		`aria-label="Layout controls"`,
		`id="toggle-tree" aria-controls="tree-panel"`,
		`id="toggle-search" aria-controls="ldap-search"`,
		`id="toggle-menu" aria-controls="top-menu"`,
		`[hidden] { display: none !important; }`,
		`search:!phoneLayout.matches, menu:!phoneLayout.matches`,
		`sidebar.hidden = !panelState.tree && !panelState.search`,
		`setAttribute('aria-expanded', String(panelState[name]))`,
		`#entry-attrs thead { display:none; }`,
		`min-width:0;`,
		`input.className = 'attribute-editor'`,
		`input.setAttribute('aria-label', 'Values for ' + attr)`,
		`help.textContent = 'One value per line'`,
		`remove.textContent = 'Remove attribute'`,
		`cell.parentElement.style.display = ''`,
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("expected mobile browse HTML to contain %q", check)
		}
	}
	if strings.Contains(body, "min-width: 520px") {
		t.Error("mobile tables must not force desktop width")
	}
}

func TestHandleBrowseRendersServerAndBackupManagement(t *testing.T) {
	body := renderBrowseBody(t)
	checks := []string{
		`Servers &amp; Backups`,
		`id="management-modal" hidden role="dialog"`,
		`/api/managed_resources`,
		`/api/attached_schema`,
		`/api/backups`,
		`id="managed-password" type="password"`,
		`id="backup-destination"`,
		`Mounted CIFS/SMB directory`,
		`Mounted NFS directory`,
		`WebDAV over HTTPS`,
		`schemaViewState.mode === 'attached'`,
		`return loadAttachedSchema(schemaViewState.attachedID, attr)`,
		`payload.operation = document.getElementById('schema-operation').value`,
		`payload.id = schemaViewState.attachedID`,
		`Sensitive, unencrypted archive`,
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("expected server/backup management HTML to contain %q", check)
		}
	}
}

func TestHandleBrowseDoesNotDuplicateOcKeyDeclaration(t *testing.T) {
	body := renderBrowseBody(t)
	if count := strings.Count(body, "const ocKey = Object.keys(data).find(k => k.toLowerCase() === 'objectclass');"); count != 1 {
		t.Fatalf("expected exactly one ocKey declaration in browse script, got %d", count)
	}
}
