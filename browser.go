package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/go-ldap/ldap/v3"

	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

func init() {
	store = sessions.NewCookieStore(generateSessionKey())
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}
}

func generateSessionKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

type TreeNode struct {
	DN            string   `json:"dn"`
	RDN           string   `json:"rdn"`
	ObjectClasses []string `json:"objectClasses"`
	HasChildren   bool     `json:"hasChildren"`
}

func getLDAPConn(r *http.Request, cfg Config) (*ldap.Conn, error) {
	session, _ := store.Get(r, "ldap-session")
	dn, ok1 := session.Values["dn"].(string)
	pwd, ok2 := session.Values["password"].(string)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("unauthorized")
	}

	conn, err := dialLDAP(cfg.LDAPServer, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if err := conn.Bind(dn, pwd); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (a *App) handleBrowse(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "ldap-session")
	dn, ok := session.Values["dn"].(string)
	if !ok || dn == "" {
		slog.Warn("browse unauthorized, redirecting to login")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	slog.Info("rendering browse for user", "dn", dn)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, err := template.New("browse").Parse(browseHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	settingsJSON, _ := json.Marshal(a.cfg.Settings)

	data := struct {
		SettingsJSON template.JS
	}{
		SettingsJSON: template.JS(settingsJSON),
	}

	if err := tmpl.Execute(w, data); err != nil {
		slog.Error("failed to execute template", "error", err)
	}
}

func (a *App) handleApiRoots(w http.ResponseWriter, r *http.Request) {
	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	// Try to fetch Root DSE
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"namingContexts", "subschemaSubentry", "monitorContext", "configContext"}, nil)
	res, err := conn.Search(req)

	var roots []TreeNode

	if a.cfg.Base != "" {
		roots = append(roots, TreeNode{DN: a.cfg.Base, RDN: a.cfg.Base, ObjectClasses: []string{"domain"}, HasChildren: true})
	}

	if err == nil && len(res.Entries) > 0 {
		entry := res.Entries[0]

		for _, nc := range entry.GetAttributeValues("namingContexts") {
			if a.cfg.Base == "" || nc != a.cfg.Base {
				roots = append(roots, TreeNode{DN: nc, RDN: nc, ObjectClasses: []string{"domain"}, HasChildren: true})
			}
		}
		if sub := entry.GetAttributeValue("subschemaSubentry"); sub != "" {
			roots = append(roots, TreeNode{DN: sub, RDN: "Schema (" + sub + ")", ObjectClasses: []string{"subschema"}, HasChildren: true})
		}
		if mon := entry.GetAttributeValue("monitorContext"); mon != "" {
			roots = append(roots, TreeNode{DN: mon, RDN: "Monitor (" + mon + ")", ObjectClasses: []string{"monitor"}, HasChildren: true})
		}
		if cfgCtx := entry.GetAttributeValue("configContext"); cfgCtx != "" {
			roots = append(roots, TreeNode{DN: cfgCtx, RDN: "Config (" + cfgCtx + ")", ObjectClasses: []string{"domain"}, HasChildren: true})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roots)
}

func (a *App) handleApiChildren(w http.ResponseWriter, r *http.Request) {
	dn := r.URL.Query().Get("dn")
	if dn == "" {
		http.Error(w, "missing dn", http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	req := ldap.NewSearchRequest(dn, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectClass"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var children []TreeNode
	for _, entry := range res.Entries {
		rdn := entry.DN
		if idx := strings.Index(rdn, ","); idx != -1 {
			rdn = rdn[:idx]
		}
		children = append(children, TreeNode{
			DN:            entry.DN,
			RDN:           rdn,
			ObjectClasses: entry.GetAttributeValues("objectClass"),
			HasChildren:   true, // Assuming it has children for lazy loading, frontend will handle empty nodes
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(children)
}

func (a *App) handleApiSettingsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.cfg.Settings)
}

func (a *App) handleApiSettingsPost(w http.ResponseWriter, r *http.Request) {
	var s Settings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.cfg.Settings = s
	SaveSettingsToDB(s)
	w.WriteHeader(http.StatusOK)
}

func (a *App) handleApiEntry(w http.ResponseWriter, r *http.Request) {
	dn := r.URL.Query().Get("dn")
	if dn == "" {
		http.Error(w, "missing dn", http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"*", "+"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		http.Error(w, "not found or error", http.StatusNotFound)
		return
	}

	attrs := make(map[string][]string)
	for _, attr := range res.Entries[0].Attributes {
		attrs[attr.Name] = attr.Values
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attrs)
}

func (a *App) handleApiModify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DN      string            `json:"dn"`
		Replace map[string]string `json:"replace"`
		Add     map[string]string `json:"add"`
		Delete  []string          `json:"delete"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(req.DN, nil)
	for k, v := range req.Replace {
		modReq.Replace(k, []string{v})
	}
	for k, v := range req.Add {
		modReq.Add(k, []string{v})
	}
	for _, k := range req.Delete {
		modReq.Delete(k, nil)
	}
	if err := conn.Modify(modReq); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "ldap-session")
	userDN, _ := session.Values["dn"].(string)
	notify(a.cfg.NtfyURI, fmt.Sprintf("User %s modified LDAP object: %s", userDN, req.DN))

	w.WriteHeader(http.StatusOK)
}

func (a *App) handleApiDelete(w http.ResponseWriter, r *http.Request) {
	dn := r.URL.Query().Get("dn")
	if dn == "" {
		http.Error(w, "missing dn", http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	delReq := ldap.NewDelRequest(dn, nil)
	if err := conn.Del(delReq); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "ldap-session")
	userDN, _ := session.Values["dn"].(string)
	notify(a.cfg.NtfyURI, fmt.Sprintf("User %s deleted LDAP object: %s", userDN, dn))

	w.WriteHeader(http.StatusOK)
}

func (a *App) handleApiMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DN    string `json:"dn"`
		NewDN string `json:"new_dn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	// Extract NewRDN and NewSuperior from NewDN
	parts := strings.SplitN(req.NewDN, ",", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid new dn format", http.StatusBadRequest)
		return
	}
	newRDN := parts[0]
	newSuperior := parts[1]

	modDNReq := ldap.NewModifyDNRequest(req.DN, newRDN, true, newSuperior)
	if err := conn.ModifyDN(modDNReq); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "ldap-session")
	userDN, _ := session.Values["dn"].(string)
	notify(a.cfg.NtfyURI, fmt.Sprintf("User %s moved/renamed object %s to %s", userDN, req.DN, req.NewDN))

	w.WriteHeader(http.StatusOK)
}

func getNextID(conn *ldap.Conn, bases []string, attr string) string {
	maxID := 10000
	for _, base := range bases {
		if base == "" {
			continue
		}
		req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{attr}, nil)
		res, err := conn.Search(req)
		if err == nil {
			for _, ent := range res.Entries {
				for _, val := range ent.GetAttributeValues(attr) {
					if id, err := strconv.Atoi(val); err == nil && id > maxID {
						maxID = id
					}
				}
			}
		}
	}
	return strconv.Itoa(maxID + 1)
}

func (a *App) handleApiCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DN         string              `json:"dn"`
		Attributes map[string][]string `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	hasPosixAccount := false
	hasPosixGroup := false
	hasStructural := false
	for _, oc := range req.Attributes["objectClass"] {
		lower := strings.ToLower(oc)
		if lower == "posixaccount" {
			hasPosixAccount = true
		}
		if lower == "posixgroup" {
			hasPosixGroup = true
		}
		if lower == "inetorgperson" || lower == "person" || lower == "account" || lower == "organizationalrole" || lower == "groupofnames" || lower == "organizationalunit" || lower == "posixgroup" {
			hasStructural = true
		}
	}
	if !hasStructural {
		if hasPosixAccount {
			req.Attributes["objectClass"] = append(req.Attributes["objectClass"], "account")
		}
	}

	bases := []string{a.cfg.Base}
	if a.cfg.Base == "" {
		rootReq := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil)
		rootRes, err := conn.Search(rootReq)
		if err == nil && len(rootRes.Entries) > 0 {
			bases = rootRes.Entries[0].GetAttributeValues("namingContexts")
		}
	}

	if hasPosixAccount {
		if len(req.Attributes["uidNumber"]) == 0 || req.Attributes["uidNumber"][0] == "" {
			req.Attributes["uidNumber"] = []string{getNextID(conn, bases, "uidNumber")}
		}
		if len(req.Attributes["gidNumber"]) == 0 || req.Attributes["gidNumber"][0] == "" {
			req.Attributes["gidNumber"] = req.Attributes["uidNumber"]
		}
		if len(req.Attributes["homeDirectory"]) == 0 || req.Attributes["homeDirectory"][0] == "" {
			if len(req.Attributes["uid"]) > 0 {
				req.Attributes["homeDirectory"] = []string{"/home/" + req.Attributes["uid"][0]}
			}
		}
	}
	if hasPosixGroup {
		if len(req.Attributes["gidNumber"]) == 0 || req.Attributes["gidNumber"][0] == "" {
			req.Attributes["gidNumber"] = []string{getNextID(conn, bases, "gidNumber")}
		}
	}

	addReq := ldap.NewAddRequest(req.DN, nil)
	for k, vals := range req.Attributes {
		var validVals []string
		for _, v := range vals {
			if v != "" {
				validVals = append(validVals, v)
			}
		}
		if len(validVals) == 0 {
			continue
		}
		if strings.ToLower(k) == "userpassword" {
			var hashed []string
			for _, v := range vals {
				if !strings.HasPrefix(v, "{") {
					if h, err := MakeSSHA(v); err == nil {
						hashed = append(hashed, h)
						continue
					}
				}
				hashed = append(hashed, v)
			}
			addReq.Attribute(k, hashed)
		} else {
			addReq.Attribute(k, vals)
		}
	}

	if err := conn.Add(addReq); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "ldap-session")
	userDN, _ := session.Values["dn"].(string)
	notify(a.cfg.NtfyURI, fmt.Sprintf("User %s created LDAP object: %s", userDN, req.DN))

	w.WriteHeader(http.StatusOK)
}

func (a *App) handleApiPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DN       string `json:"dn"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	hash, err := MakeSSHA(req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	modReq := ldap.NewModifyRequest(req.DN, nil)
	modReq.Replace("userPassword", []string{hash})
	if err := conn.Modify(modReq); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "ldap-session")
	userDN, _ := session.Values["dn"].(string)
	notify(a.cfg.NtfyURI, fmt.Sprintf("User %s changed password for: %s", userDN, req.DN))

	w.WriteHeader(http.StatusOK)
}

func (a *App) handleApiSearch(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		http.Error(w, "missing filter", http.StatusBadRequest)
		return
	}
	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	bases := []string{a.cfg.Base}
	if a.cfg.Base == "" {
		rootReq := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil)
		rootRes, err := conn.Search(rootReq)
		if err == nil && len(rootRes.Entries) > 0 {
			bases = rootRes.Entries[0].GetAttributeValues("namingContexts")
		}
	}

	var results []string
	for _, base := range bases {
		if base == "" {
			continue
		}
		sReq := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 100, 0, false, filter, []string{"dn"}, nil)
		sRes, err := conn.Search(sReq)
		if err != nil {
			continue
		}
		for _, ent := range sRes.Entries {
			results = append(results, ent.DN)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

const browseHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>LDAP Browser</title>
  <style>
    :root { --bg: #121212; --text: #e0e0e0; --sidebar-bg: #1e1e1e; --border: #333; --hover: #2a2a2a; --selected-bg: #1e3a8a; --selected-text: #bfdbfe; --table-bg: #1e1e1e; --th-bg: #2a2a2a; }
    body.light { --bg: #f4f6f8; --text: #1f2937; --sidebar-bg: #fff; --border: #ddd; --hover: #e5e7eb; --selected-bg: #bfdbfe; --selected-text: #1e3a8a; --table-bg: #fff; --th-bg: #f9fafb; }
    body { display: flex; height: 100vh; margin: 0; font-family: sans-serif; background: var(--bg); color: var(--text); }
    #sidebar { width: 400px; border-right: 1px solid var(--border); overflow-y: auto; padding: 10px; background: var(--sidebar-bg); box-shadow: 2px 0 5px rgba(0,0,0,0.05); }
    #content { flex: 1; padding: 20px; overflow-y: auto; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .header h2, .header h3 { margin: 0; color: inherit; }
    .btn { padding: 6px 12px; background: #dc2626; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 14px; margin-left: 5px;}
    .tree-node { margin-left: 15px; list-style: none; line-height: 1.8; white-space: nowrap; }
    .tree-ul { padding-left: 0; margin: 0; }
    .expand-icon { cursor: pointer; display: inline-block; width: 20px; text-align: center; color: #6b7280; font-size: 12px; }
    .item-text { cursor: pointer; padding: 3px 6px; border-radius: 4px; color: inherit; font-size: 15px; }
    .item-text:hover { background: var(--hover); }
    .selected { background: var(--selected-bg) !important; color: var(--selected-text) !important; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; background: var(--table-bg); box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 6px; overflow: hidden; }
    th, td { border: 1px solid var(--border); padding: 12px; text-align: left; font-size: 14px; }
    th { background: var(--th-bg); font-weight: 600; width: 30%; color: inherit; }
    td { word-break: break-all; color: inherit; font-family: monospace; }
    #quick-create { margin-bottom: 15px; padding: 10px; border-bottom: 1px solid var(--border); }
    .qc-btn { display: inline-block; padding: 4px 8px; margin: 2px; background: #3b82f6; color: white; border-radius: 4px; font-size: 12px; cursor: pointer; text-decoration: none; }
    #context-menu { display: none; position: absolute; background: var(--sidebar-bg); border: 1px solid var(--border); box-shadow: 0 2px 5px rgba(0,0,0,0.2); z-index: 1000; padding: 5px 0; border-radius: 4px; }
    .cm-item { padding: 8px 15px; cursor: pointer; color: var(--text); font-size: 14px; }
    .cm-item:hover { background: var(--hover); }
    #settings-modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center; }
    .modal-content { background: var(--sidebar-bg); padding: 20px; border-radius: 6px; width: 400px; color: var(--text); border: 1px solid var(--border); }
    .modal-actions { text-align: right; margin-top: 15px; }
  </style>
</head>
<body>
  <div id="sidebar">
    <div class="header">
      <h3>LDAP Tree</h3>
      <div>
        <button class="btn" style="background: #4b5563;" onclick="openSettings()">Settings</button>
        <a href="/logout" class="btn">Logout</a>
      </div>
    </div>
    <div id="quick-create">
      <strong>Quick Create:</strong><br/>
    </div>
    <ul class="tree-ul" id="tree-root"></ul>
  </div>
  <div id="content">
    <div class="header">
      <h2>Entry Details</h2>
    </div>
    <div style="display:flex; justify-content:space-between; margin-bottom: 15px; align-items:center;">
      <div id="entry-dn" style="flex:1; font-family: monospace; background: var(--hover); padding: 10px; border-radius: 4px; border: 1px solid var(--border);">Select an entry to view details.</div>
      <button id="btn-add-attr" class="btn" style="display:none; background: #3b82f6; margin-left: 10px;" onclick="showAddAttribute()">Add Attribute</button>
      <button id="btn-edit" class="btn" style="display:none; margin-left: 10px;" onclick="toggleEdit()">Edit</button>
      <button id="btn-save" class="btn" style="display:none; background: #10b981; margin-left: 10px;" onclick="saveEdits()">Save</button>
      <button id="btn-delete" class="btn" style="display:none; margin-left: 10px;" onclick="deleteEntry()">Delete</button>
    </div>
    <div id="add-attr-panel" style="display:none; margin-bottom: 15px; padding: 10px; background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 4px;">
      <select id="add-attr-select" style="padding: 4px; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></select>
      <input type="text" id="add-attr-val" style="padding: 4px; background: var(--bg); color: var(--text); border: 1px solid var(--border);">
      <button class="btn" style="background: #10b981; padding: 4px 8px;" onclick="addAttribute()">Add</button>
    </div>
    <table id="entry-attrs" style="display:none;">
      <thead><tr><th>Attribute</th><th>Value(s)</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div id="context-menu"></div>

  <div id="qc-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center;">
    <div class="modal-content" style="max-height: 80vh; overflow-y: auto;">
      <h3 id="qc-title">Quick Create</h3>
      <div id="qc-form"></div>
      <div class="modal-actions">
        <button class="btn" style="background: #6b7280;" onclick="document.getElementById('qc-modal').style.display='none'">Cancel</button>
        <button class="btn" style="background: #10b981;" onclick="submitQuickCreate()">Create</button>
      </div>
    </div>
  </div>

  <div id="group-select-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center;">
    <div class="modal-content" style="max-height: 80vh; overflow-y: auto;">
      <h3 id="group-select-title">Select Group</h3>
      <div id="group-select-list" style="margin-top: 15px; margin-bottom: 15px; max-height: 300px; overflow-y: auto;"></div>
      <div class="modal-actions">
        <button class="btn" style="background: #6b7280;" onclick="document.getElementById('group-select-modal').style.display='none'">Cancel</button>
      </div>
    </div>
  </div>

  <div id="settings-modal">
    <div class="modal-content">
      <h3>Settings</h3>
      <textarea id="settings-json" rows="15" style="width:100%; margin-top:10px; font-family:monospace; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></textarea>
      <div class="modal-actions">
        <button class="btn" style="background: #6b7280;" onclick="document.getElementById('settings-modal').style.display='none'">Cancel</button>
        <button class="btn" style="background: #10b981;" onclick="saveSettings()">Save</button>
      </div>
    </div>
  </div>

  <script>
    const settings = {{.SettingsJSON}};

    if (settings && settings.ui && settings.ui.theme === "light") {
        document.body.classList.add("light");
    }

    const qcDiv = document.getElementById('quick-create');
    if (settings && settings.objects) {
        for (const [objName, objTmpl] of Object.entries(settings.objects)) {
            if (objTmpl.pin_quick_create) {
                const btn = document.createElement('a');
                btn.className = 'qc-btn';
                btn.textContent = objName;
                btn.onclick = () => openQuickCreate(objName, objTmpl);
                qcDiv.appendChild(btn);
            }
        }
    }

    function getIcon(ocs) {
        if (!ocs) return '📄';
        const classes = ocs.map(c => c.toLowerCase());
        if (classes.includes('inetorgperson')) return '🪪';
        if (classes.includes('posixaccount')) return '🧑‍💻';
        if (classes.includes('person') || classes.includes('user')) return '👤';
        if (classes.includes('groupofnames')) return '🗂️';
        if (classes.includes('posixgroup')) return '👥';
        if (classes.includes('group')) return '👥';
        if (classes.includes('organizationalunit')) return '📁';
        if (classes.includes('domain') || classes.includes('dcobject')) return '🌍';
        if (classes.includes('subschema')) return '📜';
        if (classes.includes('monitor')) return '📊';
        if (classes.includes('computer') || classes.includes('device')) return '💻';
        return '📄';
    }

    async function loadRoots() {
        const res = await fetch('/api/roots');
        if (!res.ok) {
            if (res.status === 401) window.location.href = '/login';
            return;
        }
        const roots = await res.json();
        const tree = document.getElementById('tree-root');
        roots.forEach(r => tree.appendChild(createNode(r)));
    }

    function createNode(nodeData) {
        const li = document.createElement('li');
        li.className = 'tree-node';

        const expander = document.createElement('span');

        li.draggable = true;
        li.ondragstart = (e) => {
            e.dataTransfer.setData('text/plain', nodeData.dn);
            e.stopPropagation();
        };
        li.ondragover = (e) => {
            e.preventDefault();
            text.style.border = "1px dashed var(--border)";
            e.stopPropagation();
        };
        li.ondragleave = (e) => {
            e.preventDefault();
            text.style.border = "none";
            e.stopPropagation();
        };
        li.ondrop = async (e) => {
            e.preventDefault();
            text.style.border = "none";
            e.stopPropagation();

            const srcDN = e.dataTransfer.getData('text/plain');
            const targetDN = nodeData.dn;

            if (!srcDN || srcDN === targetDN) return;

            const rdn = srcDN.split(',')[0];
            const newDN = rdn + "," + targetDN;

            if (!confirm("Move " + srcDN + " -> " + newDN + "?")) return;

            const res = await fetch('/api/move', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dn: srcDN, new_dn: newDN })
            });

            if (res.ok) {
                document.getElementById('tree-root').innerHTML = '';
                loadRoots();
                if (currentEntryDN === srcDN) {
                    loadEntry(newDN);
                }
            } else {
                alert('Move failed. Ensure you have permissions and are moving to a valid container.');
            }
        };

        expander.className = 'expand-icon';
        expander.textContent = nodeData.hasChildren ? '▶' : ' ';

        const icon = document.createElement('span');
        icon.textContent = getIcon(nodeData.objectClasses) + ' ';

        const text = document.createElement('span');
        text.className = 'item-text';
        text.textContent = nodeData.rdn || nodeData.dn;
        text.onclick = () => {
            document.querySelectorAll('.selected').forEach(e => e.classList.remove('selected'));
            text.classList.add('selected');
            loadEntry(nodeData.dn);
        };
        text.oncontextmenu = (e) => {
            e.preventDefault();
            const cm = document.getElementById('context-menu');
            cm.innerHTML = '';

            if (settings && settings.ui && settings.ui.context_menu) {
                settings.ui.context_menu.forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'cm-item';
                    div.textContent = item.name;
                    div.onclick = new Function('dn', item.action).bind(null, nodeData.dn);
                    cm.appendChild(div);
                });
            }

            const ocs = (nodeData.objectClasses || []).map(c => c.toLowerCase());
            const addAction = (name, fn) => {
                const div = document.createElement('div');
                div.className = 'cm-item';
                div.textContent = name;
                div.onclick = fn;
                cm.appendChild(div);
            };

            addAction('Add OrganizationalUnit', () => alert('Add OU under ' + nodeData.dn));

            if (ocs.includes('person') || ocs.includes('inetorgperson') || ocs.includes('posixaccount')) {
                addAction('Set Password', () => setPassword(nodeData.dn));
                addAction('Add to posixGroup', () => showGroupSelector('posixGroup', nodeData.dn));
                addAction('Add to groupOfNames', () => showGroupSelector('groupOfNames', nodeData.dn));
            }
            if (ocs.includes('posixgroup')) {
                addAction('Add members', () => showMemberSelector(nodeData.dn));
            }

            cm.style.display = 'block';
            cm.style.left = e.pageX + 'px';
            cm.style.top = e.pageY + 'px';
        };

        const childrenUl = document.createElement('ul');
        childrenUl.className = 'tree-ul';
        childrenUl.style.display = 'none';

        let expanded = false;
        let loaded = false;

        expander.onclick = async () => {
            if (!nodeData.hasChildren) return;
            if (!expanded) {
                if (!loaded) {
                    expander.textContent = '⌛';
                    const res = await fetch('/api/children?dn=' + encodeURIComponent(nodeData.dn));
                    if (res.ok) {
                        const children = await res.json();
                        if (children && children.length > 0) {
                            children.forEach(c => childrenUl.appendChild(createNode(c)));
                            expander.textContent = '▼';
                        } else {
                            expander.textContent = ' ';
                            nodeData.hasChildren = false;
                        }
                    } else {
                        expander.textContent = '▶';
                        alert('Failed to load children');
                    }
                    loaded = true;
                } else {
                    expander.textContent = '▼';
                }
                childrenUl.style.display = 'block';
                expanded = true;
            } else {
                childrenUl.style.display = 'none';
                expander.textContent = '▶';
                expanded = false;
            }
        };

        li.appendChild(expander);
        li.appendChild(icon);
        li.appendChild(text);
        li.appendChild(childrenUl);
        return li;
    }

    let currentEntryDN = '';
    let currentEntryData = {};
    let isEditing = false;

    async function loadEntry(dn) {
        if (isEditing) toggleEdit();
        const res = await fetch('/api/entry?dn=' + encodeURIComponent(dn));
        if (!res.ok) {
        	alert('Failed to load entry details. You might not have permission.');
        	return;
        }
        const data = await res.json();
        currentEntryDN = dn;
        currentEntryData = data;
        document.getElementById('entry-dn').textContent = dn;
        document.getElementById('btn-edit').style.display = 'inline-block';
        document.getElementById('btn-delete').style.display = 'inline-block';
        const tbody = document.querySelector('#entry-attrs tbody');
        tbody.innerHTML = '';

        const attrs = Object.keys(data).sort();
        for (const attr of attrs) {
            const tr = document.createElement('tr');
            const tdAttr = document.createElement('td');
            tdAttr.textContent = attr;
            const tdVals = document.createElement('td');
            tdVals.className = 'val-cell';
            tdVals.dataset.attr = attr;

            data[attr].forEach((val, idx) => {
                if (typeof val === 'string' && /^[a-zA-Z][a-zA-Z0-9-]*=[^,]+,.*=/.test(val)) {
                    const a = document.createElement('a');
                    a.textContent = val.split(',')[0];
                    a.title = val;
                    a.href = "#";
                    a.onclick = (e) => { e.preventDefault(); loadEntry(val); };
                    a.style.color = "#3b82f6";
                    a.style.textDecoration = "none";
                    tdVals.appendChild(a);
                } else {
                    tdVals.appendChild(document.createTextNode(val));
                }
                if (idx < data[attr].length - 1) {
                    tdVals.appendChild(document.createTextNode(', '));
                }
            });
            tr.appendChild(tdAttr);
            tr.appendChild(tdVals);
            tbody.appendChild(tr);
        }
        document.getElementById('entry-attrs').style.display = 'table';
        document.getElementById('add-attr-panel').style.display = 'none';
        document.getElementById('btn-add-attr').style.display = 'none';
    }

    async function showAddAttribute() {
        const ocs = currentEntryData['objectClass'] || [];
        const res = await fetch('/api/schema?oc=' + encodeURIComponent(ocs.join(',')));
        if (!res.ok) return;
        const schema = await res.json();
        const sel = document.getElementById('add-attr-select');
        sel.innerHTML = '';
        const existing = Object.keys(currentEntryData).map(k => k.toLowerCase());
        const available = [...(schema.must||[]), ...(schema.may||[])].filter(a => !existing.includes(a.toLowerCase()));
        available.sort().forEach(a => {
            const opt = document.createElement('option');
            opt.value = a;
            opt.textContent = a;
            sel.appendChild(opt);
        });
        document.getElementById('add-attr-panel').style.display = 'block';
    }

    function addAttribute() {
        const attr = document.getElementById('add-attr-select').value;
        const val = document.getElementById('add-attr-val').value;
        if (!attr || val === "") return;
        currentEntryData[attr] = [val];
        isEditing = false;
        loadEntry(currentEntryDN);
        toggleEdit();
    }

    function toggleEdit() {
        isEditing = !isEditing;
        document.getElementById('btn-edit').textContent = isEditing ? 'Cancel' : 'Edit';
        document.getElementById('btn-save').style.display = isEditing ? 'inline-block' : 'none';
        document.getElementById('btn-add-attr').style.display = isEditing ? 'inline-block' : 'none';
        if (!isEditing) document.getElementById('add-attr-panel').style.display = 'none';

        const readOnly = ['userpassword', 'modifiersname', 'modifytimestamp', 'subschemasubentry', 'memberof', 'creatorsname', 'createtimestamp', 'contextcsn', 'entrydn', 'entrycsn', 'entryuuid', 'hasalsubordinates', 'numsubordinates'];
        const cells = document.querySelectorAll('.val-cell');
        cells.forEach(cell => {
            const attr = cell.dataset.attr;
            if (isEditing) {
                if (readOnly.includes(attr.toLowerCase())) {
                    cell.style.opacity = '0.5';
                    return;
                }
                const val = currentEntryData[attr].join(', ');
                cell.innerHTML = '<input type="text" style="width:80%; box-sizing:border-box; padding:4px;" value="' + val.replace(/"/g, '&quot;') + '"><button onclick="deleteAttr(\'' + attr + '\')" style="margin-left:5px; background:#dc2626; color:white; border:none; padding:4px 8px; border-radius:4px; cursor:pointer;">X</button>';
            } else {
                cell.style.opacity = '1';
                cell.innerHTML = '';
                currentEntryData[attr].forEach((val, idx) => {
                    if (typeof val === 'string' && /^[a-zA-Z][a-zA-Z0-9-]*=[^,]+,.*=/.test(val)) {
                        const a = document.createElement('a');
                        a.textContent = val.split(',')[0];
                        a.title = val;
                        a.href = "#";
                        a.onclick = (e) => { e.preventDefault(); loadEntry(val); };
                        a.style.color = "#3b82f6";
                        a.style.textDecoration = "none";
                        cell.appendChild(a);
                    } else {
                        cell.appendChild(document.createTextNode(val));
                    }
                    if (idx < currentEntryData[attr].length - 1) {
                        cell.appendChild(document.createTextNode(', '));
                    }
                });
            }
        });
    }

    let pendingDeletes = [];
    window.deleteAttr = function(attr) {
        pendingDeletes.push(attr);
        const cell = document.querySelector('.val-cell[data-attr="'+attr+'"]');
        if (cell) cell.parentElement.style.display = 'none';
    };

    async function saveEdits() {
        const replace = {};
        const cells = document.querySelectorAll('.val-cell');
        cells.forEach(cell => {
            const attr = cell.dataset.attr;
            if (pendingDeletes.includes(attr)) return;
            const input = cell.querySelector('input');
            if (input) {
                const newVal = input.value;
                const oldVal = currentEntryData[attr].join(', ');
                if (newVal !== oldVal) {
                    replace[attr] = newVal;
                }
            }
        });

        if (Object.keys(replace).length === 0 && pendingDeletes.length === 0) {
            toggleEdit();
            return;
        }

        const res = await fetch('/api/modify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dn: currentEntryDN, replace: replace, delete: pendingDeletes })
        });
        pendingDeletes = [];

        if (res.ok) {
            alert('Saved successfully!');
            loadEntry(currentEntryDN);
        } else {
            alert('Failed to save changes.');
        }
    }

    async function deleteEntry() {
        if (!currentEntryDN) return;
        if (!confirm("Are you sure you want to delete " + currentEntryDN + "?")) return;
        const res = await fetch('/api/delete?dn=' + encodeURIComponent(currentEntryDN), { method: 'DELETE' });
        if (res.ok) {
            alert('Deleted successfully!');
            document.getElementById('entry-dn').textContent = "Select an entry to view details.";
            document.getElementById('btn-edit').style.display = 'none';
            document.getElementById('btn-delete').style.display = 'none';
            document.getElementById('btn-save').style.display = 'none';
            document.getElementById('btn-add-attr').style.display = 'none';
            document.getElementById('add-attr-panel').style.display = 'none';
            document.getElementById('entry-attrs').style.display = 'none';

            document.getElementById('tree-root').innerHTML = '';
            loadRoots();
        } else {
            alert('Failed to delete: You might not have permission or it is not empty.');
        }
    }

    document.addEventListener('click', (e) => {
        if (!e.target.closest('#context-menu')) {
            document.getElementById('context-menu').style.display = 'none';
        }
    });

    function openSettings() {
        document.getElementById('settings-json').value = JSON.stringify(settings, null, 2);
        document.getElementById('settings-modal').style.display = 'flex';
    }

    async function openQuickCreate(objName, objTmpl) {
        document.getElementById('qc-title').textContent = "Create " + objName;
        document.getElementById('qc-modal').style.display = 'flex';
        const formDiv = document.getElementById('qc-form');
        formDiv.innerHTML = 'Loading schema...';

        try {
            const res = await fetch('/api/schema?oc=' + encodeURIComponent(objName));
            if (!res.ok) throw new Error('Failed to load schema');
            const data = await res.json();

            let html = '<div style="margin-bottom: 10px;"><strong>Location:</strong><br><input type="text" id="qc-location" value="' + (objTmpl.default_location || '') + '" style="width:100%; padding:5px; margin-top:5px; box-sizing:border-box;"></div>';
            let finalClasses = data.classes ? data.classes : [];
            if (!finalClasses.some(c => c.toLowerCase() === objName.toLowerCase())) {
                finalClasses.push(objName);
            }
            html += '<input type="hidden" id="qc-classes" value="' + finalClasses.join(',') + '">';
            html += '<input type="hidden" id="qc-dn-param" value="' + (objTmpl.dn_parameter || '') + '">';

            if (data.must && data.must.length > 0) {
                html += '<h4>Required Attributes</h4>';
                data.must.forEach(attr => {
                    if (attr.toLowerCase() === 'objectclass') return;
                    html += '<div style="margin-bottom: 5px;"><label>' + attr + '*</label><br><input type="text" class="qc-input-must" data-attr="' + attr + '" style="width:100%; padding:5px; box-sizing:border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></div>';
                });
            }
            if (data.may && data.may.length > 0) {
                html += '<h4>Optional Attributes</h4>';
                data.may.forEach(attr => {
                    if (attr.toLowerCase() === 'objectclass') return;
                    html += '<div style="margin-bottom: 5px;"><label>' + attr + '</label><br><input type="text" class="qc-input-may" data-attr="' + attr + '" style="width:100%; padding:5px; box-sizing:border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></div>';
                });
            }
            formDiv.innerHTML = html;
        } catch(e) {
            formDiv.innerHTML = '<span style="color:red">Error: ' + e.message + '</span>';
        }
    }

    async function submitQuickCreate() {
        const loc = document.getElementById('qc-location').value;
        const dnParam = document.getElementById('qc-dn-param').value;
        const classes = document.getElementById('qc-classes').value.split(',').filter(x => x);

        const attrs = {};
        let dnParamValue = '';

        let hasError = false;
        document.querySelectorAll('.qc-input-must').forEach(input => {
            const attr = input.getAttribute('data-attr');
            const val = input.value.trim();
            if (!val) {
                if (!['uidnumber', 'gidnumber', 'homedirectory'].includes(attr.toLowerCase())) {
                    hasError = true;
                }
            } else {
                attrs[attr] = [val];
                if (attr.toLowerCase() === dnParam.toLowerCase()) {
                    dnParamValue = val;
                }
            }
        });
        if (hasError) {
            alert('Please fill out all required fields.');
            return;
        }

        document.querySelectorAll('.qc-input-may').forEach(input => {
            const attr = input.getAttribute('data-attr');
            const val = input.value.trim();
            if (val) {
                if (attrs[attr]) {
                    attrs[attr].push(val);
                } else {
                    attrs[attr] = [val];
                }
                if (attr.toLowerCase() === dnParam.toLowerCase()) {
                    dnParamValue = val;
                }
            }
        });

        if (!dnParamValue) {
            alert('The DN parameter (' + dnParam + ') must have a value.');
            return;
        }

        attrs['objectClass'] = classes;

        const dn = dnParam + '=' + dnParamValue + ',' + loc;

        const res = await fetch('/api/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dn: dn, attributes: attrs })
        });

        if (res.ok) {
            alert('Created successfully!');
            document.getElementById('qc-modal').style.display='none';
            document.getElementById('tree-root').innerHTML = '';
            loadRoots();
        } else {
            const errText = await res.text();
            alert('Failed to create: ' + errText);
        }
    }

    async function showGroupSelector(type, userDN) {
        document.getElementById('group-select-title').textContent = "Add to " + type;
        const listDiv = document.getElementById('group-select-list');
        listDiv.innerHTML = 'Loading...';
        document.getElementById('group-select-modal').style.display = 'flex';

        let filter = '';
        if (type === 'posixGroup') {
            const uRes = await fetch('/api/entry?dn=' + encodeURIComponent(userDN));
            const uData = await uRes.json();
            const uid = (uData['uid'] && uData['uid'][0]) || '';
            if (!uid) {
                listDiv.innerHTML = 'User has no uid attribute';
                return;
            }
            filter = '(&(objectClass=posixGroup)(!(memberUid=' + uid + ')))';
        } else if (type === 'groupOfNames') {
            filter = '(&(objectClass=groupOfNames)(!(member=' + userDN + ')))';
        }

        const res = await fetch('/api/search?filter=' + encodeURIComponent(filter));
        if (!res.ok) {
            listDiv.innerHTML = 'Search failed';
            return;
        }
        const groups = await res.json() || [];
        if (groups.length === 0) {
            listDiv.innerHTML = 'No eligible groups found.';
            return;
        }

        listDiv.innerHTML = '';
        groups.forEach(g => {
            const div = document.createElement('div');
            div.style.padding = "8px";
            div.style.borderBottom = "1px solid var(--border)";
            div.style.cursor = "pointer";
            div.title = g;
            div.textContent = g.split(',')[0];
            div.onclick = () => addToGroup(type, g, userDN);
            listDiv.appendChild(div);
        });
    }

    async function addToGroup(type, groupDN, userDN) {
        let attr = '';
        let val = '';
        if (type === 'posixGroup') {
            const uRes = await fetch('/api/entry?dn=' + encodeURIComponent(userDN));
            const uData = await uRes.json();
            val = (uData['uid'] && uData['uid'][0]) || '';
            attr = 'memberUid';
        } else {
            attr = 'member';
            val = userDN;
        }

        if (!val) return;

        const res = await fetch('/api/modify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ dn: groupDN, add: { [attr]: val } })
        });

        if (res.ok) {
            alert('Added successfully!');
            document.getElementById('group-select-modal').style.display='none';
        } else {
            alert('Failed to add to group');
        }
    }

    async function showMemberSelector(groupDN) {
        document.getElementById('group-select-title').textContent = "Add members to " + groupDN;
        const listDiv = document.getElementById('group-select-list');
        listDiv.innerHTML = 'Loading...';
        document.getElementById('group-select-modal').style.display = 'flex';

        const gRes = await fetch('/api/entry?dn=' + encodeURIComponent(groupDN));
        const gData = await gRes.json();
        const members = gData['memberUid'] || [];

        let filter = '';
        if (members.length > 0) {
            const exclusion = members.map(m => '(!(uid=' + m + '))').join('');
            filter = '(&(objectClass=posixAccount)' + exclusion + ')';
        } else {
            filter = '(objectClass=posixAccount)';
        }

        const res = await fetch('/api/search?filter=' + encodeURIComponent(filter));
        if (!res.ok) {
            listDiv.innerHTML = 'Search failed';
            return;
        }
        const users = await res.json() || [];
        if (users.length === 0) {
            listDiv.innerHTML = 'No eligible users found.';
            return;
        }

        listDiv.innerHTML = '';
        users.forEach(u => {
            const div = document.createElement('div');
            div.style.padding = "8px";
            div.style.borderBottom = "1px solid var(--border)";
            div.style.cursor = "pointer";
            div.title = u;
            div.textContent = u.split(',')[0];
            div.onclick = () => addMemberToGroup(groupDN, u);
            listDiv.appendChild(div);
        });
    }

    async function addMemberToGroup(groupDN, userDN) {
        const uRes = await fetch('/api/entry?dn=' + encodeURIComponent(userDN));
        const uData = await uRes.json();
        const uid = (uData['uid'] && uData['uid'][0]) || '';

        if (!uid) return;

        const res = await fetch('/api/modify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ dn: groupDN, add: { memberUid: uid } })
        });

        if (res.ok) {
            alert('Added successfully!');
            document.getElementById('group-select-modal').style.display='none';
        } else {
            alert('Failed to add member');
        }
    }

    async function setPassword(dn) {
        const pwd = prompt("Enter new password for " + dn + ":");
        if (!pwd) return;
        const res = await fetch('/api/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dn: dn, password: pwd })
        });
        if (res.ok) {
            alert('Password updated successfully');
        } else {
            alert('Failed to update password');
        }
    }

    async function saveSettings() {
        try {
            const newSettings = JSON.parse(document.getElementById('settings-json').value);
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newSettings)
            });
            if (res.ok) {
                location.reload();
            } else {
                alert('Failed to save settings');
            }
        } catch (e) {
            alert('Invalid JSON format');
        }
    }

    loadRoots();
  </script>
</body>
</html>`
