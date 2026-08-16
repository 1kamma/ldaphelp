package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type groupSelectorOption struct {
	DN          string
	Label       string
	Description string
}

type groupSelectorData struct {
	Type   string
	UserDN string
	Query  string
	Groups []groupSelectorOption
	Error  string
	Empty  bool
}

var groupSelectorTemplate = template.Must(template.New("group-selector").Parse(`
<div id="group-selector-state">
  <input type="hidden" name="type" value="{{.Type}}">
  <input type="hidden" name="userDN" value="{{.UserDN}}">
</div>
<div style="padding:8px; border-bottom:1px solid var(--border);">
  <input type="text"
         name="q"
         value="{{.Query}}"
         placeholder="Filter groups..."
         style="width:100%; padding:6px; box-sizing:border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border);"
         hx-get="/ui/groups/select"
         hx-include="#group-selector-state, this"
         hx-trigger="keyup changed delay:250ms, search"
         hx-target="#group-select-list"
         hx-swap="innerHTML">
</div>
{{if .Error}}
  <div style="padding:8px; color:#fca5a5;">{{.Error}}</div>
{{else if .Empty}}
  <div style="padding:8px;">No eligible groups found.</div>
{{else}}
  <div style="max-height:min(60vh, 420px); overflow-y:auto;">
    {{range .Groups}}
      <div style="padding:8px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; gap:10px; align-items:flex-start;">
        <div style="min-width:0; flex:1 1 auto;">
          <div style="font-weight:600; overflow-wrap:anywhere;">{{.Label}}</div>
          <div style="font-size:12px; opacity:0.75; overflow-wrap:anywhere;">{{.DN}}</div>
          {{if .Description}}<div style="font-size:12px; opacity:0.85; margin-top:4px; overflow-wrap:anywhere;">{{.Description}}</div>{{end}}
        </div>
        <button class="btn"
                style="background:#10b981; margin-left:0; white-space:nowrap;"
                data-type="{{$.Type}}"
                data-group-dn="{{.DN}}"
                data-user-dn="{{$.UserDN}}"
                onclick="addToGroup(this.dataset.type, this.dataset.groupDn, this.dataset.userDn)">Add</button>
      </div>
    {{end}}
  </div>
{{end}}
`))

type settingsFragmentData struct {
	Settings    Settings
	UIJSON      string
	ObjectsJSON string
	TypeJSON    string
	IconsJSON   string
	SaveError   string
}

var settingsTemplate = template.Must(template.New("settings-fragment").Parse(`
<div id="settings-modal-content" class="modal-content modal-scroll-shell" style="width: 600px;">
  <form hx-post="/ui/settings" hx-target="#settings-modal-content" hx-swap="outerHTML" style="display:flex; flex-direction:column; min-height:0; max-height:80vh;">
    <div class="modal-scroll-body" style="padding:20px;">
      <h3>Settings</h3>
      {{if .SaveError}}<div style="margin-bottom:12px; padding:10px; border-radius:4px; background:#7f1d1d; color:#fecaca;">{{.SaveError}}</div>{{end}}

      <h4>Theme & Custom Context Menu (JSON)</h4>
      <div class="form-help">Use this for theme selection and optional custom actions that should appear in addition to the built-in type-aware menu.</div>
      <textarea name="ui_json" id="settings-ui-json" rows="4" style="width:100%; font-family:monospace; background: var(--bg); color: var(--text); border: 1px solid var(--border);">{{.UIJSON}}</textarea>

      <h4>Quick Create Objects (JSON)</h4>
      <div class="form-help">Configure which object types appear in Quick Create and which attribute builds the DN.</div>
      <textarea name="objects_json" id="settings-objects-json" rows="4" style="width:100%; font-family:monospace; background: var(--bg); color: var(--text); border: 1px solid var(--border);">{{.ObjectsJSON}}</textarea>

      <h4>Entry Type Actions (JSON)</h4>
      <div class="form-help">Map object classes to right-click capabilities like adding members or setting passwords.</div>
      <textarea name="type_actions_json" id="settings-type-actions-json" rows="8" style="width:100%; font-family:monospace; background: var(--bg); color: var(--text); border: 1px solid var(--border);">{{.TypeJSON}}</textarea>

      <h4>ObjectClass Icons (JSON)</h4>
      <div class="form-help">Assign an icon per objectClass. Example: {"inetorgperson":"🪪","posixaccount":"🐧"}</div>
      <textarea name="icons_json" id="settings-icons-json" rows="6" style="width:100%; font-family:monospace; background: var(--bg); color: var(--text); border: 1px solid var(--border);">{{.IconsJSON}}</textarea>

      <h4>Default gidNumber</h4>
      <div class="form-help">Used as the default value for new posixAccount and posixGroup entries. Defaults to 1000.</div>
      <input type="text" name="default_gid_number" id="settings-default-gid-number" value="{{.Settings.DefaultGIDNumber}}" style="width:100%; padding:4px; background: var(--bg); color: var(--text); border: 1px solid var(--border);" />

      <h4>Default posixGroup DN (optional fallback source)</h4>
      <div class="form-help">If set and no explicit default gidNumber is configured, LDAP Help can read the group's gidNumber from this DN.</div>
      <input type="text" name="default_group" id="settings-default-group" value="{{.Settings.DefaultGroup}}" style="width:100%; padding:4px; background: var(--bg); color: var(--text); border: 1px solid var(--border);" />

      <hr style="margin: 20px 0; border: 0; border-top: 1px solid var(--border);" />

      <h3>Branding</h3>
      <h4>Direct URL/path (runtime)</h4>
      <input type="text" name="assets_logo" id="settings-logo-url" class="input-field" value="{{.Settings.Assets.Logo}}" placeholder="Logo URL/path (or embedded:logo)" style="width: 100%; margin-top: 5px;" />
      <input type="text" name="assets_favicon" id="settings-favicon-url" class="input-field" value="{{.Settings.Assets.Favicon}}" placeholder="Favicon URL/path (or embedded:icon)" style="width: 100%; margin-top: 5px;" />

      <h4 style="margin-top: 15px;">Embed (upload from browser)</h4>
      <div style="display:flex; gap:10px; align-items:center; margin-top: 5px; flex-wrap: wrap;">
        <input type="file" id="settings-logo-file" class="input-field" style="flex:1 1 280px;" />
        <button type="button" class="btn" style="background:#4b5563;" onclick="embedAssetFromUpload('logo', 'settings-logo-file')">Upload & Embed Logo</button>
      </div>
      <div style="display:flex; gap:10px; align-items:center; margin-top: 10px; flex-wrap: wrap;">
        <input type="file" id="settings-favicon-file" class="input-field" style="flex:1 1 280px;" />
        <button type="button" class="btn" style="background:#4b5563;" onclick="embedAssetFromUpload('icon', 'settings-favicon-file')">Upload & Embed Favicon</button>
      </div>

      <h4 style="margin-top: 15px;">Embed from server filesystem (source file)</h4>
      <div style="display:flex; gap:10px; align-items:center; margin-top: 5px; flex-wrap: wrap;">
        <input type="text" name="logo_source_file" id="settings-logo-source-file" class="input-field" value="{{.Settings.Assets.LogoSourceFile}}" placeholder="/etc/ldaphelp/branding/logo.png (or relative path if server supports it)" style="flex:1 1 280px;" />
        <button type="button" class="btn" style="background:#4b5563;" onclick="embedAssetFromSourceFile('logo', 'settings-logo-source-file')">Embed Logo</button>
      </div>
      <div style="display:flex; gap:10px; align-items:center; margin-top: 10px; flex-wrap: wrap;">
        <input type="text" name="favicon_source_file" id="settings-favicon-source-file" class="input-field" value="{{.Settings.Assets.FaviconSourceFile}}" placeholder="/etc/ldaphelp/branding/favicon.svg (or relative path if server supports it)" style="flex:1 1 280px;" />
        <button type="button" class="btn" style="background:#4b5563;" onclick="embedAssetFromSourceFile('icon', 'settings-favicon-source-file')">Embed Favicon</button>
      </div>
      <div style="margin-top: 10px; color: var(--text); opacity: 0.85; font-size: 12px; line-height: 1.4;">
        Tip: After embedding, set the runtime fields above to <code>embedded:logo</code> and <code>embedded:icon</code>.
      </div>

      <hr style="margin: 20px 0; border: 0; border-top: 1px solid var(--border);" />

      <h3>Session Settings</h3>
      <label>TTL (minutes): <input type="number" name="session_ttl" id="settings-session-ttl" value="{{.Settings.Session.TTLMinutes}}" style="width: 100px; background: var(--bg); color: var(--text); border: 1px solid var(--border);" /></label><br>
      <label style="margin-top: 10px; display: inline-block;">Idle (minutes): <input type="number" name="session_idle" id="settings-session-idle" value="{{.Settings.Session.IdleMinutes}}" style="width: 100px; background: var(--bg); color: var(--text); border: 1px solid var(--border);" /></label>

      <hr style="margin: 20px 0; border: 0; border-top: 1px solid var(--border);" />

      <h3>SSO Connections</h3>
      <h4>SAML</h4>
      <label><input type="checkbox" name="saml_enabled" id="saml-enabled" {{if .Settings.SSO.SAML.Enabled}}checked{{end}}> Enabled</label><br>
      <input type="text" name="saml_idp" id="saml-idp" class="input-field" value="{{.Settings.SSO.SAML.IdPURL}}" placeholder="IdP URL" style="width: 100%; margin-top: 5px;" />
      <input type="text" name="saml_entity" id="saml-entity" class="input-field" value="{{.Settings.SSO.SAML.EntityID}}" placeholder="Entity ID" style="width: 100%; margin-top: 5px;" />
      <textarea name="saml_cert" id="saml-cert" rows="3" class="input-field" placeholder="Certificate" style="width: 100%; margin-top: 5px;">{{.Settings.SSO.SAML.Cert}}</textarea>

      <h4>OIDC</h4>
      <label><input type="checkbox" name="oidc_enabled" id="oidc-enabled" {{if .Settings.SSO.OIDC.Enabled}}checked{{end}}> Enabled</label><br>
      <input type="text" name="oidc_issuer" id="oidc-issuer" class="input-field" value="{{.Settings.SSO.OIDC.IssuerURL}}" placeholder="Issuer URL" style="width: 100%; margin-top: 5px;" />
      <input type="text" name="oidc_clientid" id="oidc-clientid" class="input-field" value="{{.Settings.SSO.OIDC.ClientID}}" placeholder="Client ID" style="width: 100%; margin-top: 5px;" />
      <input type="text" name="oidc_clientsecret" id="oidc-clientsecret" class="input-field" value="{{.Settings.SSO.OIDC.ClientSecret}}" placeholder="Client Secret" style="width: 100%; margin-top: 5px;" />
    </div>
    <div class="modal-actions modal-footer-fixed" style="padding:12px 20px;">
      <button type="button" class="btn" style="background: #6b7280;" onclick="document.getElementById('settings-modal').style.display='none'">Cancel</button>
      <button type="submit" class="btn" style="background: #10b981;">Save</button>
    </div>
  </form>
</div>
`))

func settingsFragmentPayload(s Settings, saveErr string) settingsFragmentData {
	uiJSON, _ := json.MarshalIndent(map[string]any{
		"theme":        s.UI.Theme,
		"context_menu": s.UI.ContextMenu,
	}, "", "  ")
	objectsJSON, _ := json.MarshalIndent(s.Objects, "", "  ")
	typeJSON, _ := json.MarshalIndent(s.UI.TypeActions, "", "  ")
	iconsJSON, _ := json.MarshalIndent(s.UI.ObjectClassIcons, "", "  ")
	return settingsFragmentData{Settings: s, UIJSON: string(uiJSON), ObjectsJSON: string(objectsJSON), TypeJSON: string(typeJSON), IconsJSON: string(iconsJSON), SaveError: saveErr}
}

func (a *App) handleUISettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = settingsTemplate.Execute(w, settingsFragmentPayload(a.cfg.Settings, ""))
}

func (a *App) handleUISaveSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = settingsTemplate.Execute(w, settingsFragmentPayload(a.cfg.Settings, err.Error()))
		return
	}

	uiRaw := r.FormValue("ui_json")
	objectsRaw := r.FormValue("objects_json")
	typeRaw := r.FormValue("type_actions_json")
	iconsRaw := r.FormValue("icons_json")
	var ui map[string]any
	var objects map[string]ObjectTemplate
	var typeActions map[string]EntryTypeActionConfig
	var objectClassIcons map[string]string
	if err := json.Unmarshal([]byte(defaultJSON(uiRaw, "{}")), &ui); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = settingsTemplate.Execute(w, settingsFragmentPayload(a.cfg.Settings, fmt.Sprintf("Invalid UI JSON: %v", err)))
		return
	}
	if err := json.Unmarshal([]byte(defaultJSON(objectsRaw, "{}")), &objects); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = settingsTemplate.Execute(w, settingsFragmentPayload(a.cfg.Settings, fmt.Sprintf("Invalid objects JSON: %v", err)))
		return
	}
	if err := json.Unmarshal([]byte(defaultJSON(typeRaw, "{}")), &typeActions); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = settingsTemplate.Execute(w, settingsFragmentPayload(a.cfg.Settings, fmt.Sprintf("Invalid entry type actions JSON: %v", err)))
		return
	}
	if err := json.Unmarshal([]byte(defaultJSON(iconsRaw, "{}")), &objectClassIcons); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = settingsTemplate.Execute(w, settingsFragmentPayload(a.cfg.Settings, fmt.Sprintf("Invalid objectClass icons JSON: %v", err)))
		return
	}

	ttl, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("session_ttl")))
	idle, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("session_idle")))
	if ttl == 0 {
		ttl = 1440
	}
	if idle == 0 {
		idle = 60
	}

	next := Settings{
		UI: UISettings{
			Theme:            strings.TrimSpace(stringValueFromMap(ui, "theme", "dark")),
			ContextMenu:      contextMenuFromUIMap(ui),
			TypeActions:      typeActions,
			ObjectClassIcons: objectClassIcons,
		},
		Objects:          objects,
		DefaultGroup:     strings.TrimSpace(r.FormValue("default_group")),
		DefaultGIDNumber: strings.TrimSpace(r.FormValue("default_gid_number")),
		Session:          SessionSettings{TTLMinutes: ttl, IdleMinutes: idle},
		Assets: EmbeddedAssetSettings{
			Logo:              strings.TrimSpace(r.FormValue("assets_logo")),
			Favicon:           strings.TrimSpace(r.FormValue("assets_favicon")),
			LogoSourceFile:    strings.TrimSpace(r.FormValue("logo_source_file")),
			FaviconSourceFile: strings.TrimSpace(r.FormValue("favicon_source_file")),
		},
		SSO: SSOSettings{
			SAML: SAMLSettings{
				Enabled:  r.FormValue("saml_enabled") != "",
				IdPURL:   strings.TrimSpace(r.FormValue("saml_idp")),
				EntityID: strings.TrimSpace(r.FormValue("saml_entity")),
				Cert:     r.FormValue("saml_cert"),
			},
			OIDC: OIDCSettings{
				Enabled:      r.FormValue("oidc_enabled") != "",
				IssuerURL:    strings.TrimSpace(r.FormValue("oidc_issuer")),
				ClientID:     strings.TrimSpace(r.FormValue("oidc_clientid")),
				ClientSecret: strings.TrimSpace(r.FormValue("oidc_clientsecret")),
			},
		},
	}
	if next.DefaultGIDNumber == "" {
		next.DefaultGIDNumber = "1000"
	}
	if next.UI.Theme == "" {
		next.UI.Theme = "dark"
	}
	if err := SaveSettingsToDB(next); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = settingsTemplate.Execute(w, settingsFragmentPayload(next, err.Error()))
		return
	}
	a.cfg.Settings = next
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func defaultJSON(raw, fallback string) string {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	return raw
}

func stringValueFromMap(m map[string]any, key, fallback string) string {
	if m == nil {
		return fallback
	}
	if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func contextMenuFromUIMap(m map[string]any) []ContextMenuAction {
	itemsRaw, ok := m["context_menu"]
	if !ok {
		return nil
	}
	buf, _ := json.Marshal(itemsRaw)
	var items []ContextMenuAction
	_ = json.Unmarshal(buf, &items)
	return items
}

type schemaFragmentData struct {
	CanEdit        bool
	SchemaAttr     string
	ObjectClasses  []SchemaClassAttr
	AttributeTypes []SchemaAttrDef
}

var schemaObjectClassesTemplate = template.Must(template.New("schema-object-classes").Parse(`
<div id="schema-fragment-root" data-can-edit="{{if .CanEdit}}true{{else}}false{{end}}" data-schema-attr="olcObjectClasses">
  {{range .ObjectClasses}}
    <div style="background:#2a2a2a;border:1px solid #444;border-radius:4px;padding:15px;">
      <h3 style="margin-top:0;color:#3b82f6;">{{if .Name}}{{.Name}}{{else}}unnamed{{end}}</h3>
      <div style="font-size:12px;color:#888;margin-bottom:10px;word-break:break-all;"><strong>DN:</strong> {{.DN}}</div>
      <div style="margin-bottom:8px;">
        <span class="type-badge">{{if .Kind}}{{.Kind}}{{else}}STRUCTURAL{{end}}</span>
        {{if .OID}}<span class="type-badge">OID {{.OID}}</span>{{end}}
      </div>
      {{if gt (len .Aliases) 1}}<div style="margin-bottom:8px;"><strong>Aliases:</strong> {{range $i, $a := .Aliases}}{{if gt $i 0}}<span class="type-badge">{{$a}}</span>{{end}}{{end}}</div>{{end}}
      {{if .Desc}}<div style="margin-bottom:8px;"><strong>Description:</strong> {{.Desc}}</div>{{end}}
      {{if .Sup}}<div style="margin-bottom:8px;"><strong>SUP:</strong> {{range .Sup}}<span class="type-badge">{{.}}</span>{{end}}</div>{{end}}
      {{if .Must}}<div style="margin-bottom:8px;"><strong>MUST:</strong><div>{{range .Must}}<span class="type-badge">{{.}}</span>{{end}}</div></div>{{end}}
      {{if .May}}<div style="margin-bottom:8px;"><strong>MAY:</strong><div>{{range .May}}<span class="type-badge">{{.}}</span>{{end}}</div></div>{{end}}
      <details style="margin-top:10px;">
        <summary style="cursor:pointer;color:#888;font-size:12px;">Raw Definition</summary>
        <pre style="background:#1e1e1e;padding:10px;border-radius:4px;font-size:12px;white-space:pre-wrap;word-break:break-all;color:#aaa;">{{.Raw}}</pre>
      </details>
    </div>
  {{end}}
</div>
`))

var schemaAttributeTypesTemplate = template.Must(template.New("schema-attribute-types").Parse(`
<div id="schema-fragment-root" data-can-edit="{{if .CanEdit}}true{{else}}false{{end}}" data-schema-attr="olcAttributeTypes">
  {{range .AttributeTypes}}
    <div style="background:#2a2a2a;border:1px solid #444;border-radius:4px;padding:15px;">
      <h3 style="margin-top:0;color:#10b981;">{{if .Name}}{{.Name}}{{else}}Unnamed{{end}}</h3>
      <div style="font-size:12px;color:#888;margin-bottom:10px;word-break:break-all;"><strong>DN:</strong> {{.DN}}</div>
      <div style="margin-bottom:8px;">
        {{if .OID}}<span class="type-badge">OID {{.OID}}</span>{{end}}
        {{if .SingleValue}}<span class="type-badge">SINGLE-VALUE</span>{{end}}
      </div>
      {{if gt (len .Aliases) 1}}<div style="margin-bottom:8px;"><strong>Aliases:</strong> {{range $i, $a := .Aliases}}{{if gt $i 0}}<span class="type-badge">{{$a}}</span>{{end}}{{end}}</div>{{end}}
      {{if .Desc}}<div style="margin-bottom:8px;"><strong>Description:</strong> {{.Desc}}</div>{{end}}
      {{if .Syntax}}<div style="margin-bottom:8px;"><strong>Syntax:</strong> <span class="type-badge" style="font-family:monospace;">{{.Syntax}}</span></div>{{end}}
      <details style="margin-top:10px;">
        <summary style="cursor:pointer;color:#888;font-size:12px;">Raw Definition</summary>
        <pre style="background:#1e1e1e;padding:10px;border-radius:4px;font-size:12px;white-space:pre-wrap;word-break:break-all;color:#aaa;">{{.Raw}}</pre>
      </details>
    </div>
  {{end}}
</div>
`))

func schemaConnForUI(a *App, w http.ResponseWriter, r *http.Request) (ldapSearchConn, error) {
	if a.ldapSearchFn != nil {
		return a.ldapSearchFn(w, r, a.cfg)
	}
	return getLDAPConn(w, r, a.cfg)
}

func (a *App) handleUISchemaObjectClasses(w http.ResponseWriter, r *http.Request) {
	conn, err := schemaConnForUI(a, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()
	data, err := loadSchemaDef(conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = schemaObjectClassesTemplate.Execute(w, schemaFragmentData{CanEdit: data.CanEdit, SchemaAttr: "olcObjectClasses", ObjectClasses: data.ObjectClasses})
}

func (a *App) handleUISchemaAttributeTypes(w http.ResponseWriter, r *http.Request) {
	conn, err := schemaConnForUI(a, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()
	data, err := loadSchemaDef(conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = schemaAttributeTypesTemplate.Execute(w, schemaFragmentData{CanEdit: data.CanEdit, SchemaAttr: "olcAttributeTypes", AttributeTypes: data.AttributeTypes})
}

type subschemaFragmentData struct {
	DN             string
	ObjectClasses  []SchemaClassAttr
	AttributeTypes []SchemaAttrDef
}

var subschemaTemplate = template.Must(template.New("subschema-fragment").Parse(`
<div id="subschema-fragment-root">
  <div class="schema-section-title">Subschema Entry</div>
  <div style="font-size:12px; opacity:0.75; margin-bottom:10px; overflow-wrap:anywhere;">{{.DN}}</div>

  <div class="schema-section-title">Object Classes ({{len .ObjectClasses}})</div>
  <div class="schema-grid">
    {{range .ObjectClasses}}
      <div class="schema-card">
        <h4>{{if .Name}}{{.Name}}{{else}}unnamed{{end}}</h4>
        <div style="margin-bottom:8px;">
          <span class="type-badge">{{if .Kind}}{{.Kind}}{{else}}STRUCTURAL{{end}}</span>
          {{if .OID}}<span class="type-badge">OID {{.OID}}</span>{{end}}
        </div>
        {{if gt (len .Aliases) 1}}<div style="margin-bottom:8px;"><strong>Aliases:</strong> {{range $i, $a := .Aliases}}{{if gt $i 0}}<span class="type-badge">{{$a}}</span>{{end}}{{end}}</div>{{end}}
        {{if .Desc}}<div style="margin-bottom:8px;"><strong>Description:</strong> {{.Desc}}</div>{{end}}
        {{if .Sup}}<div style="margin-bottom:8px;"><strong>SUP:</strong> {{range .Sup}}<span class="type-badge">{{.}}</span>{{end}}</div>{{end}}
        {{if .Must}}<div style="margin-bottom:8px;"><strong>MUST:</strong> {{range .Must}}<span class="type-badge">{{.}}</span>{{end}}</div>{{end}}
        {{if .May}}<div style="margin-bottom:8px;"><strong>MAY:</strong> {{range .May}}<span class="type-badge">{{.}}</span>{{end}}</div>{{end}}
        <details><summary>Raw definition</summary><pre class="schema-raw">{{.Raw}}</pre></details>
      </div>
    {{end}}
  </div>

  <div class="schema-section-title">Attribute Types ({{len .AttributeTypes}})</div>
  <div class="schema-grid">
    {{range .AttributeTypes}}
      <div class="schema-card">
        <h4>{{if .Name}}{{.Name}}{{else}}Unnamed{{end}}</h4>
        <div style="margin-bottom:8px;">
          {{if .OID}}<span class="type-badge">OID {{.OID}}</span>{{end}}
          {{if .SingleValue}}<span class="type-badge">SINGLE-VALUE</span>{{end}}
        </div>
        {{if gt (len .Aliases) 1}}<div style="margin-bottom:8px;"><strong>Aliases:</strong> {{range $i, $a := .Aliases}}{{if gt $i 0}}<span class="type-badge">{{$a}}</span>{{end}}{{end}}</div>{{end}}
        {{if .Desc}}<div style="margin-bottom:8px;"><strong>Description:</strong> {{.Desc}}</div>{{end}}
        {{if .Syntax}}<div style="margin-bottom:8px;"><strong>Syntax:</strong> <span class="type-badge" style="font-family:monospace;">{{.Syntax}}</span></div>{{end}}
        <details><summary>Raw definition</summary><pre class="schema-raw">{{.Raw}}</pre></details>
      </div>
    {{end}}
  </div>
</div>
`))

func (a *App) handleUISubschema(w http.ResponseWriter, r *http.Request) {
	dn := strings.TrimSpace(r.URL.Query().Get("dn"))
	if dn == "" {
		http.Error(w, "missing dn", http.StatusBadRequest)
		return
	}
	conn, err := schemaConnForUI(a, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()
	entry, err := ldapReadBaseEntry(conn, dn, []string{"objectClasses", "attributeTypes"})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	data := subschemaFragmentData{DN: dn}
	for _, raw := range entry.GetAttributeValues("objectClasses") {
		parsed := parseObjectClass(raw)
		data.ObjectClasses = append(data.ObjectClasses, SchemaClassAttr{Raw: raw, DN: dn, OID: parsed.OID, Name: parsed.Name, Aliases: parsed.Aliases, Desc: parsed.Desc, Kind: parsed.Kind, Sup: parsed.Sup, Must: parsed.Must, May: parsed.May})
	}
	for _, raw := range entry.GetAttributeValues("attributeTypes") {
		parsed := parseAttributeType(raw)
		parsed.DN = dn
		data.AttributeTypes = append(data.AttributeTypes, *parsed)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = subschemaTemplate.Execute(w, data)
}

func (a *App) handleUIGroupSelector(w http.ResponseWriter, r *http.Request) {
	groupType := strings.TrimSpace(r.URL.Query().Get("type"))
	userDN := strings.TrimSpace(r.URL.Query().Get("userDN"))
	query := strings.TrimSpace(r.URL.Query().Get("q"))

	data := groupSelectorData{Type: groupType, UserDN: userDN, Query: query}
	if groupType == "" || userDN == "" {
		data.Error = "Missing group type or user DN"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = groupSelectorTemplate.Execute(w, data)
		return
	}

	var conn ldapSearchConn
	var err error
	if a.ldapSearchFn != nil {
		conn, err = a.ldapSearchFn(w, r, a.cfg)
	} else {
		conn, err = getLDAPConn(w, r, a.cfg)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	groups, err := searchEligibleGroups(conn, a.cfg, groupType, userDN, query)
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Groups = groups
		data.Empty = len(groups) == 0
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = groupSelectorTemplate.Execute(w, data)
}

func searchEligibleGroups(conn ldapSearchConn, cfg Config, groupType, userDN, query string) ([]groupSelectorOption, error) {
	userEntry, err := ldapReadBaseEntry(conn, userDN, []string{"uid"})
	if err != nil {
		return nil, err
	}

	searchAttrs := []string{"cn", "description", "gidNumber"}
	baseQuery := map[string][]string{"q": {query}}
	switch groupType {
	case "posixGroup":
		uid := strings.TrimSpace(userEntry.GetAttributeValue("uid"))
		if uid == "" {
			return nil, nil
		}
		baseQuery["objectClass"] = []string{"posixGroup"}
		baseQuery["search_attr"] = []string{"cn", "description", "gidNumber", "ou"}
		filter, err := buildLDAPSearchFilter(baseQuery)
		if err != nil {
			return nil, err
		}
		filter = "(&" + filter + "(!(memberUid=" + ldap.EscapeFilter(uid) + ")))"
		return executeGroupSearch(conn, cfg, filter, searchAttrs)
	case "groupOfNames":
		baseQuery["objectClass"] = []string{"groupOfNames"}
		baseQuery["search_attr"] = []string{"cn", "description", "ou"}
		filter, err := buildLDAPSearchFilter(baseQuery)
		if err != nil {
			return nil, err
		}
		filter = "(&" + filter + "(!(member=" + ldap.EscapeFilter(userDN) + ")))"
		return executeGroupSearch(conn, cfg, filter, searchAttrs)
	default:
		return nil, nil
	}
}

func ldapReadBaseEntry(conn ldapSearchConn, dn string, attrs []string) (*ldap.Entry, error) {
	res, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", attrs, nil))
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("entry not found")
	}
	return res.Entries[0], nil
}

func executeGroupSearch(conn ldapSearchConn, cfg Config, filter string, attrs []string) ([]groupSelectorOption, error) {
	bases := getLDAPSearchBases(conn, cfg, true)
	bases = normalizeSearchBases(bases)

	var groups []groupSelectorOption
	seen := make(map[string]bool)
	for _, base := range bases {
		if strings.TrimSpace(base) == "" {
			continue
		}
		res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 100, 0, false, filter, attrs, nil))
		if err != nil {
			continue
		}
		for _, ent := range res.Entries {
			if seen[strings.ToLower(ent.DN)] {
				continue
			}
			seen[strings.ToLower(ent.DN)] = true
			label := ent.GetAttributeValue("cn")
			if label == "" {
				label = ent.DN
				if idx := strings.Index(label, ","); idx != -1 {
					label = label[:idx]
				}
			}
			desc := strings.TrimSpace(ent.GetAttributeValue("description"))
			if gid := strings.TrimSpace(ent.GetAttributeValue("gidNumber")); gid != "" {
				if desc != "" {
					desc += " · "
				}
				desc += "gidNumber=" + gid
			}
			groups = append(groups, groupSelectorOption{DN: ent.DN, Label: label, Description: desc})
		}
	}

	sort.Slice(groups, func(i, j int) bool {
		return strings.ToLower(groups[i].Label) < strings.ToLower(groups[j].Label)
	})
	return groups, nil
}

type quickCreateField struct {
	Name     string
	Required bool
	Value    string
}

type quickCreateFragmentData struct {
	ObjectName      string
	DefaultLocation string
	DNParameter     string
	ClassCSV        string
	RequiredFields  []quickCreateField
	OptionalFields  []quickCreateField
	Error           string
}

var quickCreateTemplate = template.Must(template.New("quick-create-fragment").Parse(`
{{if .Error}}
  <div style="padding:10px; border-radius:4px; background:#7f1d1d; color:#fecaca;">{{.Error}}</div>
{{else}}
  <div id="quick-create-form" data-object-name="{{.ObjectName}}">
    <div style="margin-bottom: 10px;"><strong>Location:</strong><br><input type="text" id="qc-location" value="{{.DefaultLocation}}" style="width:100%; padding:5px; margin-top:5px; box-sizing:border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></div>
    <input type="hidden" id="qc-classes" value="{{.ClassCSV}}">
    <input type="hidden" id="qc-dn-param" value="{{.DNParameter}}">

    {{if .RequiredFields}}
      <h4>Required Attributes</h4>
      {{range .RequiredFields}}
        <div style="margin-bottom: 5px;"><label>{{.Name}}*</label><br><input type="text" class="qc-input-must" data-attr="{{.Name}}" value="{{.Value}}" style="width:100%; padding:5px; box-sizing:border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></div>
      {{end}}
    {{end}}

    {{if .OptionalFields}}
      <h4>Optional Attributes</h4>
      {{range .OptionalFields}}
        <div style="margin-bottom: 5px;"><label>{{.Name}}</label><br><input type="text" class="qc-input-may" data-attr="{{.Name}}" value="{{.Value}}" style="width:100%; padding:5px; box-sizing:border-box; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></div>
      {{end}}
    {{end}}
  </div>
{{end}}
`))

func defaultQuickCreateGID(s Settings) string {
	if strings.TrimSpace(s.DefaultGIDNumber) != "" {
		return strings.TrimSpace(s.DefaultGIDNumber)
	}
	return "1000"
}

func quickCreateFieldValue(attr string, cfg Config) string {
	switch strings.ToLower(strings.TrimSpace(attr)) {
	case "gidnumber":
		return defaultQuickCreateGID(cfg.Settings)
	default:
		return ""
	}
}

func buildQuickCreateFields(attrs []string, required bool, cfg Config) []quickCreateField {
	var fields []quickCreateField
	for _, attr := range attrs {
		if strings.EqualFold(attr, "objectClass") {
			continue
		}
		fields = append(fields, quickCreateField{Name: attr, Required: required, Value: quickCreateFieldValue(attr, cfg)})
	}
	return fields
}

func resolveQuickCreateTemplate(cfg Config, objectName string) (ObjectTemplate, bool) {
	for name, tmpl := range cfg.Settings.Objects {
		if strings.EqualFold(name, objectName) {
			return tmpl, true
		}
	}
	return ObjectTemplate{}, false
}

func (a *App) handleUIQuickCreate(w http.ResponseWriter, r *http.Request) {
	objectName := strings.TrimSpace(r.URL.Query().Get("name"))
	if objectName == "" {
		http.Error(w, "missing object name", http.StatusBadRequest)
		return
	}
	tmpl, ok := resolveQuickCreateTemplate(a.cfg, objectName)
	if !ok {
		http.Error(w, "unknown quick create object", http.StatusNotFound)
		return
	}
	conn, err := schemaConnForUI(a, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	classes, must, may, err := getResolvedSchema(conn, []string{objectName})
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = quickCreateTemplate.Execute(w, quickCreateFragmentData{ObjectName: objectName, Error: err.Error()})
		return
	}
	foundClass := false
	for _, className := range classes {
		if strings.EqualFold(className, objectName) {
			foundClass = true
			break
		}
	}
	if !foundClass {
		classes = append(classes, objectName)
		sort.Slice(classes, func(i, j int) bool { return strings.ToLower(classes[i]) < strings.ToLower(classes[j]) })
	}
	dnParam := strings.TrimSpace(tmpl.DNParameter)
	if dnParam == "" {
		dnParam = "cn"
	}
	data := quickCreateFragmentData{
		ObjectName:      objectName,
		DefaultLocation: tmpl.DefaultLocation,
		DNParameter:     dnParam,
		ClassCSV:        strings.Join(classes, ","),
		RequiredFields:  buildQuickCreateFields(must, true, a.cfg),
		OptionalFields:  buildQuickCreateFields(may, false, a.cfg),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = quickCreateTemplate.Execute(w, data)
}
