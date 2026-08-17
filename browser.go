package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

type LDAPSearchEntry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes,omitempty"`
}

type LDAPSearchResponse struct {
	Results       []LDAPSearchEntry `json:"results"`
	Count         int               `json:"count"`
	SearchedBases []string          `json:"searched_bases"`
	Errors        []string          `json:"errors,omitempty"`
	Truncated     bool              `json:"truncated"`
}

type ldapSearchConn interface {
	ldapSearcher
	Close() error
}

func getLDAPConn(w http.ResponseWriter, r *http.Request, cfg Config) (*ldap.Conn, error) {
	session, _ := store.Get(r, "ldap-session")
	dn, ok := session.Values["dn"].(string)
	if !ok || strings.TrimSpace(dn) == "" {
		if w != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
		return nil, fmt.Errorf("unauthorized")
	}

	created, okC := session.Values["created"].(int64)
	lastActive, okL := session.Values["last_active"].(int64)
	if okC && okL {
		now := time.Now().Unix()
		ttlMax := created + int64(cfg.Settings.Session.TTLMinutes)*60
		idleMax := lastActive + int64(cfg.Settings.Session.IdleMinutes)*60

		if now > ttlMax || now > idleMax {
			session.Options.MaxAge = -1
			if w != nil {
				session.Save(r, w)
				http.Error(w, "session expired", http.StatusUnauthorized)
			}
			return nil, fmt.Errorf("session expired")
		}
		session.Values["last_active"] = now
		if w != nil {
			session.Save(r, w)
		}
	}

	conn, err := dialLDAP(cfg.LDAPServer, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if pwd, ok := session.Values["password"].(string); ok && pwd != "" {
		if err := conn.Bind(dn, pwd); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}

	authMethod, _ := session.Values["auth_method"].(string)
	if authMethod != "saml" && authMethod != "oidc" && authMethod != "sso" {
		conn.Close()
		return nil, fmt.Errorf("session has no ldap password")
	}

	bindDN := strings.TrimSpace(cfg.ExternalAPI.BindDN)
	bindPassword := cfg.ExternalAPI.BindPassword
	if bindDN == "" || bindPassword == "" {
		storedCreds, err := LoadCredentialsFromDB(cfg.EncryptionKey)
		if err == nil && strings.TrimSpace(storedCreds.BindDN) != "" && storedCreds.BindPassword != "" {
			bindDN = strings.TrimSpace(storedCreds.BindDN)
			bindPassword = storedCreds.BindPassword
		}
	}
	if bindDN == "" || bindPassword == "" {
		conn.Close()
		return nil, fmt.Errorf("sso session requires configured ldap bind credentials")
	}
	if err := conn.Bind(bindDN, bindPassword); err != nil {
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

	created, okC := session.Values["created"].(int64)
	lastActive, okL := session.Values["last_active"].(int64)
	if okC && okL {
		now := time.Now().Unix()
		ttlMax := created + int64(a.cfg.Settings.Session.TTLMinutes)*60
		idleMax := lastActive + int64(a.cfg.Settings.Session.IdleMinutes)*60
		if now > ttlMax || now > idleMax {
			session.Options.MaxAge = -1
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		session.Values["last_active"] = now
		session.Save(r, w)
	}

	slog.Info("rendering browse for user", "dn", dn)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, err := template.New("browse").Parse(browseHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	settingsJSON, _ := json.Marshal(a.cfg.Settings)

	// Resolve AssetURL for templates (favicon/logo).
	// - values come from settings.assets.* (path/URL) or from embedded:* (served from SQLite)
	resolveAsset := func(settingValue string, embeddedName string, embeddedPath string) string {
		v := strings.TrimSpace(settingValue)
		if v == "" {
			return ""
		}
		if strings.HasPrefix(v, "embedded:") {
			if bin, _ := GetEmbeddedAssetBinary(embeddedName); bin != nil {
				return embeddedPath
			}
			if b64, _ := GetEmbeddedAssetBase64(embeddedName); b64 != "" {
				return embeddedPath
			}
			return ""
		}
		return v
	}

	assetURL := struct {
		Logo    string
		Favicon string
	}{
		Logo: resolveAsset(a.cfg.Settings.Assets.Logo, "logo", "assets/embedded/logo"),
		// Use SVG as favicon if configured; browsers that support it will render it fine.
		Favicon: resolveAsset(a.cfg.Settings.Assets.Favicon, "icon", "assets/embedded/icon"),
	}

	data := struct {
		SettingsJSON   template.JS
		AssetURL       any
		ServerTimeZone string
	}{
		SettingsJSON:   template.JS(settingsJSON),
		AssetURL:       assetURL,
		ServerTimeZone: time.Now().Location().String(),
	}

	if err := tmpl.Execute(w, data); err != nil {
		slog.Error("failed to execute template", "error", err)
	}
}

func (a *App) handleApiRoots(w http.ResponseWriter, r *http.Request) {
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

	conn, err := getLDAPConn(w, r, a.cfg)
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
	if strings.TrimSpace(s.DefaultGIDNumber) == "" {
		s.DefaultGIDNumber = "1000"
	}
	if s.UI.TypeActions == nil {
		s.UI.TypeActions = a.cfg.Settings.UI.TypeActions
	}
	a.cfg.Settings = s
	SaveSettingsToDB(s)
	w.WriteHeader(http.StatusOK)
}

func isBinaryAttributeValue(attrName string, raw []byte) bool {
	lower := strings.ToLower(strings.TrimSpace(attrName))
	switch lower {
	case "jpegphoto", "photo", "thumbnailphoto", "usercertificate", "usersmimecertificate", "objectsid", "objectguid", "audio", "binary":
		return true
	}
	if len(raw) == 0 {
		return false
	}
	if !utf8.Valid(raw) {
		return true
	}
	for _, b := range raw {
		if b == 0 {
			return true
		}
	}
	return false
}

func encodeBinaryAttributeValue(attrName string, raw []byte) string {
	contentType := http.DetectContentType(raw)
	encoded := base64.StdEncoding.EncodeToString(raw)
	lower := strings.ToLower(strings.TrimSpace(attrName))
	if strings.Contains(lower, "photo") || strings.HasPrefix(contentType, "image/") {
		return "data:" + contentType + ";base64," + encoded
	}
	return "base64:" + encoded
}

func (a *App) handleApiEntry(w http.ResponseWriter, r *http.Request) {
	dn := r.URL.Query().Get("dn")
	if dn == "" {
		http.Error(w, "missing dn", http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(w, r, a.cfg)
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
		if len(attr.ByteValues) == 0 {
			attrs[attr.Name] = attr.Values
			continue
		}

		vals := make([]string, 0, len(attr.ByteValues))
		for i, raw := range attr.ByteValues {
			if isBinaryAttributeValue(attr.Name, raw) {
				vals = append(vals, encodeBinaryAttributeValue(attr.Name, raw))
				continue
			}
			if i < len(attr.Values) && attr.Values[i] != "" {
				vals = append(vals, attr.Values[i])
			} else {
				vals = append(vals, string(raw))
			}
		}
		attrs[attr.Name] = vals
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attrs)
}

func (a *App) handleApiModify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DN           string              `json:"dn"`
		Replace      map[string][]string `json:"replace"`
		Add          map[string][]string `json:"add"`
		Delete       []string            `json:"delete"`
		DeleteValues map[string][]string `json:"delete_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conn, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(req.DN, nil)
	for k, v := range req.Replace {
		modReq.Replace(k, v)
	}
	for k, v := range req.Add {
		modReq.Add(k, v)
	}
	for _, k := range req.Delete {
		modReq.Delete(k, nil)
	}
	for k, v := range req.DeleteValues {
		modReq.Delete(k, v)
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

	conn, err := getLDAPConn(w, r, a.cfg)
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

	conn, err := getLDAPConn(w, r, a.cfg)
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

func (a *App) handleApiDefaultGid(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if strings.TrimSpace(a.cfg.Settings.DefaultGIDNumber) != "" {
		w.Write([]byte(strings.TrimSpace(a.cfg.Settings.DefaultGIDNumber)))
		return
	}

	if a.cfg.Settings.DefaultGroup == "" {
		w.Write([]byte("1000"))
		return
	}

	conn, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, "Failed to connect to LDAP", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	searchReq := ldap.NewSearchRequest(
		a.cfg.Settings.DefaultGroup,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"gidNumber"}, nil,
	)

	res, err := conn.Search(searchReq)
	if err != nil || len(res.Entries) == 0 {
		w.Write([]byte("1000"))
		return
	}

	gid := strings.TrimSpace(res.Entries[0].GetAttributeValue("gidNumber"))
	if gid == "" {
		gid = "1000"
	}
	w.Write([]byte(gid))
}

func (a *App) handleApiNextID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	attr := r.URL.Query().Get("attr")
	if attr == "" {
		http.Error(w, "Missing attr", http.StatusBadRequest)
		return
	}
	conn, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	bases := getLDAPSearchBases(conn, a.cfg, true)

	id := getNextID(conn, bases, attr)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(id))
}
func getNextID(conn *ldap.Conn, bases []string, attr string) string {
	maxID := 1000
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

	conn, err := getLDAPConn(w, r, a.cfg)
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

	bases := getLDAPSearchBases(conn, a.cfg, true)

	if hasPosixAccount {
		if len(req.Attributes["uidNumber"]) == 0 || req.Attributes["uidNumber"][0] == "" {
			req.Attributes["uidNumber"] = []string{getNextID(conn, bases, "uidNumber")}
		}
		if len(req.Attributes["gidNumber"]) == 0 || req.Attributes["gidNumber"][0] == "" {
			delete(req.Attributes, "gidNumber")
		}
		if len(req.Attributes["homeDirectory"]) == 0 || req.Attributes["homeDirectory"][0] == "" {
			if len(req.Attributes["uid"]) > 0 {
				req.Attributes["homeDirectory"] = []string{"/home/" + req.Attributes["uid"][0]}
			}
		}
	}
	if hasPosixGroup {
		if len(req.Attributes["gidNumber"]) == 0 || req.Attributes["gidNumber"][0] == "" {
			delete(req.Attributes, "gidNumber")
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

	// Special case: groupOfNames often requires a member attribute at create-time.
	// We create the entry as requested, then normalize membership in createAGroupOfNames().
	isGroupOfNames := false
	for _, oc := range req.Attributes["objectClass"] {
		if strings.EqualFold(oc, "groupOfNames") {
			isGroupOfNames = true
		}
	}

	if isGroupOfNames {
		if err := createAGroupOfNames(conn, req.DN, addReq); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := conn.Add(addReq); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	session, _ := store.Get(r, "ldap-session")
	userDN, _ := session.Values["dn"].(string)
	notify(a.cfg.NtfyURI, fmt.Sprintf("User %s created LDAP object: %s", userDN, req.DN))

	w.WriteHeader(http.StatusOK)
}
func createAGroupOfNames(conn *ldap.Conn, dn string, request *ldap.AddRequest) error {
	// 1) Create the group entry
	if err := conn.Add(request); err != nil {
		return err
	}

	// 2) Collect any placeholder "member" values from the ADD request
	var placeholders []string
	for _, a := range request.Attributes {
		if strings.EqualFold(a.Type, "member") {
			placeholders = append(placeholders, a.Vals...)
			break
		}
	}

	// 3) Modify: delete placeholders, then add self DN
	modReq := ldap.NewModifyRequest(dn, nil)

	if len(placeholders) > 0 {
		modReq.Changes = append(modReq.Changes, ldap.Change{
			Operation: ldap.DeleteAttribute,
			Modification: ldap.PartialAttribute{
				Type: "member",
				Vals: placeholders,
			},
		})
	}

	modReq.Changes = append(modReq.Changes, ldap.Change{
		Operation: ldap.AddAttribute,
		Modification: ldap.PartialAttribute{
			Type: "member",
			Vals: []string{dn},
		},
	})

	return conn.Modify(modReq)
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
	conn, err := getLDAPConn(w, r, a.cfg)
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

	query := r.URL.Query()
	filter, err := buildLDAPSearchFilter(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scope, err := parseLDAPSearchScope(query.Get("scope"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit, err := parseLDAPSearchLimit(query.Get("limit"), query.Get("full"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bases := query["base"]
	if len(bases) == 0 {
		bases = getLDAPSearchBases(conn, a.cfg, true)
	}
	bases = normalizeSearchBases(bases)

	attrs := parseSearchAttributes(query)
	if len(attrs) == 0 {
		attrs = []string{"dn"}
	}
	format := strings.ToLower(strings.TrimSpace(query.Get("format")))
	structured := format == "entries" || query.Has("attrs") || query.Has("attr") || strings.EqualFold(query.Get("include_attrs"), "true")

	var results []string
	response := LDAPSearchResponse{SearchedBases: bases}
	for _, base := range bases {
		if base == "" {
			continue
		}

		searchLimit := limit
		if limit > 0 {
			remaining := limit - len(results)
			if structured {
				remaining = limit - len(response.Results)
			}
			if remaining <= 0 {
				response.Truncated = true
				break
			}
			searchLimit = remaining
		}

		sReq := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, searchLimit, 0, false, filter, attrs, nil)
		sRes, err := conn.Search(sReq)
		if err != nil {
			response.Errors = append(response.Errors, fmt.Sprintf("%s: %v", base, err))
			continue
		}
		for _, ent := range sRes.Entries {
			if structured {
				response.Results = append(response.Results, ldapSearchEntryFromLDAP(ent, attrs))
			} else {
				results = append(results, ent.DN)
			}
			if limit > 0 {
				if structured && len(response.Results) >= limit {
					response.Truncated = true
					break
				}
				if !structured && len(results) >= limit {
					response.Truncated = true
					break
				}
			}
		}
		if response.Truncated {
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if structured {
		response.Count = len(response.Results)
		json.NewEncoder(w).Encode(response)
		return
	}
	json.NewEncoder(w).Encode(results)
}

func buildLDAPSearchFilter(query map[string][]string) (string, error) {
	filter := strings.TrimSpace(firstQueryValue(query, "filter"))
	if filter != "" {
		return filter, nil
	}

	objectClass := strings.TrimSpace(firstQueryValue(query, "objectClass"))
	if objectClass == "" {
		objectClass = strings.TrimSpace(firstQueryValue(query, "object_class"))
	}

	q := strings.TrimSpace(firstQueryValue(query, "q"))
	if q == "" {
		if objectClass != "" {
			return fmt.Sprintf("(objectClass=%s)", ldap.EscapeFilter(objectClass)), nil
		}
		return "(objectClass=*)", nil
	}

	attributes := query["search_attr"]
	if len(attributes) == 0 {
		attributes = []string{"cn", "uid", "mail", "sn", "givenName", "displayName", "description"}
	}

	var parts []string
	escapedQ := ldap.EscapeFilter(q)
	for _, attr := range attributes {
		attr = strings.TrimSpace(attr)
		if attr == "" || strings.ContainsAny(attr, "=()") {
			continue
		}
		parts = append(parts, fmt.Sprintf("(%s=*%s*)", attr, escapedQ))
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no valid search attributes")
	}

	searchFilter := "(|" + strings.Join(parts, "") + ")"
	if objectClass != "" {
		searchFilter = fmt.Sprintf("(&(objectClass=%s)%s)", ldap.EscapeFilter(objectClass), searchFilter)
	}
	return searchFilter, nil
}

func firstQueryValue(query map[string][]string, key string) string {
	values := query[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func parseLDAPSearchScope(raw string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "sub", "subtree", "whole":
		return ldap.ScopeWholeSubtree, nil
	case "one", "single", "children":
		return ldap.ScopeSingleLevel, nil
	case "base", "object":
		return ldap.ScopeBaseObject, nil
	default:
		return 0, fmt.Errorf("invalid scope %q", raw)
	}
}

func parseLDAPSearchLimit(raw string, fullRaw string) (int, error) {
	if strings.EqualFold(strings.TrimSpace(fullRaw), "true") {
		return 0, nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 100, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 0 {
		return 0, fmt.Errorf("limit must be a non-negative integer")
	}
	return limit, nil
}

func parseSearchAttributes(query map[string][]string) []string {
	var attrs []string
	for _, raw := range query["attrs"] {
		attrs = append(attrs, strings.Split(raw, ",")...)
	}
	attrs = append(attrs, query["attr"]...)

	seen := make(map[string]bool)
	var normalized []string
	for _, attr := range attrs {
		attr = strings.TrimSpace(attr)
		if attr == "" || seen[strings.ToLower(attr)] {
			continue
		}
		seen[strings.ToLower(attr)] = true
		normalized = append(normalized, attr)
	}
	return normalized
}

func normalizeSearchBases(rawBases []string) []string {
	seen := make(map[string]bool)
	var bases []string
	for _, base := range rawBases {
		base = strings.TrimSpace(base)
		if base == "" || seen[strings.ToLower(base)] {
			continue
		}
		seen[strings.ToLower(base)] = true
		bases = append(bases, base)
	}
	return bases
}

func ldapSearchEntryFromLDAP(ent *ldap.Entry, requestedAttrs []string) LDAPSearchEntry {
	result := LDAPSearchEntry{DN: ent.DN}
	if len(requestedAttrs) == 1 && strings.EqualFold(requestedAttrs[0], "dn") {
		return result
	}
	result.Attributes = make(map[string][]string)
	for _, attr := range ent.Attributes {
		result.Attributes[attr.Name] = attr.Values
	}
	return result
}

const browseHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>LDAP Browser</title>
  <link rel="icon" href="{{.AssetURL.Favicon}}">
  <script src="https://unpkg.com/htmx.org@2.0.6"></script>
  <style>
    :root { --bg: #121212; --text: #e0e0e0; --sidebar-bg: #1e1e1e; --border: #333; --hover: #2a2a2a; --selected-bg: #1e3a8a; --selected-text: #bfdbfe; --table-bg: #1e1e1e; --th-bg: #2a2a2a; }
    body.light { --bg: #f4f6f8; --text: #1f2937; --sidebar-bg: #fff; --border: #ddd; --hover: #e5e7eb; --selected-bg: #bfdbfe; --selected-text: #1e3a8a; --table-bg: #fff; --th-bg: #f9fafb; }
    html, body { height: 100%; margin: 0; font-family: sans-serif; background: var(--bg); color: var(--text); overflow: hidden; }
    body { display: flex; height: 100%; }
    #sidebar {
        width: min(400px, 34vw);
        min-width: 280px;
        min-height: 0;
        display: flex;
        flex-direction: column;
        border-right: 1px solid var(--border);
        overflow-y: auto;
        overflow-x: hidden;
        padding: 10px;
        background: var(--sidebar-bg);
        box-shadow: 2px 0 5px rgba(0,0,0,0.05);
        box-sizing: border-box;
        height: 100%;
    }
    #content {
        flex: 1;
        min-width: 0;
        min-height: 0;
        padding: 20px;
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }
    .header { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
    .header h2, .header h3 { margin: 0; color: inherit; }
    .header-actions { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .btn { padding: 6px 12px; background: #dc2626; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 14px; margin-left: 5px; max-width: 100%;}
    .tree-node { margin-left: 15px; list-style: none; line-height: 1.8; white-space: nowrap; }
    .tree-scroll-container {
        flex: 1 1 auto;
        min-height: 0;
        overflow-y: auto;
        overflow-x: hidden;
        height: 100%;
    }
    #tree-root {
        padding-left: 6px;
        width: 100%;
        height: 100%;
    }
    .tree-ul { padding-left: 0; margin: 0; }
    .expand-icon { cursor: pointer; display: inline-block; width: 20px; text-align: center; color: #6b7280; font-size: 12px; }
    .item-icon { display: inline-flex; align-items: center; justify-content: center; width: 1.15em; height: 1.15em; margin-right: 0.35em; vertical-align: text-bottom; color: inherit; }
    .item-icon svg { width: 100%; height: 100%; display: block; }
    .item-icon-fallback { font-size: 0.95em; line-height: 1; }
    .item-text { cursor: pointer; padding: 3px 6px; border-radius: 4px; color: inherit; font-size: 15px; }
    .item-text:hover { background: var(--hover); }
    .selected { background: var(--selected-bg) !important; color: var(--selected-text) !important; font-weight: bold; }
    .table-wrap {
        width: 100%;
        overflow: visible;
    }
    table { width: 100%; border-collapse: collapse; background: var(--table-bg); box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 6px; }
    th, td { border: 1px solid var(--border); padding: 12px; text-align: left; font-size: 14px; }
    th { background: var(--th-bg); font-weight: 600; width: 30%; color: inherit; }
    td { word-break: break-all; color: inherit; font-family: monospace; }
    #quick-create { margin-bottom: 15px; padding: 10px; border-bottom: 1px solid var(--border); }
    .qc-btn { display: inline-block; padding: 4px 8px; margin: 2px; background: #3b82f6; color: white; border-radius: 4px; font-size: 12px; cursor: pointer; text-decoration: none; }
    #ldap-search { margin-bottom: 15px; padding: 10px; border-bottom: 1px solid var(--border); }
    #ldap-search input, #ldap-search select { width: 100%; box-sizing: border-box; margin-top: 6px; padding: 6px; background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 4px; }
    #ldap-search summary { cursor: pointer; margin-top: 8px; color: #93c5fd; font-size: 13px; }
    #ldap-search-results { margin-top: 10px; max-height: 260px; overflow-y: auto; font-size: 13px; }
    .search-result { padding: 6px; border-bottom: 1px solid var(--border); cursor: pointer; overflow-wrap: anywhere; }
    .search-result:hover { background: var(--hover); }
    .search-result small { display: block; opacity: 0.75; margin-top: 2px; }
    #context-menu { display: none; position: absolute; background: var(--sidebar-bg); border: 1px solid var(--border); box-shadow: 0 2px 5px rgba(0,0,0,0.2); z-index: 1000; padding: 5px 0; border-radius: 4px; }
    .cm-item { padding: 8px 15px; cursor: pointer; color: var(--text); font-size: 14px; touch-action: manipulation; }
    .cm-item:hover { background: var(--hover); }
    #settings-modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center; }
    #qc-modal, #group-select-modal, #settings-modal, #credential-modal, #schema-modal { padding: 10px; box-sizing: border-box; }
    .modal-content { background: var(--sidebar-bg); padding: 20px; border-radius: 6px; width: 400px; color: var(--text); border: 1px solid var(--border); box-sizing: border-box; max-width: 100%; }
    .modal-scroll-shell { display: flex; flex-direction: column; max-height: min(92vh, calc(100dvh - 20px)); overflow: hidden; }
    .modal-scroll-body { flex: 1 1 auto; min-height: 0; overflow-y: auto; overscroll-behavior: contain; }
    .modal-actions { text-align: right; margin-top: 15px; }
    .modal-footer-fixed { flex: 0 0 auto; border-top: 1px solid var(--border); padding-top: 12px; margin-top: 0; background: var(--sidebar-bg); position: sticky; bottom: 0; padding-bottom: max(12px, env(safe-area-inset-bottom)); }
    .form-help { margin: 4px 0 10px 0; color: #9ca3af; font-size: 12px; line-height: 1.4; }
    .type-badge { display:inline-block; margin-right:6px; margin-bottom:6px; padding:2px 8px; border-radius:999px; background: var(--hover); font-size:12px; }
    .image-preview { display:block; margin-top:8px; max-width:320px; max-height:240px; border:1px solid var(--border); border-radius:6px; }
    .schema-card { background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-top: 10px; }
    .schema-card h4 { margin: 0 0 8px 0; font-family: sans-serif; }
    .schema-section-title { margin-top: 14px; margin-bottom: 6px; font-size: 13px; font-weight: 600; font-family: sans-serif; color: inherit; }
    .schema-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; }
    .schema-raw { margin-top: 8px; white-space: pre-wrap; word-break: break-word; font-size: 12px; color: #9ca3af; }
    .subschema-scroll-panel { max-height: min(70vh, 900px); overflow-y: auto; overscroll-behavior: contain; padding-right: 4px; }
    .entry-scroll-container { flex: 1 1 auto; min-height: 0; overflow-y: auto; overflow-x: hidden; }
    .entry-toolbar { display:flex; justify-content:space-between; gap:10px; margin-bottom:15px; align-items:center; flex-wrap:wrap; }
    .entry-toolbar-actions { display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }
    .entry-toolbar-actions .btn, .header-actions .btn { margin-left: 0; }
    .entry-dn-box { flex:1 1 320px; min-width:0; font-family: monospace; background: var(--hover); padding: 10px; border-radius: 4px; border: 1px solid var(--border); cursor: pointer; overflow-wrap:anywhere; }
    .inline-editor-row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    .inline-editor-row > input, .inline-editor-row > select { flex:1 1 220px; min-width:0; }
    #context-menu { max-width: min(280px, calc(100vw - 16px)); }
    @media (min-width: 1440px) {
      #sidebar { width: min(440px, 30vw); }
      #content { padding: 28px; }
      .schema-grid { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
    }
    @media (max-width: 900px) {
      body { flex-direction: column; overflow: auto; }
      #sidebar { width: 100%; min-width: 0; max-height: 42vh; border-right: none; border-bottom: 1px solid var(--border); box-shadow: none; }
      #content { width: 100%; padding: 14px; }
      .modal-content { width: min(680px, calc(100vw - 20px)); }
    }
    @media (max-width: 640px) {
      body { font-size: 14px; }
      #sidebar { padding: 8px; max-height: 46vh; }
      #content { padding: 10px; }
      .header { margin-bottom: 14px; }
      .header-actions { width: 100%; justify-content: stretch; }
      .header-actions .btn, .entry-toolbar-actions .btn, .modal-actions .btn { flex: 1 1 140px; }
      .btn { padding: 8px 10px; }
      th, td { padding: 8px; font-size: 13px; }
      table { min-width: 520px; }
      #qc-modal, #group-select-modal, #settings-modal, #credential-modal, #schema-modal { align-items: flex-start; padding: max(8px, env(safe-area-inset-top)) 6px max(8px, env(safe-area-inset-bottom)); }
      .modal-content { width: calc(100vw - 12px) !important; max-height: min(94vh, calc(100dvh - 16px)); padding: 14px; border-radius: 10px; }
      .modal-scroll-body { padding-right: 2px; }
      .modal-actions { display:flex; gap:8px; flex-wrap:wrap; }
      .modal-footer-fixed { padding-top: 10px; }
      .schema-grid { grid-template-columns: 1fr; }
      .subschema-scroll-panel { max-height: min(62vh, calc(100dvh - 220px)); }
      .entry-dn-box { flex-basis: 100%; }
      .entry-toolbar-actions { width: 100%; justify-content: stretch; }
      .inline-editor-row { flex-direction: column; align-items: stretch; }
      #ldap-search-results { max-height: 200px; }
      #context-menu { left: 8px !important; right: 8px; width: auto; }
    }
  </style>
</head>
<body>
  <div id="sidebar">
    <div class="header">
      <h3>LDAP Tree</h3>
      <div class="header-actions">
        <button onclick="showSchemaManager()" style="background:#3b82f6;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Schema Manager</button>
        <button class="btn" style="background: #4b5563;" onclick="openSettings()">Settings</button>
        <a href="/logout" class="btn">Logout</a>
      </div>
    </div>
    <div id="quick-create">
      <strong>Quick Create:</strong><br/>
    </div>
    <div id="ldap-search">
      <strong>LDAP Search</strong>
      <input type="text" id="ldap-search-q" placeholder="Text search across LDAP..." onkeydown="if (event.key === 'Enter') runLDAPSearch()" />
      <button class="btn" style="background:#3b82f6; margin:8px 0 0 0; width:100%;" onclick="runLDAPSearch()">Search</button>
      <details>
        <summary>Parameterized search</summary>
        <input type="text" id="ldap-search-filter" placeholder="LDAP filter, e.g. (objectClass=*)" />
        <input type="text" id="ldap-search-base" placeholder="Base DN override, optional" />
        <input type="text" id="ldap-search-attrs" value="cn,uid,mail,objectClass" placeholder="Returned attrs, comma-separated" />
        <select id="ldap-search-scope">
          <option value="subtree">Subtree</option>
          <option value="one">One level</option>
          <option value="base">Base object</option>
        </select>
        <input type="number" id="ldap-search-limit" value="100" min="0" placeholder="Limit, 0 for full" />
      </details>
      <div id="ldap-search-results"></div>
    </div>
    <div class="tree-scroll-container">
      <ul class="tree-ul" id="tree-root"></ul>
    </div>
  </div>
  <div id="content">
    <div class="header">
      <h2>Entry Details</h2>
      <div class="header-actions">
        <button onclick="showSchemaManager()" style="background:#3b82f6;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Schema Manager</button>
      </div>
    </div>
    <div class="entry-scroll-container">
      <div class="entry-toolbar">
        <div id="entry-dn" class="entry-dn-box" title="Click to copy DN" onclick="copyDN()">Select an entry to view details.</div>
        <div class="entry-toolbar-actions">
          <button id="btn-add-oc" class="btn" style="display:none; background: #8b5cf6;" onclick="showAddObjectClass()">Add Object Class</button>
          <button id="btn-add-attr" class="btn" style="display:none; background: #3b82f6;" onclick="showAddAttribute()">Add Attribute</button>
          <button id="btn-edit" class="btn" style="display:none;" onclick="toggleEdit()">Edit</button>
          <button id="btn-save" class="btn" style="display:none; background: #10b981;" onclick="saveEdits()">Save</button>
          <button id="btn-delete" class="btn" style="display:none;" onclick="deleteEntry()">Delete</button>
        </div>
      </div>
      <div id="add-attr-panel" style="display:none; margin-bottom: 15px; padding: 10px; background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 4px;">
        <div class="inline-editor-row">
          <select id="add-attr-select" style="padding: 4px; background: var(--bg); color: var(--text); border: 1px solid var(--border);"></select>
          <input type="text" id="add-attr-val" style="padding: 4px; background: var(--bg); color: var(--text); border: 1px solid var(--border);">
          <button class="btn" style="background: #10b981; padding: 4px 8px;" onclick="addAttribute()">Add</button>
        </div>
      </div>
      <div id="add-oc-panel" style="display:none; margin-bottom: 15px; padding: 10px; background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 4px;">
        <div class="inline-editor-row">
          <input type="text" id="add-oc-name" placeholder="Object Class Name" style="padding: 4px; background: var(--bg); color: var(--text); border: 1px solid var(--border);">
          <button class="btn" style="background: #3b82f6; padding: 4px 8px;" onclick="nextAddObjectClass()">Next</button>
        </div>
        <div id="add-oc-attrs" style="margin-top: 10px; display:none;"></div>
        <button id="btn-submit-oc" class="btn" style="display:none; background: #10b981; padding: 4px 8px; margin-top: 10px;" onclick="submitAddObjectClass()">Submit</button>
      </div>
      <div class="table-wrap">
        <table id="entry-attrs">
          <thead><tr><th>Attribute</th><th>Value(s)</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
    </div>

  <div id="context-menu"></div>

  <div id="qc-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center;">
    <div class="modal-content modal-scroll-shell" style="width: min(520px, calc(100vw - 20px));">
      <div class="modal-scroll-body" style="padding: 20px;">
        <h3 id="qc-title" style="margin: 0 0 12px 0; max-width: 100%; white-space: normal; overflow-wrap: anywhere; word-break: break-word;">Quick Create</h3>
        <div id="qc-form">Select an object type to create.</div>
      </div>
      <div class="modal-actions modal-footer-fixed" style="padding:12px 20px;">
        <button class="btn" style="background: #6b7280;" onclick="document.getElementById('qc-modal').style.display='none'">Cancel</button>
        <button class="btn" style="background: #10b981;" onclick="submitQuickCreate()">Create</button>
      </div>
    </div>
  </div>

  <div id="group-select-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center;">
    <div class="modal-content modal-scroll-shell" style="width: min(520px, calc(100vw - 20px));">
      <div class="modal-scroll-body">
        <h3 id="group-select-title" style="margin: 0 0 12px 0; max-width: 100%; white-space: normal; overflow-wrap: anywhere; word-break: break-word;">Select Group</h3>
        <div id="group-select-list" style="margin-top: 15px; margin-bottom: 15px; min-height: 120px; overflow-y: auto;"></div>
      </div>
      <div class="modal-actions modal-footer-fixed">
        <button class="btn" style="background: #6b7280;" onclick="document.getElementById('group-select-modal').style.display='none'">Cancel</button>
      </div>
    </div>
  </div>

  <div id="settings-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center;">
    <div id="settings-modal-content" class="modal-content modal-scroll-shell" style="width: min(600px, calc(100vw - 20px));">
      <div class="modal-scroll-body" style="padding: 20px;">Loading settings...</div>
    </div>
  </div>

  <div id="credential-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 2000; align-items: center; justify-content: center;">
    <div class="modal-content modal-scroll-shell" style="width: min(400px, calc(100vw - 20px));">
      <div class="modal-scroll-body">
        <h3 style="margin-top:0;">Add Credential to Vault</h3>
        <div class="form-group">
          <label>User (cn, uid, sn, or full DN)</label>
          <input type="text" id="cred-user" class="input-field" style="width: 100%; box-sizing: border-box;" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="cred-password" class="input-field" style="width: 100%; box-sizing: border-box;" />
        </div>
      </div>
      <div class="modal-actions modal-footer-fixed">
        <button class="btn" style="background: #6b7280;" onclick="document.getElementById('credential-modal').style.display='none'">Cancel</button>
        <button class="btn" style="background: #10b981;" onclick="submitAddCredential()">Save</button>
      </div>
    </div>
  </div>

  <script>
    const settings = {{.SettingsJSON}};
    const serverTimeZone = {{printf "%q" .ServerTimeZone}};

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

    function escapeHTML(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function getTypeActionDefaults() {
        return {
            domain: { add_organizational_unit: true },
            organization: { add_organizational_unit: true },
            organizationalunit: { add_organizational_unit: true },
            inetorgperson: {
                add_credential: true,
                set_password: true,
                add_to_posix_group: true,
                add_to_group_of_names: true,
            },
            person: {
                add_credential: true,
                set_password: true,
                add_to_posix_group: true,
                add_to_group_of_names: true,
            },
            posixaccount: {
                add_credential: true,
                set_password: true,
                add_to_posix_group: true,
                add_to_group_of_names: true,
            },
            posixgroup: { add_members: true },
            groupofnames: { add_members: true },
        };
    }

    function resolveTypeActions(ocs) {
        const classes = (ocs || []).map(c => c.toLowerCase());
        const configured = (settings && settings.ui && settings.ui.type_actions) || {};
        const merged = {};
        const defaults = getTypeActionDefaults();
        classes.forEach(cls => {
            if (defaults[cls]) Object.assign(merged, defaults[cls]);
            if (configured[cls]) Object.assign(merged, configured[cls]);
        });
        return merged;
    }

    function getObjectClassIconMap() {
        return {
            top: 'dot',
            person: 'person',
            organizationalperson: 'person',
            inetorgperson: 'person',
            user: 'person',
            account: 'person',
            posixaccount: 'person',
            groupofnames: 'group',
            groupofuniquenames: 'group',
            posixgroup: 'group',
            group: 'group',
            organizationalunit: 'folder',
            organization: 'building',
            domain: 'globe',
            dcobject: 'globe',
            subschema: 'scroll',
            monitor: 'chart',
            computer: 'screen',
            device: 'screen',
        };
    }

    function getObjectClassHierarchy() {
        return {
            top: null,
            person: 'top',
            organizationalperson: 'person',
            inetorgperson: 'organizationalperson',
            user: 'organizationalperson',
            account: 'top',
            posixaccount: 'account',
            groupofnames: 'top',
            groupofuniquenames: 'top',
            posixgroup: 'top',
            group: 'top',
            organizationalunit: 'top',
            organization: 'top',
            domain: 'top',
            dcobject: 'domain',
            subschema: 'top',
            monitor: 'top',
            computer: 'top',
            device: 'top',
        };
    }

    function getIconClass(ocs) {
        if (!ocs || !ocs.length) return null;
        const classes = [...new Set(ocs.map(c => String(c).trim().toLowerCase()).filter(Boolean))];
        const iconMap = {
            ...getObjectClassIconMap(),
            ...((settings && settings.ui && settings.ui.object_class_icons) || {}),
        };
        const hierarchy = getObjectClassHierarchy();

        const getDepth = (cls) => {
            let depth = 0;
            let current = cls;
            const seen = new Set();
            while (current && !seen.has(current)) {
                seen.add(current);
                current = hierarchy[current] || null;
                depth += 1;
            }
            return depth;
        };

        const candidates = classes.filter(cls => iconMap[cls]);
        if (!candidates.length) return null;

        candidates.sort((a, b) => {
            const depthDiff = getDepth(b) - getDepth(a);
            if (depthDiff !== 0) return depthDiff;
            return a.localeCompare(b);
        });

        return candidates[0];
    }

    function renderSVGIcon(name) {
        const icons = {
            dot: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="2.25" fill="currentColor"></circle></svg>',
            person: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="5" r="2.5" fill="none" stroke="currentColor" stroke-width="1.5"></circle><path d="M3.5 13c.6-2.2 2.3-3.5 4.5-3.5s3.9 1.3 4.5 3.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"></path></svg>',
            group: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="6" cy="5.25" r="2.1" fill="none" stroke="currentColor" stroke-width="1.4"></circle><circle cx="11.25" cy="6.25" r="1.75" fill="none" stroke="currentColor" stroke-width="1.2"></circle><path d="M2.75 13c.45-2 1.95-3.2 3.95-3.2 2.05 0 3.56 1.18 4 3.2" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"></path><path d="M9.2 12.8c.22-1.35 1.18-2.2 2.55-2.2 1.05 0 1.9.42 2.5 1.35" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"></path></svg>',
            folder: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M1.75 4.5h4.1l1.3 1.5H14.25v5.75a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"></path><path d="M1.75 6h12.5" fill="none" stroke="currentColor" stroke-width="1.4"></path></svg>',
            building: '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="3" y="2.5" width="10" height="11" rx="1" fill="none" stroke="currentColor" stroke-width="1.4"></rect><path d="M6 5.25h1.2M8.8 5.25H10M6 7.75h1.2M8.8 7.75H10M6 10.25h1.2M8.8 10.25H10M7.9 13.5V11.2" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"></path></svg>',
            globe: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" stroke-width="1.4"></circle><path d="M2.8 8h10.4M8 2.5c1.6 1.5 2.5 3.4 2.5 5.5S9.6 12 8 13.5M8 2.5C6.4 4 5.5 5.9 5.5 8s.9 4 2.5 5.5" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"></path></svg>',
            scroll: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M5 2.5h5.25A1.75 1.75 0 0 1 12 4.25v6.5A1.75 1.75 0 0 1 10.25 12.5H5.75A1.75 1.75 0 0 0 4 14.25" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M5.75 12.5A1.75 1.75 0 1 1 4 10.75V4.25A1.75 1.75 0 0 1 5.75 2.5M6.5 5.5h3M6.5 8h3" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"></path></svg>',
            chart: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2.5 13.25h11" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"></path><path d="M4.5 11V8.75M8 11V5.5M11.5 11V7" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"></path></svg>',
            screen: '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="2.25" y="3" width="11.5" height="7.5" rx="1" fill="none" stroke="currentColor" stroke-width="1.4"></rect><path d="M6 13h4M8 10.5V13" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"></path></svg>',
            file: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4.25 2.5h4.75L12 5.5v7A1 1 0 0 1 11 13.5H4.25a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"></path><path d="M9 2.5v3h3" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"></path></svg>',
        };
        return icons[name] || icons.file;
    }

    function getIconMarkup(ocs) {
        const cls = getIconClass(ocs);
        if (!cls) {
            return renderSVGIcon('file');
        }

        const configured = settings && settings.ui && settings.ui.object_class_icons && settings.ui.object_class_icons[cls];
        if (configured && String(configured).trim().startsWith('<svg')) {
            return String(configured).trim();
        }

        const builtInName = getObjectClassIconMap()[cls];
        if (builtInName) {
            return renderSVGIcon(builtInName);
        }

        if (configured) {
            return '<span class="item-icon-fallback">' + escapeHTML(String(configured)) + '</span>';
        }

        return renderSVGIcon('file');
    }

    function updateTreeNodeAppearance(dn, objectClasses) {
        document.querySelectorAll('.tree-node').forEach(node => {
            if (node.dataset.dn !== dn) return;
            if (node._nodeData) {
                node._nodeData.objectClasses = objectClasses;
            }
            const icon = node.querySelector('.item-icon');
            if (icon) {
                icon.innerHTML = getIconMarkup(objectClasses);
            }
        });
    }

    function hideContextMenu() {
        document.getElementById('context-menu').style.display = 'none';
    }

    function showContextMenuAt(x, y, items) {
        const cm = document.getElementById('context-menu');
        cm.innerHTML = '';
        (items || []).forEach(item => {
            const div = document.createElement('div');
            div.className = 'cm-item';
            div.textContent = item.name;
            div.onclick = () => {
                hideContextMenu();
                item.action();
            };
            cm.appendChild(div);
        });
        if (!items || !items.length) {
            hideContextMenu();
            return;
        }
        cm.style.visibility = 'hidden';
        cm.style.display = 'block';
        cm.style.left = '0px';
        cm.style.top = '0px';
        const rect = cm.getBoundingClientRect();
        const minLeft = window.scrollX + 8;
        const minTop = window.scrollY + 8;
        const maxLeft = window.scrollX + window.innerWidth - rect.width - 8;
        const maxTop = window.scrollY + window.innerHeight - rect.height - 8;
        cm.style.left = Math.max(minLeft, Math.min(x, maxLeft)) + 'px';
        cm.style.top = Math.max(minTop, Math.min(y, maxTop)) + 'px';
        cm.style.visibility = 'visible';
    }

    function consumeLongPressClick(el, event) {
        if (!el || el.dataset.longPressMenuOpen !== 'true') {
            return false;
        }
        el.dataset.longPressMenuOpen = 'false';
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }
        return true;
    }

    function attachLongPressContextMenu(el, getItems) {
        if (!el) return;
        let timer = null;
        let startPoint = null;

        const clearLongPress = () => {
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
            startPoint = null;
        };

        el.addEventListener('touchstart', (event) => {
            if (!event.touches || event.touches.length !== 1) {
                clearLongPress();
                return;
            }
            const touch = event.touches[0];
            startPoint = { x: touch.pageX, y: touch.pageY };
            el.dataset.longPressMenuOpen = 'false';
            timer = setTimeout(() => {
                timer = null;
                const items = (getItems && getItems()) || [];
                if (!items.length || !startPoint) {
                    return;
                }
                el.dataset.longPressMenuOpen = 'true';
                showContextMenuAt(startPoint.x, startPoint.y, items);
            }, 550);
        }, { passive: true });

        el.addEventListener('touchmove', (event) => {
            if (!timer || !startPoint || !event.touches || event.touches.length !== 1) {
                return;
            }
            const touch = event.touches[0];
            if (Math.abs(touch.pageX - startPoint.x) > 12 || Math.abs(touch.pageY - startPoint.y) > 12) {
                clearLongPress();
            }
        }, { passive: true });

        el.addEventListener('touchend', (event) => {
            if (el.dataset.longPressMenuOpen === 'true') {
                event.preventDefault();
            }
            clearLongPress();
        }, { passive: false });

        el.addEventListener('touchcancel', clearLongPress, { passive: true });
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

    function firstAttr(attrs, names) {
        attrs = attrs || {};
        const keys = Object.keys(attrs);
        for (const name of names) {
            const key = keys.find(k => k.toLowerCase() === name.toLowerCase());
            if (key && attrs[key] && attrs[key].length > 0) return attrs[key][0];
        }
        return '';
    }

    async function runLDAPSearch() {
        const resultsDiv = document.getElementById('ldap-search-results');
        resultsDiv.innerHTML = 'Searching...';

        const params = new URLSearchParams();
        params.set('format', 'entries');

        const q = document.getElementById('ldap-search-q').value.trim();
        const filter = document.getElementById('ldap-search-filter').value.trim();
        const base = document.getElementById('ldap-search-base').value.trim();
        const attrs = document.getElementById('ldap-search-attrs').value.trim();
        const scope = document.getElementById('ldap-search-scope').value;
        const limit = document.getElementById('ldap-search-limit').value.trim();

        if (filter) {
            params.set('filter', filter);
        } else if (q) {
            params.set('q', q);
        } else {
            params.set('filter', '(objectClass=*)');
        }
        if (base) params.append('base', base);
        if (attrs) params.set('attrs', attrs);
        if (scope) params.set('scope', scope);
        if (limit !== '') {
            params.set('limit', limit);
            if (limit === '0') params.set('full', 'true');
        }

        const res = await fetch('/api/search?' + params.toString());
        if (!res.ok) {
            resultsDiv.innerHTML = 'Search failed: ' + await res.text();
            return;
        }

        const data = await res.json();
        const entries = data.results || [];
        if (entries.length === 0) {
            resultsDiv.innerHTML = 'No results.';
            return;
        }

        resultsDiv.innerHTML = '';
        const meta = document.createElement('div');
        meta.style.padding = '6px';
        meta.style.opacity = '0.8';
        meta.textContent = data.count + ' result(s)' + (data.truncated ? ' (truncated)' : '');
        resultsDiv.appendChild(meta);

        entries.forEach(entry => {
            const div = document.createElement('div');
            div.className = 'search-result';
            const label = firstAttr(entry.attributes, ['cn', 'uid', 'mail', 'displayName']) || entry.dn.split(',')[0];
            div.textContent = label;
            const dn = document.createElement('small');
            dn.textContent = entry.dn;
            div.appendChild(dn);
            div.onclick = () => loadEntry(entry.dn);
            resultsDiv.appendChild(div);
        });

        if (data.errors && data.errors.length > 0) {
            const errors = document.createElement('div');
            errors.style.padding = '6px';
            errors.style.color = '#fca5a5';
            errors.textContent = 'Some bases failed: ' + data.errors.join('; ');
            resultsDiv.appendChild(errors);
        }
    }

    function createNode(nodeData) {
        const li = document.createElement('li');
        li.className = 'tree-node';
        li.dataset.dn = nodeData.dn;
        li._nodeData = nodeData;

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
        icon.className = 'item-icon';
        icon.innerHTML = getIconMarkup(nodeData.objectClasses);

        const text = document.createElement('span');
        text.className = 'item-text';
        text.textContent = nodeData.rdn || nodeData.dn;
        const buildTreeNodeActions = () => {
            const actions = [];

            if (settings && settings.ui && settings.ui.context_menu) {
                settings.ui.context_menu.forEach(item => {
                    actions.push({
                        name: item.name,
                        action: () => new Function('dn', item.action).bind(null, nodeData.dn)(),
                    });
                });
            }

            const typeActions = resolveTypeActions(nodeData.objectClasses || []);
            if (typeActions.add_organizational_unit) {
                actions.push({ name: 'Add OrganizationalUnit', action: () => alert('Add OU under ' + nodeData.dn) });
            }
            if (typeActions.add_credential) {
                actions.push({ name: 'Add Credential', action: () => showAddCredentialModal(nodeData.dn) });
            }
            if (typeActions.set_password) {
                actions.push({ name: 'Set Password', action: () => setPassword(nodeData.dn) });
            }
            if (typeActions.add_to_posix_group) {
                actions.push({ name: 'Add to posixGroup', action: () => showGroupSelector('posixGroup', nodeData.dn) });
            }
            if (typeActions.add_to_group_of_names) {
                actions.push({ name: 'Add to groupOfNames', action: () => showGroupSelector('groupOfNames', nodeData.dn) });
            }
            if (typeActions.add_members) {
                if ((nodeData.objectClasses || []).some(c => c.toLowerCase() === 'posixgroup')) {
                    actions.push({ name: 'Add members', action: () => showMemberSelector('posixGroup', nodeData.dn) });
                }
                if ((nodeData.objectClasses || []).some(c => c.toLowerCase() === 'groupofnames')) {
                    actions.push({ name: 'Add members', action: () => showMemberSelector('groupOfNames', nodeData.dn) });
                }
            }
            return actions;
        };

        text.onclick = (e) => {
            if (consumeLongPressClick(text, e)) return;
            document.querySelectorAll('.selected').forEach(e => e.classList.remove('selected'));
            text.classList.add('selected');
            loadEntry(nodeData.dn);
        };
        text.oncontextmenu = (e) => {
            e.preventDefault();
            showContextMenuAt(e.pageX, e.pageY, buildTreeNodeActions());
        };
        attachLongPressContextMenu(text, buildTreeNodeActions);

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
                            children.sort((a, b) => a.rdn.localeCompare(b.rdn)).forEach(c => childrenUl.appendChild(createNode(c)));
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

    function parseLDAPGeneralizedTime(value) {
        if (typeof value !== 'string') return null;
        const match = value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?(Z|[+-]\d{4})$/);
        if (!match) return null;

        const [, year, month, day, hour, minute, second, fraction, tz] = match;
        let millis = 0;
        if (fraction) {
            millis = Math.round(Number('0.' + fraction) * 1000);
        }

        let timestamp = Date.UTC(
            Number(year),
            Number(month) - 1,
            Number(day),
            Number(hour),
            Number(minute),
            Number(second),
            millis,
        );

        if (tz !== 'Z') {
            const sign = tz[0] === '+' ? 1 : -1;
            const offsetHours = Number(tz.slice(1, 3));
            const offsetMinutes = Number(tz.slice(3, 5));
            const offsetMillis = ((offsetHours * 60) + offsetMinutes) * 60 * 1000;
            timestamp -= sign * offsetMillis;
        }

        const date = new Date(timestamp);
        return Number.isNaN(date.getTime()) ? null : date;
    }

    function formatDateTimeInTimeZone(date, timeZone) {
        const pad = (n) => String(n).padStart(2, '0');

        if (timeZone && timeZone !== 'Local') {
            try {
                const parts = new Intl.DateTimeFormat('en-CA', {
                    timeZone,
                    hour12: false,
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                }).formatToParts(date);

                const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
                return values.year + '-' + values.month + '-' + values.day + 'T' +
                    values.hour + ':' + values.minute + ':' + values.second;
            } catch (_) {
            }
        }

        return date.getFullYear() + '-' +
            pad(date.getMonth() + 1) + '-' +
            pad(date.getDate()) + 'T' +
            pad(date.getHours()) + ':' +
            pad(date.getMinutes()) + ':' +
            pad(date.getSeconds());
    }

    function formatAttributeValueForDisplay(value) {
        const parsed = parseLDAPGeneralizedTime(value);
        if (!parsed) return value;
        return formatDateTimeInTimeZone(parsed, serverTimeZone);
    }

    function isImageValue(value) {
        return typeof value === 'string' && value.startsWith('data:image/');
    }

    function isBase64BinaryValue(value) {
        return typeof value === 'string' && value.startsWith('base64:');
    }

    function isBinaryDisplayValue(value) {
        return isImageValue(value) || isBase64BinaryValue(value);
    }

    function parseSchemaDefinition(raw) {
        const readNames = () => {
            const listMatch = raw.match(/NAME\s+\(([^)]+)\)/);
            if (listMatch) {
                return [...listMatch[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
            }
            const singleMatch = raw.match(/NAME\s+'([^']+)'/);
            return singleMatch ? [singleMatch[1]] : [];
        };
        const readList = (label) => {
            const match = raw.match(new RegExp(label + '\\s+([A-Za-z0-9._-]+|\\([^)]+\\))'));
            if (!match) return [];
            return match[1].replace(/^\(|\)$/g, '').split('$').map(s => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
        };
        const names = readNames();
        const oidMatch = raw.match(/^\(\s*([0-9.]+)/);
        const descMatch = raw.match(/DESC\s+'([^']+)'/);
        const syntaxMatch = raw.match(/SYNTAX\s+([0-9.]+(?:\{\d+\})?)/);
        return {
            raw,
            oid: oidMatch ? oidMatch[1] : '',
            name: names[0] || 'Unnamed',
            aliases: names.slice(1),
            desc: descMatch ? descMatch[1] : '',
            sup: readList('SUP'),
            must: readList('MUST'),
            may: readList('MAY'),
            syntax: syntaxMatch ? syntaxMatch[1] : '',
            kind: raw.includes(' AUXILIARY') ? 'AUXILIARY' : (raw.includes(' ABSTRACT') ? 'ABSTRACT' : 'STRUCTURAL'),
            singleValue: raw.includes(' SINGLE-VALUE'),
        };
    }

    function renderSubschemaValue(attrName, values) {
        const wrapper = document.createElement('div');
        const lower = (attrName || '').toLowerCase();
        const isObjectClasses = lower === 'objectclasses';
        const isAttributeTypes = lower === 'attributetypes';
        if (!isObjectClasses && !isAttributeTypes) {
            values.forEach((val, idx) => appendAttributeValue(wrapper, attrName, val, idx, values.length));
            return wrapper;
        }

        const title = document.createElement('div');
        title.className = 'schema-section-title';
        title.textContent = (isObjectClasses ? 'Parsed Object Classes' : 'Parsed Attribute Types') + ' (' + values.length + ')';
        wrapper.appendChild(title);

        const grid = document.createElement('div');
        grid.className = 'schema-grid';
        values.forEach(raw => {
            const parsed = parseSchemaDefinition(raw);
            const card = document.createElement('div');
            card.className = 'schema-card';
            card.innerHTML = '<h4>' + parsed.name + '</h4>' +
                '<div>' + (parsed.oid ? '<span class="type-badge">OID ' + parsed.oid + '</span>' : '') +
                (isObjectClasses ? '<span class="type-badge">' + parsed.kind + '</span>' : '') +
                (!isObjectClasses && parsed.singleValue ? '<span class="type-badge">SINGLE-VALUE</span>' : '') +
                '</div>' +
                (parsed.aliases.length ? '<div><strong>Aliases:</strong> ' + parsed.aliases.map(a => '<span class="type-badge">' + a + '</span>').join('') + '</div>' : '') +
                (parsed.desc ? '<div><strong>Description:</strong> ' + parsed.desc + '</div>' : '') +
                (parsed.sup.length ? '<div><strong>SUP:</strong> ' + parsed.sup.map(a => '<span class="type-badge">' + a + '</span>').join('') + '</div>' : '') +
                (parsed.must.length ? '<div><strong>MUST:</strong> ' + parsed.must.map(a => '<span class="type-badge">' + a + '</span>').join('') + '</div>' : '') +
                (parsed.may.length ? '<div><strong>MAY:</strong> ' + parsed.may.map(a => '<span class="type-badge">' + a + '</span>').join('') + '</div>' : '') +
                (!isObjectClasses && parsed.syntax ? '<div><strong>SYNTAX:</strong> <span class="type-badge">' + parsed.syntax + '</span></div>' : '');
            const details = document.createElement('details');
            details.innerHTML = '<summary>Raw definition</summary><div class="schema-raw"></div>';
            details.querySelector('.schema-raw').textContent = raw;
            card.appendChild(details);
            grid.appendChild(card);
        });
        wrapper.appendChild(grid);
        return wrapper;
    }

    function appendAttributeValue(container, attrName, value, idx, totalValues) {
        const attrLower = (attrName || '').toLowerCase();
        if (isImageValue(value)) {
            const link = document.createElement('a');
            link.href = value;
            link.target = '_blank';
            link.textContent = 'View image';
            link.style.color = '#3b82f6';
            link.style.textDecoration = 'none';
            container.appendChild(link);

            const img = document.createElement('img');
            img.src = value;
            img.alt = attrName;
            img.className = 'image-preview';
            container.appendChild(img);
        } else if (isBase64BinaryValue(value)) {
            const details = document.createElement('details');
            const summary = document.createElement('summary');
            summary.textContent = 'Binary value (base64)';
            details.appendChild(summary);
            const code = document.createElement('code');
            code.textContent = value.slice('base64:'.length);
            code.style.display = 'block';
            code.style.whiteSpace = 'pre-wrap';
            code.style.wordBreak = 'break-all';
            code.style.marginTop = '6px';
            details.appendChild(code);
            container.appendChild(details);
        } else if (typeof value === 'string' && /^[a-zA-Z][a-zA-Z0-9-]*=[^,]+,.*=/.test(value)) {
            const a = document.createElement('a');
            a.textContent = value.split(',')[0];
            a.title = value;
            a.href = '#';
            const memberOfActions = () => attrLower === 'memberof' ? [{
                name: 'Remove from group',
                action: () => removeMembership(value),
            }] : [];
            a.onclick = (e) => {
                e.preventDefault();
                if (consumeLongPressClick(a, e)) return;
                loadEntry(value);
            };
            a.oncontextmenu = (e) => {
                if (attrLower !== 'memberof') return;
                e.preventDefault();
                showContextMenuAt(e.pageX, e.pageY, memberOfActions());
            };
            attachLongPressContextMenu(a, memberOfActions);
            a.style.color = '#3b82f6';
            a.style.textDecoration = 'none';
            container.appendChild(a);
        } else {
            container.appendChild(document.createTextNode(formatAttributeValueForDisplay(value)));
        }
        if (idx < totalValues - 1) {
            container.appendChild(document.createTextNode(', '));
        }
    }

    function copyDN() {
        const text = document.getElementById('entry-dn').textContent;
        if (text && text !== "Select an entry to view details.") {
            navigator.clipboard.writeText(text).then(() => {
                const el = document.getElementById('entry-dn');
                const origBg = el.style.background;
                el.style.background = '#10b981';
                setTimeout(() => { el.style.background = origBg; }, 250);
            });
        }
    }

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
        const ocKey = Object.keys(data).find(k => k.toLowerCase() === 'objectclass');
        const objectClasses = ocKey ? (data[ocKey] || []) : [];
        const isSubschemaEntry = objectClasses.some(v => String(v).toLowerCase() === 'subschema');
        for (const attr of attrs) {
            const tr = document.createElement('tr');
            const tdAttr = document.createElement('td');
            tdAttr.textContent = attr;
            const tdVals = document.createElement('td');
            tdVals.className = 'val-cell';
            tdVals.dataset.attr = attr;

            if (isSubschemaEntry && ['objectclasses', 'attributetypes'].includes(attr.toLowerCase())) {
                continue;
            }
            data[attr].forEach((val, idx) => appendAttributeValue(tdVals, attr, val, idx, data[attr].length));
            tr.appendChild(tdAttr);
            tr.appendChild(tdVals);
            tbody.appendChild(tr);
        }
        if (isSubschemaEntry) {
            const tr = document.createElement('tr');
            const tdAttr = document.createElement('td');
            tdAttr.textContent = 'subschema';
            const tdVals = document.createElement('td');
            tdVals.innerHTML = '<div id="subschema-fragment-slot" style="padding:4px 0;">Loading subschema...</div>';
            tr.appendChild(tdAttr);
            tr.appendChild(tdVals);
            tbody.insertBefore(tr, tbody.firstChild);
            if (window.htmx) {
                htmx.ajax('GET', '/ui/subschema?dn=' + encodeURIComponent(dn), {
                    target: '#subschema-fragment-slot',
                    swap: 'innerHTML'
                });
            }
        }
        if (ocKey) {
            updateTreeNodeAppearance(dn, objectClasses);
        }
        document.getElementById('entry-attrs').style.display = 'table';
        document.getElementById('add-attr-panel').style.display = 'none';
        document.getElementById('btn-add-attr').style.display = 'none';
        document.getElementById('btn-add-oc').style.display = 'none';
        document.getElementById('add-oc-panel').style.display = 'none';
    }

    function showAddObjectClass() {
        document.getElementById('add-attr-panel').style.display = 'none';
        document.getElementById('add-oc-panel').style.display = 'block';
        document.getElementById('add-oc-attrs').style.display = 'none';
        document.getElementById('btn-submit-oc').style.display = 'none';
        document.getElementById('add-oc-name').value = '';
    }

    async function nextAddObjectClass() {
        const objName = document.getElementById('add-oc-name').value.trim();
        if (!objName) return;

        const res = await fetch('/api/schema?oc=' + encodeURIComponent(objName));
        if (!res.ok) {
            alert("Failed to fetch schema for " + objName);
            return;
        }
        const schema = await res.json();

        const existing = Object.keys(currentEntryData).map(k => k.toLowerCase());
        const missingMust = (schema.must || []).filter(a => !existing.includes(a.toLowerCase()));

        const container = document.getElementById('add-oc-attrs');
        container.innerHTML = '<h4>Required Missing Attributes:</h4>';
        container.style.display = 'block';

        for (const attr of missingMust) {
            const row = document.createElement('div');
            row.style.marginBottom = '5px';
            const label = document.createElement('label');
            label.textContent = attr + ': ';
            label.style.display = 'inline-block';
            label.style.width = '120px';
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'oc-attr-input';
            input.dataset.attr = attr;
            input.style.padding = '4px';
            input.style.background = 'var(--bg)';
            input.style.color = 'var(--text)';
            input.style.border = '1px solid var(--border)';

            if (attr.toLowerCase() === 'uidnumber') {
                row.style.display = 'none';
                input.type = 'hidden';
                const nextIdRes = await fetch('/api/next_id?attr=uidNumber');
                if (nextIdRes.ok) {
                    input.value = await nextIdRes.text();
                }
            } else if (attr.toLowerCase() === 'gidnumber') {
                const defGidRes = await fetch('/api/default_gid');
                if (defGidRes.ok) {
                    input.value = await defGidRes.text();
                }
            } else if (attr.toLowerCase() === 'uid') {
                const cnKey = Object.keys(currentEntryData).find(k => k.toLowerCase() === 'cn');
                if (cnKey && currentEntryData[cnKey].length > 0) {
                    input.value = currentEntryData[cnKey][0];
                }
            }

            row.appendChild(label);
            row.appendChild(input);
            container.appendChild(row);
        }

        document.getElementById('btn-submit-oc').style.display = 'block';
    }

    async function submitAddObjectClass() {
        const objName = document.getElementById('add-oc-name').value.trim();
        if (!objName) return;

        const inputs = document.querySelectorAll('.oc-attr-input');
        const reqData = { dn: currentEntryDN, add: { objectclass: [objName] }, replace: {}, delete: [] };

        let allFilled = true;
        inputs.forEach(input => {
            const val = input.value.trim();
            if (!val) {
                allFilled = false;
            } else {
                reqData.add[input.dataset.attr] = [val];
            }
        });

        if (!allFilled) {
            alert("Please fill all required missing attributes.");
            return;
        }

        const res = await fetch('/api/modify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(reqData)
        });

        if (res.ok) {
            document.getElementById('add-oc-panel').style.display = 'none';
            document.getElementById('tree-root').innerHTML = '';
            loadRoots();
            loadEntry(currentEntryDN);
        } else {
            alert("Failed to add object class: " + await res.text());
        }
    }

    async function showAddAttribute() {
        document.getElementById('add-oc-panel').style.display = 'none';
        const ocKey = Object.keys(currentEntryData).find(k => k.toLowerCase() === 'objectclass');
        const ocs = ocKey ? currentEntryData[ocKey] : [];
        const res = await fetch('/api/schema?oc=' + encodeURIComponent(ocs.join(',')));
        if (!res.ok) return;
        const schema = await res.json();
        const sel = document.getElementById('add-attr-select');
        sel.innerHTML = '';
        document.getElementById('add-attr-val').value = '';
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

    async function addAttribute() {
        const attr = document.getElementById('add-attr-select').value;
        const val = document.getElementById('add-attr-val').value;
        if (!attr || val === "") return;

        const res = await fetch('/api/modify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dn: currentEntryDN, add: { [attr]: [val] } })
        });

        if (res.ok) {
            isEditing = false;
            document.getElementById('add-attr-val').value = '';
            loadEntry(currentEntryDN);
            document.getElementById('add-attr-panel').style.display = 'none';
        } else {
            alert('Failed to add attribute.');
        }
    }

    function toggleEdit() {
        isEditing = !isEditing;
        document.getElementById('btn-edit').textContent = isEditing ? 'Cancel' : 'Edit';
        document.getElementById('btn-save').style.display = isEditing ? 'inline-block' : 'none';
        document.getElementById('btn-add-attr').style.display = isEditing ? 'inline-block' : 'none';
        document.getElementById('btn-add-oc').style.display = isEditing ? 'inline-block' : 'none';
        if (!isEditing) { document.getElementById('add-attr-panel').style.display = 'none'; document.getElementById('add-oc-panel').style.display = 'none'; }

        const readOnly = ['userpassword', 'modifiersname', 'modifytimestamp', 'subschemasubentry', 'memberof', 'creatorsname', 'createtimestamp', 'contextcsn', 'entrydn', 'entrycsn', 'entryuuid', 'hasalsubordinates', 'numsubordinates'];
        const cells = document.querySelectorAll('.val-cell');
        cells.forEach(cell => {
            const attr = cell.dataset.attr;
            if (isEditing) {
                if (readOnly.includes(attr.toLowerCase())) {
                    cell.style.opacity = '0.5';
                    return;
                }
                if (currentEntryData[attr].some(isBinaryDisplayValue)) {
                    cell.style.opacity = '0.5';
                    return;
                }
                const val = currentEntryData[attr].join('\n'); const rows = Math.max(1, currentEntryData[attr].length);
                cell.innerHTML = '<textarea style="width:80%; box-sizing:border-box; padding:4px; vertical-align:top;" rows="' + rows + '">' + val.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</textarea><button onclick="deleteAttr(\'' + attr + '\')" style="margin-left:5px; background:#dc2626; color:white; border:none; padding:4px 8px; border-radius:4px; cursor:pointer;">X</button>';
            } else {
                cell.style.opacity = '1';
                cell.innerHTML = '';
                currentEntryData[attr].forEach((val, idx) => appendAttributeValue(cell, attr, val, idx, currentEntryData[attr].length));
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
            const input = cell.querySelector('textarea');
            if (input) {
                const newVals = input.value.split('\n').map(s => s.trim()).filter(s => s !== '');
                const oldVals = currentEntryData[attr];
                if (JSON.stringify(newVals) !== JSON.stringify(oldVals)) {
                    replace[attr] = newVals;
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
            document.getElementById('tree-root').innerHTML = '';
            loadRoots();
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
        document.getElementById('btn-add-oc').style.display = 'none';
        document.getElementById('add-oc-panel').style.display = 'none';
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
            hideContextMenu();
        }
    });
    document.addEventListener('scroll', hideContextMenu, true);
    window.addEventListener('resize', hideContextMenu);

    async function openSettings() {
        document.getElementById('settings-modal').style.display = 'flex';
        if (window.htmx) {
            htmx.ajax('GET', '/ui/settings', {
                target: '#settings-modal-content',
                swap: 'outerHTML'
            });
            return;
        }
        alert('HTMX is not available.');
    }

    async function embedAssetFromSourceFile(name, inputId) {
        const src = (document.getElementById(inputId).value || '').trim();
        if (!src) {
            alert('Source file path is empty');
            return;
        }

        const form = new FormData();
        form.append('name', name); // "logo" or "icon"
        form.append('mode', 'embedded');
        form.append('source_file', src);

        const res = await fetch('/api/assets/upload', {
            method: 'POST',
            body: form
        });

        if (res.ok) {
            alert('Embedded successfully. Reloading...');
            location.reload();
        } else {
            const err = await res.text();
            alert('Embed failed: ' + err);
        }
    }

    async function embedAssetFromUpload(name, fileInputId) {
        const inp = document.getElementById(fileInputId);
        const f = inp && inp.files && inp.files[0];
        if (!f) {
            alert('No file selected');
            return;
        }

        const form = new FormData();
        form.append('name', name); // "logo" or "icon"
        form.append('mode', 'embedded');
        form.append('file', f, f.name);

        const res = await fetch('/api/assets/upload', {
            method: 'POST',
            body: form
        });

        if (res.ok) {
            alert('Uploaded & embedded successfully. Reloading...');
            location.reload();
        } else {
            const err = await res.text();
            alert('Upload/embed failed: ' + err);
        }
    }

    async function openQuickCreate(objName, objTmpl) {
        document.getElementById('qc-title').textContent = "Create " + objName;
        document.getElementById('qc-modal').style.display = 'flex';
        const formDiv = document.getElementById('qc-form');
        formDiv.innerHTML = 'Loading schema...';

        if (window.htmx) {
            htmx.ajax('GET', '/ui/quick-create?name=' + encodeURIComponent(objName), {
                target: '#qc-form',
                swap: 'innerHTML'
            });
            return;
        }

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
        listDiv.style.display = 'block';
        document.getElementById('group-select-modal').style.display = 'flex';

        if (window.htmx) {
            htmx.ajax('GET', '/ui/groups/select?type=' + encodeURIComponent(type) + '&userDN=' + encodeURIComponent(userDN), {
                target: '#group-select-list',
                swap: 'innerHTML'
            });
            return;
        }

        listDiv.innerHTML = 'HTMX is not available.';
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
            body: JSON.stringify({ dn: groupDN, add: { [attr]: [val] } })
        });

        if (res.ok) {
            alert('Added successfully!');
            document.getElementById('group-select-modal').style.display='none';
        } else {
            alert('Failed to add to group');
        }
    }

    async function removeMembership(groupDN) {
        if (!currentEntryDN) return;
        if (!confirm('Remove ' + currentEntryDN + ' from ' + groupDN + '?')) return;

        const [groupRes, userRes] = await Promise.all([
            fetch('/api/entry?dn=' + encodeURIComponent(groupDN)),
            fetch('/api/entry?dn=' + encodeURIComponent(currentEntryDN)),
        ]);
        if (!groupRes.ok || !userRes.ok) {
            alert('Failed to inspect group membership');
            return;
        }

        const groupData = await groupRes.json();
        const userData = await userRes.json();
        const deleteValues = {};

        const memberVals = groupData['member'] || [];
        if (memberVals.includes(currentEntryDN)) {
            deleteValues.member = [currentEntryDN];
        }

        const uid = (userData['uid'] && userData['uid'][0]) || '';
        const memberUidVals = groupData['memberUid'] || [];
        if (uid && memberUidVals.includes(uid)) {
            deleteValues.memberUid = [uid];
        }

        if (Object.keys(deleteValues).length === 0) {
            alert('No removable membership values were found on the target group.');
            return;
        }

        const res = await fetch('/api/modify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ dn: groupDN, delete_values: deleteValues })
        });

        if (res.ok) {
            alert('Membership removed successfully!');
            loadEntry(currentEntryDN);
        } else {
            alert('Failed to remove membership: ' + await res.text());
        }
    }

    async function showMemberSelector(type, groupDN) {
        document.getElementById('group-select-title').textContent = "Add members to " + groupDN;
        const listDiv = document.getElementById('group-select-list');
        listDiv.innerHTML = 'Loading...';
        document.getElementById('group-select-modal').style.display = 'flex';

        const gRes = await fetch('/api/entry?dn=' + encodeURIComponent(groupDN));
        const gData = await gRes.json();

        // Build "eligible users" filter depending on group type
        let members = [];
        let filter = '';

        if (type === 'posixGroup') {
            members = gData['memberUid'] || [];
            if (members.length > 0) {
                const exclusion = members.map(m => '(!(uid=' + m + '))').join('');
                filter = '(&(objectClass=posixAccount)' + exclusion + ')';
            } else {
                filter = '(objectClass=posixAccount)';
            }
        } else if (type === 'groupOfNames') {
            members = gData['member'] || [];
            if (members.length > 0) {
                const exclusion = members.map(dn => '(!(distinguishedName=' + dn + '))').join('');
                // We keep this broad: any "person-ish" entries are candidates
                filter = '(|(objectClass=inetOrgPerson)(objectClass=person)(objectClass=posixAccount))' + exclusion;
                filter = '(&' + filter + ')';
            } else {
                filter = '(|(objectClass=inetOrgPerson)(objectClass=person)(objectClass=posixAccount))';
            }
        } else {
            listDiv.innerHTML = 'Unsupported group type';
            return;
        }

        const res = await fetch('/api/search?filter=' + encodeURIComponent(filter));
        if (!res.ok) {
            listDiv.innerHTML = 'Search failed';
            return;
        }
        let users = await res.json() || [];
        if (users.length === 0) {
            listDiv.innerHTML = 'No eligible users found.';
            return;
        }

        // Keep filter input fixed by rendering it outside the scrollable results container.
        listDiv.innerHTML = '';

        const filterWrap = document.createElement('div');
        filterWrap.style.padding = "8px";
        filterWrap.style.borderBottom = "1px solid var(--border)";

        const input = document.createElement('input');
        input.type = 'text';
        input.placeholder = 'Filter users...';
        input.style.width = '100%';
        input.style.padding = '6px';
        input.style.boxSizing = 'border-box';
        input.style.background = 'var(--bg)';
        input.style.color = 'var(--text)';
        input.style.border = '1px solid var(--border)';
        filterWrap.appendChild(input);

        // Layout note:
        // We avoid any custom scrollbar styling so native desktop scrollbars (including arrows
        // where the OS/browser provides them) remain visible and are not suppressed.
        // Make the results pane responsive to screen size and let it scroll natively.
        listDiv.style.display = 'flex';
        listDiv.style.flexDirection = 'column';
        listDiv.style.maxHeight = 'min(70vh, 520px)';

        filterWrap.style.flex = '0 0 auto';

        const resultsDiv = document.createElement('div');
        resultsDiv.style.flex = '1 1 auto';
        resultsDiv.style.minHeight = '0';
        resultsDiv.style.overflowY = 'auto';

        listDiv.appendChild(filterWrap);
        listDiv.appendChild(resultsDiv);

        const render = (needle) => {
            resultsDiv.innerHTML = '';

            const q = (needle || '').toLowerCase().trim();
            const filtered = q ? users.filter(u => u.toLowerCase().includes(q)) : users;

            if (filtered.length === 0) {
                const empty = document.createElement('div');
                empty.style.padding = "8px";
                empty.textContent = 'No matches.';
                resultsDiv.appendChild(empty);
                return;
            }

            filtered.forEach(u => {
                const div = document.createElement('div');
                div.style.padding = "8px";
                div.style.borderBottom = "1px solid var(--border)";
                div.style.cursor = "pointer";
                div.title = u;
                div.textContent = u.split(',')[0];
                div.onclick = () => addMemberToGroup(type, groupDN, u);
                resultsDiv.appendChild(div);
            });
        };

        input.oninput = () => render(input.value);
        render('');
    }

    async function addMemberToGroup(type, groupDN, userDN) {
        let attr = '';
        let val = '';

        if (type === 'posixGroup') {
            const uRes = await fetch('/api/entry?dn=' + encodeURIComponent(userDN));
            const uData = await uRes.json();
            val = (uData['uid'] && uData['uid'][0]) || '';
            attr = 'memberUid';
        } else if (type === 'groupOfNames') {
            attr = 'member';
            val = userDN;
        } else {
            return;
        }

        if (!val) return;

        const res = await fetch('/api/modify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ dn: groupDN, add: { [attr]: [val] } })
        });

        if (res.ok) {
            alert('Added successfully!');
            document.getElementById('group-select-modal').style.display='none';
        } else {
            const errText = await res.text();
            alert('Failed to add member: ' + errText);
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


    loadRoots();
  </script>
<div id="schema-modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;align-items:center;justify-content:center;padding:10px;box-sizing:border-box;">
    <div class="modal-content modal-scroll-shell" style="width:min(1400px, calc(100vw - 20px));max-width:100%;max-height:92vh;">
        <div class="modal-scroll-body">
        <div class="header" style="margin-bottom:20px;">
            <h2 style="margin:0;">Schema Manager</h2>
            <div class="header-actions">
                <button onclick="document.getElementById('schema-modal').style.display='none'" style="background:#ef4444;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Close</button>
            </div>
        </div>
        <div class="header-actions" style="margin-bottom:20px; justify-content:flex-start;">
            <button hx-get="/ui/schema/object-classes" hx-target="#schema-content" hx-swap="innerHTML" onclick="prepareSchemaTab('olcObjectClasses')" style="background:#3b82f6;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Object Classes</button>
            <button hx-get="/ui/schema/attribute-types" hx-target="#schema-content" hx-swap="innerHTML" onclick="prepareSchemaTab('olcAttributeTypes')" style="background:#3b82f6;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Attribute Types</button>
        </div>
        <div id="schema-admin-login" style="display:none;margin-bottom:20px;background:#2a2a2a;padding:15px;border-radius:4px;">
            <h3>Schema Admin Login</h3>
            <p style="color:#aaa;font-size:14px;">Your current login cannot edit the schema. Provide credentials that can.</p>
            <input type="text" id="schema-admin-dn" placeholder="Admin DN (e.g., cn=admin,cn=config)" style="width:100%;margin-bottom:10px;padding:8px;background:#1e1e1e;color:white;border:1px solid #444;" />
            <input type="password" id="schema-admin-pwd" placeholder="Password" style="width:100%;margin-bottom:10px;padding:8px;background:#1e1e1e;color:white;border:1px solid #444;" />
            <button onclick="unlockSchemaEdit()" style="background:#f59e0b;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Unlock Editing</button>
        </div>
        <div id="schema-add-form" style="display:none;margin-bottom:20px;background:#2a2a2a;padding:15px;border-radius:4px;">
            <h3>Add New Schema Item</h3>
            <input type="text" id="schema-dn" placeholder="DN (e.g., cn={1}core,cn=schema,cn=config)" style="width:100%;margin-bottom:10px;padding:8px;background:#1e1e1e;color:white;border:1px solid #444;" />
            <input type="text" id="schema-attr" placeholder="Attribute (e.g., olcObjectClasses)" style="width:100%;margin-bottom:10px;padding:8px;background:#1e1e1e;color:white;border:1px solid #444;" />
            <textarea id="schema-value" placeholder="Raw Definition Value" style="width:100%;margin-bottom:10px;padding:8px;background:#1e1e1e;color:white;border:1px solid #444;min-height:100px;"></textarea>
            <button onclick="addSchemaItem()" style="background:#10b981;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Add Item</button>
        </div>
        <div id="schema-content" style="display:grid;grid-template-columns:repeat(auto-fill, minmax(min(100%, 320px), 1fr));gap:20px;"></div>
        </div>
        <div class="modal-actions modal-footer-fixed">
            <button onclick="document.getElementById('schema-modal').style.display='none'" class="btn" style="background:#6b7280;">Close</button>
        </div>
    </div>
</div>

<script>
function showSchemaManager() {
    document.getElementById('schema-modal').style.display = 'flex';
    prepareSchemaTab('olcObjectClasses');
    if (window.htmx) {
        htmx.ajax('GET', '/ui/schema/object-classes', { target: '#schema-content', swap: 'innerHTML' });
    }
}

let tempAdminDN = '';
let tempAdminPwd = '';

function unlockSchemaEdit() {
    tempAdminDN = document.getElementById('schema-admin-dn').value;
    tempAdminPwd = document.getElementById('schema-admin-pwd').value;
    if (tempAdminDN && tempAdminPwd) {
        document.getElementById('schema-admin-login').style.display = 'none';
        document.getElementById('schema-add-form').style.display = 'block';
    }
}

function prepareSchemaTab(attr) {
    document.getElementById('schema-attr').value = attr;
}

function applySchemaEditState() {
    const root = document.getElementById('schema-fragment-root');
    const canEdit = !!(root && root.dataset.canEdit === 'true');
    if (canEdit || (tempAdminDN && tempAdminPwd)) {
        document.getElementById('schema-add-form').style.display = 'block';
        document.getElementById('schema-admin-login').style.display = 'none';
    } else {
        document.getElementById('schema-add-form').style.display = 'none';
        document.getElementById('schema-admin-login').style.display = 'block';
    }
    if (root && root.dataset.schemaAttr) {
        document.getElementById('schema-attr').value = root.dataset.schemaAttr;
    }
}

document.body.addEventListener('htmx:afterSwap', function (evt) {
    if (evt.target && evt.target.id === 'schema-content') {
        applySchemaEditState();
    }
});

async function addSchemaItem() {
    const dn = document.getElementById('schema-dn').value;
    const attr = document.getElementById('schema-attr').value;
    const val = document.getElementById('schema-value').value;

    if (!dn || !attr || !val) {
        alert("Please fill all fields");
        return;
    }

    try {
        const payload = {dn: dn, attribute: attr, values: [val]};
        if (tempAdminDN && tempAdminPwd) {
            payload.adminDn = tempAdminDN;
            payload.adminPwd = tempAdminPwd;
        }

        const res = await fetch('/api/schema_modify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            alert('Added successfully!');
            document.getElementById('schema-value').value = '';
            loadSchema(attr === 'olcObjectClasses' ? 'objectClasses' : 'attributeTypes');
        } else {
            const err = await res.text();
            alert('Failed: ' + err);
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

function showAddCredentialModal(dn) {
    document.getElementById('cred-user').value = dn || '';
    document.getElementById('cred-password').value = '';
    document.getElementById('credential-modal').style.display = 'flex';
}

async function submitAddCredential() {
    const user = document.getElementById('cred-user').value;
    const password = document.getElementById('cred-password').value;
    if (!user || !password) {
        alert('User and Password are required');
        return;
    }

    try {
        const res = await fetch('/api/user_credential', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ user, password })
        });
        if (res.ok) {
            alert('Credential saved successfully!');
            document.getElementById('credential-modal').style.display = 'none';
        } else {
            const err = await res.text();
            alert('Failed: ' + err);
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}
</script>
</body>
</html>`
