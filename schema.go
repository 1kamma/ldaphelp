package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type SchemaClass struct {
	OID     string
	Name    string
	Aliases []string
	Desc    string
	Kind    string
	Sup     []string
	Must    []string
	May     []string
}

func parseList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	parts := strings.Split(s, "$")
	var res []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "'")
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func parseNames(def string) []string {
	reNamesList := regexp.MustCompile(`NAME\s+\(([^)]+)\)`)
	reSingleName := regexp.MustCompile(`NAME\s+'([^']+)'`)
	if m := reNamesList.FindStringSubmatch(def); len(m) > 1 {
		reQuoted := regexp.MustCompile(`'([^']+)'`)
		parts := reQuoted.FindAllStringSubmatch(m[1], -1)
		var names []string
		for _, part := range parts {
			if len(part) > 1 {
				names = append(names, strings.ToLower(strings.TrimSpace(part[1])))
			}
		}
		return names
	}
	if m := reSingleName.FindStringSubmatch(def); len(m) > 1 {
		return []string{strings.ToLower(strings.TrimSpace(m[1]))}
	}
	return nil
}

func parseObjectClass(oc string) *SchemaClass {
	reOID := regexp.MustCompile(`^\(\s*([0-9.]+)`)
	reSup := regexp.MustCompile(`SUP\s+([a-zA-Z0-9_-]+|\([^)]+\))`)
	reMust := regexp.MustCompile(`MUST\s+([a-zA-Z0-9_-]+|\([^)]+\))`)
	reMay := regexp.MustCompile(`MAY\s+([a-zA-Z0-9_-]+|\([^)]+\))`)
	reDesc := regexp.MustCompile(`DESC\s+'([^']+)'`)

	c := &SchemaClass{Kind: "STRUCTURAL"}
	if m := reOID.FindStringSubmatch(oc); len(m) > 1 {
		c.OID = strings.TrimSpace(m[1])
	}
	c.Aliases = parseNames(oc)
	if len(c.Aliases) > 0 {
		c.Name = c.Aliases[0]
	}
	if m := reDesc.FindStringSubmatch(oc); len(m) > 1 {
		c.Desc = strings.TrimSpace(m[1])
	}
	if strings.Contains(oc, " AUXILIARY") {
		c.Kind = "AUXILIARY"
	} else if strings.Contains(oc, " ABSTRACT") {
		c.Kind = "ABSTRACT"
	}

	if mSup := reSup.FindStringSubmatch(oc); len(mSup) > 1 {
		c.Sup = parseList(mSup[1])
	}
	if mMust := reMust.FindStringSubmatch(oc); len(mMust) > 1 {
		c.Must = parseList(mMust[1])
	}
	if mMay := reMay.FindStringSubmatch(oc); len(mMay) > 1 {
		c.May = parseList(mMay[1])
	}

	return c
}

func getResolvedSchema(conn ldapSearcher, targetClasses []string) (classes []string, must []string, may []string, err error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"subschemaSubentry"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return nil, nil, nil, fmt.Errorf("could not find subschemaSubentry")
	}

	subschemaDN := res.Entries[0].GetAttributeValue("subschemaSubentry")
	if subschemaDN == "" {
		subschemaDN = "cn=Subschema"
	}

	reqSchema := ldap.NewSearchRequest(subschemaDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=subschema)", []string{"objectClasses"}, nil)
	resSchema, err := conn.Search(reqSchema)
	if err != nil || len(resSchema.Entries) == 0 {
		return nil, nil, nil, fmt.Errorf("could not read schema from %s", subschemaDN)
	}

	schemaClasses := make(map[string]*SchemaClass)
	for _, ocStr := range resSchema.Entries[0].GetAttributeValues("objectClasses") {
		c := parseObjectClass(ocStr)
		if c.Name != "" {
			schemaClasses[c.Name] = c
		}
	}

	visited := make(map[string]bool)
	var resolve func(name string)
	resolve = func(name string) {
		name = strings.ToLower(name)
		if visited[name] {
			return
		}
		visited[name] = true
		c, ok := schemaClasses[name]
		if !ok {
			return
		}
		must = append(must, c.Must...)
		may = append(may, c.May...)
		for _, sup := range c.Sup {
			resolve(sup)
		}
	}

	for _, tc := range targetClasses {
		resolve(tc)
	}

	// deduplicate
	uniqueMust := make(map[string]bool)
	uniqueMay := make(map[string]bool)
	var finalMust, finalMay []string

	for _, m := range must {
		m = strings.ToLower(m)
		if !uniqueMust[m] {
			uniqueMust[m] = true
			finalMust = append(finalMust, m)
		}
	}
	for _, m := range may {
		m = strings.ToLower(m)
		// Don't add to MAY if it's already in MUST
		if !uniqueMay[m] && !uniqueMust[m] {
			uniqueMay[m] = true
			finalMay = append(finalMay, m)
		}
	}

	var finalClasses []string
	for c := range visited {
		finalClasses = append(finalClasses, c)
	}

	sort.Strings(finalClasses)
	sort.Strings(finalMust)
	sort.Strings(finalMay)

	return finalClasses, finalMust, finalMay, nil
}

func (a *App) handleApiSchema(w http.ResponseWriter, r *http.Request) {
	oc := r.URL.Query().Get("oc")
	if oc == "" {
		http.Error(w, "missing objectClass (oc)", http.StatusBadRequest)
		return
	}
	ocs := strings.Split(oc, ",")

	conn, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	classes, must, may, err := getResolvedSchema(conn, ocs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{
		"classes": classes,
		"must":    must,
		"may":     may,
	})
}

type SchemaDef struct {
	CanEdit        bool              `json:"canEdit"`
	ObjectClasses  []SchemaClassAttr `json:"objectClasses"`
	AttributeTypes []SchemaAttrDef   `json:"attributeTypes"`
}

type ReplicaTarget struct {
	URL    string `json:"url"`
	Label  string `json:"label"`
	Source string `json:"source"`
	DN     string `json:"dn,omitempty"`
}

type SchemaClassAttr struct {
	Raw     string   `json:"raw"`
	DN      string   `json:"dn"`
	OID     string   `json:"oid"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
	Desc    string   `json:"desc"`
	Kind    string   `json:"kind"`
	Sup     []string `json:"sup"`
	Must    []string `json:"must"`
	May     []string `json:"may"`
}

type SchemaAttrDef struct {
	Raw         string   `json:"raw"`
	DN          string   `json:"dn"`
	OID         string   `json:"oid"`
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Syntax      string   `json:"syntax"`
	Desc        string   `json:"desc"`
	SingleValue bool     `json:"singleValue"`
}

func parseAttributeType(at string) *SchemaAttrDef {
	reOID := regexp.MustCompile(`^\(\s*([0-9.]+)`)
	reSyntax := regexp.MustCompile(`SYNTAX\s+([0-9.]+(?:\{\d+\})?)`)
	reDesc := regexp.MustCompile(`DESC\s+'([^']+)'`)

	def := &SchemaAttrDef{Raw: at}
	if m := reOID.FindStringSubmatch(at); len(m) > 1 {
		def.OID = strings.TrimSpace(m[1])
	}
	def.Aliases = parseNames(at)
	if len(def.Aliases) > 0 {
		def.Name = def.Aliases[0]
	}
	if m := reSyntax.FindStringSubmatch(at); len(m) > 1 {
		def.Syntax = m[1]
	}
	if m := reDesc.FindStringSubmatch(at); len(m) > 1 {
		def.Desc = m[1]
	}
	def.SingleValue = strings.Contains(at, " SINGLE-VALUE")

	syntaxMap := map[string]string{
		"1.3.6.1.4.1.1466.115.121.1.15": "Directory String",
		"1.3.6.1.4.1.1466.115.121.1.27": "Integer",
		"1.3.6.1.4.1.1466.115.121.1.7":  "Boolean",
		"1.3.6.1.4.1.1466.115.121.1.26": "IA5 String",
		"1.3.6.1.4.1.1466.115.121.1.38": "OID",
		"1.3.6.1.4.1.1466.115.121.1.40": "Octet String",
		"1.3.6.1.4.1.1466.115.121.1.50": "Telephone Number",
		"1.3.6.1.4.1.1466.115.121.1.24": "Generalized Time",
	}

	if readable, ok := syntaxMap[def.Syntax]; ok {
		def.Syntax = fmt.Sprintf("%s (%s)", readable, def.Syntax)
	}

	return def
}

func normalizeLDAPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "'\"")
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimSuffix(strings.ToLower(raw), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func replicaLabelFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

func parseReplicaURLsFromServerID(value string) []string {
	var urls []string
	for _, part := range strings.Fields(strings.TrimSpace(value)) {
		normalized := normalizeLDAPURL(part)
		if strings.HasPrefix(normalized, "ldap://") || strings.HasPrefix(normalized, "ldaps://") {
			urls = append(urls, normalized)
		}
	}
	return urls
}

func parseReplicaURLsFromSyncrepl(value string) []string {
	re := regexp.MustCompile(`(?i)\bprovider=([^\s]+)`)
	matches := re.FindAllStringSubmatch(value, -1)
	var urls []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		normalized := normalizeLDAPURL(m[1])
		if strings.HasPrefix(normalized, "ldap://") || strings.HasPrefix(normalized, "ldaps://") {
			urls = append(urls, normalized)
		}
	}
	return urls
}

func detectReplicaTargets(conn ldapSearcher, cfg Config) ([]ReplicaTarget, error) {
	res, err := conn.Search(ldap.NewSearchRequest("cn=config", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"olcServerID", "olcSyncRepl", "olcSyncrepl", "cn"}, nil))
	if err != nil {
		return nil, fmt.Errorf("failed to inspect cn=config for replication peers: %w", err)
	}

	current := normalizeLDAPURL(cfg.LDAPServer)
	seen := make(map[string]ReplicaTarget)
	addTarget := func(rawURL, source, dn string) {
		normalized := normalizeLDAPURL(rawURL)
		if normalized == "" || normalized == current {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = ReplicaTarget{URL: normalized, Label: replicaLabelFromURL(normalized), Source: source, DN: dn}
	}

	for _, entry := range res.Entries {
		for _, value := range entry.GetAttributeValues("olcServerID") {
			for _, target := range parseReplicaURLsFromServerID(value) {
				addTarget(target, "olcServerID", entry.DN)
			}
		}
		for _, attr := range []string{"olcSyncRepl", "olcSyncrepl"} {
			for _, value := range entry.GetAttributeValues(attr) {
				for _, target := range parseReplicaURLsFromSyncrepl(value) {
					addTarget(target, attr, entry.DN)
				}
			}
		}
	}

	var targets []ReplicaTarget
	for _, target := range seen {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Label == targets[j].Label {
			return targets[i].URL < targets[j].URL
		}
		return targets[i].Label < targets[j].Label
	})
	return targets, nil
}

func getSessionLDAPCredentials(r *http.Request) (string, string, error) {
	session, _ := store.Get(r, "ldap-session")
	dn, _ := session.Values["dn"].(string)
	pwd, _ := session.Values["password"].(string)
	if strings.TrimSpace(dn) == "" || pwd == "" {
		return "", "", fmt.Errorf("session has no reusable ldap credentials")
	}
	return dn, pwd, nil
}

func connectReplicaTarget(r *http.Request, targetURL, bindDN, bindPwd string) (*ldap.Conn, error) {
	targetURL = normalizeLDAPURL(targetURL)
	if targetURL == "" {
		return nil, fmt.Errorf("missing replica url")
	}
	if strings.TrimSpace(bindDN) == "" || bindPwd == "" {
		sessionDN, sessionPwd, err := getSessionLDAPCredentials(r)
		if err != nil {
			return nil, fmt.Errorf("missing bind credentials for replica and current session cannot be reused")
		}
		bindDN = sessionDN
		bindPwd = sessionPwd
	}
	conn, err := dialLDAP(targetURL, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}
	if err := conn.Bind(bindDN, bindPwd); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}
	return conn, nil
}

func loadSchemaDef(conn ldapSearcher) (SchemaDef, error) {
	req := ldap.NewSearchRequest("cn=schema,cn=config", ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"olcObjectClasses", "olcAttributeTypes", "cn"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return SchemaDef{}, fmt.Errorf("Failed to read cn=schema,cn=config: %w", err)
	}

	var schemaDef SchemaDef

	reqCheck := ldap.NewSearchRequest("cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil)
	if _, err := conn.Search(reqCheck); err == nil {
		schemaDef.CanEdit = true
	}

	for _, entry := range res.Entries {
		for _, ocStr := range entry.GetAttributeValues("olcObjectClasses") {
			c := parseObjectClass(ocStr)
			schemaDef.ObjectClasses = append(schemaDef.ObjectClasses, SchemaClassAttr{
				Raw: ocStr, DN: entry.DN, OID: c.OID, Name: c.Name, Aliases: c.Aliases, Desc: c.Desc, Kind: c.Kind, Sup: c.Sup, Must: c.Must, May: c.May,
			})
		}
		for _, atStr := range entry.GetAttributeValues("olcAttributeTypes") {
			def := parseAttributeType(atStr)
			def.DN = entry.DN
			schemaDef.AttributeTypes = append(schemaDef.AttributeTypes, *def)
		}
	}

	sort.Slice(schemaDef.ObjectClasses, func(i, j int) bool {
		return schemaDef.ObjectClasses[i].Name < schemaDef.ObjectClasses[j].Name
	})
	sort.Slice(schemaDef.AttributeTypes, func(i, j int) bool {
		return schemaDef.AttributeTypes[i].Name < schemaDef.AttributeTypes[j].Name
	})
	return schemaDef, nil
}

func (a *App) handleApiSchemaManagerList(w http.ResponseWriter, r *http.Request) {
	conn, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	schemaDef, err := loadSchemaDef(conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schemaDef)
}

func (a *App) handleApiSchemaReplicasList(w http.ResponseWriter, r *http.Request) {
	conn, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	targets, err := detectReplicaTargets(conn, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(targets)
}

func (a *App) handleApiReplicaSchemaManagerList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		URL     string `json:"url"`
		BindDN  string `json:"bindDn"`
		BindPwd string `json:"bindPwd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	conn, err := connectReplicaTarget(r, req.URL, req.BindDN, req.BindPwd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	schemaDef, err := loadSchemaDef(conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schemaDef)
}

func (a *App) handleApiReplicaSchemaManagerModify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL       string   `json:"url"`
		BindDN    string   `json:"bindDn"`
		BindPwd   string   `json:"bindPwd"`
		DN        string   `json:"dn"`
		Attribute string   `json:"attribute"`
		Values    []string `json:"values"`
		AdminDN   string   `json:"adminDn"`
		AdminPwd  string   `json:"adminPwd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	connectDN := req.BindDN
	connectPwd := req.BindPwd
	if strings.TrimSpace(req.AdminDN) != "" && req.AdminPwd != "" {
		connectDN = req.AdminDN
		connectPwd = req.AdminPwd
	}
	conn, err := connectReplicaTarget(r, req.URL, connectDN, connectPwd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	modifyReq := ldap.NewModifyRequest(req.DN, nil)
	modifyReq.Add(req.Attribute, req.Values)
	if err := conn.Modify(modifyReq); err != nil {
		http.Error(w, "Failed to modify replica schema: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (a *App) handleApiSchemaManagerModify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conn, err := getLDAPConn(w, r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	var req struct {
		DN        string   `json:"dn"`
		Attribute string   `json:"attribute"`
		Values    []string `json:"values"`
		AdminDN   string   `json:"adminDn"`
		AdminPwd  string   `json:"adminPwd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var editConn *ldap.Conn
	if req.AdminDN != "" && req.AdminPwd != "" {
		editConn, err = dialLDAP(a.cfg.LDAPServer, 5*time.Second)
		if err != nil {
			http.Error(w, "Failed to connect with admin credentials: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer editConn.Close()
		if err := editConn.Bind(req.AdminDN, req.AdminPwd); err != nil {
			http.Error(w, "Admin bind failed: "+err.Error(), http.StatusUnauthorized)
			return
		}
	} else {
		editConn = conn
	}

	modifyReq := ldap.NewModifyRequest(req.DN, nil)
	modifyReq.Add(req.Attribute, req.Values)

	if err := editConn.Modify(modifyReq); err != nil {
		http.Error(w, "Failed to modify schema: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
