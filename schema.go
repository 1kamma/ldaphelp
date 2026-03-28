package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type SchemaClass struct {
	Name string
	Sup  []string
	Must []string
	May  []string
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

func parseObjectClass(oc string) *SchemaClass {
	reName := regexp.MustCompile(`NAME\s+(?:\(\s*'([^']+)'|'([^']+)'|([a-zA-Z0-9_-]+))`)
	reSup := regexp.MustCompile(`SUP\s+([a-zA-Z0-9_-]+|\([^)]+\))`)
	reMust := regexp.MustCompile(`MUST\s+([a-zA-Z0-9_-]+|\([^)]+\))`)
	reMay := regexp.MustCompile(`MAY\s+([a-zA-Z0-9_-]+|\([^)]+\))`)

	c := &SchemaClass{}

	mName := reName.FindStringSubmatch(oc)
	if len(mName) > 3 {
		if mName[1] != "" {
			c.Name = strings.ToLower(mName[1])
		} else if mName[2] != "" {
			c.Name = strings.ToLower(mName[2])
		} else {
			c.Name = strings.ToLower(mName[3])
		}
	} else {
		// Try fallback name parse
		parts := strings.Fields(oc)
		if len(parts) > 3 && parts[2] == "NAME" {
			c.Name = strings.ToLower(strings.Trim(parts[3], "'"))
		}
	}

	mSup := reSup.FindStringSubmatch(oc)
	if len(mSup) > 1 {
		c.Sup = parseList(mSup[1])
	}

	mMust := reMust.FindStringSubmatch(oc)
	if len(mMust) > 1 {
		c.Must = parseList(mMust[1])
	}

	mMay := reMay.FindStringSubmatch(oc)
	if len(mMay) > 1 {
		c.May = parseList(mMay[1])
	}

	return c
}

func getResolvedSchema(conn *ldap.Conn, targetClasses []string) (classes []string, must []string, may []string, err error) {
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

	return finalClasses, finalMust, finalMay, nil
}

func (a *App) handleApiSchema(w http.ResponseWriter, r *http.Request) {
	oc := r.URL.Query().Get("oc")
	if oc == "" {
		http.Error(w, "missing objectClass (oc)", http.StatusBadRequest)
		return
	}
	ocs := strings.Split(oc, ",")

	conn, err := getLDAPConn(r, a.cfg)
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

type SchemaClassAttr struct {
	Raw  string   `json:"raw"`
	DN   string   `json:"dn"`
	Name string   `json:"name"`
	Sup  []string `json:"sup"`
	Must []string `json:"must"`
	May  []string `json:"may"`
}

type SchemaAttrDef struct {
	Raw    string `json:"raw"`
	DN     string `json:"dn"`
	Name   string `json:"name"`
	Syntax string `json:"syntax"`
	Desc   string `json:"desc"`
}

func parseAttributeType(at string) *SchemaAttrDef {
	reName := regexp.MustCompile(`NAME\s+(?:\(\s*'([^']+)'|'([^']+)'|([a-zA-Z0-9_-]+))`)
	reSyntax := regexp.MustCompile(`SYNTAX\s+([0-9.]+(?:\{\d+\})?)`)
	reDesc := regexp.MustCompile(`DESC\s+'([^']+)'`)

	def := &SchemaAttrDef{Raw: at}

	if m := reName.FindStringSubmatch(at); len(m) > 0 {
		if m[1] != "" {
			def.Name = m[1]
		} else if m[2] != "" {
			def.Name = m[2]
		} else {
			def.Name = m[3]
		}
	}
	if m := reSyntax.FindStringSubmatch(at); len(m) > 1 {
		def.Syntax = m[1]
	}
	if m := reDesc.FindStringSubmatch(at); len(m) > 1 {
		def.Desc = m[1]
	}

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

func (a *App) handleApiSchemaManagerList(w http.ResponseWriter, r *http.Request) {
	conn, err := getLDAPConn(r, a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer conn.Close()

	req := ldap.NewSearchRequest("cn=schema,cn=config", ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"olcObjectClasses", "olcAttributeTypes", "cn"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		http.Error(w, "Failed to read cn=schema,cn=config: "+err.Error(), http.StatusInternalServerError)
		return
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
				Raw: ocStr, DN: entry.DN, Name: c.Name, Sup: c.Sup, Must: c.Must, May: c.May,
			})
		}
		for _, atStr := range entry.GetAttributeValues("olcAttributeTypes") {
			def := parseAttributeType(atStr)
			def.DN = entry.DN
			schemaDef.AttributeTypes = append(schemaDef.AttributeTypes, *def)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schemaDef)
}

func (a *App) handleApiSchemaManagerModify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conn, err := getLDAPConn(r, a.cfg)
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
