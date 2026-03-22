package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
