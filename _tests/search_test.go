package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestBuildLDAPSearchFilter(t *testing.T) {
	tests := []struct {
		name  string
		query map[string][]string
		want  string
	}{
		{
			name:  "raw filter wins",
			query: map[string][]string{"filter": {"(uid=alice)"}},
			want:  "(uid=alice)",
		},
		{
			name:  "empty query defaults to full ldap search",
			query: map[string][]string{},
			want:  "(objectClass=*)",
		},
		{
			name:  "object class only",
			query: map[string][]string{"objectClass": {"posixAccount"}},
			want:  "(objectClass=posixAccount)",
		},
		{
			name:  "text query escapes ldap filter metacharacters",
			query: map[string][]string{"q": {"alice*)("}, "search_attr": {"uid"}},
			want:  "(|(uid=*alice\\2a\\29\\28*))",
		},
		{
			name:  "text query with object class",
			query: map[string][]string{"q": {"alice"}, "object_class": {"inetOrgPerson"}, "search_attr": {"cn"}},
			want:  "(&(objectClass=inetOrgPerson)(|(cn=*alice*)))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildLDAPSearchFilter(tt.query)
			if err != nil {
				t.Fatalf("buildLDAPSearchFilter() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("buildLDAPSearchFilter() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildLDAPSearchFilterRejectsInvalidSearchAttributes(t *testing.T) {
	_, err := buildLDAPSearchFilter(map[string][]string{
		"q":           {"alice"},
		"search_attr": {"uid)(bad"},
	})
	if err == nil {
		t.Fatal("expected invalid search attributes to fail")
	}
}

func TestParseLDAPSearchScope(t *testing.T) {
	tests := []struct {
		raw  string
		want int
	}{
		{"", ldap.ScopeWholeSubtree},
		{"subtree", ldap.ScopeWholeSubtree},
		{"one", ldap.ScopeSingleLevel},
		{"children", ldap.ScopeSingleLevel},
		{"base", ldap.ScopeBaseObject},
	}

	for _, tt := range tests {
		got, err := parseLDAPSearchScope(tt.raw)
		if err != nil {
			t.Fatalf("parseLDAPSearchScope(%q) error = %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("parseLDAPSearchScope(%q) = %d, want %d", tt.raw, got, tt.want)
		}
	}

	if _, err := parseLDAPSearchScope("invalid"); err == nil {
		t.Fatal("expected invalid scope to fail")
	}
}

func TestParseLDAPSearchLimit(t *testing.T) {
	tests := []struct {
		raw     string
		fullRaw string
		want    int
	}{
		{"", "", 100},
		{"10", "", 10},
		{"0", "", 0},
		{"10", "true", 0},
	}

	for _, tt := range tests {
		got, err := parseLDAPSearchLimit(tt.raw, tt.fullRaw)
		if err != nil {
			t.Fatalf("parseLDAPSearchLimit(%q, %q) error = %v", tt.raw, tt.fullRaw, err)
		}
		if got != tt.want {
			t.Fatalf("parseLDAPSearchLimit(%q, %q) = %d, want %d", tt.raw, tt.fullRaw, got, tt.want)
		}
	}

	for _, raw := range []string{"-1", "abc"} {
		if _, err := parseLDAPSearchLimit(raw, ""); err == nil {
			t.Fatalf("expected limit %q to fail", raw)
		}
	}
}

func TestParseSearchAttributes(t *testing.T) {
	got := parseSearchAttributes(map[string][]string{
		"attrs": {"cn, uid,mail", "CN"},
		"attr":  {"objectClass", "mail"},
	})
	want := []string{"cn", "uid", "mail", "objectClass"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("parseSearchAttributes() = %#v, want %#v", got, want)
	}
}

func TestNormalizeSearchBases(t *testing.T) {
	got := normalizeSearchBases([]string{" dc=example,dc=com ", "", "DC=example,DC=com", "dc=other,dc=com"})
	want := []string{"dc=example,dc=com", "dc=other,dc=com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("normalizeSearchBases() = %#v, want %#v", got, want)
	}
}

func TestLDAPSearchEntryFromLDAP(t *testing.T) {
	ent := ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
		"cn":          {"Alice"},
		"objectClass": {"inetOrgPerson"},
	})

	dnOnly := ldapSearchEntryFromLDAP(ent, []string{"dn"})
	if dnOnly.DN != ent.DN || dnOnly.Attributes != nil {
		t.Fatalf("dn-only entry = %#v", dnOnly)
	}

	withAttrs := ldapSearchEntryFromLDAP(ent, []string{"cn", "objectClass"})
	if withAttrs.Attributes["cn"][0] != "Alice" {
		t.Fatalf("expected cn attribute in %#v", withAttrs)
	}
}

type fakeLDAPSearchConn struct {
	requests []*ldap.SearchRequest
	closed   bool
	search   func(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (f *fakeLDAPSearchConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.requests = append(f.requests, req)
	if f.search != nil {
		return f.search(req)
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeLDAPSearchConn) Close() error {
	f.closed = true
	return nil
}

func TestHandleApiSearchE2EStructuredAllNamingContexts(t *testing.T) {
	fake := &fakeLDAPSearchConn{}
	fake.search = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.BaseDN == "" {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=example,dc=com", "dc=other,dc=com"}}),
			}}, nil
		}
		if req.BaseDN == "dc=example,dc=com" {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{"cn": {"Alice"}, "uid": {"alice"}, "mail": {"alice@example.com"}}),
			}}, nil
		}
		if req.BaseDN == "dc=other,dc=com" {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=alice,dc=other,dc=com", map[string][]string{"cn": {"Alice Other"}, "uid": {"alice2"}}),
			}}, nil
		}
		return nil, errors.New("unexpected base")
	}

	app := &App{
		cfg: Config{Base: "ou=users,dc=example,dc=com"},
		ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) {
			return fake, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/search?format=entries&q=alice&attrs=cn,uid,mail&limit=2", nil)
	rec := httptest.NewRecorder()
	app.handleApiSearch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !fake.closed {
		t.Fatal("expected ldap connection to be closed")
	}

	var got LDAPSearchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got.Count != 2 || len(got.Results) != 2 {
		t.Fatalf("count/results = %d/%d, body = %s", got.Count, len(got.Results), rec.Body.String())
	}
	if got.Results[0].DN != "uid=alice,dc=example,dc=com" {
		t.Fatalf("first result DN = %q", got.Results[0].DN)
	}
	if len(fake.requests) != 3 {
		t.Fatalf("request count = %d, want root + 2 bases", len(fake.requests))
	}
	if fake.requests[1].Filter != "(|(cn=*alice*)(uid=*alice*)(mail=*alice*)(sn=*alice*)(givenName=*alice*)(displayName=*alice*)(description=*alice*))" {
		t.Fatalf("filter = %q", fake.requests[1].Filter)
	}
	if strings.Join(fake.requests[1].Attributes, ",") != "cn,uid,mail" {
		t.Fatalf("attrs = %#v", fake.requests[1].Attributes)
	}
}

func TestHandleApiSearchE2EDNOnlyBackwardCompatible(t *testing.T) {
	fake := &fakeLDAPSearchConn{}
	fake.search = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.BaseDN == "" {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=example,dc=com"}}),
			}}, nil
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("cn=admins,dc=example,dc=com", nil),
			ldap.NewEntry("cn=users,dc=example,dc=com", nil),
		}}, nil
	}
	app := &App{ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) {
		return fake, nil
	}}

	req := httptest.NewRequest(http.MethodGet, "/api/search?filter=(objectClass=posixGroup)", nil)
	rec := httptest.NewRecorder()
	app.handleApiSearch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got []string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if strings.Join(got, "|") != "cn=admins,dc=example,dc=com|cn=users,dc=example,dc=com" {
		t.Fatalf("got %#v", got)
	}
}

func TestHandleApiSearchE2EParameterizedBaseScopeFull(t *testing.T) {
	fake := &fakeLDAPSearchConn{}
	fake.search = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.BaseDN == "" {
			t.Fatal("root DSE should not be queried when base is provided")
		}
		if req.BaseDN != "ou=people,dc=example,dc=com" {
			t.Fatalf("BaseDN = %q", req.BaseDN)
		}
		if req.Scope != ldap.ScopeSingleLevel {
			t.Fatalf("Scope = %d, want single level", req.Scope)
		}
		if req.SizeLimit != 0 {
			t.Fatalf("SizeLimit = %d, want unlimited", req.SizeLimit)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("uid=bob,ou=people,dc=example,dc=com", map[string][]string{"uid": {"bob"}}),
		}}, nil
	}
	app := &App{ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) {
		return fake, nil
	}}

	req := httptest.NewRequest(http.MethodGet, "/api/search?format=entries&base=ou=people,dc=example,dc=com&scope=one&full=true&filter=(uid=bob)&attr=uid", nil)
	rec := httptest.NewRecorder()
	app.handleApiSearch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got LDAPSearchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got.Count != 1 || got.Results[0].Attributes["uid"][0] != "bob" {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
}
