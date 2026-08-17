package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

type fakeSubschemaConn struct {
	search func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	closed bool
}

func (f *fakeSubschemaConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.search != nil {
		return f.search(req)
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeSubschemaConn) Close() error {
	f.closed = true
	return nil
}

func TestHandleUISubschemaRendersParsedFragment(t *testing.T) {
	fake := &fakeSubschemaConn{search: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.BaseDN == "cn=subschema" {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("cn=subschema", map[string][]string{
					"objectClasses":  {"( 2.5.6.9 NAME 'groupOfNames' DESC 'Group of names' SUP top STRUCTURAL MUST ( cn $ member ) MAY ( description ) )"},
					"attributeTypes": {"( 2.5.4.3 NAME 'cn' DESC 'Common name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"},
				}),
			}}, nil
		}
		return &ldap.SearchResult{}, nil
	}}
	app := &App{ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) { return fake, nil }}
	req := httptest.NewRequest(http.MethodGet, "/ui/subschema?dn=cn=subschema", nil)
	rec := httptest.NewRecorder()
	app.handleUISubschema(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"subschema-scroll-panel", "Subschema Entry", "groupofnames", "Group of names", "Attribute Types", "Common name", "SINGLE-VALUE"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %s", want, body)
		}
	}
	if !fake.closed {
		t.Fatal("expected connection close")
	}
}
