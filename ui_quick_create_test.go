package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

type fakeQuickCreateConn struct {
	search func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	closed bool
}

func (f *fakeQuickCreateConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.search != nil {
		return f.search(req)
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeQuickCreateConn) Close() error {
	f.closed = true
	return nil
}

func TestHandleUIQuickCreateRendersFragment(t *testing.T) {
	fake := &fakeQuickCreateConn{search: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.BaseDN {
		case "":
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("", map[string][]string{"subschemaSubentry": {"cn=Subschema"}}),
			}}, nil
		case "cn=Subschema":
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("cn=Subschema", map[string][]string{
					"objectClasses": {
						"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( description ) )",
						"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP person STRUCTURAL MAY ( mail $ uid $ gidNumber ) )",
					},
				}),
			}}, nil
		default:
			return &ldap.SearchResult{}, nil
		}
	}}
	app := &App{
		cfg: Config{Settings: Settings{
			DefaultGIDNumber: "1000",
			Objects: map[string]ObjectTemplate{
				"inetOrgPerson": {DefaultLocation: "ou=users,dc=example,dc=com", DNParameter: "uid", PinQuickCreate: true},
			},
		}},
		ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) { return fake, nil },
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/quick-create?name=inetOrgPerson", nil)
	rec := httptest.NewRecorder()
	app.handleUIQuickCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"quick-create-form",
		"id=\"qc-location\"",
		"ou=users,dc=example,dc=com",
		"id=\"qc-classes\"",
		"id=\"qc-dn-param\" value=\"uid\"",
		"data-attr=\"cn\"",
		"data-attr=\"sn\"",
		"data-attr=\"gidnumber\" value=\"1000\"",
		"data-attr=\"mail\"",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %s", want, body)
		}
	}
	if !fake.closed {
		t.Fatal("expected connection close")
	}
}
