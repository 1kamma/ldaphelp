package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

type fakeUIConn struct {
	requests []*ldap.SearchRequest
	closed   bool
	search   func(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (f *fakeUIConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.requests = append(f.requests, req)
	if f.search != nil {
		return f.search(req)
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeUIConn) Close() error {
	f.closed = true
	return nil
}

func TestHandleUIGroupSelectorRendersEligibleGroupOfNames(t *testing.T) {
	fake := &fakeUIConn{}
	fake.search = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.BaseDN {
		case "uid=alice,dc=example,dc=com":
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{"uid": {"alice"}}),
			}}, nil
		case "":
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=example,dc=com"}}),
			}}, nil
		case "dc=example,dc=com":
			if !strings.Contains(req.Filter, "objectClass=groupOfNames") {
				t.Fatalf("expected groupOfNames filter, got %q", req.Filter)
			}
			if !strings.Contains(req.Filter, "member=uid=alice,dc=example,dc=com") {
				t.Fatalf("expected member exclusion in filter, got %q", req.Filter)
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("cn=admins,dc=example,dc=com", map[string][]string{"cn": {"admins"}, "description": {"Admin group"}}),
			}}, nil
		default:
			return &ldap.SearchResult{}, nil
		}
	}

	app := &App{ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) {
		return fake, nil
	}}

	req := httptest.NewRequest(http.MethodGet, "/ui/groups/select?type=groupOfNames&userDN=uid=alice,dc=example,dc=com&q=adm", nil)
	rec := httptest.NewRecorder()
	app.handleUIGroupSelector(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Filter groups...", "admins", "Admin group", "data-type=\"groupOfNames\"", "data-group-dn=\"cn=admins,dc=example,dc=com\""} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %s", want, body)
		}
	}
	if !fake.closed {
		t.Fatal("expected ldap connection to be closed")
	}
}
