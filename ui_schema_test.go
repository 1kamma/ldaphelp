package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

type fakeSchemaUIConn struct {
	search func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	closed bool
}

func (f *fakeSchemaUIConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.search != nil {
		return f.search(req)
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeSchemaUIConn) Close() error {
	f.closed = true
	return nil
}

func TestHandleUISchemaObjectClassesRendersFragment(t *testing.T) {
	fake := &fakeSchemaUIConn{search: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.BaseDN {
		case "cn=schema,cn=config":
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("cn={0}core,cn=schema,cn=config", map[string][]string{"olcObjectClasses": {"( 2.5.6.9 NAME 'groupOfNames' DESC 'Group of names' SUP top STRUCTURAL MUST ( cn $ member ) MAY ( description ) )"}}),
			}}, nil
		case "cn=config":
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=config", map[string][]string{"dn": {"cn=config"}})}}, nil
		default:
			return &ldap.SearchResult{}, nil
		}
	}}
	app := &App{ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) { return fake, nil }}
	req := httptest.NewRequest(http.MethodGet, "/ui/schema/object-classes", nil)
	rec := httptest.NewRecorder()
	app.handleUISchemaObjectClasses(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"schema-fragment-root", "data-schema-attr=\"olcObjectClasses\"", "groupofnames", "Group of names", "OID 2.5.6.9"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %s", want, body)
		}
	}
	if !fake.closed {
		t.Fatal("expected connection close")
	}
}

func TestHandleUISchemaAttributeTypesRendersFragment(t *testing.T) {
	fake := &fakeSchemaUIConn{search: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.BaseDN {
		case "cn=schema,cn=config":
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("cn={0}core,cn=schema,cn=config", map[string][]string{"olcAttributeTypes": {"( 2.5.4.3 NAME 'cn' DESC 'Common name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"}}),
			}}, nil
		case "cn=config":
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=config", map[string][]string{"dn": {"cn=config"}})}}, nil
		default:
			return &ldap.SearchResult{}, nil
		}
	}}
	app := &App{ldapSearchFn: func(http.ResponseWriter, *http.Request, Config) (ldapSearchConn, error) { return fake, nil }}
	req := httptest.NewRequest(http.MethodGet, "/ui/schema/attribute-types", nil)
	rec := httptest.NewRecorder()
	app.handleUISchemaAttributeTypes(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"schema-fragment-root", "data-schema-attr=\"olcAttributeTypes\"", ">cn<", "Common name", "SINGLE-VALUE"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q, got %s", want, body)
		}
	}
	if !fake.closed {
		t.Fatal("expected connection close")
	}
}
