package main

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLDAPDNWithinBase(t *testing.T) {
	tests := []struct {
		dn, base string
		want     bool
	}{
		{"ou=users,dc=example,dc=com", "dc=example,dc=com", true},
		{"OU=Users,DC=Example,DC=Com", "dc=example,dc=com", true},
		{"dc=example,dc=com", "dc=example,dc=com", false},
		{"dc=other,dc=com", "dc=example,dc=com", false},
		{"", "dc=example,dc=com", false},
	}
	for _, tt := range tests {
		got := ldapDNWithinBase(tt.dn, tt.base)
		if got != tt.want {
			t.Fatalf("ldapDNWithinBase(%q, %q) = %v, want %v", tt.dn, tt.base, got, tt.want)
		}
	}
}

func TestGetLDAPSearchBasesUsesNamingContextsAndPrunesNestedBase(t *testing.T) {
	fake := &fakeLDAPSearchConn{search: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.BaseDN != "" {
			t.Fatalf("BaseDN = %q, want Root DSE", req.BaseDN)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("", map[string][]string{"namingContexts": {"dc=example,dc=com", "dc=other,dc=com"}}),
		}}, nil
	}}

	got := getLDAPSearchBases(fake, Config{Base: "ou=users,dc=example,dc=com"}, true)
	want := []string{"dc=example,dc=com", "dc=other,dc=com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("getLDAPSearchBases() = %#v, want %#v", got, want)
	}
}

func TestGetLDAPSearchBasesFallsBackToConfiguredBase(t *testing.T) {
	fake := &fakeLDAPSearchConn{search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{}, nil
	}}

	got := getLDAPSearchBases(fake, Config{Base: "dc=example,dc=com"}, true)
	if strings.Join(got, "|") != "dc=example,dc=com" {
		t.Fatalf("getLDAPSearchBases() = %#v", got)
	}
}

func TestMakeSSHA(t *testing.T) {
	hash, err := MakeSSHA("secret")
	if err != nil {
		t.Fatalf("MakeSSHA() error = %v", err)
	}
	if !strings.HasPrefix(hash, "{SSHA}") {
		t.Fatalf("MakeSSHA() = %q", hash)
	}
	if len(hash) <= len("{SSHA}") {
		t.Fatalf("MakeSSHA() too short: %q", hash)
	}
}
