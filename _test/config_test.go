package main

import "testing"

func TestConfigValidate(t *testing.T) {
	if err := (Config{LDAPServer: "ldaps://ldap.example.com", Attribute: "uid"}).Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	err := (Config{}).Validate()
	if err == nil {
		t.Fatal("expected missing required fields")
	}
	if got := err.Error(); got != "missing required field(s): ldap_server, attribute" {
		t.Fatalf("error = %q", got)
	}
}

func TestGenerateEncryptionKey(t *testing.T) {
	key := generateEncryptionKey()
	if key == "" {
		t.Fatal("generateEncryptionKey() returned empty key")
	}
}
