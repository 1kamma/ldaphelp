package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Fatal("expected equal strings to match")
	}
	if constantTimeEqual("abc", "abd") {
		t.Fatal("expected different strings not to match")
	}
	if constantTimeEqual("abc", "abcd") {
		t.Fatal("expected different lengths not to match")
	}
}

func TestAuthorizeExternalAPI(t *testing.T) {
	app := &App{cfg: Config{ExternalAPI: ExternalAPISettings{Enabled: true, Key: "key", Secret: "secret"}}}
	req := httptest.NewRequest(http.MethodPost, "/public-api/update-fields", nil)
	req.Header.Set("X-API-Key", "key")
	req.Header.Set("X-API-Secret", "secret")
	if err := app.authorizeExternalAPI(req); err != nil {
		t.Fatalf("authorizeExternalAPI() error = %v", err)
	}

	req.Header.Set("X-API-Secret", "wrong")
	if err := app.authorizeExternalAPI(req); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid credentials error, got %v", err)
	}

	app.cfg.ExternalAPI.Enabled = false
	if err := app.authorizeExternalAPI(req); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled error, got %v", err)
	}
}

func TestAllowedExternalAttributes(t *testing.T) {
	app := &App{cfg: Config{ExternalAPI: ExternalAPISettings{AllowedAttributes: []string{" mail ", "telephoneNumber", ""}}}}
	got := app.allowedExternalAttributes()
	if got["mail"] != "mail" {
		t.Fatalf("mail mapping missing: %#v", got)
	}
	if got["telephonenumber"] != "telephoneNumber" {
		t.Fatalf("telephoneNumber mapping missing: %#v", got)
	}
	if _, ok := got[""]; ok {
		t.Fatalf("empty attribute should be ignored: %#v", got)
	}
}

func TestFilterNonEmpty(t *testing.T) {
	got := filterNonEmpty([]string{" alice ", "", "bob", "   "})
	if strings.Join(got, "|") != "alice|bob" {
		t.Fatalf("filterNonEmpty() = %#v", got)
	}
}
