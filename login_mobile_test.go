package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginMobileTemplate(t *testing.T) {
	app := &App{}
	rec := httptest.NewRecorder()
	app.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<html lang="en">`,
		`name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content"`,
		`min-height: 100dvh`,
		`env(safe-area-inset-bottom)`,
		`max-width: 440px`,
		`font-size: 16px`,
		`min-height: 48px`,
		`button:focus-visible`,
		`<main class="login-container" aria-labelledby="login-title">`,
		`<form method="POST" action="/login">`,
		`<label for="username">Username</label>`,
		`id="username" type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required`,
		`<label for="password">Password</label>`,
		`id="password" type="password" name="password" autocomplete="current-password" required`,
		`type="button" aria-controls="password" aria-label="Show password" hidden`,
		`passwordToggle.hidden = false`,
		`passwordInput.type = show ? 'text' : 'password'`,
		`passwordToggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password')`,
		`fetch('/recover'`,
		`body: 'username=' + encodeURIComponent(u)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}
	for _, unwanted := range []string{`autofocus`, `; height: 100vh;`, `src=""`, `href=""`, `class="sso-heading"`} {
		if strings.Contains(body, unwanted) {

			t.Errorf("login page contains %q", unwanted)
		}
	}
}

func TestLoginSSOAndAssets(t *testing.T) {
	for _, tc := range []struct {
		name string
		saml bool
		oidc bool
	}{
		{name: "password only"},
		{name: "SAML", saml: true},
		{name: "OIDC", oidc: true},
		{name: "both", saml: true, oidc: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &App{}
			app.cfg.Settings.SSO.SAML.Enabled = tc.saml
			app.cfg.Settings.SSO.OIDC.Enabled = tc.oidc
			app.cfg.Settings.Assets.Logo = "/custom-logo.png"
			app.cfg.Settings.Assets.Favicon = "/custom-icon.png"
			rec := httptest.NewRecorder()
			app.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			body := rec.Body.String()
			for marker, want := range map[string]bool{
				`href="/login/saml"`:      tc.saml,
				`href="/login/oidc"`:      tc.oidc,
				`class="sso-heading"`:     tc.saml || tc.oidc,
				`src="/custom-logo.png"`:  true,
				`href="/custom-icon.png"`: true,
				`action="/login"`:         true,
			} {
				if got := strings.Contains(body, marker); got != want {
					t.Errorf("presence of %q = %v, want %v", marker, got, want)
				}
			}
		})
	}
}
