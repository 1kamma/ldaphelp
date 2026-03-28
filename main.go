package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type App struct {
	cfg Config
}

func notify(uri, message string) {
	if uri == "" {
		return
	}
	go func() {
		req, err := http.NewRequest(http.MethodPost, uri, strings.NewReader(message))
		if err != nil {
			slog.Error("failed to create ntfy request", "error", err)
			return
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			slog.Error("failed to send ntfy push", "error", err)
			return
		}
		resp.Body.Close()
	}()
}

func main() {
	if err := initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := LoadConfig("config.yaml")
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	app := &App{cfg: cfg}

	mux := http.NewServeMux()

	mux.HandleFunc("/ldap/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)

	// Browser API routes
	mux.HandleFunc("/browse", app.handleBrowse)
	mux.HandleFunc("/api/roots", app.handleApiRoots)
	mux.HandleFunc("/api/children", app.handleApiChildren)
	mux.HandleFunc("/api/entry", app.handleApiEntry)
	mux.HandleFunc("/api/schema", app.handleApiSchema)
	mux.HandleFunc("/api/schema_manager", app.handleApiSchemaManagerList)
	mux.HandleFunc("/api/schema_modify", app.handleApiSchemaManagerModify)
	mux.HandleFunc("/api/modify", app.handleApiModify)
	mux.HandleFunc("/api/password", app.handleApiPassword)
	mux.HandleFunc("/api/search", app.handleApiSearch)
	mux.HandleFunc("/api/delete", app.handleApiDelete)
	mux.HandleFunc("/api/move", app.handleApiMove)
	mux.HandleFunc("/api/create", app.handleApiCreate)
	mux.HandleFunc("/api/next_id", app.handleApiNextID)
	mux.HandleFunc("/api/default_gid", app.handleApiDefaultGid)
	mux.HandleFunc("/api/user_credential", app.handleApiUserCredential)
	// mux.HandleFunc("/api/rebind", app.handleApiRebind)
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			app.handleApiSettingsPost(w, r)
		} else {
			app.handleApiSettingsGet(w, r)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	slog.Info("starting server on ", "Joined", cfg.Server.Joined)
	if err := http.ListenAndServe(cfg.Server.Joined, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.New("login").Parse(`
		<!doctype html>
		<html>
		<head>
		  <meta charset="utf-8">
		  <title>LDAP Login</title>
		  <style>
		    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #121212; color: #e0e0e0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
		    .login-container { background: #1e1e1e; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); width: 100%; max-width: 320px; border: 1px solid #333; }
		    h2 { margin-top: 0; margin-bottom: 24px; text-align: center; color: #fff; }
		    .form-group { margin-bottom: 16px; }
		    label { display: block; margin-bottom: 8px; font-size: 14px; color: #bbb; }
		    input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #444; border-radius: 4px; background: #2a2a2a; color: #fff; box-sizing: border-box; }
		    input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #3b82f6; }
		    button { width: 100%; padding: 12px; background: #3b82f6; color: #fff; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; margin-top: 8px; font-weight: bold; }
		    button:hover { background: #2563eb; }
		    .error { color: #ef4444; background: #7f1d1d; padding: 10px; border-radius: 4px; margin-bottom: 16px; font-size: 14px; text-align: center; border: 1px solid #991b1b; }
		  </style>
		</head>
		<body>
			<div class="login-container">
				<h2>LDAP Login</h2>
				{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
				<form method="POST" action="/login">
					<div class="form-group">
						<label>Username</label>
						<input type="text" name="username" required autofocus>
					</div>
					<div class="form-group">
						<label>Password</label>
						<input type="password" name="password" required>
					</div>
					<button type="submit">Login</button>
				</form>
				{{if or .SAMLEnabled .OIDCEnabled}}
				<hr style="border: 0; border-top: 1px solid #444; margin: 20px 0;">
				<div style="text-align: center; color: #bbb; margin-bottom: 10px;">Or log in with</div>
				{{if .SAMLEnabled}}
				<button type="button" style="background: #8b5cf6; margin-bottom: 10px;" onclick="location.href='/login/saml'">Login with SAML</button>
				{{end}}
				{{if .OIDCEnabled}}
				<button type="button" style="background: #10b981;" onclick="location.href='/login/oidc'">Login with OIDC</button>
				{{end}}
				{{end}}
			</div>
		</body>
		</html>
		`))
		tmpl.Execute(w, map[string]interface{}{"SAMLEnabled": a.cfg.Settings.SSO.SAML.Enabled, "OIDCEnabled": a.cfg.Settings.SSO.OIDC.Enabled})
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		dn, err := AuthenticateUser(a.cfg, username, password, 8*time.Second)
		if err != nil {
			slog.Warn("login failed", "username", username, "error", err)
			w.Write([]byte("Login failed: " + err.Error()))
			return
		}

		session, _ := store.Get(r, "ldap-session")
		session.Values["dn"] = dn
		session.Values["password"] = password
		session.Save(r, w)

		notify(a.cfg.NtfyURI, "User logged in: "+dn)

		http.Redirect(w, r, "/browse", http.StatusFound)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "ldap-session")
	if dn, ok := session.Values["dn"].(string); ok && dn != "" {
		notify(a.cfg.NtfyURI, "User logged out: "+dn)
	}
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *App) handleApiUserCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "ldap-session")
	ownerDN, ok := session.Values["dn"].(string)
	if !ok || ownerDN == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	targetDN := req.User
	if !strings.Contains(targetDN, "=") {
		conn, err := getLDAPConn(r, a.cfg)
		if err != nil {
			http.Error(w, "Failed to connect to LDAP", http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		searchReq := ldap.NewSearchRequest(
			"", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(|(uid=%s)(cn=%s)(sn=%s))", ldap.EscapeFilter(req.User), ldap.EscapeFilter(req.User), ldap.EscapeFilter(req.User)),
			[]string{"dn"}, nil,
		)

		var foundDN string
		searchReq.BaseDN = a.cfg.Base
		res, err := conn.Search(searchReq)
		if err == nil && len(res.Entries) > 0 {
			foundDN = res.Entries[0].DN
		}

		if foundDN == "" {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		targetDN = foundDN
	}

	// Verify password
	conn, err := dialLDAP(a.cfg.LDAPServer, 8*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to LDAP", http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	if err := conn.Bind(targetDN, req.Password); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := SaveUserCredential(ownerDN, targetDN, req.Password, a.cfg.EncryptionKey); err != nil {
		http.Error(w, "Failed to save credential", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
