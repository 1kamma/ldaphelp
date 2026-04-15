package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// handleUploadAsset accepts multipart/form-data uploads to store "icon" and "logo" in SQLite.
// Fields:
// - name: "icon" or "logo"
// - mode: "embedded" (store in DB and set settings to embedded:*), or "redirect" (set settings to provided redirect_url)
// - file: the uploaded file (required for embedded mode)
// - redirect_url: required for redirect mode
func (a *App) handleUploadAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require a valid session (same rules as other authenticated APIs)
	session, _ := store.Get(r, "ldap-session")
	if dn, ok := session.Values["dn"].(string); !ok || dn == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB
		http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	mode := strings.TrimSpace(r.FormValue("mode"))

	if name != "icon" && name != "logo" {
		http.Error(w, "invalid name (must be 'icon' or 'logo')", http.StatusBadRequest)
		return
	}
	if mode != "embedded" && mode != "redirect" {
		http.Error(w, "invalid mode (must be 'embedded' or 'redirect')", http.StatusBadRequest)
		return
	}

	switch mode {
	case "redirect":
		u := strings.TrimSpace(r.FormValue("redirect_url"))
		if u == "" {
			http.Error(w, "redirect_url is required for redirect mode", http.StatusBadRequest)
			return
		}
		if name == "logo" {
			a.cfg.Settings.Assets.Logo = u
		} else {
			a.cfg.Settings.Assets.Favicon = u
		}
		if err := SaveSettingsToDB(a.cfg.Settings); err != nil {
			http.Error(w, "failed to save settings: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return

	case "embedded":
		f, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file is required for embedded mode: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer f.Close()

		b, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(b) == 0 {
			http.Error(w, "empty upload", http.StatusBadRequest)
			return
		}

		if err := SaveUploadedAsset(name, b); err != nil {
			http.Error(w, "failed to save embedded asset: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Store pointer in settings
		if name == "logo" {
			a.cfg.Settings.Assets.Logo = "embedded:logo"
		} else {
			a.cfg.Settings.Assets.Favicon = "embedded:icon"
		}
		if err := SaveSettingsToDB(a.cfg.Settings); err != nil {
			http.Error(w, "failed to save settings: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}
}

func (a *App) handleEmbeddedIcon(w http.ResponseWriter, r *http.Request) {
	a.serveEmbeddedAsset(w, r, "icon", "image/png")
}

func (a *App) handleEmbeddedLogo(w http.ResponseWriter, r *http.Request) {
	a.serveEmbeddedAsset(w, r, "logo", "image/png")
}

func (a *App) serveEmbeddedAsset(w http.ResponseWriter, r *http.Request, name string, defaultContentType string) {
	// Try binary first (best), fall back to base64
	bin, err := GetEmbeddedAssetBinary(name)
	if err != nil {
		http.Error(w, "failed to read embedded asset: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if bin != nil {
		w.Header().Set("Content-Type", defaultContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bin)
		return
	}

	b64, err := GetEmbeddedAssetBase64(name)
	if err != nil {
		http.Error(w, "failed to read embedded asset: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if b64 == "" {
		http.NotFound(w, r)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		http.Error(w, "failed to decode embedded asset: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", defaultContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decoded)
}

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

func resolvePaths() (configPath, dbPath string) {
	if _, err := os.Stat("./config.yaml"); err == nil {
		configPath = "./config.yaml"
	} else if _, err := os.Stat("/etc/ldaphelp/config.yaml"); err == nil {
		configPath = "/etc/ldaphelp/config.yaml"
	} else {
		if err := os.MkdirAll("/etc/ldaphelp", 0755); err == nil || !os.IsPermission(err) {
			configPath = "/etc/ldaphelp/config.yaml"
		} else {
			configPath = "./config.yaml"
		}
	}

	if _, err := os.Stat("./ldaphelp.db"); err == nil {
		dbPath = "./ldaphelp.db"
	} else if _, err := os.Stat("/var/lib/ldaphelp/ldaphelp.db"); err == nil {
		dbPath = "/var/lib/ldaphelp/ldaphelp.db"
	} else {
		if err := os.MkdirAll("/var/lib/ldaphelp", 0755); err == nil {
			dbPath = "/var/lib/ldaphelp/ldaphelp.db"
		} else {
			dbPath = "./ldaphelp.db"
		}
	}

	return configPath, dbPath
}

func main() {
	configPath, dbPath := resolvePaths()

	if err := initDB(dbPath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := LoadConfig(configPath)
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
	mux.HandleFunc("/recover", app.handleRecover)

	mux.HandleFunc("/logout", app.handleLogout)
	mux.Handle("/assets/", http.FileServer(http.FS(embeddedFiles)))

	// Browser API routes
	mux.HandleFunc("/browse", app.handleBrowse)
	mux.HandleFunc("/api/roots", app.handleApiRoots)

	// Embedded assets (served from SQLite) + upload endpoint
	mux.HandleFunc("/api/assets/upload", app.handleUploadAsset)
	mux.HandleFunc("/assets/embedded/icon", app.handleEmbeddedIcon)
	mux.HandleFunc("/assets/embedded/logo", app.handleEmbeddedLogo)

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
		  <link rel="icon" href="{{.AssetURL.Favicon}}">
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
				<div style="text-align:center;margin-bottom:20px;"><img src="{{.AssetURL.Logo}}" alt="Logo" style="width:100px;height:100px;border-radius:50%;"></div>
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

<div style="text-align:center; margin-top: 15px;">
    <a href="#" onclick="recoverPassword()" style="color:#3b82f6; font-size:14px; text-decoration:none;">Forgot Password?</a>
</div>
<script>
function recoverPassword() {
    var u = prompt("Enter your username to request a password reset:");
    if (u) {
        fetch('/recover', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'username=' + encodeURIComponent(u)
        }).then(() => alert('Password recovery request sent.'));
    }
}
</script>

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
		// Decide what to show for favicon/logo:
		// - Source of truth is settings.embedded_assets.logo / settings.embedded_assets.favicon.
		// - If a value starts with "embedded:", serve from SQLite via our endpoints (only if data exists).
		// - Otherwise, treat it as a direct URL/path (recommended: relative paths when behind a reverse proxy prefix).
		//
		// No hardcoded packaged filenames: if the user does not configure these settings,
		// the UI will render without a logo and without a favicon.
		assetURL := struct {
			Logo    string
			Favicon string
		}{
			Logo:    "",
			Favicon: "",
		}

		resolveAsset := func(settingValue string, embeddedName string, embeddedPath string) string {
			v := strings.TrimSpace(settingValue)
			if v == "" {
				return ""
			}

			if strings.HasPrefix(v, "embedded:") {
				// Only use embedded endpoint if data exists; otherwise return empty.
				if bin, _ := GetEmbeddedAssetBinary(embeddedName); bin != nil {
					return embeddedPath
				}
				if b64, _ := GetEmbeddedAssetBase64(embeddedName); b64 != "" {
					return embeddedPath
				}
				return ""
			}

			// Redirect/path mode
			return v
		}

		assetURL.Logo = resolveAsset(
			a.cfg.Settings.Assets.Logo,
			"logo",
			"assets/embedded/logo",
		)
		assetURL.Favicon = resolveAsset(
			a.cfg.Settings.Assets.Favicon,
			"icon",
			"assets/embedded/icon",
		)

		tmpl.Execute(w, map[string]interface{}{
			"SAMLEnabled": a.cfg.Settings.SSO.SAML.Enabled,
			"OIDCEnabled": a.cfg.Settings.SSO.OIDC.Enabled,
			"AssetURL":    assetURL,
		})
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
		session.Values["created"] = time.Now().Unix()
		session.Values["last_active"] = time.Now().Unix()
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
		conn, err := getLDAPConn(w, r, a.cfg)
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

func (a *App) handleRecover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.FormValue("username")
	if username != "" {
		slog.Info("password recovery requested", "username", username)
		notify(a.cfg.NtfyURI, "Password recovery requested for user: "+username)
	}
	w.WriteHeader(http.StatusOK)
}
