package main

import (
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
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
	mux.HandleFunc("/api/modify", app.handleApiModify)
	mux.HandleFunc("/api/password", app.handleApiPassword)
	mux.HandleFunc("/api/search", app.handleApiSearch)
	mux.HandleFunc("/api/delete", app.handleApiDelete)
	mux.HandleFunc("/api/move", app.handleApiMove)
	mux.HandleFunc("/api/create", app.handleApiCreate)
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

	slog.Info("starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
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
			</div>
		</body>
		</html>
		`))
		tmpl.Execute(w, nil)
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
