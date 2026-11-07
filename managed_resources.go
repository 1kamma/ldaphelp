package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ManagedResource is shared by attached servers and backup destinations.
// Password is available only from getManagedResource, never from list or JSON.
type ManagedResource struct {
	ID                    int64  `json:"id"`
	Name                  string `json:"name"`
	Kind                  string `json:"kind"`
	URI                   string `json:"uri"`
	Username              string `json:"username"`
	Path                  string `json:"path"`
	Password              string `json:"-"`
	HasPassword           bool   `json:"has_password"`
	SchemaOnly            bool   `json:"schema_only"`
	UseSessionCredentials bool   `json:"use_session_credentials"`
}

var errManagedInvalid = errors.New("invalid managed resource")
var errManagedSessionCredentials = errors.New("current session has no reusable LDAP credentials; sign in with an LDAP password or use saved credentials for this attachment (SSO sessions may not provide a password)")

var managedResourcesMigrationMu sync.Mutex

func ensureManagedResources() error {
	managedResourcesMigrationMu.Lock()
	defer managedResourcesMigrationMu.Unlock()
	if db == nil {
		return errors.New("database unavailable")
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS managed_resources (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
 uri TEXT NOT NULL, username TEXT NOT NULL, path TEXT NOT NULL,
 encrypted_password TEXT NOT NULL DEFAULT '',
 schema_only INTEGER NOT NULL DEFAULT 0,
 use_session_credentials INTEGER NOT NULL DEFAULT 0)`)
	if err != nil {
		return err
	}
	for _, column := range []string{"schema_only", "use_session_credentials"} {
		exists, err := managedResourceColumnExists(column)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.Exec(`ALTER TABLE managed_resources ADD COLUMN ` + column + ` INTEGER NOT NULL DEFAULT 0`); err != nil {
			// Another connection may have migrated after our introspection.
			if exists, checkErr := managedResourceColumnExists(column); checkErr != nil || !exists {
				return err
			}
		}
	}
	return nil
}

func managedResourceColumnExists(column string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(managed_resources)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		found = found || name == column
	}
	return found, rows.Err()
}

func listManagedResources(owner string) ([]ManagedResource, error) {
	if err := ensureManagedResources(); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT id,name,kind,uri,username,path,encrypted_password <> '',schema_only,use_session_credentials FROM managed_resources WHERE owner=? ORDER BY id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ManagedResource, 0)
	for rows.Next() {
		var item ManagedResource
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.URI, &item.Username, &item.Path, &item.HasPassword, &item.SchemaOnly, &item.UseSessionCredentials); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// The authenticated envelope prevents ciphertext transplantation across owners
// or rows while reusing the application's AES-GCM encryption helpers.
type managedSecret struct {
	Owner    string `json:"owner"`
	ID       int64  `json:"id"`
	Password string `json:"password"`
}

func getManagedResource(owner string, id int64, key string) (ManagedResource, error) {
	var item ManagedResource
	if err := ensureManagedResources(); err != nil {
		return item, err
	}
	var encrypted string
	err := db.QueryRow(`SELECT id,name,kind,uri,username,path,encrypted_password,schema_only,use_session_credentials FROM managed_resources WHERE owner=? AND id=?`, owner, id).Scan(&item.ID, &item.Name, &item.Kind, &item.URI, &item.Username, &item.Path, &encrypted, &item.SchemaOnly, &item.UseSessionCredentials)
	if err != nil {
		return ManagedResource{}, err
	}
	item.HasPassword = encrypted != ""
	if item.HasPassword {
		clear, err := decrypt(encrypted, key)
		if err != nil {
			return ManagedResource{}, errors.New("cannot decrypt managed resource")
		}
		var secret managedSecret
		if json.Unmarshal([]byte(clear), &secret) != nil || secret.Owner != owner || secret.ID != id || secret.Password == "" {
			return ManagedResource{}, errors.New("invalid managed resource secret")
		}
		item.Password = secret.Password
	}
	return item, nil
}

func validateManagedResource(item *ManagedResource, hasPassword bool) error {
	item.Name = strings.TrimSpace(item.Name)
	item.Username = strings.TrimSpace(item.Username)
	if item.ID < 0 || item.Name == "" || len(item.Name) > 256 {
		return errManagedInvalid
	}
	if item.Kind != "ldap" && (item.SchemaOnly || item.UseSessionCredentials) {
		return errManagedInvalid
	}
	switch item.Kind {
	case "ldap", "webdav":
		u, err := url.Parse(item.URI)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.Contains(item.URI, "#") {
			return errManagedInvalid
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return errManagedInvalid
			}
		}
		if item.Kind == "ldap" {
			if (u.Scheme != "ldap" && u.Scheme != "ldaps") || (u.Path != "" && u.Path != "/") || item.Path != "" {
				return errManagedInvalid
			}
			if item.UseSessionCredentials {
				if item.Username != "" || hasPassword || item.Password != "" {
					return errManagedInvalid
				}
			} else {
				dn, err := ldap.ParseDN(item.Username)
				if err != nil || len(dn.RDNs) == 0 || !hasPassword {
					return errManagedInvalid
				}
			}
		} else {
			if u.Scheme != "https" {
				return errManagedInvalid
			}
			if !strings.HasSuffix(u.Path, "/") {
				u.Path += "/"
				u.RawPath = ""
			}
			item.URI = u.String()
			if _, err := backupDAVCollection(*item); err != nil {
				return errManagedInvalid
			}
		}
	case "local", "cifs", "nfs":
		// CIFS credentials belong to the OS mount, not to this application.
		if item.URI != "" || item.Username != "" || hasPassword || !filepath.IsAbs(item.Path) {
			return errManagedInvalid
		}
		info, err := os.Stat(item.Path)
		if err != nil || !info.IsDir() {
			return errManagedInvalid
		}
	default:
		return errManagedInvalid
	}
	return nil
}

// A nil or empty password preserves the existing password in saved mode only.
// Session mode erases the stored secret. Password and
// HasPassword on item are output-only; callers must use the password argument.
func saveManagedResource(owner string, item ManagedResource, password *string, key string) (int64, error) {
	if strings.TrimSpace(owner) == "" {
		return 0, errManagedInvalid
	}
	if err := ensureManagedResources(); err != nil {
		return 0, err
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	encrypted := ""
	if item.ID != 0 {
		if err := tx.QueryRow(`SELECT encrypted_password FROM managed_resources WHERE owner=? AND id=?`, owner, item.ID).Scan(&encrypted); err != nil {
			return 0, err
		}
	}
	newPassword := password != nil && *password != ""
	if item.UseSessionCredentials {
		if newPassword {
			return 0, errManagedInvalid
		}
		encrypted = ""
	}
	// Password and HasPassword are output-only, not alternate credential inputs.
	item.Password = ""
	item.HasPassword = false
	if err := validateManagedResource(&item, newPassword || encrypted != ""); err != nil {
		return 0, err
	}
	if item.ID == 0 {
		result, err := tx.Exec(`INSERT INTO managed_resources(owner,name,kind,uri,username,path) VALUES(?,?,?,?,?,?)`, owner, item.Name, item.Kind, item.URI, item.Username, item.Path)
		if err != nil {
			return 0, err
		}
		item.ID, err = result.LastInsertId()
		if err != nil {
			return 0, err
		}
	}
	if newPassword {
		data, err := json.Marshal(managedSecret{Owner: owner, ID: item.ID, Password: *password})
		if err != nil {
			return 0, err
		}
		encrypted, err = encrypt(string(data), key)
		if err != nil {
			return 0, errors.New("cannot encrypt managed resource")
		}
	}
	_, err = tx.Exec(`UPDATE managed_resources SET name=?,kind=?,uri=?,username=?,path=?,encrypted_password=?,schema_only=?,use_session_credentials=? WHERE owner=? AND id=?`, item.Name, item.Kind, item.URI, item.Username, item.Path, encrypted, item.SchemaOnly, item.UseSessionCredentials, owner, item.ID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return item.ID, nil
}

func deleteManagedResource(owner string, id int64) error {
	if err := ensureManagedResources(); err != nil {
		return err
	}
	result, err := db.Exec(`DELETE FROM managed_resources WHERE owner=? AND id=?`, owner, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}

// managedOwner checks the signed cookie without opening an LDAP connection.
func (a *App) managedOwner(w http.ResponseWriter, r *http.Request) (string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	session, err := store.Get(r, "ldap-session")
	if err != nil || session.IsNew {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	owner, ok := session.Values["dn"].(string)
	created, okC := session.Values["created"].(int64)
	active, okA := session.Values["last_active"].(int64)
	now := time.Now().Unix()
	ttl, idle := a.cfg.Settings.Session.TTLMinutes, a.cfg.Settings.Session.IdleMinutes
	if !ok || strings.TrimSpace(owner) == "" || !okC || !okA || created <= 0 || active < created || active > now || created > now || ttl <= 0 || idle <= 0 || now-created >= int64(ttl)*60 || now-active >= int64(idle)*60 {
		http.Error(w, "unauthorized or session expired", http.StatusUnauthorized)
		return "", false
	}
	session.Values["last_active"] = now
	if err := session.Save(r, w); err != nil {
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return "", false
	}
	return owner, true
}

func managedJSONRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site request denied", http.StatusForbidden)
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		// TLS may terminate at a reverse proxy. Keep the host check strict and
		// allow its HTTPS origin without trusting arbitrary forwarded headers.
		validScheme := u != nil && (u.Scheme == scheme || (r.TLS == nil && u.Scheme == "https"))
		if err != nil || !validScheme || !strings.EqualFold(u.Host, r.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			http.Error(w, "foreign origin denied", http.StatusForbidden)
			return false
		}
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return false
	}
	if decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return false
	}
	return true
}

func managedError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "resource not found", http.StatusNotFound)
	case errors.Is(err, errManagedInvalid):
		http.Error(w, "invalid managed resource", http.StatusBadRequest)
	default:
		http.Error(w, "managed resource operation failed", http.StatusInternalServerError)
	}
}

func managedJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (a *App) handleManagedResources(w http.ResponseWriter, r *http.Request) {
	owner, ok := a.managedOwner(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := listManagedResources(owner)
		if err != nil {
			managedError(w, err)
			return
		}
		managedJSON(w, items)
	case http.MethodPost:
		var req struct {
			ID                    int64   `json:"id"`
			Name                  string  `json:"name"`
			Kind                  string  `json:"kind"`
			URI                   string  `json:"uri"`
			Username              string  `json:"username"`
			Path                  string  `json:"path"`
			Password              *string `json:"password"`
			SchemaOnly            bool    `json:"schema_only"`
			UseSessionCredentials bool    `json:"use_session_credentials"`
		}
		if !managedJSONRequest(w, r, &req) {
			return
		}
		id, err := saveManagedResource(owner, ManagedResource{ID: req.ID, Name: req.Name, Kind: req.Kind, URI: req.URI, Username: req.Username, Path: req.Path, SchemaOnly: req.SchemaOnly, UseSessionCredentials: req.UseSessionCredentials}, req.Password, a.cfg.EncryptionKey)
		if err != nil {
			managedError(w, err)
			return
		}
		managedJSON(w, map[string]int64{"id": id})
	case http.MethodDelete:
		var req struct {
			ID int64 `json:"id"`
		}
		if !managedJSONRequest(w, r, &req) {
			return
		}
		if req.ID <= 0 {
			managedError(w, errManagedInvalid)
			return
		}
		if err := deleteManagedResource(owner, req.ID); err != nil {
			managedError(w, err)
			return
		}
		managedJSON(w, map[string]bool{"ok": true})
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// resolveManagedLDAPCredentials never falls back to service or saved credentials.
// Resolve on a copy so a reusable session password cannot reach persistence.
func resolveManagedLDAPCredentials(r *http.Request, item ManagedResource) (ManagedResource, error) {
	if !item.UseSessionCredentials {
		return item, nil
	}
	if item.Kind != "ldap" {
		return ManagedResource{}, errManagedInvalid
	}
	if _, err := store.Get(r, "ldap-session"); err != nil {
		return ManagedResource{}, errManagedSessionCredentials
	}
	dn, password, err := getSessionLDAPCredentials(r)
	if err != nil {
		return ManagedResource{}, errManagedSessionCredentials
	}
	item.Username = dn
	item.Password = password
	item.UseSessionCredentials = false
	return item, nil
}

func connectManagedLDAPForRequest(r *http.Request, item ManagedResource) (*ldap.Conn, error) {
	resolved, err := resolveManagedLDAPCredentials(r, item)
	if err != nil {
		return nil, err
	}
	return connectManagedLDAP(resolved)
}

func connectManagedLDAP(item ManagedResource) (*ldap.Conn, error) {
	if item.Kind != "ldap" || validateManagedResource(&item, item.Password != "") != nil {
		return nil, errManagedInvalid
	}
	conn, err := ldap.DialURL(item.URI, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		return nil, errors.New("attached LDAP connection failed")
	}
	conn.SetTimeout(10 * time.Second)
	if err := conn.Bind(item.Username, item.Password); err != nil {
		conn.Close()
		return nil, errors.New("attached LDAP bind failed")
	}
	return conn, nil
}

type managedSchemaChange struct {
	ID        int64    `json:"id"`
	DN        string   `json:"dn"`
	Attribute string   `json:"attribute"`
	Values    []string `json:"values"`
	Operation string   `json:"operation"`
}

func validateManagedSchemaChange(req managedSchemaChange) error {
	target, err := ldap.ParseDN(req.DN)
	base, _ := ldap.ParseDN("cn=schema,cn=config")
	if err != nil || (!base.EqualFold(target) && !base.AncestorOfFold(target)) {
		return errManagedInvalid
	}
	if req.ID <= 0 || (req.Attribute != "olcObjectClasses" && req.Attribute != "olcAttributeTypes") {
		return errManagedInvalid
	}
	switch req.Operation {
	case "add":
		if len(req.Values) == 0 {
			return errManagedInvalid
		}
	case "replace", "delete":
	default:
		return errManagedInvalid
	}
	for _, value := range req.Values {
		if strings.TrimSpace(value) == "" {
			return errManagedInvalid
		}
	}
	return nil
}

func (a *App) handleAttachedSchema(w http.ResponseWriter, r *http.Request) {
	owner, ok := a.managedOwner(w, r)
	if !ok {
		return
	}
	var req managedSchemaChange
	switch r.Method {
	case http.MethodGet:
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil || id <= 0 {
			managedError(w, errManagedInvalid)
			return
		}
		req.ID = id
	case http.MethodPost:
		if !managedJSONRequest(w, r, &req) {
			return
		}
		if err := validateManagedSchemaChange(req); err != nil {
			managedError(w, err)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	item, err := getManagedResource(owner, req.ID, a.cfg.EncryptionKey)
	if err != nil {
		managedError(w, err)
		return
	}
	if item.Kind != "ldap" {
		managedError(w, errManagedInvalid)
		return
	}
	conn, err := connectManagedLDAPForRequest(r, item)
	if err != nil {
		if errors.Is(err, errManagedSessionCredentials) {
			http.Error(w, errManagedSessionCredentials.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "attached LDAP unavailable", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	if r.Method == http.MethodPost {
		modification := ldap.NewModifyRequest(req.DN, nil)
		switch req.Operation {
		case "add":
			modification.Add(req.Attribute, req.Values)
		case "replace":
			modification.Replace(req.Attribute, req.Values)
		case "delete":
			modification.Delete(req.Attribute, req.Values)
		}
		// The attached bind identity's LDAP ACL is the authorization boundary.
		if err := conn.Modify(modification); err != nil {
			status := http.StatusBadGateway
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
				status = http.StatusForbidden
			}
			http.Error(w, "attached schema modification failed", status)
			return
		}
	}
	schema, err := loadSchemaDef(conn)
	if err != nil {
		http.Error(w, "attached schema read failed", http.StatusBadGateway)
		return
	}
	managedJSON(w, schema)
}
