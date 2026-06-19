package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type publicAPIUpdateFieldsRequest struct {
	DN     string              `json:"dn"`
	Fields map[string][]string `json:"fields"`
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (a *App) authorizeExternalAPI(r *http.Request) error {
	cfg := a.cfg.ExternalAPI
	if !cfg.Enabled {
		return fmt.Errorf("external api is disabled")
	}
	if strings.TrimSpace(cfg.Key) == "" || strings.TrimSpace(cfg.Secret) == "" {
		return fmt.Errorf("external api credentials are not configured")
	}

	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	secret := strings.TrimSpace(r.Header.Get("X-API-Secret"))
	if !constantTimeEqual(key, cfg.Key) || !constantTimeEqual(secret, cfg.Secret) {
		return fmt.Errorf("invalid api credentials")
	}
	return nil
}

func (a *App) getExternalLDAPConn() (*ldap.Conn, error) {
	bindDN := strings.TrimSpace(a.cfg.ExternalAPI.BindDN)
	bindPassword := a.cfg.ExternalAPI.BindPassword

	if bindDN == "" || bindPassword == "" {
		storedCreds, err := LoadCredentialsFromDB(a.cfg.EncryptionKey)
		if err == nil && strings.TrimSpace(storedCreds.BindDN) != "" && storedCreds.BindPassword != "" {
			bindDN = strings.TrimSpace(storedCreds.BindDN)
			bindPassword = storedCreds.BindPassword
		}
	}

	if bindDN == "" || bindPassword == "" {
		return nil, fmt.Errorf("no ldap bind credentials configured for external api")
	}

	conn, err := dialLDAP(a.cfg.LDAPServer, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}
	if err := conn.Bind(bindDN, bindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}
	return conn, nil
}

func (a *App) allowedExternalAttributes() map[string]string {
	allowed := make(map[string]string, len(a.cfg.ExternalAPI.AllowedAttributes))
	for _, attr := range a.cfg.ExternalAPI.AllowedAttributes {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		allowed[strings.ToLower(attr)] = attr
	}
	return allowed
}

func filterNonEmpty(values []string) []string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *App) handlePublicAPIUpdateFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := a.authorizeExternalAPI(r); err != nil {
		status := http.StatusUnauthorized
		if err.Error() == "external api is disabled" {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	allowed := a.allowedExternalAttributes()
	if len(allowed) == 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no allowed_attributes configured for external api"})
		return
	}

	var req publicAPIUpdateFieldsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	req.DN = strings.TrimSpace(req.DN)
	if req.DN == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dn is required"})
		return
	}
	if len(req.Fields) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "fields is required"})
		return
	}

	conn, err := a.getExternalLDAPConn()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(req.DN, nil)
	updated := make([]string, 0, len(req.Fields))

	for attr, values := range req.Fields {
		normalized := strings.ToLower(strings.TrimSpace(attr))
		canonicalAttr, ok := allowed[normalized]
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": fmt.Sprintf("attribute %q is not allowed", attr)})
			return
		}

		filtered := filterNonEmpty(values)
		if len(filtered) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("attribute %q requires at least one non-empty value", attr)})
			return
		}

		modReq.Replace(canonicalAttr, filtered)
		updated = append(updated, canonicalAttr)
	}

	if len(updated) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid fields provided"})
		return
	}

	if err := conn.Modify(modReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	notify(a.cfg.NtfyURI, fmt.Sprintf("External API modified LDAP object %s fields: %s", req.DN, strings.Join(updated, ", ")))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"dn":      req.DN,
		"updated": updated,
	})
}
