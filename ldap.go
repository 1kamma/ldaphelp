package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func dialLDAP(serverURL string, timeout time.Duration) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return ldap.DialURL(serverURL, ldap.DialWithDialer(dialer))
}

func AuthenticateUser(cfg Config, username, password string, timeout time.Duration) (string, error) {
	if username == "" || password == "" {
		return "", fmt.Errorf("username and password are required")
	}

	conn, err := dialLDAP(cfg.LDAPServer, timeout)
	if err != nil {
		return "", fmt.Errorf("ldap dial failed: %w", err)
	}
	defer conn.Close()

	// If the username looks like a direct DN, try to bind with it first
	if strings.Contains(username, "=") {
		if err := conn.Bind(username, password); err == nil {
			return username, nil
		}
	}

	bases := []string{cfg.Base}
	if cfg.Base == "" {
		rootReq := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil)
		rootRes, err := conn.Search(rootReq)
		if err == nil && len(rootRes.Entries) > 0 {
			bases = rootRes.Entries[0].GetAttributeValues("namingContexts")
		}
		if len(bases) == 0 {
			return "", fmt.Errorf("no base dn configured and namingContexts not found")
		}
	}

	if username == "admin" || username == "Manager" {
		adminDNs := []string{
			"cn=admin,cn=config",
			"cn=config",
			"cn=Directory Manager",
			"cn=" + username + "," + cfg.Base,
		}
		for _, base := range bases {
			if base != "" {
				adminDNs = append(adminDNs, fmt.Sprintf("cn=%s,%s", username, base))
			}
		}

		for _, dn := range adminDNs {
			if err := conn.Bind(dn, password); err == nil {
				return dn, nil
			}
		}
	}

	// Anonymous bind for search
	if err := conn.UnauthenticatedBind(""); err != nil {
		// Ignore error, some servers dont require explicit unauth bind
	}

	filter := fmt.Sprintf("(%s=%s)", cfg.Attribute, ldap.EscapeFilter(username))
	var userDN string

	for _, base := range bases {
		req := ldap.NewSearchRequest(
			base,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			2,
			0,
			false,
			filter,
			[]string{"dn"},
			nil,
		)

		res, err := conn.Search(req)
		if err != nil {
			continue
		}
		if len(res.Entries) == 1 {
			if userDN != "" {
				return "", fmt.Errorf("multiple users matched across bases")
			}
			userDN = res.Entries[0].DN
		} else if len(res.Entries) > 1 {
			return "", fmt.Errorf("multiple users matched")
		}
	}

	if userDN == "" {
		return "", fmt.Errorf("user not found")
	}
	if err := conn.Bind(userDN, password); err != nil {
		return "", fmt.Errorf("invalid credentials")
	}
	
	return userDN, nil
}

type LDAPCheckResult struct {
	Connected bool
	Message   string
}

func CheckLDAPConnection(cfg Config, bindDN, bindPassword string, timeout time.Duration) LDAPCheckResult {
	conn, err := dialLDAP(cfg.LDAPServer, timeout)
	if err != nil {
		return LDAPCheckResult{Connected: false, Message: err.Error()}
	}
	defer conn.Close()

	if err := conn.Bind(bindDN, bindPassword); err != nil {
		return LDAPCheckResult{Connected: false, Message: fmt.Sprintf("bind failed: %v", err)}
	}

	return LDAPCheckResult{Connected: true, Message: "ok"}
}

func MakeSSHA(password string) (string, error) {
	salt := make([]byte, 4)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := sha1.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	b64 := base64.StdEncoding.EncodeToString(append(hash.Sum(nil), salt...))
	return "{SSHA}" + b64, nil
}
