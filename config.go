package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ObjectTemplate struct {
	DefaultLocation string `yaml:"default_location" json:"default_location"`
	DNParameter     string `yaml:"dn_parameter" json:"dn_parameter"`
	PinQuickCreate  bool   `yaml:"pin_quick_create" json:"pin_quick_create"`
}

type ContextMenuAction struct {
	Name   string `yaml:"name" json:"name"`
	Action string `yaml:"action" json:"action"`
}

type UISettings struct {
	Theme       string              `yaml:"theme" json:"theme"`
	ContextMenu []ContextMenuAction `yaml:"context_menu" json:"context_menu"`
}

type SSOSettings struct {
	SAML SAMLSettings `yaml:"saml" json:"saml"`
	OIDC OIDCSettings `yaml:"oidc" json:"oidc"`
}

type SAMLSettings struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	IdPURL   string `yaml:"idp_url" json:"idp_url"`
	EntityID string `yaml:"entity_id" json:"entity_id"`
	Cert     string `yaml:"cert" json:"cert"`
}

type OIDCSettings struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	IssuerURL    string `yaml:"issuer_url" json:"issuer_url"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
}

type SessionSettings struct {
	TTLMinutes  int `yaml:"ttl_minutes" json:"ttl_minutes"`
	IdleMinutes int `yaml:"idle_minutes" json:"idle_minutes"`
}

type EmbeddedAssetSettings struct {
	// Runtime values:
	// - If set to "embedded:logo" / "embedded:icon", the server will serve the bytes from SQLite `embeded_data`.
	// - Otherwise, treat as a direct URL/path (e.g. "https://..." or "/some/prefix/assets/logo.png").
	Logo    string `yaml:"logo" json:"logo"`
	Favicon string `yaml:"favicon" json:"favicon"`

	// Source files (filesystem paths) for startup bootstrapping into SQLite:
	// If these are set, the server should load the file bytes at startup, store them into SQLite
	// (`embeded_data`), and then flip the runtime values above to "embedded:logo"/"embedded:icon".
	//
	// Relative-first source path resolution (for *_source_file):
	// - Prefer treating configured source paths as RELATIVE first:
	//   - If SourceBaseDir is set, try SourceBaseDir + "/" + source_file.
	//   - If SourceBaseDir is empty, try the source_file as-is (relative to the server working directory).
	// - If that resolved file does not exist / can't be read, fall back to treating the configured value as a literal path
	//   (i.e., use it as-is as a full/absolute path).
	//
	// In other words: relative-first (against SourceBaseDir), then fall back to the literal path.
	//
	// Examples:
	//  source_base_dir: /etc/ldaphelp/branding
	//  logo_source_file: logo.png
	//  favicon_source_file: favicon.svg
	SourceBaseDir string `yaml:"source_base_dir" json:"source_base_dir"`

	// Examples (literal paths):
	//  logo_source_file: /etc/ldaphelp/branding/logo.png
	//  favicon_source_file: /etc/ldaphelp/branding/favicon.svg
	LogoSourceFile    string `yaml:"logo_source_file" json:"logo_source_file"`
	FaviconSourceFile string `yaml:"favicon_source_file" json:"favicon_source_file"`
}

type Settings struct {
	SSO          SSOSettings               `yaml:"sso" json:"sso"`
	UI           UISettings                `yaml:"ui" json:"ui"`
	Objects      map[string]ObjectTemplate `yaml:"objects" json:"objects"`
	DefaultGroup string                    `yaml:"default_group" json:"default_group"`
	Session      SessionSettings           `yaml:"session" json:"session"`

	// New: controls whether logo/favicon are embedded (served from DB) or redirected (external URL)
	Assets EmbeddedAssetSettings `yaml:"assets" json:"assets"`
}

type Config struct {
	LDAPServer    string   `yaml:"ldap_server"`
	Base          string   `yaml:"base"`
	Attribute     string   `yaml:"attribute"`
	NtfyURI       string   `yaml:"ntfy_uri"`
	EncryptionKey string   `yaml:"encryption_key"`
	Settings      Settings `yaml:"settings"`
	Server        Server   `yaml:"server"`
}

type Server struct {
	Host   string `yaml:"host" json:"host"`
	Port   int    `yaml:"port" json:"port"`
	Joined string
}

type Credentials struct {
	BindDN       string
	BindPassword string
}

func generateEncryptionKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			emptyCfg := Config{
				LDAPServer:    "",
				Base:          "",
				Attribute:     "",
				NtfyURI:       "",
				EncryptionKey: generateEncryptionKey(),
				Settings: Settings{
					Session: SessionSettings{
						TTLMinutes:  1440,
						IdleMinutes: 60,
					},
					UI: UISettings{
						Theme: "dark",
						ContextMenu: []ContextMenuAction{
							{Name: "Action 1", Action: "alert('Action 1')"},
							{Name: "Action 2", Action: "alert('Action 2')"},
						},
					},
					Objects: map[string]ObjectTemplate{
						"inetOrgPerson": {
							DefaultLocation: "",
							DNParameter:     "uid",
							PinQuickCreate:  true,
						},
					},
					Assets: EmbeddedAssetSettings{
						Logo:    "",
						Favicon: "",
					},
				},
				Server: Server{
					Host: "localhost",
					Port: 8080,
				},
			}
			if out, marshalErr := yaml.Marshal(emptyCfg); marshalErr == nil {
				os.WriteFile(path, out, 0644)
			}
			return Config{}, fmt.Errorf("config file %q was missing and has been created with empty values. Please fill it out and restart", path)
		}
		return Config{}, fmt.Errorf("read config file %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse yaml in %q: %w", path, err)
	}
	if cfg.Settings.UI.Theme == "" {
		cfg.Settings.UI.Theme = "dark"
	}
	cfg.Server.Joined = strings.Join([]string{cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port)}, ":")
	dbSettings, errDb := LoadSettingsFromDB()
	if errDb == nil && (dbSettings.UI.Theme != "" || len(dbSettings.Objects) > 0) {
		// Merge settings with precedence:
		// - YAML wins when it explicitly sets a value (i.e., differs from the zero-value/default)
		// - DB provides values for fields not set in YAML
		//
		// This keeps user-changed settings in DB, while allowing config.yaml to override them
		// when you intentionally specify a different value in YAML.

		yamlSettings := cfg.Settings

		// Start from DB (baseline), then overlay YAML where YAML is explicitly set.
		merged := dbSettings

		// ---- UI ----
		if yamlSettings.UI.Theme != "" {
			merged.UI.Theme = yamlSettings.UI.Theme
		}
		if len(yamlSettings.UI.ContextMenu) > 0 {
			merged.UI.ContextMenu = yamlSettings.UI.ContextMenu
		}

		// ---- Objects ----
		if yamlSettings.Objects != nil && len(yamlSettings.Objects) > 0 {
			if merged.Objects == nil {
				merged.Objects = map[string]ObjectTemplate{}
			}
			for k, v := range yamlSettings.Objects {
				merged.Objects[k] = v
			}
		}

		// ---- DefaultGroup ----
		if strings.TrimSpace(yamlSettings.DefaultGroup) != "" {
			merged.DefaultGroup = yamlSettings.DefaultGroup
		}

		// ---- Session ----
		// If YAML specifies non-zero values, it wins.
		if yamlSettings.Session.TTLMinutes != 0 {
			merged.Session.TTLMinutes = yamlSettings.Session.TTLMinutes
		}
		if yamlSettings.Session.IdleMinutes != 0 {
			merged.Session.IdleMinutes = yamlSettings.Session.IdleMinutes
		}

		// ---- SSO ----
		// YAML overrides DB if enabled or if any relevant field is specified.
		if yamlSettings.SSO.SAML.Enabled ||
			strings.TrimSpace(yamlSettings.SSO.SAML.IdPURL) != "" ||
			strings.TrimSpace(yamlSettings.SSO.SAML.EntityID) != "" ||
			strings.TrimSpace(yamlSettings.SSO.SAML.Cert) != "" {
			merged.SSO.SAML = yamlSettings.SSO.SAML
		}
		if yamlSettings.SSO.OIDC.Enabled ||
			strings.TrimSpace(yamlSettings.SSO.OIDC.IssuerURL) != "" ||
			strings.TrimSpace(yamlSettings.SSO.OIDC.ClientID) != "" ||
			strings.TrimSpace(yamlSettings.SSO.OIDC.ClientSecret) != "" {
			merged.SSO.OIDC = yamlSettings.SSO.OIDC
		}

		// ---- Assets (logo/favicon) ----
		// YAML wins when it provides a non-empty path/value.
		if strings.TrimSpace(yamlSettings.Assets.Logo) != "" {
			merged.Assets.Logo = yamlSettings.Assets.Logo
		}
		if strings.TrimSpace(yamlSettings.Assets.Favicon) != "" {
			merged.Assets.Favicon = yamlSettings.Assets.Favicon
		}

		cfg.Settings = merged
	} else {
		_ = SaveSettingsToDB(cfg.Settings)
	}

	// Note:
	// Embedding configured /assets/* branding files into SQLite is performed during startup in main,
	// after initDB() has run, because the embedding step needs access to both the DB handle and the
	// embedded assets filesystem.

	if cfg.Settings.Session.TTLMinutes == 0 {
		cfg.Settings.Session.TTLMinutes = 1440
		// Initialize new asset settings if not explicitly set by DB
		if cfg.Settings.Assets.Logo == "" {
			cfg.Settings.Assets.Logo = ""
		}
		if cfg.Settings.Assets.Favicon == "" {
			cfg.Settings.Assets.Favicon = ""
		}
	}
	if cfg.Settings.Session.IdleMinutes == 0 {
		cfg.Settings.Session.IdleMinutes = 60
	}

	if len(cfg.Settings.UI.ContextMenu) == 0 {
		cfg.Settings.UI.ContextMenu = []ContextMenuAction{
			{Name: "Action 1", Action: "alert('Action 1')"},
			{Name: "Action 2", Action: "alert('Action 2')"},
		}
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var missing []string
	if strings.TrimSpace(c.LDAPServer) == "" {
		missing = append(missing, "ldap_server")
	}
	if strings.TrimSpace(c.Attribute) == "" {
		missing = append(missing, "attribute")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}
