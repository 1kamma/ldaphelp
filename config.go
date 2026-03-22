package main

import (
	"errors"
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

type Settings struct {
	UI      UISettings                `yaml:"ui" json:"ui"`
	Objects map[string]ObjectTemplate `yaml:"objects" json:"objects"`
}

type Config struct {
	LDAPServer string   `yaml:"ldap_server"`
	Base       string   `yaml:"base"`
	Attribute  string   `yaml:"attribute"`
	NtfyURI    string   `yaml:"ntfy_uri"`
	Settings   Settings `yaml:"settings"`
	Server     Server   `yaml:"server"`
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

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			emptyCfg := Config{
				LDAPServer: "",
				Base:       "",
				Attribute:  "",
				NtfyURI:    "",
				Settings: Settings{
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
		cfg.Settings = dbSettings
	} else {
		_ = SaveSettingsToDB(cfg.Settings)
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

func LoadCredentialsFromEnv() (Credentials, error) {
	creds := Credentials{
		BindDN:       strings.TrimSpace(os.Getenv("LDAP_BIND_DN")),
		BindPassword: os.Getenv("LDAP_BIND_PASSWORD"),
	}
	if creds.BindDN == "" || creds.BindPassword == "" {
		return Credentials{}, errors.New("missing LDAP_BIND_DN or LDAP_BIND_PASSWORD in environment")
	}
	return creds, nil
}
