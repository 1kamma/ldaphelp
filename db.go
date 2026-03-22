package main

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "ldaphelp.db")
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, data TEXT)")
	return err
}

func LoadSettingsFromDB() (Settings, error) {
	var data string
	err := db.QueryRow("SELECT data FROM settings WHERE id = 1").Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return Settings{}, nil // Return empty settings if none exist yet
		}
		return Settings{}, fmt.Errorf("query settings: %w", err)
	}

	var s Settings
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return Settings{}, fmt.Errorf("unmarshal settings: %w", err)
	}
	return s, nil
}

func SaveSettingsToDB(s Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}

	_, err = db.Exec("INSERT OR REPLACE INTO settings (id, data) VALUES (1, ?)", string(b))
	if err != nil {
		return fmt.Errorf("insert/update settings: %w", err)
	}
	return nil
}
