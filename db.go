package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	_ "modernc.org/sqlite"
	"strings"
)

var db *sql.DB

func initDB(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	// Core operational tables
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, data TEXT)")
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, bind_dn TEXT, bind_password TEXT)")
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS user_credentials (owner_dn TEXT, target_dn TEXT, encrypted_password TEXT)")
	if err != nil {
		return err
	}
	// New table for embedded assets
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS embeded_data (item_name TEXT PRIMARY KEY, item_based TEXT, item_binary BLOB)")
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

func encrypt(plaintext string, base64Key string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(cryptoText string, base64Key string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func LoadCredentialsFromDB(encryptionKey string) (Credentials, error) {
	var bindDN, encryptedPassword string
	err := db.QueryRow("SELECT bind_dn, bind_password FROM credentials WHERE id = 1").Scan(&bindDN, &encryptedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return Credentials{}, nil
		}
		return Credentials{}, fmt.Errorf("query credentials: %w", err)
	}

	bindPassword, err := decrypt(encryptedPassword, encryptionKey)
	if err != nil {
		return Credentials{}, fmt.Errorf("decrypt password: %w", err)
	}

	return Credentials{
		BindDN:       bindDN,
		BindPassword: bindPassword,
	}, nil
}

func SaveCredentialsToDB(creds Credentials, encryptionKey string) error {
	encryptedPassword, err := encrypt(creds.BindPassword, encryptionKey)
	if err != nil {
		return fmt.Errorf("encrypt password: %w", err)
	}

	_, err = db.Exec("INSERT OR REPLACE INTO credentials (id, bind_dn, bind_password) VALUES (1, ?, ?)", creds.BindDN, encryptedPassword)
	if err != nil {
		return fmt.Errorf("insert/update credentials: %w", err)
	}
	return nil
}

func SaveUserCredential(ownerDN, targetDN, clearPassword, encryptionKey string) error {
	encryptedPassword, err := encrypt(clearPassword, encryptionKey)
	if err != nil {
		return fmt.Errorf("encrypt password: %w", err)
	}

	_, err = db.Exec(
		"INSERT OR REPLACE INTO user_credentials (owner_dn, target_dn, encrypted_password) VALUES (?, ?, ?)",
		ownerDN, targetDN, encryptedPassword,
	)
	if err != nil {
		return fmt.Errorf("insert user credential: %w", err)
	}
	return nil
}

func GetUserCredentials(ownerDN, encryptionKey string) (map[string]string, error) {
	rows, err := db.Query("SELECT target_dn, encrypted_password FROM user_credentials WHERE owner_dn = ?", ownerDN)
	if err != nil {
		return nil, fmt.Errorf("query user credentials: %w", err)
	}
	defer rows.Close()

	creds := make(map[string]string)
	for rows.Next() {
		var targetDN, encryptedPassword string
		if err := rows.Scan(&targetDN, &encryptedPassword); err != nil {
			return nil, fmt.Errorf("scan user credential: %w", err)
		}

		clearPassword, err := decrypt(encryptedPassword, encryptionKey)
		if err != nil {
			continue // skip entries we can't decrypt
		}
		creds[targetDN] = clearPassword
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return creds, nil
}

// SaveUploadedAsset saves the file content to the embeded_data table.
// - assetName should be a stable key like "icon" or "logo" (your current convention).
// - item_based stores base64 data (so templates/handlers can serve it as a data URL if desired).
// - item_binary stores the raw bytes.
func SaveUploadedAsset(assetName string, fileData []byte) error {
	assetName = strings.TrimSpace(assetName)
	if assetName == "" {
		return fmt.Errorf("asset name is required")
	}

	base64Data := base64.StdEncoding.EncodeToString(fileData)

	_, err := db.Exec(
		"INSERT OR REPLACE INTO embeded_data (item_name, item_based, item_binary) VALUES (?, ?, ?)",
		assetName, base64Data, fileData,
	)
	if err != nil {
		return fmt.Errorf("save asset %q: %w", assetName, err)
	}

	return nil
}

// GetEmbeddedAssetBase64 returns the base64 form for an embedded asset by name (e.g. "icon", "logo").
// Returns ("", nil) if not found.
func GetEmbeddedAssetBase64(assetName string) (string, error) {
	assetName = strings.TrimSpace(assetName)
	if assetName == "" {
		return "", fmt.Errorf("asset name is required")
	}

	var itemBase64 string
	err := db.QueryRow(
		"SELECT item_based FROM embeded_data WHERE item_name = ?",
		assetName,
	).Scan(&itemBase64)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("query embeded_data for %q: %w", assetName, err)
	}
	return itemBase64, nil
}

// GetEmbeddedAssetBinary returns the raw bytes for an embedded asset by name.
// Returns (nil, nil) if not found.
func GetEmbeddedAssetBinary(assetName string) ([]byte, error) {
	assetName = strings.TrimSpace(assetName)
	if assetName == "" {
		return nil, fmt.Errorf("asset name is required")
	}

	var b []byte
	err := db.QueryRow(
		"SELECT item_binary FROM embeded_data WHERE item_name = ?",
		assetName,
	).Scan(&b)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query embeded_data binary for %q: %w", assetName, err)
	}
	return b, nil
}
