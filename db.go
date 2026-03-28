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
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, bind_dn TEXT, bind_password TEXT)")
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS user_credentials (owner_dn TEXT, target_dn TEXT, encrypted_password TEXT)")
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

	_, err = db.Exec("DELETE FROM user_credentials WHERE owner_dn = ? AND target_dn = ?", ownerDN, targetDN)
	if err != nil {
		return fmt.Errorf("delete old credential: %w", err)
	}

	_, err = db.Exec("INSERT INTO user_credentials (owner_dn, target_dn, encrypted_password) VALUES (?, ?, ?)", ownerDN, targetDN, encryptedPassword)
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
