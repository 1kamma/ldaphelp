package main

import (
	"path/filepath"
	"testing"
)

func initTestDB(t *testing.T) {
	t.Helper()
	if db != nil {
		_ = db.Close()
	}
	if err := initDB(filepath.Join(t.TempDir(), "ldaphelp-test.db")); err != nil {
		t.Fatalf("initDB() error = %v", err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
			db = nil
		}
	})
}

func TestEncryptDecrypt(t *testing.T) {
	key := generateEncryptionKey()
	encrypted, err := encrypt("secret", key)
	if err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}
	if encrypted == "secret" {
		t.Fatal("encrypted text should not equal plaintext")
	}
	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt() error = %v", err)
	}
	if decrypted != "secret" {
		t.Fatalf("decrypt() = %q", decrypted)
	}
}

func TestSettingsPersistence(t *testing.T) {
	initTestDB(t)

	want := Settings{
		UI: UISettings{Theme: "light"},
		Objects: map[string]ObjectTemplate{
			"inetOrgPerson": {DefaultLocation: "ou=users,dc=example,dc=com", DNParameter: "uid", PinQuickCreate: true},
		},
	}
	if err := SaveSettingsToDB(want); err != nil {
		t.Fatalf("SaveSettingsToDB() error = %v", err)
	}
	got, err := LoadSettingsFromDB()
	if err != nil {
		t.Fatalf("LoadSettingsFromDB() error = %v", err)
	}
	if got.UI.Theme != "light" || !got.Objects["inetOrgPerson"].PinQuickCreate {
		t.Fatalf("LoadSettingsFromDB() = %#v", got)
	}
}

func TestCredentialsPersistence(t *testing.T) {
	initTestDB(t)
	key := generateEncryptionKey()

	want := Credentials{BindDN: "cn=admin,dc=example,dc=com", BindPassword: "secret"}
	if err := SaveCredentialsToDB(want, key); err != nil {
		t.Fatalf("SaveCredentialsToDB() error = %v", err)
	}
	got, err := LoadCredentialsFromDB(key)
	if err != nil {
		t.Fatalf("LoadCredentialsFromDB() error = %v", err)
	}
	if got != want {
		t.Fatalf("LoadCredentialsFromDB() = %#v, want %#v", got, want)
	}
}

func TestUserCredentialsPersistence(t *testing.T) {
	initTestDB(t)
	key := generateEncryptionKey()

	if err := SaveUserCredential("owner", "target", "secret", key); err != nil {
		t.Fatalf("SaveUserCredential() error = %v", err)
	}
	got, err := GetUserCredentials("owner", key)
	if err != nil {
		t.Fatalf("GetUserCredentials() error = %v", err)
	}
	if got["target"] != "secret" {
		t.Fatalf("GetUserCredentials() = %#v", got)
	}
}

func TestEmbeddedAssetPersistence(t *testing.T) {
	initTestDB(t)

	if err := SaveUploadedAsset("logo", []byte("bytes")); err != nil {
		t.Fatalf("SaveUploadedAsset() error = %v", err)
	}
	b64, err := GetEmbeddedAssetBase64("logo")
	if err != nil {
		t.Fatalf("GetEmbeddedAssetBase64() error = %v", err)
	}
	if b64 == "" {
		t.Fatal("expected base64 asset")
	}
	bin, err := GetEmbeddedAssetBinary("logo")
	if err != nil {
		t.Fatalf("GetEmbeddedAssetBinary() error = %v", err)
	}
	if string(bin) != "bytes" {
		t.Fatalf("GetEmbeddedAssetBinary() = %q", string(bin))
	}
}
