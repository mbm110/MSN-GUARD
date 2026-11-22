package settings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigratedIdentityPreservesInt64AcrossRestart(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	dir := t.TempDir()
	data := []byte(`{"legacy_migration_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_id":9007199254740993,"user_data":{"legacyID":9007199254740993,"legacyUserData":{"userId":9007199254740993}}}`)
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := InitSettings(dir); err != nil {
			t.Fatal(err)
		}
		if GetInt64(UserIDKey) != 9007199254740993 {
			t.Fatal("rounded adopted user ID")
		}
		var user struct{ LegacyID int64 }
		if err := GetStruct(UserDataKey, &user); err != nil || user.LegacyID != 9007199254740993 {
			t.Fatalf("rounded cached user ID: %+v %v", user, err)
		}
		if err := Set(LocaleKey, "fa-IR"); err != nil {
			t.Fatal(err)
		}
		Reset()
	}
}

func TestSettingsPreserveNumbersAcrossReload(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	data := []byte(`{"user_id":9007199254740993,"user_data":{"legacyID":9007199254740993,"ratio":0.25},"fraction":1.5}`)
	require.NoError(t, os.WriteFile(path, data, 0600))
	require.NoError(t, InitSettings(dir))
	for range 2 {
		assert.Equal(t, int64(9007199254740993), GetInt64(UserIDKey))
		assert.Equal(t, "9007199254740993", GetString(UserIDKey))
		assert.Equal(t, 1.5, GetFloat64("fraction"))
		var user struct {
			LegacyID int64
			Ratio    float64
		}
		require.NoError(t, GetStruct(UserDataKey, &user))
		assert.Equal(t, int64(9007199254740993), user.LegacyID)
		assert.Equal(t, 0.25, user.Ratio)
		require.NoError(t, Set(LocaleKey, "en-US"))
		require.NoError(t, Reload())
	}
}

func TestSettingsJSONRejectsTrailingData(t *testing.T) {
	for _, raw := range []string{`{"user_id":1} {"user_id":2}`, `{"user_id":1} invalid`} {
		_, err := (settingsJSON{}).Unmarshal([]byte(raw))
		require.Error(t, err)
	}
}
