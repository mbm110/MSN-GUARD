package deviceid

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp) // isolate from any real legacy deviceID on the dev machine
	id1 := Get(tmp)
	require.True(t, len(id1) > 8)
	id2 := Get(tmp)
	require.Equal(t, id1, id2)
}

func TestMigrateLegacyDeviceID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("migration is non-windows only")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	legacyDir := filepath.Join(home, ".lanternsecrets")
	require.NoError(t, os.Mkdir(legacyDir, 0o755))
	legacyID := "legacy-device-id-12345"
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, ".deviceid"), []byte(legacyID), 0o644))

	data := t.TempDir()
	require.Equal(t, legacyID, Get(data), "should return the migrated legacy ID")

	newFile := filepath.Join(data, ".lanternsecrets", ".deviceid")
	contents, err := os.ReadFile(newFile)
	require.NoError(t, err)
	require.Equal(t, legacyID, string(contents), "legacy ID should be copied to new location")

	// Legacy file should remain in place.
	_, err = os.Stat(filepath.Join(legacyDir, ".deviceid"))
	require.NoError(t, err, "legacy file should not be deleted")

	// Second call reads from the new location and returns the same ID.
	require.Equal(t, legacyID, Get(data))
}
