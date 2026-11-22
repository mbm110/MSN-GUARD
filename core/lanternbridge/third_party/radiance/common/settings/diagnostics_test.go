package settings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimePathsDoNotCreateDestinationSettings(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	dataDir, logDir := t.TempDir(), t.TempDir()
	require.NoError(t, SetRuntimePaths(dataDir, logDir))
	require.Equal(t, dataDir, GetString(DataPathKey))
	require.Equal(t, logDir, GetString(LogPathKey))
	require.False(t, k.initialized)
	_, err := os.Stat(filepath.Join(dataDir, settingsFileName))
	require.ErrorIs(t, err, os.ErrNotExist)
}
