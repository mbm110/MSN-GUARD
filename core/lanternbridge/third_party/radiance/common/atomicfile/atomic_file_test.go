package atomicfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0600))
	require.NoError(t, WriteFile(path, []byte("new"), 0600))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new", string(contents))
	temporary, err := filepath.Glob(path + ".tmp*")
	require.NoError(t, err)
	assert.Empty(t, temporary)
}

func TestWriteFileFailedReplacementPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	require.NoError(t, os.Mkdir(path, 0700))
	old := filepath.Join(path, "old")
	require.NoError(t, os.WriteFile(old, []byte("preserved"), 0600))

	require.Error(t, WriteFile(path, []byte("replacement"), 0600))

	contents, err := os.ReadFile(old)
	require.NoError(t, err)
	assert.Equal(t, "preserved", string(contents))
	temporary, err := filepath.Glob(path + ".tmp*")
	require.NoError(t, err)
	assert.Empty(t, temporary)
}
