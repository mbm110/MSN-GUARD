package atomicfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWriteFileLockedDestinationPreservesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, windows.CloseHandle(handle)) })

	require.Error(t, WriteFile(path, []byte("replacement"), 0600))

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "original", string(contents))
	temporary, err := filepath.Glob(path + ".tmp*")
	require.NoError(t, err)
	assert.Empty(t, temporary)
}
