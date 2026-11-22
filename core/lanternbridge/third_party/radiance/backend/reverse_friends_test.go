package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/fileperm"
)

// otherMode is a mode that isn't fileperm.File, as a file saved before
// reverse-friends.json took fileperm.File may have.
func otherMode() os.FileMode {
	if fileperm.File == 0o600 {
		return 0o640
	}
	return 0o600
}

func TestReverseFriendsSavedInTheSharedFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix file modes")
	}
	path := filepath.Join(t.TempDir(), reverseFriendsFileName)
	f := &reverseFriends{path: path, byPairing: map[string]string{pairingHash("pairing-a"): ppFriendA}}
	f.saveLocked()

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, fileperm.File, info.Mode().Perm())
}

// A file saved in another mode, which on macOS left the app unable to read
// what the root network extension saved, is saved again in fileperm.File when
// loaded, keeping its friends.
func TestReverseFriendsLoadRepairsTheFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix file modes")
	}
	path := filepath.Join(t.TempDir(), reverseFriendsFileName)
	(&reverseFriends{path: path, byPairing: map[string]string{pairingHash("pairing-a"): ppFriendA}}).saveLocked()
	require.NoError(t, os.Chmod(path, otherMode()))

	f := loadReverseFriends(path)
	assert.True(t, f.has(ppFriendA))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, fileperm.File, info.Mode().Perm())
}

// The repair replaces only a regular file: a link's target keeps its mode.
func TestReverseFriendsLoadLeavesALinkedFileAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix file modes")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	(&reverseFriends{path: target, byPairing: map[string]string{pairingHash("pairing-a"): ppFriendA}}).saveLocked()
	require.NoError(t, os.Chmod(target, otherMode()))
	path := filepath.Join(dir, reverseFriendsFileName)
	require.NoError(t, os.Symlink(target, path))

	loadReverseFriends(path)
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, otherMode(), info.Mode().Perm())
	linkInfo, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, linkInfo.Mode().Type())
}
