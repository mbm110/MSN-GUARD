//go:build !windows

package dirsecurity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/getlantern/radiance/common/fileperm"
)

func TestSecureRepairsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := []string{"wg.key", filepath.Join("sub", "lantern.log")}
	for _, name := range files {
		writeOpenFileAt(t, filepath.Join(dir, name))
	}
	private := filepath.Join(dir, "rejections.json")
	if err := os.WriteFile(private, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := writeOpenFile(t)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	if err := Secure(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if want := 0o666 & fileperm.File; info.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", name, info.Mode().Perm(), want)
		}
	}
	info, err := os.Stat(private)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("Secure widened a private file to %v", info.Mode().Perm())
	}
	info, err = os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o666 {
		t.Errorf("Secure followed a link: target has mode %v", info.Mode().Perm())
	}
}

func TestSecureRefusesHardLinks(t *testing.T) {
	dir := t.TempDir()
	outside := writeOpenFile(t)
	if err := os.Link(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if err := Secure(dir); !errors.Is(err, errHardLink) {
		t.Fatalf("Secure returned %v for a hard-linked file, want %v", err, errHardLink)
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o666 {
		t.Errorf("Secure changed a hard-linked file to %v", info.Mode().Perm())
	}
}

// writeOpenFile creates a file outside any directory under test with mode
// 0666, which Secure would narrow on every build.
func writeOpenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "outside")
	writeOpenFileAt(t, path)
	return path
}

func writeOpenFileAt(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod, unlike WriteFile, is not masked by the umask.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
}
