//go:build !windows

package dirsecurity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/getlantern/radiance/common/fileperm"
)

// Prepare creates missing directories with mode 0755 before applying the umask.
// Existing permissions are unchanged.
func Prepare(path string) error {
	return os.MkdirAll(path, 0o755)
}

// Secure does what [Prepare] does and also removes permissions beyond
// [fileperm.File] from every regular file already under path, never touching
// anything outside it. It fails if a file is hard-linked, stopping at the
// first one.
func Secure(path string) error {
	if err := Prepare(path); err != nil {
		return err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		return narrowMode(root, name)
	})
}

var errHardLink = errors.New("file is a hard link")

// narrowMode checks and changes the file through one handle, so it cannot be
// swapped for a hard link in between.
func narrowMode(root *os.Root, name string) error {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("secure %s: not a regular file", name)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return fmt.Errorf("secure %s: %w", name, errHardLink)
	}
	mode := info.Mode().Perm() & fileperm.File
	if mode == info.Mode().Perm() {
		return nil
	}
	return f.Chmod(mode)
}
