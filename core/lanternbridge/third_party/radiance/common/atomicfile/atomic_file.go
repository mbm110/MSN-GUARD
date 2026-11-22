// Package atomicfile provides functions to read and write files atomically.
package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile writes data to a file named by filename atomically.
func WriteFile(filename string, data []byte, perm os.FileMode) (err error) {
	// renaming a file is atomic at the OS level on POSIX systems, so we write to a temp file
	// and then rename it to the target filename.
	f, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			_ = os.Remove(f.Name())
		}
	}()

	if _, err = f.Write(data); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err = f.Chmod(perm); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}

func ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
