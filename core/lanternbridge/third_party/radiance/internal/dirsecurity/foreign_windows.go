//go:build windows

package dirsecurity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrNotPrivate means a foreign file is owned by, or grants access to, someone
// other than its expected owner, SYSTEM and Administrators, or has no access
// list to check.
var ErrNotPrivate = errors.New("file is not private")

// ForeignDir is a directory the process does not own. While it is open, it
// and the directories above it cannot be deleted or replaced.
type ForeignDir struct {
	path    string
	handles []windows.Handle
}

// OpenForeignDir opens the directory at path. It fails with an error wrapping
// [ErrUnsafePath] if path is not one [LocalDirectoryPath] accepts, or if it or
// a directory above it is a reparse point.
func OpenForeignDir(path string) (*ForeignDir, error) {
	path, err := LocalDirectoryPath(path)
	if err != nil {
		return nil, err
	}
	handles, err := openDirectoryChain(path)
	if err != nil {
		return nil, err
	}
	return &ForeignDir{path: path, handles: handles}, nil
}

// Open opens name, a single path element, in d for reading without following
// a reparse point. It fails with an error wrapping [ErrUnsafePath] if name is
// not a single element, or is a reparse point or a hard-linked file.
func (d *ForeignDir) Open(name string) (*ForeignFile, error) {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return nil, fmt.Errorf("%w: %q is not a single path element", ErrUnsafePath, name)
	}
	path := filepath.Join(d.path, name)
	handle, info, err := openPath(path, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err != nil {
		return nil, err
	}
	return &ForeignFile{File: os.NewFile(uintptr(handle), path), handle: handle, info: info}, nil
}

// Close releases the directory.
func (d *ForeignDir) Close() error {
	closeHandles(d.handles)
	return nil
}

// ForeignFile is a file the process does not own, opened for reading.
type ForeignFile struct {
	*os.File
	handle windows.Handle
	info   windows.ByHandleFileInformation
}

// IsDir reports whether f is a directory.
func (f *ForeignFile) IsDir() bool {
	return f.info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
}

// Size returns the size of f when it was opened.
func (f *ForeignFile) Size() int64 {
	return int64(f.info.FileSizeHigh)<<32 | int64(f.info.FileSizeLow)
}

// PrivateTo returns an error unless f is owned by the user sid, SYSTEM or
// Administrators and only allows access to them. The error is [ErrNotPrivate]
// unless reading f's security information fails.
func (f *ForeignFile) PrivateTo(sid string) error {
	sd, err := windows.GetSecurityInfo(f.handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return verifyRequestDescriptor(sd, sid)
}

func verifyRequestDescriptor(sd *windows.SECURITY_DESCRIPTOR, sourceSID string) error {
	if sd == nil {
		return ErrNotPrivate
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !(trustedOwner(owner.String()) || owner.String() == sourceSID) {
		return ErrNotPrivate
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return ErrNotPrivate
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrNotPrivate
		}
		principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !(trustedOwner(principal) || principal == sourceSID) {
			return ErrNotPrivate
		}
	}
	return nil
}
