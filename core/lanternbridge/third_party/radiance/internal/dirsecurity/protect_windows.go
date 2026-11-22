//go:build windows

package dirsecurity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/getlantern/radiance/common/fileperm"
)

const (
	administratorsSID = "S-1-5-32-544"
	localSystemSID    = "S-1-5-18"

	// rootMarkerName prevents retained handles from converting the secured root
	// into a junction, which requires an empty directory.
	rootMarkerName = ".lantern-secured"
)

// ErrUnsafePath means a path cannot be secured or read safely. The path is
// ambiguous or not on a fixed local drive; it, a directory above it or
// something inside it is a reparse point, a hard-linked file, the wrong kind
// of object, or a directory owned by anyone other than the current user,
// SYSTEM or Administrators; or it was replaced while being secured. A
// replacement may succeed on retry; otherwise the error lasts until the
// offending object is fixed or the path is changed.
var ErrUnsafePath = errors.New("unsafe path")

// Prepare creates the directory at path if missing and, if it is named Lantern,
// restricts the directory to Administrators and the user the process runs as,
// or SYSTEM when that user is an elevated administrator. A directory with any
// other name is only created. Files and directories created in it afterwards
// inherit the restriction; existing contents keep their own permissions (see
// [Secure]). It fails with [ErrUnsafePath] if the directory has an untrusted
// owner or a directory above it is a reparse point. It also fails while
// another handle can write, rename or delete the directory.
func Prepare(path string) error {
	return prepare(path, false)
}

// Secure applies [Prepare] and restricts existing contents of Lantern directories.
//
// For names equal to Lantern ignoring case, it leaves a marker and replaces
// files with restricted copies inaccessible through previously opened handles.
// Other names are only created. It stops at the first error and wraps
// [ErrUnsafePath] for untrusted directory owners, reparse points or hard links.
func Secure(path string) error {
	return prepare(path, true)
}

func prepare(path string, secureContents bool) error {
	p, err := currentPrincipals()
	if err != nil {
		return err
	}
	return prepareAs(path, secureContents, p)
}

func prepareAs(path string, secureContents bool, p principals) error {
	var err error
	if !managedName(path) {
		return os.MkdirAll(path, 0o755)
	}
	path, err = LocalDirectoryPath(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	parents, err := openDirectoryChain(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer closeHandles(parents)
	if err := createRestricted(path, p); err != nil {
		return err
	}
	handle, info, err := openPath(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return err
	}
	owner, err := objectOwner(handle)
	windows.CloseHandle(handle)
	if err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, path)
	}
	// A foreign owner may hold a handle that can rewrite the DACL after the reset.
	if !p.trusts(owner) {
		return fmt.Errorf("%w: %s is owned by %s", ErrUnsafePath, path, owner)
	}
	if err := resetDirectory(path, info, p); err != nil {
		return err
	}
	if !secureContents {
		return nil
	}
	if err := markRoot(path, info); err != nil {
		return err
	}
	return secureChildren(path, p)
}

// markRoot creates the root marker if missing, then confirms through a handle that does
// not follow reparse points that the same directory still holds it.
func markRoot(path string, info windows.ByHandleFileInformation) error {
	marker, err := os.OpenFile(filepath.Join(path, rootMarkerName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileperm.File)
	if err == nil {
		if err := marker.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	handle, current, err := openPath(path, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(handle), path)
	defer directory.Close()
	if info.VolumeSerialNumber != current.VolumeSerialNumber || info.FileIndexHigh != current.FileIndexHigh || info.FileIndexLow != current.FileIndexLow {
		return fmt.Errorf("%w: %s changed while being secured", ErrUnsafePath, path)
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return err
	}
	if !slices.Contains(names, rootMarkerName) {
		return fmt.Errorf("%w: %s lost its marker while being secured", ErrUnsafePath, path)
	}
	return nil
}

func managedName(path string) bool {
	return strings.EqualFold(filepath.Base(path), "Lantern")
}

func currentUserSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// principals are who a restricted object is owned by and granted to, besides
// Administrators, and the user the process runs as.
type principals struct {
	owner, grantee, user string
}

// currentPrincipals selects SYSTEM access for elevated administrators.
func currentPrincipals() (principals, error) {
	user, err := currentUserSID()
	if err != nil {
		return principals{}, err
	}
	switch {
	case user == localSystemSID:
		return principals{owner: localSystemSID, grantee: localSystemSID, user: user}, nil
	case isElevatedAdministrator():
		return principals{owner: administratorsSID, grantee: localSystemSID, user: user}, nil
	default:
		return principals{owner: user, grantee: user, user: user}, nil
	}
}

func isElevatedAdministrator() bool {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

func (p principals) trusts(sid string) bool {
	return sid == p.user || sid == localSystemSID || sid == administratorsSID
}

func (p principals) directorySecurity() string {
	return fmt.Sprintf(`O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FA;;;BA)`, p.owner, p.grantee)
}

// createRestricted creates path with the restriction already applied, so it is
// never briefly open to other users.
func createRestricted(path string, p principals) error {
	sd, err := windows.SecurityDescriptorFromString(p.directorySecurity())
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, &sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return nil
}

func secureChildren(dir string, p principals) error {
	readHandle, _, err := openPath(dir, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(readHandle), dir)
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if err := secureChild(dir, entry.Name(), p); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func secureChild(dir, name string, p principals) error {
	path := filepath.Join(dir, name)
	handle, info, err := openPath(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return err
	}
	owner, err := objectOwner(handle)
	windows.CloseHandle(handle)
	if err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		if err := rebuildFile(dir, name); err != nil {
			return fmt.Errorf("replace %s owned by %s: %w", path, owner, err)
		}
		return nil
	}
	if !p.trusts(owner) {
		return fmt.Errorf("%w: %s is owned by %s", ErrUnsafePath, path, owner)
	}
	if err := resetDirectory(path, info, p); err != nil {
		return err
	}
	return secureChildren(path, p)
}

// resetDirectory replaces the owner and DACL of a directory a trusted
// principal owns. The exclusive open fails while another handle can write,
// rename or delete it.
func resetDirectory(path string, info windows.ByHandleFileInformation, p principals) error {
	// MAXIMUM_ALLOWED prevents SetSecurityInfo from traversing unchecked descendants.
	exclusive, lockedInfo, err := openPath(path, windows.MAXIMUM_ALLOWED, windows.FILE_SHARE_READ)
	if err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	defer windows.CloseHandle(exclusive)
	if info.VolumeSerialNumber != lockedInfo.VolumeSerialNumber || info.FileIndexHigh != lockedInfo.FileIndexHigh || info.FileIndexLow != lockedInfo.FileIndexLow {
		return fmt.Errorf("%w: %s changed while being secured", ErrUnsafePath, path)
	}
	owner, dacl, err := securityParts(p.directorySecurity())
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(exclusive, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

// rebuildFile replaces dir\name with a copy created by this process, which
// inherits dir's restriction. It fails while another handle can write or
// delete the original, or denies its deletion.
func rebuildFile(dir, name string) error {
	handle, info, err := openPath(filepath.Join(dir, name), windows.GENERIC_READ, windows.FILE_SHARE_READ)
	if err != nil {
		return err
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if err := requireCopySpace(dir, size); err != nil {
		windows.CloseHandle(handle)
		return err
	}
	file := os.NewFile(uintptr(handle), name)
	tmp, err := os.CreateTemp(dir, name+".tmp*")
	if err != nil {
		file.Close()
		return err
	}
	_, err = io.Copy(tmp, file)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if syncErr := tmp.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = replaceOpenFile(tmp.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// requireCopySpace checks the full logical size because copying expands sparse holes.
func requireCopySpace(dir string, size uint64) error {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	var available uint64
	if err := windows.GetDiskFreeSpaceEx(path, &available, nil, nil); err != nil {
		return err
	}
	if size > available {
		return fmt.Errorf("copy requires %d bytes, %d available: %w", size, available, windows.ERROR_DISK_FULL)
	}
	return nil
}

// fileRenameInfo is FILE_RENAME_INFO with the Flags member of its union.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// replaceOpenFile renames src over dst. Where the OS and volume support POSIX
// renames, it succeeds while other handles have dst open, and those handles
// keep referring to the original file; it fails while a handle that can read,
// write or delete dst denies deletion. Elsewhere it fails while any handle has
// dst open.
func replaceOpenFile(src, dst string) error {
	target, err := windows.UTF16FromString(dst)
	if err != nil {
		return err
	}
	handle, _, err := openPath(src, windows.DELETE|windows.SYNCHRONIZE, windows.FILE_SHARE_READ)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	nameBytes := (len(target) - 1) * 2
	buf := make([]byte, int(unsafe.Sizeof(fileRenameInfo{}))+nameBytes)
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	info.FileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&info.FileName[0], len(target)), target)
	err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buf[0], uint32(len(buf)))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS
		err = windows.SetFileInformationByHandle(handle, windows.FileRenameInfo, &buf[0], uint32(len(buf)))
	}
	if err != nil {
		return fmt.Errorf("rename %s to %s: %w", src, dst, err)
	}
	return nil
}

func objectOwner(handle windows.Handle) (string, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", errors.New("object has no owner")
	}
	return owner.String(), nil
}

func securityParts(sddl string) (*windows.SID, *windows.ACL, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, nil, err
	}
	return owner, dacl, nil
}

type unsafePath string

func (e unsafePath) Error() string { return string(e) }

func (unsafePath) Is(target error) bool { return target == ErrUnsafePath }

func trustedOwner(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544"
}

// LocalDirectoryPath returns path if it is an unambiguous absolute path on a
// fixed local drive, and otherwise an error wrapping [ErrUnsafePath].
func LocalDirectoryPath(path string) (string, error) {
	if path != filepath.Clean(path) {
		return "", unsafePath("ambiguous directory path")
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path) || strings.ContainsRune(path[2:], ':') {
		return "", unsafePath("directory must use an absolute local drive path")
	}
	for _, component := range strings.Split(path[3:], `\`) {
		if component == "" || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return "", unsafePath("ambiguous directory path")
		}
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return "", unsafePath("directory must be on a fixed local drive")
	}
	return path, nil
}

func closeHandles(handles []windows.Handle) {
	for i := len(handles) - 1; i >= 0; i-- {
		windows.CloseHandle(handles[i])
	}
}

func openDirectoryChain(path string) ([]windows.Handle, error) {
	var handles []windows.Handle
	current := filepath.VolumeName(path) + `\`
	parts := append([]string{""}, strings.Split(strings.TrimPrefix(path, current), `\`)...)
	for _, part := range parts {
		if part != "" {
			current = filepath.Join(current, part)
		}
		handle, info, err := openPath(current, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		handles = append(handles, handle)
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			closeHandles(handles)
			return nil, unsafePath("path contains a non-directory")
		}
	}
	return handles, nil
}

func openPath(path string, access, share uint32) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, info, err
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, info, err
	}
	err = windows.GetFileInformationByHandle(handle, &info)
	if err == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		err = unsafePath("path contains a reparse point")
	}
	if err == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks != 1 {
		err = unsafePath("path contains a hard link")
	}
	if err != nil {
		windows.CloseHandle(handle)
		return 0, info, err
	}
	return handle, info, nil
}
