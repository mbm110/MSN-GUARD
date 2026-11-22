//go:build windows

package dirsecurity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSnapshotPermissions(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	tests := []struct {
		name, sddl string
		valid      bool
	}{
		{"original user", `O:` + sid + `G:` + sid + `D:P(A;;FA;;;` + sid + `)(A;;FA;;;SY)(A;;FA;;;BA)`, true},
		{"administrator", fileSecurity, true},
		{"inherited private", `O:` + sid + `G:` + sid + `D:(A;;FA;;;` + sid + `)(A;;FA;;;SY)`, true},
		{"untrusted owner", `O:IUG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`, false},
		{"other reader", `O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)`, false},
		{"other writer", `O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;WD)`, false},
		{"null DACL", `O:BAG:BAD:NO_ACCESS_CONTROL`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyRequestDescriptor(sd, sid); (err == nil) != test.valid {
				t.Fatalf("accepted = %v, want %v: %v", err == nil, test.valid, err)
			}
		})
	}
}

func TestLocalMigrationPathsRejectAliases(t *testing.T) {
	for _, path := range []string{`relative`, `\\server\share\Lantern`, `\\?\C:\Lantern`, `C:Lantern`, `C:\Lantern:stream`, `C:\Lantern.`, `C:\Lantern `, `C:\Lantern\..\Lantern`, `C:\Lantern\.\data`} {
		if _, err := LocalDirectoryPath(path); err == nil {
			t.Fatalf("accepted path %q", path)
		}
	}
}

func TestSnapshotRejectsHardLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(dir, "alias.json")); err != nil {
		t.Fatal(err)
	}
	handle, _, err := openPath(target, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err == nil {
		windows.CloseHandle(handle)
		t.Fatal("accepted hard-linked snapshot")
	}
}

func TestSnapshotRejectsReparsePoints(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.json")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	handle, _, err := openPath(alias, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err == nil {
		windows.CloseHandle(handle)
		t.Fatal("accepted reparse snapshot")
	}
}

func TestPrepareRestrictsDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	requireRestricted(t, path)

	if err := os.WriteFile(filepath.Join(path, "servers.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireRestricted(t, filepath.Join(path, "servers.json"))
}

func TestPrepareOnlyCreatesOtherNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, _ := sd.Control(); control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatal("restricted a directory not named Lantern")
	}
}

func TestSecureResetsExistingContents(t *testing.T) {
	user := testUser(t)
	path := filepath.Join(t.TempDir(), "Lantern")
	createWithSecurity(t, path, `D:P(A;OICI;FA;;;`+user+`)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)`)
	child := filepath.Join(path, "config.json")
	if err := os.WriteFile(child, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Secure(path); err != nil {
		t.Fatal(err)
	}
	requireRestricted(t, path)
	requireRestricted(t, child)
}

func TestSecureRefusesHardLinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(path, "planted")); err != nil {
		t.Fatal(err)
	}
	if err := Secure(path); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Secure = %v, want ErrUnsafePath", err)
	}
}

func TestSecureRefusesRetainedRootHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := windows.CreateFile(name, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(retained)
	if err := Secure(path); err == nil {
		t.Fatal("secured a directory another handle can rename")
	}
}

func TestRebuildFileDetachesRetainedHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "servers.json")
	if err := os.WriteFile(target, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := windows.CreateFile(name, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(retained)

	if err := rebuildFile(path, "servers.json"); err != nil {
		t.Fatal(err)
	}
	tryGrantEveryone(t, retained)
	requireRestricted(t, target)
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "planted" {
		t.Fatalf("rebuilt contents = %q, %v", got, err)
	}
}

func testUser(t *testing.T) string {
	t.Helper()
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// requireRestricted fails unless path grants access only to the current
// principals' grantee and Administrators.
func requireRestricted(t *testing.T, path string) {
	t.Helper()
	p, err := currentPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("%s: unexpected access list: %v", path, err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask) != fileAllAccess || !(sid == p.grantee || sid == administratorsSID) {
			t.Fatalf("%s: unexpected access for %s", path, sid)
		}
	}
}

func createWithSecurity(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal(err)
	}
}

const (
	fileAllAccess = 0x1f01ff
	usersSID      = "S-1-5-32-545"
	fileSecurity  = `O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`
)

func TestSecureReplacesForeignOwnedFile(t *testing.T) {
	user := testUser(t)
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "servers.json")
	if err := os.WriteFile(target, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	setForeignOwner(t, target, `D:P(A;;FA;;;`+user+`)(A;;FA;;;BU)`)
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := windows.CreateFile(name, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(retained)

	if err := Secure(path); err != nil {
		t.Fatal(err)
	}
	tryGrantEveryone(t, retained)
	requireRestricted(t, target)
	if got, err := os.ReadFile(target); err != nil || string(got) != "planted" {
		t.Fatalf("replaced contents = %q, %v", got, err)
	}
}

func TestSecureRefusesForeignOwnedDirectory(t *testing.T) {
	user := testUser(t)
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(path, "planted")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	setForeignOwner(t, sub, `D:P(A;OICI;FA;;;`+user+`)(A;OICI;FA;;;BU)`)
	if err := Secure(path); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Secure = %v, want ErrUnsafePath", err)
	}
}

func TestPrepareRefusesForeignOwnedRoot(t *testing.T) {
	user := testUser(t)
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	setForeignOwner(t, path, `D:P(A;OICI;FA;;;`+user+`)(A;OICI;FA;;;BU)`)
	if err := Prepare(path); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Prepare = %v, want ErrUnsafePath", err)
	}
}

// setForeignOwner makes Users the owner of path with the given DACL. Assigning
// an owner other than oneself needs SeRestorePrivilege, so the test is skipped
// without it.
func setForeignOwner(t *testing.T, path, dacl string) {
	t.Helper()
	enablePrivilege(t, "SeRestorePrivilege")
	owner, err := windows.StringToSid(usersSID)
	if err != nil {
		t.Fatal(err)
	}
	_, acl, err := securityParts(dacl)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil); err != nil {
		t.Skipf("cannot assign a foreign owner: %v", err)
	}
}

func enablePrivilege(t *testing.T, name string) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Skipf("open process token: %v", err)
	}
	var luid windows.LUID
	privilege, err := windows.UTF16PtrFromString(name)
	if err != nil {
		token.Close()
		t.Fatal(err)
	}
	if err := windows.LookupPrivilegeValue(nil, privilege, &luid); err != nil {
		token.Close()
		t.Skipf("look up %s: %v", name, err)
	}
	set := func(attributes uint32) error {
		privileges := windows.Tokenprivileges{PrivilegeCount: 1}
		privileges.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: attributes}
		return windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
	}
	if err := set(windows.SE_PRIVILEGE_ENABLED); err != nil {
		token.Close()
		t.Skipf("enable %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = set(0)
		token.Close()
	})
}

func TestPrepareAcceptsDirectorySecuredByAdministrator(t *testing.T) {
	if !isElevatedAdministrator() {
		t.Skip("requires an elevated administrator")
	}
	user := testUser(t)
	path := filepath.Join(t.TempDir(), "Lantern")
	installer := principals{owner: administratorsSID, grantee: localSystemSID, user: user}
	if err := prepareAs(path, true, installer); err != nil {
		t.Fatal(err)
	}
	service := principals{owner: user, grantee: user, user: user}
	if err := prepareAs(path, false, service); err != nil {
		t.Fatalf("a directory the installer secured must be accepted by the service: %v", err)
	}
}

func TestSecureMarksRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Secure(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, rootMarkerName)); err != nil {
		t.Fatalf("secured root has no marker: %v", err)
	}
	if err := Secure(path); err != nil {
		t.Fatalf("securing a marked root again: %v", err)
	}
}

func TestSecureReplacesMarkerWithRetainedReadHandle(t *testing.T) {
	for name, previousSecure := range map[string]bool{"existing": false, "secured": true} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Lantern")
			if err := Prepare(path); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(path, rootMarkerName)
			if previousSecure {
				if err := Secure(path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			name, err := windows.UTF16PtrFromString(target)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(retained)

			if err := Secure(path); err != nil {
				t.Fatal(err)
			}
			requireRestricted(t, target)
			if err := Secure(path); err != nil {
				t.Fatalf("securing a marked root again: %v", err)
			}
		})
	}
}

func TestSecurePreservesLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "large.cache")
	original, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	const (
		size = (64 << 20) + 1
		head = "start of large file"
		tail = "end of large file"
	)
	if err := original.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := original.WriteAt([]byte(head), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := original.WriteAt([]byte(tail), size-int64(len(tail))); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}

	if err := Secure(path); err != nil {
		t.Fatal(err)
	}
	requireRestricted(t, target)
	rebuilt, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer rebuilt.Close()
	info, err := rebuilt.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != size {
		t.Fatalf("rebuilt size = %d, want %d", info.Size(), size)
	}
	for _, part := range []struct {
		offset int64
		want   string
	}{{0, head}, {size - int64(len(tail)), tail}} {
		got := make([]byte, len(part.want))
		if _, err := rebuilt.ReadAt(got, part.offset); err != nil {
			t.Fatal(err)
		}
		if string(got) != part.want {
			t.Fatalf("rebuilt contents at %d = %q, want %q", part.offset, got, part.want)
		}
	}
}

func TestRequireCopySpace(t *testing.T) {
	dir := t.TempDir()
	for _, size := range []uint64{0, 1} {
		if err := requireCopySpace(dir, size); err != nil {
			t.Fatalf("requireCopySpace(%d): %v", size, err)
		}
	}
	if err := requireCopySpace(dir, ^uint64(0)); !errors.Is(err, windows.ERROR_DISK_FULL) {
		t.Fatalf("requireCopySpace(MaxUint64) = %v, want ERROR_DISK_FULL", err)
	}
	if err := requireCopySpace(filepath.Join(dir, "missing"), 0); err == nil {
		t.Fatal("accepted a directory whose free space cannot be queried")
	}
}

func TestRebuildFileRejectsSparseFileLargerThanFreeSpace(t *testing.T) {
	dir := t.TempDir()
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	if err := windows.GetDiskFreeSpaceEx(path, nil, &total, nil); err != nil {
		t.Fatal(err)
	}
	if total >= 1<<63-1 {
		t.Skip("volume capacity exceeds the maximum file size")
	}
	size := int64(total + 1)
	target := filepath.Join(dir, "sparse.cache")
	original, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	var returned uint32
	if err := windows.DeviceIoControl(windows.Handle(original.Fd()), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil); err != nil {
		if errors.Is(err, windows.ERROR_INVALID_FUNCTION) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("sparse files unavailable: %v", err)
		}
		t.Fatal(err)
	}
	const content = "original"
	if _, err := original.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := original.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	locked := os.NewFile(uintptr(retained), target)
	defer locked.Close()
	var overlapped windows.Overlapped
	// A missing preflight must fail on the first read instead of filling the disk.
	if err := windows.LockFileEx(retained, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		t.Fatal(err)
	}
	if err := rebuildFile(dir, filepath.Base(target)); !errors.Is(err, windows.ERROR_DISK_FULL) {
		t.Fatalf("rebuildFile = %v, want ERROR_DISK_FULL", err)
	}
	info, err := locked.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != size {
		t.Fatalf("original size = %d, want %d", info.Size(), size)
	}
	got := make([]byte, len(content))
	if _, err := locked.ReadAt(got, 0); err != nil || string(got) != content {
		t.Fatalf("original contents = %q, %v", got, err)
	}
	leftovers, err := filepath.Glob(target + ".tmp*")
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files = %v, %v", leftovers, err)
	}
}

func TestSecureDetachesRetainedHandlesOnTrustedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "servers.json")
	if err := os.WriteFile(target, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := windows.CreateFile(name, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(retained)

	if err := Secure(path); err != nil {
		t.Fatal(err)
	}
	tryGrantEveryone(t, retained)
	requireRestricted(t, target)
}

func TestRebuildFileFailsWhileHandleDeniesDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Lantern")
	if err := Prepare(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "servers.json")
	if err := os.WriteFile(target, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	// Sharing only binds handles with data access.
	retained, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(retained)

	err = rebuildFile(path, "servers.json")
	if err == nil {
		t.Fatal("replaced a file another handle denies deleting")
	}
	if !strings.Contains(err.Error(), "rename ") {
		t.Fatalf("rebuildFile failed before renaming: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "planted" {
		t.Fatalf("original contents = %q, %v", got, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(path, "servers.json.tmp*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("left temporary files: %v", leftovers)
	}
}

// tryGrantEveryone tries to grant Everyone full access through handle, which
// refers to a file that has since been replaced. Windows may refuse the change
// or apply it to the original; either way the replacement must not change.
func tryGrantEveryone(t *testing.T, handle windows.Handle) {
	t.Helper()
	_, open, err := securityParts(`D:(A;;FA;;;WD)`)
	if err != nil {
		t.Fatal(err)
	}
	windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, open, nil)
}
