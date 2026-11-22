//go:build windows

package legacymigration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fileSecurity  = `O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`
	fileAllAccess = 0x1f01ff
)

func TestProtectedDestinationPermissions(t *testing.T) {
	for _, test := range []struct {
		sddl  string
		valid bool
	}{
		{fileSecurity, true},
		{`O:SYG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)`, true},
		{`O:BAG:BAD:(A;;FA;;;BA)(A;;FA;;;SY)`, false},
		{`O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;IU)`, false},
		{`O:IUG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)`, false},
		{`O:BAG:BAD:P(A;;FR;;;BA)(A;;FA;;;SY)`, false},
	} {
		sd, err := windows.SecurityDescriptorFromString(test.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyProtectedDescriptor(sd, fileAllAccess, true); (err == nil) != test.valid {
			t.Fatalf("descriptor %s: %v", test.sddl, err)
		}
	}
}

func TestPrivateSnapshotRead(t *testing.T) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := tokenUser.User.Sid.String()
	dir := t.TempDir()
	request := requestFixture()
	request.SourceDirectory = dir
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "snapshot.json")
	privateSnapshot(t, target, raw, sid)
	got, err := readRequestFile(target, sid, dir, request.MigrationID)
	if err != nil || got != request {
		t.Fatalf("snapshot = %#v, %v", got, err)
	}
	if _, err := readRequestFile(target, sid, dir, strings.Repeat("b", 32)); err == nil {
		t.Fatal("accepted unrelated migration")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	privateSnapshot(t, target, []byte(strings.Repeat("x", maxRequestBytes+1)), sid)
	if _, err := readRequestFile(target, sid, dir, request.MigrationID); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
}

func privateSnapshot(t *testing.T, target string, raw []byte, sid string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(`D:P(A;;FA;;;` + sid + `)(A;;FA;;;SY)(A;;FA;;;BA)`)
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), target)
	if _, err := file.Write(raw); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
