//go:build windows

package serviceowner

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestGrantProcessQueryPreservesPermissions(t *testing.T) {
	handle := processQueryTestHandle(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := windows.SecurityDescriptorFromString(`D:P(D;;0x10;;;S-1-5-21-1-2-3-1002)(A;;GA;;;` + user.User.Sid.String() + `)`)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := baseline.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	before := processQueryTestDescriptor(t, handle)
	if err := grantProcessQuery(handle, sid); err != nil {
		t.Fatal(err)
	}
	after := processQueryTestDescriptor(t, handle)
	beforeOwner, _, _ := before.Owner()
	afterOwner, _, _ := after.Owner()
	if beforeOwner.String() != afterOwner.String() {
		t.Fatal("changed process owner")
	}
	original, _, _ := before.DACL()
	granted, _, _ := after.DACL()
	if granted.AceCount != original.AceCount+1 {
		t.Fatalf("ACE count = %d, want %d", granted.AceCount, original.AceCount+1)
	}
	var preserved uint32
	for i := uint32(0); i < uint32(granted.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(granted, i, &ace); err != nil {
			t.Fatal(err)
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != 0x1000 {
				t.Fatal("granted rights beyond limited process query")
			}
			continue
		}
		var old *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(original, preserved, &old); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize)), unsafe.Slice((*byte)(unsafe.Pointer(old)), int(old.Header.AceSize))) {
			t.Fatal("changed an existing process access entry")
		}
		preserved++
	}
	if preserved != uint32(original.AceCount) {
		t.Fatal("removed an existing process access entry")
	}
	if err := grantProcessQuery(handle, sid); err != nil {
		t.Fatal(err)
	}
	if again := processQueryTestDescriptor(t, handle); again.String() != after.String() {
		t.Fatal("repeated grant changed process permissions")
	}
	if err := grantProcessQuery(handle, nil); err == nil {
		t.Fatal("accepted a missing owner SID")
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := grantProcessQuery(handle, sid); err == nil {
		t.Fatal("accepted a null process DACL")
	}
	if dacl, _, err := processQueryTestDescriptor(t, handle).DACL(); err != nil || dacl != nil {
		t.Fatal("changed the rejected null process DACL")
	}
}

func processQueryTestDescriptor(t *testing.T, handle windows.Handle) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

func processQueryTestHandle(t *testing.T) windows.Handle {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestProcessQueryChild$")
	command.Env = append(os.Environ(), "RADIANCE_PROCESS_QUERY_CHILD=1")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		stdin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		if err := command.Wait(); err != nil {
			t.Error(err)
		}
	})
	handle, err := windows.OpenProcess(windows.READ_CONTROL|windows.WRITE_DAC, false, uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(handle) })
	return handle
}

func TestProcessQueryChild(t *testing.T) {
	if os.Getenv("RADIANCE_PROCESS_QUERY_CHILD") == "1" {
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
}
