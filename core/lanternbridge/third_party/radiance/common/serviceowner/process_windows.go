package serviceowner

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// GrantProcessQuery grants the configured owner limited query access to the current LocalSystem process.
func GrantProcessQuery() error {
	value, err := Load()
	if err != nil || value == "" {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("service process is not running as LocalSystem")
	}
	sid, err := parseSID(value)
	if err != nil {
		return err
	}
	return grantProcessQuery(windows.CurrentProcess(), sid)
}

func grantProcessQuery(handle windows.Handle, sid *windows.SID) error {
	if sid == nil {
		return errors.New("missing service owner SID")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read service process permissions: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("service process permissions are unrestricted")
	}
	var pinned runtime.Pinner
	pinned.Pin(sid)
	defer pinned.Unpin()
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.PROCESS_QUERY_LIMITED_INFORMATION,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	dacl, err = windows.ACLFromEntries(entries, dacl)
	if err != nil {
		return fmt.Errorf("merge service process permissions: %w", err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("grant service process query access: %w", err)
	}
	return nil
}
