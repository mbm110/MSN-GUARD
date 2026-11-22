// Package serviceowner stores the Windows service's authorized user in administrator-controlled storage.
package serviceowner

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	keyPath     = `Software\Lantern\Service`
	valueName   = "OwnerSID"
	keySecurity = `O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)`
)

var (
	advapi         = windows.NewLazySystemDLL("advapi32.dll")
	regCreateKeyEx = advapi.NewProc("RegCreateKeyExW")
	regFlushKey    = advapi.NewProc("RegFlushKey")
)

// Load returns the service owner's SID, or an empty string when no owner is configured.
func Load() (string, error) { return load(keyPath) }

func load(path string) (string, error) {
	key, err := openKey(path, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer key.Close()
	sid, kind, err := key.GetStringValue(valueName)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read service owner: %w", err)
	}
	if kind != registry.SZ {
		return "", errors.New("invalid service owner value type")
	}
	if _, err := parseSID(sid); err != nil {
		return "", err
	}
	return sid, nil
}

// Save durably records sid; replacing an existing service owner is rejected.
func Save(sid string) error { return save(keyPath, sid) }

func save(path, sid string) error {
	if _, err := parseSID(sid); err != nil {
		return err
	}
	if err := createKey(path); err != nil {
		return err
	}
	existing, err := load(path)
	if err != nil {
		return err
	}
	if existing != "" && existing != sid {
		return errors.New("service owner is already configured")
	}
	key, err := openKey(path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.SetStringValue(valueName, sid); err != nil {
		return fmt.Errorf("persist service owner: %w", err)
	}
	result, _, _ := regFlushKey.Call(uintptr(key))
	if result != 0 {
		return fmt.Errorf("flush service owner: %w", windows.Errno(result))
	}
	return nil
}

func parseSID(value string) (*windows.SID, error) {
	sid, err := windows.StringToSid(value)
	if err != nil || sid.String() != value || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil, errors.New("invalid service owner SID")
	}
	return sid, nil
}

func openKey(path string, access uint32) (registry.Key, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, access|windows.READ_CONTROL|registry.WOW64_64KEY)
	if err != nil {
		return 0, err
	}
	if err := verifyKey(key); err != nil {
		key.Close()
		return 0, fmt.Errorf("untrusted service owner permissions: %w", err)
	}
	return key, nil
}

func createKey(path string) error {
	sd, err := windows.SecurityDescriptorFromString(keySecurity)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	keyName, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var key registry.Key
	var disposition uint32
	result, _, _ := regCreateKeyEx.Call(uintptr(registry.LOCAL_MACHINE), uintptr(unsafe.Pointer(keyName)), 0, 0, 0,
		uintptr(registry.READ|registry.WOW64_64KEY), uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&disposition)))
	runtime.KeepAlive(sd)
	if result != 0 {
		return fmt.Errorf("create service owner key: %w", windows.Errno(result))
	}
	defer key.Close()
	return verifyKey(key)
}

func verifyKey(key registry.Key) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(key), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return verifyDescriptor(sd)
}

func verifyDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trustedPrincipal(owner.String()) {
		return errors.New("owner is not SYSTEM or Administrators")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("service owner key permits inherited access")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return errors.New("expected exactly two restricted access entries")
	}
	seen := make(map[string]bool, 2)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask) != registry.ALL_ACCESS || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			return errors.New("unexpected service owner access entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !trustedPrincipal(sid) || seen[sid] {
			return errors.New("unexpected service owner access principal")
		}
		seen[sid] = true
	}
	return nil
}

func trustedPrincipal(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544"
}
