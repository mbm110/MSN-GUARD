//go:build windows

package legacymigration

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/getlantern/radiance/common/serviceowner"
	"github.com/getlantern/radiance/internal/dirsecurity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Import verifies and imports a private snapshot before the destination service starts.
func Import(ctx context.Context, sid, source, id, requestPath string, verify Verify, saveOwner func(string) error) error {
	if err := requireAdministrator(); err != nil {
		return err
	}
	parsedSID, err := windows.StringToSid(sid)
	if err != nil || parsedSID.String() != sid || parsedSID.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("invalid migration source SID")
	}
	_, _, accountType, err := parsedSID.LookupAccount("")
	if err != nil || accountType != windows.SidTypeUser {
		return errors.New("migration source SID does not identify a user")
	}
	source, err = dirsecurity.LocalDirectoryPath(source)
	if err != nil {
		return err
	}
	ancestors, err := dirsecurity.OpenForeignDir(source)
	if err != nil {
		return errors.New("invalid migration source directory")
	}
	defer ancestors.Close()
	request, err := readRequestFile(requestPath, sid, source, id)
	if err != nil {
		return err
	}
	dataDir, err := serviceDataDirectory()
	if err != nil {
		return err
	}
	return withImportLock(func() error {
		if err := requireStoppedDestination(); err != nil {
			return err
		}
		if saveOwner == nil {
			return errors.New("missing service owner persistence")
		}
		owner, err := serviceowner.Load()
		if err != nil {
			return err
		}
		if owner != "" && owner != sid {
			return ErrConflict
		}
		if err := dirsecurity.Secure(dataDir); err != nil {
			return err
		}
		return importSettings(ctx, dataDir, request, verify, func() error {
			return saveOwner(sid)
		})
	})
}

func requireStoppedDestination() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService("LanternSvc")
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		return ErrConflict
	}
	return nil
}

func requireAdministrator() error {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	member, err := windows.Token(0).IsMember(sid)
	if err != nil || !member {
		return ErrUnauthorized
	}
	return nil
}

func withImportLock(fn func() error) error {
	sd, err := windows.SecurityDescriptorFromString(`O:BAG:BAD:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)`)
	if err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(`Global\Lantern.LegacyImport`)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateMutexEx(&sa, name, 0, windows.MUTEX_ALL_ACCESS)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	defer windows.CloseHandle(handle)
	if err := verifyProtectedObject(handle, windows.SE_KERNEL_OBJECT, windows.MUTEX_ALL_ACCESS, true); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, err := windows.WaitForSingleObject(handle, 10000)
	if err != nil {
		return err
	}
	if result != windows.WAIT_OBJECT_0 && result != windows.WAIT_ABANDONED {
		return errors.New("legacy import is busy")
	}
	defer windows.ReleaseMutex(handle)
	return fn()
}

func readRequestFile(path, sid, source, id string) (Request, error) {
	path, err := dirsecurity.LocalDirectoryPath(path)
	if err != nil {
		return Request{}, errors.New("invalid migration snapshot path")
	}
	ancestors, err := dirsecurity.OpenForeignDir(filepath.Dir(path))
	if err != nil {
		return Request{}, errors.New("invalid migration snapshot directory")
	}
	defer ancestors.Close()
	file, err := ancestors.Open(filepath.Base(path))
	if err != nil {
		return Request{}, errors.New("cannot open migration snapshot")
	}
	defer file.Close()
	if file.IsDir() || file.Size() > maxRequestBytes {
		return Request{}, errors.New("invalid migration snapshot size")
	}
	if file.PrivateTo(sid) != nil {
		return Request{}, errors.New("migration snapshot permissions are not private")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxRequestBytes+1))
	if err != nil {
		return Request{}, errors.New("cannot read migration snapshot")
	}
	return decodeRequest(raw, source, id)
}

func verifyProtectedObject(handle windows.Handle, kind windows.SE_OBJECT_TYPE, access uint32, protected bool) error {
	sd, err := windows.GetSecurityInfo(handle, kind, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return verifyProtectedDescriptor(sd, access, protected)
}

func verifyProtectedDescriptor(sd *windows.SECURITY_DESCRIPTOR, access uint32, protected bool) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trustedOwner(owner.String()) {
		return errors.New("owner is not SYSTEM or Administrators")
	}
	control, _, err := sd.Control()
	if err != nil || protected && control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("security descriptor permits inherited access")
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
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask) != access || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			return errors.New("unexpected access entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !trustedOwner(sid) || seen[sid] {
			return errors.New("unexpected access principal")
		}
		seen[sid] = true
	}
	return nil
}

func trustedOwner(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544"
}

func serviceDataDirectory() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "Lantern"), nil
}
