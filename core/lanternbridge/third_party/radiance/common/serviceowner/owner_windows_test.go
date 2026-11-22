package serviceowner

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestProtectedOwnerDescriptor(t *testing.T) {
	for _, test := range []struct {
		name, sddl string
		valid      bool
	}{
		{"restricted", keySecurity, true},
		{"system owner", `O:SYG:SYD:P(A;;KA;;;BA)(A;;KA;;;SY)`, true},
		{"inherited", `O:BAG:BAD:(A;;KA;;;SY)(A;;KA;;;BA)`, false},
		{"untrusted owner", `O:IUG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)`, false},
		{"interactive read", `O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;IU)`, false},
		{"interactive write", `O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;IU)`, false},
		{"duplicate administrator", `O:BAG:BAD:P(A;;KA;;;BA)(A;;KA;;;BA)`, false},
		{"inherited only", `O:BAG:BAD:P(A;CIIO;KA;;;SY)(A;;KA;;;BA)`, false},
		{"insufficient access", `O:BAG:BAD:P(A;;KR;;;SY)(A;;KA;;;BA)`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyDescriptor(sd); (err == nil) != test.valid {
				t.Fatalf("verification error = %v, expected valid = %v", err, test.valid)
			}
		})
	}
}

func TestOwnerSID(t *testing.T) {
	for _, value := range []string{"", "invalid", "S-1-5-18", "s-1-5-21-1-2-3-1001"} {
		if _, err := parseSID(value); err == nil {
			t.Errorf("accepted invalid owner %q", value)
		}
	}
	if _, err := parseSID("S-1-5-21-1-2-3-1001"); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedOwnerPersistence(t *testing.T) {
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	member, err := windows.Token(0).IsMember(admin)
	if err != nil || !member {
		t.Skip("requires an elevated Windows test process")
	}
	name := fmt.Sprintf("Lantern-ServiceOwner-Test-%d-%d", os.Getpid(), time.Now().UnixNano())
	path := `Software\` + name
	if sid, err := load(path); err != nil || sid != "" {
		t.Fatalf("missing owner = %q, %v", sid, err)
	}
	t.Cleanup(func() {
		software, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software`, registry.WRITE|registry.WOW64_64KEY)
		if err != nil {
			t.Error(err)
			return
		}
		defer software.Close()
		if err := registry.DeleteKey(software, name); err != nil {
			t.Error(err)
		}
	})
	const owner = "S-1-5-21-1-2-3-1001"
	if err := save(path, owner); err != nil {
		t.Fatal(err)
	}
	if sid, err := load(path); err != nil || sid != owner {
		t.Fatalf("stored owner = %q, %v", sid, err)
	}
	if err := save(path, owner); err != nil {
		t.Fatal(err)
	}
	if err := save(path, "S-1-5-21-1-2-3-1002"); err == nil {
		t.Fatal("replaced an existing service owner")
	}
	key, err := openKey(path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	if err := key.SetExpandStringValue(valueName, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path); err == nil {
		t.Fatal("accepted a non-REG_SZ owner")
	}
	if err := key.SetStringValue(valueName, "invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path); err == nil {
		t.Fatal("accepted an invalid persisted SID")
	}
}
