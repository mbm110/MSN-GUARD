package legacymigration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requestFixture() Request {
	return Request{Version: 1, MigrationID: strings.Repeat("a", 32), SourceDirectory: `C:\Users\Original\Lantern`, UserID: 9007199254740993, Token: "original-token", DeviceID: "original-device", Locale: "fa-IR", AutoReport: true, ProxyAll: true, AutoLaunch: true}
}

func verifiedFixture(request Request, level string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"legacyID": request.UserID, "legacyToken": request.Token,
		"legacyUserData": map[string]any{"userId": request.UserID, "token": request.Token, "deviceID": request.DeviceID, "userLevel": level, "email": "original@example.com"},
	})
	return raw
}

func accepting(request Request) Verify {
	return func(ctx context.Context, got Request) (json.RawMessage, string, error) {
		if got != request {
			return nil, "", errors.New("changed request")
		}
		return verifiedFixture(request, "pro"), "pro", nil
	}
}

func TestSnapshotBinding(t *testing.T) {
	request := requestFixture()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeRequest(raw, strings.ToLower(request.SourceDirectory), request.MigrationID); err != nil || got != request {
		t.Fatalf("snapshot = %#v, %v", got, err)
	}
	for name, mutate := range map[string]func(*Request){
		"version":      func(r *Request) { r.Version = 2 },
		"migration":    func(r *Request) { r.MigrationID = strings.Repeat("b", 32) },
		"source":       func(r *Request) { r.SourceDirectory += "-other" },
		"source alias": func(r *Request) { r.SourceDirectory += `\.\` },
		"account":      func(r *Request) { r.UserID = 0 },
		"token":        func(r *Request) { r.Token = "" },
		"device":       func(r *Request) { r.DeviceID = "" },
		"control":      func(r *Request) { r.Locale = "en\nUS" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			mutate(&invalid)
			raw, _ := json.Marshal(invalid)
			if _, err := decodeRequest(raw, request.SourceDirectory, request.MigrationID); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
		})
	}
	for _, invalid := range [][]byte{nil, []byte(strings.Repeat("x", maxRequestBytes+1)), append(append([]byte{}, raw...), []byte(`{}`)...), append([]byte(`{"unknown":true,`), raw[1:]...)} {
		if _, err := decodeRequest(invalid, request.SourceDirectory, request.MigrationID); err == nil {
			t.Fatal("accepted invalid JSON snapshot")
		}
	}
}

func TestImportPreservesIdentityPreferencesAndSource(t *testing.T) {
	dir := t.TempDir()
	request := requestFixture()
	original := filepath.Join(dir, "original.snapshot")
	if err := os.WriteFile(original, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	ownerSaved := false
	err := importSettings(context.Background(), dir, request, accepting(request), func() error { ownerSaved = true; return nil })
	if err != nil || !ownerSaved {
		t.Fatalf("import = %v, owner saved = %v", err, ownerSaved)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := json.Unmarshal(settings["user_id"], &id); err != nil || id != request.UserID {
		t.Fatalf("user ID = %d, %v", id, err)
	}
	for key, expected := range map[string]string{"token": `"original-token"`, "device_id": `"original-device"`, "locale": `"fa-IR"`, "user_level": `"pro"`, "email": `"original@example.com"`, "telemetry_enabled": "true", "smart_routing": "false", "auto_connect": "false"} {
		if string(settings[key]) != expected {
			t.Fatalf("%s = %s, want %s", key, settings[key], expected)
		}
	}
	for _, key := range []string{"legacy_migration_id", "legacy_migration_sha256", "legacy_auto_launch"} {
		if _, exists := settings[key]; exists {
			t.Fatalf("import wrote runtime migration field %s", key)
		}
	}
	source, err := os.ReadFile(original)
	if err != nil || string(source) != "unchanged" {
		t.Fatalf("source changed: %q, %v", source, err)
	}
}

func TestImportIsIdempotentAndPreservesLaterSettings(t *testing.T) {
	dir := t.TempDir()
	request := requestFixture()
	saveOwner := func() error { return nil }
	if err := importSettings(context.Background(), dir, request, accepting(request), saveOwner); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "settings.json")
	before, _ := os.ReadFile(target)
	before = []byte(strings.Replace(string(before), `"locale":"fa-IR"`, `"locale":"en-US"`, 1))
	if err := os.WriteFile(target, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := importSettings(context.Background(), dir, request, accepting(request), saveOwner); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(target)
	if string(after) != string(before) {
		t.Fatal("repeat import changed existing settings")
	}
}

func TestImportRejectsConflictingDestination(t *testing.T) {
	for _, name := range []string{"settings.json", "local.json", "settings.yaml", "settings.yml", filepath.Join("data", "settings.json"), filepath.Join("data", "local.json")} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			before := []byte(`{"user_id":99,"token":"other"}`)
			if err := os.WriteFile(target, before, 0600); err != nil {
				t.Fatal(err)
			}
			err := importSettings(context.Background(), dir, requestFixture(), func(context.Context, Request) (json.RawMessage, string, error) {
				t.Fatal("verified over conflicting settings")
				return nil, "", nil
			}, func() error { t.Fatal("changed owner over conflicting settings"); return nil })
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("import = %v", err)
			}
			after, _ := os.ReadFile(target)
			if string(after) != string(before) {
				t.Fatal("changed conflicting settings")
			}
		})
	}
}

func TestImportFailureDoesNotPersistIdentity(t *testing.T) {
	request := requestFixture()
	for _, failure := range []string{"verification", "wrong account", "wrong device", "wrong token", "wrong level"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			saveOwner := func() error { t.Fatal("saved owner before verification"); return nil }
			verify := func(context.Context, Request) (json.RawMessage, string, error) {
				invalid := request
				switch failure {
				case "verification":
					return nil, "", errors.New("upstream original-token")
				case "wrong account":
					invalid.UserID++
				case "wrong device":
					invalid.DeviceID += "-other"
				case "wrong token":
					invalid.Token += "-other"
				case "wrong level":
					return verifiedFixture(request, "unknown"), "unknown", nil
				}
				return verifiedFixture(invalid, "pro"), "pro", nil
			}
			err := importSettings(context.Background(), dir, request, verify, saveOwner)
			if err == nil || strings.Contains(err.Error(), request.Token) {
				t.Fatalf("unsafe failure: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "settings.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failure persisted identity: %v", err)
			}
		})
	}
}

func TestImportWriteFailureDoesNotSaveOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	request := requestFixture()
	err := importSettings(context.Background(), dir, request, accepting(request), func() error {
		t.Fatal("saved owner without settings")
		return nil
	})
	if err == nil {
		t.Fatal("import succeeded without a writable settings directory")
	}
}

func TestImportOwnerFailureCanRetry(t *testing.T) {
	dir := t.TempDir()
	request := requestFixture()
	ownerErr := errors.New("owner write failed")
	err := importSettings(context.Background(), dir, request, accepting(request), func() error {
		if _, err := os.Stat(filepath.Join(dir, "settings.json")); err != nil {
			t.Fatalf("settings were not committed before the owner: %v", err)
		}
		if err := checkDestination(dir, request); err != nil {
			t.Fatalf("committed settings have a different identity: %v", err)
		}
		return ownerErr
	})
	if !errors.Is(err, ownerErr) {
		t.Fatalf("import = %v, want owner failure", err)
	}
	target := filepath.Join(dir, "settings.json")
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	before = []byte(strings.Replace(string(before), `"locale":"fa-IR"`, `"locale":"en-US"`, 1))
	if err := os.WriteFile(target, before, 0600); err != nil {
		t.Fatal(err)
	}
	ownerSaved := false
	if err := importSettings(context.Background(), dir, request, accepting(request), func() error { ownerSaved = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !ownerSaved {
		t.Fatal("retry did not save owner")
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != string(before) {
		t.Fatalf("retry changed existing settings: %v", err)
	}
}
