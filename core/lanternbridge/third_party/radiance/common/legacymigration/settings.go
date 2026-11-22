package legacymigration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
)

const maxRequestBytes = 64 << 10

var migrationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func decodeRequest(raw []byte, source, id string) (Request, error) {
	var request Request
	if len(raw) == 0 || len(raw) > maxRequestBytes {
		return request, errors.New("invalid migration snapshot size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return Request{}, errors.New("invalid migration snapshot JSON")
	}
	return request, validateRequest(request, source, id)
}

func validateRequest(request Request, source, id string) error {
	if request.Version != 1 || !migrationIDPattern.MatchString(id) || request.MigrationID != id || source == "" || !sameDirectory(request.SourceDirectory, source) || request.UserID <= 0 {
		return errors.New("invalid migration snapshot binding")
	}
	for _, field := range []struct {
		value    string
		max      int
		required bool
	}{
		{request.Token, 4096, true}, {request.DeviceID, 256, true}, {request.Locale, 128, false},
	} {
		if len(field.value) > field.max || field.required && field.value == "" || strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
			return errors.New("invalid migration snapshot identity")
		}
	}
	return nil
}

func sameDirectory(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, `\`, "/"), strings.ReplaceAll(b, `\`, "/"))
}

type userData struct {
	LegacyID       int64  `json:"legacyID"`
	LegacyToken    string `json:"legacyToken"`
	LegacyUserData *struct {
		UserID    int64  `json:"userId"`
		Token     string `json:"token"`
		DeviceID  string `json:"deviceID"`
		UserLevel string `json:"userLevel"`
		Email     string `json:"email"`
	} `json:"legacyUserData"`
}

func verifiedUser(raw json.RawMessage, request Request, level string) (*userData, error) {
	var user userData
	if level != "free" && level != "pro" || json.Unmarshal(raw, &user) != nil || user.LegacyUserData == nil || user.LegacyID != request.UserID || user.LegacyToken != request.Token {
		return nil, errors.New("invalid verified legacy identity")
	}
	data := user.LegacyUserData
	if data.UserID != request.UserID || data.Token != request.Token || data.DeviceID != request.DeviceID || data.UserLevel != level {
		return nil, errors.New("invalid verified legacy identity")
	}
	return &user, nil
}

func importSettings(ctx context.Context, dataDir string, request Request, verify Verify, saveOwner func() error) error {
	if err := validateRequest(request, request.SourceDirectory, request.MigrationID); err != nil {
		return err
	}
	if err := checkDestination(dataDir, request); err != nil {
		return err
	}
	if verify == nil {
		return errors.New("missing legacy identity verification")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, level, err := verify(ctx, request)
	if err != nil {
		return errors.New("legacy identity verification unavailable")
	}
	user, err := verifiedUser(raw, request, level)
	if err != nil {
		return err
	}
	if saveOwner == nil {
		return errors.New("missing service owner persistence")
	}
	if err := writeSettings(dataDir, request, raw, level, user.LegacyUserData.Email); err != nil {
		return err
	}
	return saveOwner()
}

func checkDestination(dataDir string, request Request) error {
	for _, name := range []string{"local.json", "settings.yaml", "settings.yml", filepath.Join("data", "settings.json"), filepath.Join("data", "local.json"), filepath.Join("data", "settings.yaml"), filepath.Join("data", "settings.yml")} {
		if _, err := os.Lstat(filepath.Join(dataDir, name)); err == nil {
			return ErrConflict
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "settings.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var current struct {
		UserID    int64           `json:"user_id"`
		Token     string          `json:"token"`
		DeviceID  string          `json:"device_id"`
		UserLevel string          `json:"user_level"`
		UserData  json.RawMessage `json:"user_data"`
	}
	if json.Unmarshal(raw, &current) != nil || current.UserID != request.UserID || current.Token != request.Token || current.DeviceID != request.DeviceID {
		return ErrConflict
	}
	if _, err := verifiedUser(current.UserData, request, current.UserLevel); err != nil {
		return ErrConflict
	}
	return nil
}

func writeSettings(dataDir string, request Request, user json.RawMessage, level, email string) error {
	if err := checkDestination(dataDir, request); err != nil {
		return err
	}
	target := filepath.Join(dataDir, "settings.json")
	if _, err := os.Stat(target); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data := map[string]any{
		"user_id": request.UserID, "token": request.Token, "device_id": request.DeviceID,
		"user_level": level, "user_data": user, "email": email,
		"locale": request.Locale, "telemetry_enabled": request.AutoReport,
		"smart_routing": !request.ProxyAll,
		// Import must not connect while the legacy app is active.
		"auto_connect": false,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(target, raw, fileperm.File)
}
