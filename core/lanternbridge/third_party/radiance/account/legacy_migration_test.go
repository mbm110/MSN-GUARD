package account

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
)

func TestVerifyLegacyIdentityDoesNotReplaceCurrentAccount(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	if err := settings.InitSettings(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := settings.Patch(settings.Settings{settings.UserIDKey: int64(99), settings.TokenKey: "current"}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user-data" || r.Header.Get(common.UserIDHeader) != "42" || r.Header.Get(common.ProTokenHeader) != "legacy" || r.Header.Get(common.DeviceIDHeader) != "device" {
			t.Error("wrong verification credentials")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"userId": 42, "token": "legacy", "userLevel": "pro"})
	}))
	defer server.Close()
	data, err := VerifyLegacyIdentity(context.Background(), server.Client(), server.URL, 42, "legacy", "device")
	if err != nil || data.LegacyID != 42 || data.LegacyUserData.DeviceID != "device" {
		t.Fatalf("verification: %v %v", data, err)
	}
	if settings.GetInt64(settings.UserIDKey) != 99 || settings.GetString(settings.TokenKey) != "current" {
		t.Fatal("verification changed current account")
	}
}

func TestVerifyLegacyIdentityFreeAccount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"userId":42}`))
	}))
	defer server.Close()
	data, err := VerifyLegacyIdentity(context.Background(), server.Client(), server.URL, 42, "legacy", "device")
	if err != nil {
		t.Fatal(err)
	}
	if data.LegacyUserData.UserLevel != "free" {
		t.Fatal("did not recognize an omitted free account level")
	}
}

func TestVerifyLegacyIdentityRejectsMismatchAndRedirect(t *testing.T) {
	for _, body := range []string{`{"userId":99,"userLevel":"pro"}`, `{"userId":42,"token":"other","userLevel":"pro"}`, `{"userId":42,"userLevel":"admin"}`, `{"error":"secret","userId":42,"userLevel":"pro"}`, `{}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		_, err := VerifyLegacyIdentity(context.Background(), server.Client(), server.URL, 42, "legacy", "device")
		server.Close()
		if err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("followed credential redirect") }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	if _, err := VerifyLegacyIdentity(context.Background(), server.Client(), server.URL, 42, "legacy", "device"); err == nil {
		t.Fatal("accepted redirect")
	}
}
