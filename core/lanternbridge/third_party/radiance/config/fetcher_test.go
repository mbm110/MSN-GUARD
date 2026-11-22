package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	C "github.com/getlantern/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
)

func TestFetchConfig(t *testing.T) {
	settings.InitSettings(t.TempDir())
	defer settings.Reset()

	settings.Set(settings.DeviceIDKey, "mock-device-id")
	settings.Set(settings.UserIDKey, 1234567890)
	settings.Set(settings.TokenKey, "mock-legacy-token")

	privateKey, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	baseCapabilities := []string{C.CapabilityNonSelectableOutbounds, C.CapabilityUnboundedTuning, C.CapabilityOutlineSmartDialer, C.CapabilityUnboundedDirectExitObfs}
	tests := []struct {
		name               string
		preferredServerLoc *C.ServerLocation
		serverStatus       int
		serverBody         string
		expectedConfig     []byte
		expectError        bool
		globalIPv6         bool
		wantCapabilities   []string
	}{
		{
			name: "successful fetch",
			preferredServerLoc: &C.ServerLocation{
				Country: "US",
			},
			serverStatus:     http.StatusOK,
			serverBody:       `{"key":"value"}`,
			expectedConfig:   []byte(`{"key":"value"}`),
			wantCapabilities: baseCapabilities,
		},
		{
			name: "global IPv6 advertises CapabilityIPv6",
			preferredServerLoc: &C.ServerLocation{
				Country: "US",
			},
			serverStatus:     http.StatusOK,
			serverBody:       `{"key":"value"}`,
			expectedConfig:   []byte(`{"key":"value"}`),
			globalIPv6:       true,
			wantCapabilities: append(slices.Clone(baseCapabilities), C.CapabilityIPv6),
		},
		{
			name: "no new config available",
			preferredServerLoc: &C.ServerLocation{
				Country: "US",
			},
			serverStatus:     http.StatusNotModified,
			expectedConfig:   nil,
			wantCapabilities: baseCapabilities,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedReq *http.Request
			var capturedBody []byte

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				capturedBody = body
				capturedReq = r
				w.WriteHeader(tt.serverStatus)
				if tt.serverBody != "" {
					w.Write([]byte(tt.serverBody))
				}
			}))
			defer srv.Close()

			f := newFetcher("en-US", nil, srv.Client()).(*fetcher)
			f.baseURL = srv.URL
			f.hasGlobalIPv6 = func() bool { return tt.globalIPv6 }

			gotConfig, err := f.fetchConfig(t.Context(), *tt.preferredServerLoc, privateKey.PublicKey().String())

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, gotConfig)
			}

			require.NotNil(t, capturedReq)
			assert.Equal(t, "application/json", capturedReq.Header.Get("Content-Type"))
			assert.Equal(t, "no-cache", capturedReq.Header.Get("Cache-Control"))

			var confReq C.ConfigRequest
			err = json.Unmarshal(capturedBody, &confReq)
			require.NoError(t, err)

			assert.Equal(t, common.Platform, confReq.Platform)
			assert.Equal(t, common.Name, confReq.AppName)
			assert.Equal(t, settings.GetString(settings.DeviceIDKey), confReq.DeviceID)
			assert.Equal(t, "1234567890", confReq.UserID,
				"UserID must serialize as a base-10 decimal string matching main's format")
			assert.Equal(t, privateKey.PublicKey().String(), confReq.WGPublicKey)
			assert.Equal(t, tt.wantCapabilities, confReq.Capabilities)
			assert.Contains(t, confReq.Capabilities, C.CapabilityUnboundedTuning,
				"the server sends Unbounded tuning only to clients advertising this")
			assert.Equal(t, "outline_smart_dialer", C.CapabilityOutlineSmartDialer,
				"the server matches this exact wire string")
			assert.Contains(t, confReq.Capabilities, C.CapabilityOutlineSmartDialer,
				"the server sends the proxyless rule-set detour only to clients advertising this")
			assert.Equal(t, "unbounded_direct_exit_obfs", C.CapabilityUnboundedDirectExitObfs,
				"the server matches this exact wire string")
			assert.Contains(t, confReq.Capabilities, C.CapabilityUnboundedDirectExitObfs,
				"the server sends the Unbounded outbound's direct_exit only to clients advertising this")
			assert.NotContains(t, confReq.Capabilities, C.CapabilityUnboundedDirectExit,
				"the server sends nothing for the pre-obfuscation capability")
			if tt.preferredServerLoc != nil {
				assert.Equal(t, tt.preferredServerLoc, confReq.PreferredLocation)
			}
		})
	}
}

// TestUserIDFormatMatchesMain exercises the same expression used in
// fetchConfig to build ConfigRequest.UserID. It guards the regression
// fixed in this PR: on main the value is serialized as a base-10
// decimal string ("0" when unset, "<digits>" when set), and we need
// refactor to match so server-side strconv.ParseInt doesn't treat an
// empty string as malformed.
func TestUserIDFormatMatchesMain(t *testing.T) {
	cases := []struct {
		name   string
		set    bool
		value  int64
		expect string
	}{
		{name: "unset -> zero", set: false, expect: "0"},
		{name: "small id", set: true, value: 42, expect: "42"},
		{name: "large id (exercises float64 JSON round-trip)", set: true, value: 1234567890, expect: "1234567890"},
	}
	require.NoError(t, settings.InitSettings(t.TempDir()))
	defer settings.Reset()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings.Clear(settings.UserIDKey)
			if tc.set {
				require.NoError(t, settings.Set(settings.UserIDKey, tc.value))
			}
			got := fmt.Sprintf("%d", settings.GetInt64(settings.UserIDKey))
			assert.Equal(t, tc.expect, got)
		})
	}
}

func TestSupportedProtocolsOmitsDenied(t *testing.T) {
	protocols := supportedProtocols()
	assert.NotEmpty(t, protocols)
	for _, p := range []string{"tor", "water", "tailscale"} {
		assert.NotContains(t, protocols, p)
	}
	assert.Contains(t, protocols, "shadowsocks")
}
