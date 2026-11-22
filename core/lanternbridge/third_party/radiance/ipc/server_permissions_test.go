package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/issue"
	"github.com/stretchr/testify/require"
)

func TestOwnerSettingsPermissions(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	require.NoError(t, settings.Set(settings.LocaleKey, "en-US"))

	api := newLocalAPI(&backend.LocalBackend{}, true)
	api.ownerSID.Store(new("original-user"))
	owner := usr{uid: "original-user"}
	for _, forbidden := range []string{
		"data_path", "log_path", "token", "user_id", "device_id", "user_data",
		"feature_overrides", "config_fetch_disabled", "unknown", "locale.nested",
	} {
		t.Run(forbidden, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"locale": "fr-FR", forbidden: "changed"})
			require.NoError(t, err)
			before := settings.GetAll()
			response := servePeerRequest(api, owner, http.MethodPatch, settingsEndpoint, string(body))
			require.Equal(t, http.StatusForbidden, response.Code)
			require.Equal(t, before, settings.GetAll())
		})
	}

	response := servePeerRequest(api, owner, http.MethodPatch, settingsEndpoint, `{"locale":"fr-FR","time_zone":"Europe/Paris","log_level":"debug"}`)
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "fr-FR", settings.GetString(settings.LocaleKey))
	require.Equal(t, "Europe/Paris", settings.GetString(settings.TimeZoneKey))
	require.Equal(t, "debug", settings.GetString(settings.LogLevelKey))

	response = servePeerRequest(api, owner, http.MethodPatch, settingsEndpoint, `{"send_logs_to_signoz":true}`)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, settings.GetBool(settings.SendLogsToSigNozKey))
	response = servePeerRequest(api, owner, http.MethodPatch, settingsEndpoint, `{"send_logs_to_signoz":"yes"}`)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.True(t, settings.GetBool(settings.SendLogsToSigNozKey))

	response = servePeerRequest(api, owner, http.MethodGet, settingsEndpoint, "")
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"locale":"fr-FR"`)
}

func TestOwnerCanPatchOrdinaryPreferences(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	preferences := settings.Settings{
		settings.LocaleKey: "en-US", settings.TimeZoneKey: "UTC", settings.LogLevelKey: "info",
		settings.TelemetryKey: false, settings.SmartRoutingKey: true, settings.AdBlockKey: false,
		settings.SplitTunnelKey: false, settings.SplitTunnelPolicyKey: "exclude",
		settings.AutoConnectKey: false, settings.PeerShareEnabledKey: false,
		settings.PeerManualPortKey: float64(0), settings.PeerServePoolKey: true,
		settings.UnboundedKey: false,
	}
	require.NoError(t, settings.Patch(preferences))
	api := newLocalAPI(&backend.LocalBackend{}, true)
	api.ownerSID.Store(new("original-user"))
	body, err := json.Marshal(preferences)
	require.NoError(t, err)
	response := servePeerRequest(api, usr{uid: "original-user"}, http.MethodPatch, settingsEndpoint, string(body))
	require.Equal(t, http.StatusOK, response.Code)

	// "Help others too" is the owner's to turn off.
	response = servePeerRequest(api, usr{uid: "original-user"}, http.MethodPatch, settingsEndpoint, `{"peer_serve_pool":false}`)
	require.Equal(t, http.StatusOK, response.Code)
	require.False(t, settings.GetBool(settings.PeerServePoolKey))
}

func TestOwnerCannotAccessEnvironment(t *testing.T) {
	const key = "IPC_OWNER_ENV_PERMISSION_TEST"
	env.Set(key, "unchanged")
	api := newLocalAPI(&backend.LocalBackend{}, true)
	api.ownerSID.Store(new("original-user"))
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodPost} {
		response := servePeerRequest(api, usr{uid: "original-user"}, method, envEndpoint, `{"`+key+`":"changed"}`)
		require.Equal(t, http.StatusForbidden, response.Code)
		require.NotContains(t, response.Body.String(), key)
		require.Equal(t, "unchanged", env.GetAll()[key])
	}
}

func TestOwnerKeepsAccountAndVPNRoutes(t *testing.T) {
	api := newLocalAPI(&backend.LocalBackend{}, true)
	api.ownerSID.Store(new("original-user"))
	for _, path := range []string{accountLoginEndpoint, vpnConnectEndpoint} {
		response := servePeerRequest(api, usr{uid: "original-user"}, http.MethodPost, path, "{")
		require.Equal(t, http.StatusBadRequest, response.Code)
	}
}

func TestAdministrativeControlsRemainAvailable(t *testing.T) {
	for _, withAuth := range []bool{true, false} {
		t.Run(map[bool]string{true: "administrator", false: "without authentication"}[withAuth], func(t *testing.T) {
			settings.Reset()
			t.Cleanup(settings.Reset)
			require.NoError(t, settings.InitSettings(t.TempDir()))
			api := newLocalAPI(&backend.LocalBackend{}, withAuth)
			api.ownerSID.Store(new("original-user"))
			peer := usr{uid: "administrator", isAdmin: true}
			response := servePeerRequest(api, peer, http.MethodPatch, settingsEndpoint, `{"data_path":"administrative-path"}`)
			require.Equal(t, http.StatusOK, response.Code)
			require.Equal(t, "administrative-path", settings.GetString(settings.DataPathKey))

			const key = "IPC_ADMIN_ENV_PERMISSION_TEST"
			response = servePeerRequest(api, peer, http.MethodPatch, envEndpoint, `{"`+key+`":"changed"}`)
			require.Equal(t, http.StatusOK, response.Code)
			require.Equal(t, "changed", env.GetAll()[key])
			response = servePeerRequest(api, peer, http.MethodGet, envEndpoint, "")
			require.Equal(t, http.StatusOK, response.Code)
			require.Contains(t, response.Body.String(), key)
		})
	}
}

func TestIssueReportDoesNotReadOwnerProvidedPaths(t *testing.T) {
	input := IssueReportRequest{
		Description:           "VPN connection failed",
		AdditionalAttachments: []string{"system-only-file"},
		Attachments:           []*issue.Attachment{{Name: "screenshot.png", Type: "image/png", Data: []byte("image bytes")}},
	}
	body, err := json.Marshal(input)
	require.NoError(t, err)
	for _, test := range []struct {
		name         string
		peer         *usr
		wantFileRead bool
	}{
		{name: "owner", peer: &usr{uid: "original-user"}},
		{name: "administrator", peer: &usr{uid: "admin", isAdmin: true}, wantFileRead: true},
		{name: "without authentication", wantFileRead: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, issueEndpoint, bytes.NewReader(body))
			if test.peer != nil {
				request = request.WithContext(context.WithValue(request.Context(), peerKey{}, *test.peer))
			}
			got, err := decodeIssueReport(request)
			require.NoError(t, err)
			require.Equal(t, input.Description, got.Description)
			require.Equal(t, input.Attachments, got.Attachments)
			if test.wantFileRead {
				require.Equal(t, input.AdditionalAttachments, got.AdditionalAttachments)
			} else {
				require.Empty(t, got.AdditionalAttachments)
			}
		})
	}
}

func servePeerRequest(api http.Handler, peer usr, method, endpoint, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, endpoint, strings.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), peerLookupKey{}, func() (usr, error) {
		return peer, nil
	}))
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	return response
}
