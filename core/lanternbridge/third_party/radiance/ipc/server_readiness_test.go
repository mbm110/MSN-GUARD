package ipc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getlantern/radiance/backend"
	"github.com/stretchr/testify/require"
)

func TestPendingBackendKeepsAuthenticatedDiagnostics(t *testing.T) {
	server := NewServer(nil, true)
	server.SetOwnerSID("original-user")
	for _, test := range []struct {
		name, uid, method, path, body string
		admin                         bool
		status                        int
	}{
		{"owner can report malformed issue", "original-user", http.MethodPost, issueEndpoint, "{", false, http.StatusBadRequest},
		{"admin can report malformed issue", "admin", http.MethodPost, issueEndpoint, "{", true, http.StatusBadRequest},
		{"unrelated user cannot report", "other-user", http.MethodPost, issueEndpoint, "{", false, http.StatusForbidden},
		{"owner cannot create account", "original-user", http.MethodPost, accountNewUserEndpoint, "{}", false, http.StatusServiceUnavailable},
		{"owner cannot change settings", "original-user", http.MethodPatch, settingsEndpoint, "{}", false, http.StatusServiceUnavailable},
		{"owner cannot connect", "original-user", http.MethodPost, vpnConnectEndpoint, "{}", false, http.StatusServiceUnavailable},
		{"unrelated user cannot read settings", "other-user", http.MethodGet, settingsEndpoint, "", false, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request = request.WithContext(context.WithValue(request.Context(), peerLookupKey{}, func() (usr, error) {
				return usr{uid: test.uid, isAdmin: test.admin}, nil
			}))
			response := httptest.NewRecorder()
			server.svr.Handler.ServeHTTP(response, request)
			require.Equal(t, test.status, response.Code)
		})
	}
	server.SetBackend(&backend.LocalBackend{})
	request := httptest.NewRequest(http.MethodGet, settingsEndpoint, nil)
	request = request.WithContext(context.WithValue(request.Context(), peerLookupKey{}, func() (usr, error) {
		return usr{uid: "original-user"}, nil
	}))
	response := httptest.NewRecorder()
	server.svr.Handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	server.SetBackend(nil)
	response = httptest.NewRecorder()
	server.svr.Handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
}

func TestPendingBackendAllowsLogStreaming(t *testing.T) {
	server := NewServer(nil, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, logsStreamEndpoint, nil).WithContext(ctx)
	server.svr.Handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "text/event-stream", response.Header().Get("Content-Type"))
}
