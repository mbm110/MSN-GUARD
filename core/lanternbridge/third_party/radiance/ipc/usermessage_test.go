package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/backend"
)

func TestUserMessageStreamReconcilesOnEveryConnection(t *testing.T) {
	api := newLocalAPI(&backend.LocalBackend{}, false)
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+userMessageEventsEndpoint, nil)
		require.NoError(t, err)
		response, err := server.Client().Do(request)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(response.Body)
		gotEvent := scanner.Scan()
		line := scanner.Text()
		response.Body.Close()
		cancel()
		require.True(t, gotEvent)
		require.Equal(t, "data: {}", line)
	}
}

func TestUserMessageRoutes(t *testing.T) {
	api := newLocalAPI(&backend.LocalBackend{}, false)

	response := serveUserMessageRequest(t, api, http.MethodGet, userMessageEndpoint, nil)
	require.Equal(t, http.StatusOK, response.Code)
	var current CurrentUserMessageResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &current))
	require.Nil(t, current.Message)

	response = serveUserMessageRequest(t, api, http.MethodPost, userMessageRefreshEndpoint, nil)
	require.Equal(t, http.StatusNoContent, response.Code)

	response = serveUserMessageRequest(t, api, http.MethodPatch, userMessageActivityEndpoint,
		UserMessageActivityRequest{Active: true})
	require.Equal(t, http.StatusNoContent, response.Code)

	response = serveUserMessageRequest(t, api, http.MethodPost, userMessageAcknowledgeEndpoint,
		UserMessageAcknowledgeRequest{DisplayID: "not-pending"})
	require.Equal(t, http.StatusConflict, response.Code)
}

func serveUserMessageRequest(
	t *testing.T,
	api http.Handler,
	method string,
	endpoint string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&encoded).Encode(body))
	}
	request := httptest.NewRequest(method, endpoint, &encoded)
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	return response
}
