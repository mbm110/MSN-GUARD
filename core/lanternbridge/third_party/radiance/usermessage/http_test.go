package usermessage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wire "github.com/getlantern/common/usermessage"
	"github.com/getlantern/kindling"

	"github.com/getlantern/radiance/common"
)

func TestHTTPFetcherContractAndCredentials(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/user-messages", r.URL.Path)
		assert.Equal(t, "12345", r.Header.Get(common.UserIDHeader))
		assert.Equal(t, "secret-token", r.Header.Get(common.ProTokenHeader))
		assert.Equal(t, "macos", r.Header.Get(common.PlatformHeader))
		assert.Equal(t, "9.2.0", r.Header.Get(common.AppVersionHeader))
		assert.Equal(t, "1", r.Header.Get(kindling.IdempotentHeader))

		var request wire.UserMessageRequest
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
			return
		}
		assert.Equal(t, testCapabilities(), request.Capabilities)
		assert.Equal(t, "fa-IR", request.Locale)
		assert.Equal(t, []string{"seen-1"}, request.SeenDisplayIDs)

		writeWireResponse(t, w, wire.UserMessageResponse{
			PollIntervalSeconds: wire.MaxPollIntervalSeconds,
			Message:             testMessage("display-1", expiresAt),
		})
	}))
	t.Cleanup(server.Close)

	fetcher := NewHTTPFetcher(
		nil,
		server.URL+"/v1/user-messages",
		testCapabilities(),
	)
	response, err := fetcher.Fetch(context.Background(), testClientContext(), []string{"seen-1"})
	require.NoError(t, err)
	require.Equal(t, "display-1", response.Message.DisplayID)
}

func TestHTTPFetcherLeavesResponseValidationToService(t *testing.T) {
	tests := map[string]func(*wire.ResolvedUserMessage){
		"surface": func(message *wire.ResolvedUserMessage) {
			message.Surface = "future_surface"
		},
		"action": func(message *wire.ResolvedUserMessage) {
			message.ButtonLabel = "Act"
			message.Action = &wire.Action{Type: "future_action"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			message := testMessage("display-1", time.Now().UTC().Add(time.Hour))
			mutate(message)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeWireResponse(t, w, wire.UserMessageResponse{
					PollIntervalSeconds: 60,
					Message:             message,
				})
			}))
			t.Cleanup(server.Close)

			response, err := NewHTTPFetcher(server.Client(), server.URL, testCapabilities()).Fetch(
				context.Background(), testClientContext(), nil,
			)
			require.NoError(t, err)
			require.Equal(t, message, response.Message)
			require.Equal(t, 60, response.PollIntervalSeconds)
		})
	}
}

func TestHTTPFetcherRejectsNonCanonicalUserID(t *testing.T) {
	for _, userID := range []string{"not-a-number", "00123", "+123", "9223372036854775808"} {
		t.Run(userID, func(t *testing.T) {
			clientContext := testClientContext()
			clientContext.UserID = userID
			_, err := NewHTTPFetcher(
				http.DefaultClient,
				"https://example.com",
				testCapabilities(),
			).Fetch(
				context.Background(), clientContext, nil,
			)
			require.ErrorIs(t, err, errCredentialsUnavailable)
		})
	}
}

func TestHTTPFetcherReturnsStructuredStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	_, err := NewHTTPFetcher(server.Client(), server.URL, testCapabilities()).Fetch(
		context.Background(), testClientContext(), nil,
	)
	var statusErr *httpStatusError
	require.ErrorAs(t, err, &statusErr)
	require.Equal(t, http.StatusUnauthorized, statusErr.statusCode)
}

func writeWireResponse(t *testing.T, w http.ResponseWriter, response wire.UserMessageResponse) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	assert.NoError(t, json.NewEncoder(w).Encode(response))
}

func testClientContext() ClientContext {
	return ClientContext{
		UserID:     "12345",
		ProToken:   "secret-token",
		Locale:     "fa-IR",
		Platform:   "macos",
		AppVersion: "9.2.0",
	}
}

func testCapabilities() wire.ClientCapabilities {
	return wire.ClientCapabilities{
		Version:  wire.CapabilityUserMessagesV1,
		Surfaces: []wire.Surface{wire.SurfaceSnackbar},
		Actions: []wire.ActionType{
			wire.ActionTypeOpenHTTPSURL,
			wire.ActionTypeOpenPlans,
		},
	}
}

func testMessage(displayID string, expiresAt time.Time) *wire.ResolvedUserMessage {
	return &wire.ResolvedUserMessage{
		DisplayID:  displayID,
		CampaignID: "campaign-1",
		RevisionID: "revision-1",
		DeliveryID: "delivery-1",
		Surface:    wire.SurfaceSnackbar,
		Locale:     "fa-IR",
		Body:       "A safe localized message",
		ExpiresAt:  expiresAt,
	}
}
