package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/traces"
)

const testReverseDevice = "device-under-test"

type reverseCall struct {
	path, deviceID, override, contentType, clientIP string
	body                                            []byte
}

func reverseServer(t *testing.T, status int, resp string) (*httptest.Server, *[]reverseCall) {
	t.Helper()
	var calls []reverseCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, reverseCall{
			path: r.URL.Path, deviceID: r.Header.Get(common.DeviceIDHeader),
			override: r.Header.Get("X-Lantern-Feature-Override"), contentType: r.Header.Get("Content-Type"),
			clientIP: r.Header.Get(common.ClientIPHeader), body: body,
		})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestReverseRegisterSendsRoutesAndDecodesTags(t *testing.T) {
	require.NoError(t, settings.Set(settings.FeatureOverridesKey, "helper_reverse"))
	t.Cleanup(func() { _ = settings.Set(settings.FeatureOverridesKey, "") })
	srv, calls := reverseServer(t, http.StatusOK, `{"observed_ip":"203.0.113.7","tags":{"`+pairingA+`":"`+tagA+`"}}`)

	api := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice)
	got, err := api.Register(context.Background(), []ReverseBlob{{PairingID: pairingA, Blob: []byte{0, 1, 2, 0xff}, Version: 1}})
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", got.ObservedIP)
	assert.Equal(t, map[string]string{pairingA: tagA}, got.Tags)

	require.Len(t, *calls, 1)
	c := (*calls)[0]
	assert.Equal(t, "/v1/helper/reverse/register", c.path)
	assert.Equal(t, testReverseDevice, c.deviceID)
	assert.Equal(t, "helper_reverse", c.override)
	assert.Equal(t, "application/json", c.contentType)
	assert.JSONEq(t, `{"routes":[{"pairing_id":"`+pairingA+`","blob":"AAEC/w==","version":1}]}`, string(c.body))
}

func TestReverseRegisterWithNoRoutesSendsAnEmptyList(t *testing.T) {
	srv, calls := reverseServer(t, http.StatusOK, `{"observed_ip":"","tags":{}}`)
	got, err := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice).Register(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "", got.ObservedIP)
	assert.Empty(t, got.Tags)
	require.Len(t, *calls, 1)
	assert.JSONEq(t, `{"routes":[]}`, string((*calls)[0].body))
}

func TestReverseDeregister(t *testing.T) {
	srv, calls := reverseServer(t, http.StatusOK, `{}`)
	require.NoError(t, NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice).Deregister(context.Background()))
	require.Len(t, *calls, 1)
	assert.Equal(t, "/v1/helper/reverse/deregister", (*calls)[0].path)
	assert.Equal(t, testReverseDevice, (*calls)[0].deviceID)
	assert.JSONEq(t, `{}`, string((*calls)[0].body))
}

func TestReverseDeregisterAcceptsAnEmptyBody(t *testing.T) {
	srv, _ := reverseServer(t, http.StatusOK, ``)
	require.NoError(t, NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice).Deregister(context.Background()))
}

func TestReverseRoutesDecodesBlobsAndBridgeConfig(t *testing.T) {
	srv, calls := reverseServer(t, http.StatusOK,
		`{"routes":[{"pairing_id":"`+pairingB+`","blob":"AAEC/w==","version":1}],"bridge_config":"{\"type\":\"samizdat\"}"}`)
	got, err := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice).Routes(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []ReverseBlob{{PairingID: pairingB, Blob: []byte{0, 1, 2, 0xff}, Version: 1}}, got.Routes)
	assert.Equal(t, `{"type":"samizdat"}`, got.BridgeConfig)
	require.Len(t, *calls, 1)
	assert.Equal(t, "/v1/helper/reverse/routes", (*calls)[0].path)
	assert.Equal(t, testReverseDevice, (*calls)[0].deviceID)
	assert.JSONEq(t, `{}`, string((*calls)[0].body))
}

func TestReverseRoutesEmpty(t *testing.T) {
	srv, _ := reverseServer(t, http.StatusOK, `{"routes":[],"bridge_config":""}`)
	got, err := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice).Routes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got.Routes)
	assert.Equal(t, "", got.BridgeConfig)
}

func TestReverseNotFoundMeansDisabled(t *testing.T) {
	srv, _ := reverseServer(t, http.StatusNotFound, `404 page not found`)
	api := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice)
	_, err := api.Register(context.Background(), nil)
	assert.ErrorIs(t, err, ErrReverseDisabled)
	assert.ErrorIs(t, api.Deregister(context.Background()), ErrReverseDisabled)
	_, err = api.Routes(context.Background())
	assert.ErrorIs(t, err, ErrReverseDisabled)
}

func TestReverseOtherStatusIsAnAPIError(t *testing.T) {
	srv, _ := reverseServer(t, http.StatusInternalServerError, "boom "+strings.Repeat("x", 4096))
	api := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice)
	_, err := api.Register(context.Background(), []ReverseBlob{{PairingID: pairingA, Blob: []byte("sealed-route-blob"), Version: 1}})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrReverseDisabled)
	var apiErr *ReverseAPIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.Status)
	assert.True(t, strings.HasPrefix(apiErr.Body, "boom"))
	assert.LessOrEqual(t, len(apiErr.Body), maxReverseErrLen)
	assert.NotContains(t, err.Error(), pairingA)
	assert.NotContains(t, err.Error(), "c2VhbGVkLXJvdXRlLWJsb2I")
	assert.NotContains(t, err.Error(), "boom")
}

func TestReverseMalformedResponseIsAnError(t *testing.T) {
	srv, _ := reverseServer(t, http.StatusOK, `{"observed_ip":`)
	_, err := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice).Register(context.Background(), nil)
	require.Error(t, err)
	var apiErr *ReverseAPIError
	assert.False(t, errors.As(err, &apiErr))
}

func TestReverseRedirectIsNotFollowedOffOriginOrTraced(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	var offOrigin bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { offOrigin = true }))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/helper/reverse/routes" {
			http.Redirect(w, r, "/v1/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/v1/elsewhere" {
			_ = json.NewEncoder(w).Encode(map[string]any{"routes": []any{}})
			return
		}
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: traces.NewRoundTripper(traces.NewHeaderAnnotatingRoundTripper(http.DefaultTransport))}
	api := NewReverseAPI(client, srv.URL+"/v1", testReverseDevice)

	_, err := api.Routes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, mem.GetSpans())

	assert.Error(t, api.Deregister(context.Background()))
	assert.False(t, offOrigin)
}

// The public IP is detected while the tunnel is down; after a network change
// it may be the old network's, so reverse requests leave it to lantern-cloud
// until it is detected again.
func TestReverseOmitsAStalePublicIP(t *testing.T) {
	common.SetPublicIP("198.51.100.9")
	t.Cleanup(func() { common.SetPublicIP("") })
	srv, calls := reverseServer(t, http.StatusOK, `{}`)
	api := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice)

	_, err := api.Register(context.Background(), nil)
	require.NoError(t, err)
	common.MarkPublicIPStale()
	_, err = api.Routes(context.Background())
	require.NoError(t, err)
	common.SetPublicIP("203.0.113.9")
	require.NoError(t, api.Deregister(context.Background()))

	require.Len(t, *calls, 3)
	assert.Equal(t, "198.51.100.9", (*calls)[0].clientIP, "before a network change")
	assert.Empty(t, (*calls)[1].clientIP, "after a network change")
	assert.Equal(t, "203.0.113.9", (*calls)[2].clientIP, "once detected again")
}

// A lookup that lands between building a request and setting its address
// leaves the request with the fresh address, never the stale one it copied.
func TestReverseOmitsAStalePublicIPReplacedMidRequest(t *testing.T) {
	common.SetPublicIP("198.51.100.9")
	common.MarkPublicIPStale()
	t.Cleanup(func() { common.SetPublicIP("") })
	reverseRequestBuilt = func() { common.SetPublicIP("203.0.113.9") }
	t.Cleanup(func() { reverseRequestBuilt = nil })
	srv, calls := reverseServer(t, http.StatusOK, `{}`)
	api := NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice)

	_, err := api.Routes(context.Background())
	require.NoError(t, err)
	require.Len(t, *calls, 1)
	assert.Equal(t, "203.0.113.9", (*calls)[0].clientIP)
}
