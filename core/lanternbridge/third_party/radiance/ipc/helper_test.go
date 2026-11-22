package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	semconv "github.com/getlantern/semconv"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/vpn"
)

func serveHelper(t *testing.T, api *localapi, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	r := httptest.NewRequest(method, path, &buf)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	return w
}

func TestHelperRelayEndpoint(t *testing.T) {
	api := newLocalAPI(&backend.LocalBackend{}, false)
	w := serveHelper(t, api, http.MethodPost, helperRelayEndpoint, HelperRelayRequest{Op: "peer/register"})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "unknown helper operation\n", w.Body.String())

	w = serveHelper(t, api, http.MethodPost, helperRelayEndpoint, HelperRelayRequest{Op: "pairings"})
	assert.Equal(t, http.StatusBadGateway, w.Code, "a backend without a relayer cannot reach lantern-cloud")
	assert.Equal(t, "helper relay failed\n", w.Body.String(), "the error is fixed text")

	w = serveHelper(t, api, http.MethodGet, helperRelayEndpoint, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHelperRelayEndpointRejectsAMalformedBody(t *testing.T) {
	api := newLocalAPI(&backend.LocalBackend{}, false)
	r := httptest.NewRequest(http.MethodPost, helperRelayEndpoint, strings.NewReader(`{"op":`))
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "bad helper relay request\n", w.Body.String())
}

// localTransport serves a Client's requests from api in-process.
type localTransport struct{ api *localapi }

func (t localTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.api.ServeHTTP(w, r)
	return w.Result(), nil
}

// A relayed request goes from ipc.Client through the endpoint and the
// backend's relayer to lantern-cloud, and lantern-cloud's answer, success or
// not, comes back as a RelayResult.
func TestHelperRelayClientRoundTrip(t *testing.T) {
	var gotPath, gotBody string
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.URL.Path == "/v1/helper/invites/claim" {
			http.Error(w, "invite already claimed or expired", http.StatusConflict)
			return
		}
		_, _ = w.Write([]byte(`{"pairings":[]}`))
	}))
	defer cloud.Close()
	b := &backend.LocalBackend{}
	b.SetHelperRelayForTest(helper.NewRelayer(cloud.Client(), cloud.URL+"/v1", nil))
	c := newClient()
	c.http.Transport = localTransport{api: newLocalAPI(b, false)}

	res, err := c.HelperRelay(context.Background(), "pairings", []byte(`{"x":1}`))
	require.NoError(t, err)
	assert.Equal(t, "/v1/helper/pairings", gotPath)
	assert.JSONEq(t, `{"x":1}`, gotBody)
	assert.Equal(t, http.StatusOK, res.Status)
	assert.JSONEq(t, `{"pairings":[]}`, string(res.Body))
	assert.Empty(t, res.Error)

	res, err = c.HelperRelay(context.Background(), "invites/claim", []byte(`{}`))
	require.NoError(t, err, "lantern-cloud's error is a result, not a relay failure")
	assert.Equal(t, http.StatusConflict, res.Status)
	assert.Equal(t, "invite already claimed or expired", res.Error)
	assert.Nil(t, res.Body)

	_, err = c.HelperRelay(context.Background(), "peer/register", nil)
	var ipcErr *Error
	require.ErrorAs(t, err, &ipcErr)
	assert.Equal(t, http.StatusBadRequest, ipcErr.Status)
}

func TestHelperPairingKeysEndpoint(t *testing.T) {
	api := newLocalAPI(&backend.LocalBackend{}, false)
	w := serveHelper(t, api, http.MethodGet, helperPairingKeysEndpoint, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	r := httptest.NewRequest(http.MethodPost, helperPairingKeysEndpoint, strings.NewReader(`{"keys":{"secret-pairing":`))
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "bad helper pairing keys request\n", w.Body.String(), "the error is fixed text")
}

// Keys pushed by ipc.Client replace the backend's whole set, and neither the
// keys nor the pairing IDs reach spans, even when the body is bad.
func TestHelperPairingKeysClientRoundTrip(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prevTP); _ = tp.Shutdown(context.Background()) })

	store := &helper.PairingKeys{}
	b := &backend.LocalBackend{}
	b.UseHelperPairingKeysForTest(store)
	api := newLocalAPI(b, false)
	c := newClient()
	c.http.Transport = localTransport{api: api}

	key := bytes.Repeat([]byte{0xA7}, 32)
	err := c.SetHelperPairingKeys(context.Background(), map[string]helper.PairingKey{
		"secret-pairing-inviter":   {Key: key, Role: "inviter"},
		"secret-pairing-volunteer": {Key: key, Role: "volunteer"},
	})
	require.NoError(t, err)
	got, ok := store.Get("secret-pairing-inviter")
	require.True(t, ok)
	assert.Equal(t, key, got)
	assert.Equal(t, []string{"secret-pairing-volunteer"}, store.IDs("volunteer"))
	assert.Same(t, store, b.HelperPairingKeys())

	require.NoError(t, c.SetHelperPairingKeys(context.Background(), nil))
	assert.Empty(t, store.IDs("inviter"), "an empty push clears the set")

	r := httptest.NewRequest(http.MethodPost, helperPairingKeysEndpoint,
		strings.NewReader(`{"keys":{"secret-pairing-bad":{"key":"`+base64.StdEncoding.EncodeToString(key)+`","role":`))
	api.ServeHTTP(httptest.NewRecorder(), r)

	for _, leak := range []string{"secret-pairing", base64.StdEncoding.EncodeToString(key), "pairing-keys"} {
		for _, s := range mem.GetSpans() {
			assert.NotContains(t, fmt.Sprint(s.Name, s.Attributes, s.Events), leak)
		}
	}
}

func TestHelperActivityEndpoint(t *testing.T) {
	api := newLocalAPI(&backend.LocalBackend{}, false)
	w := serveHelper(t, api, http.MethodGet, helperActivityEndpoint, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var a struct {
		Day           string `json:"day"`
		ActiveSeconds int64  `json:"active_seconds"`
		RelayedBytes  uint64 `json:"relayed_bytes"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &a))
	assert.Regexp(t, `^\d{4}-\d{2}-\d{2}$`, a.Day)
	assert.Zero(t, a.ActiveSeconds)
}

func TestHelperActivityClientRoundTrip(t *testing.T) {
	c := newClient()
	c.http.Transport = localTransport{api: newLocalAPI(&backend.LocalBackend{}, false)}
	a, err := c.HelperActivity(context.Background())
	require.NoError(t, err)
	assert.Regexp(t, `^\d{4}-\d{2}-\d{2}$`, a.Day)
	assert.Zero(t, a.RelayedBytes)
}

func TestPersonalProxyStatusClientRoundTrip(t *testing.T) {
	c := newClient()
	c.http.Transport = localTransport{api: newLocalAPI(&backend.LocalBackend{}, false)}
	statuses, err := c.PersonalProxyStatus(context.Background())
	require.NoError(t, err)
	assert.Empty(t, statuses)
}

func TestHelperLiveClientRoundTrip(t *testing.T) {
	helper.DefaultLive.Reset()
	t.Cleanup(helper.DefaultLive.Reset)
	c := newClient()
	c.http.Transport = localTransport{api: newLocalAPI(&backend.LocalBackend{}, false)}

	s, err := c.HelperLive(context.Background())
	require.NoError(t, err)
	assert.Empty(t, s.Pairings)

	helper.DefaultLive.Open("test", "k", "pairing-1", nil)
	helper.DefaultLive.Add("pairing-1", helper.LiveThreshold)
	s, err = c.HelperLive(context.Background())
	require.NoError(t, err)
	require.Len(t, s.Pairings, 1)
	assert.Equal(t, "pairing-1", s.Pairings[0].PairingID)
	assert.True(t, s.Pairings[0].Connected)
	assert.NotZero(t, s.Pairings[0].Since)

	w := serveHelper(t, newLocalAPI(&backend.LocalBackend{}, false), http.MethodGet, helperLiveEndpoint, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var raw struct {
		Pairings []map[string]any `json:"pairings"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	require.Len(t, raw.Pairings, 1)
	assert.ElementsMatch(t, []string{"pairing_id", "connected", "since"}, mapKeys(raw.Pairings[0]))
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A body that is not JSON is refused before marshalling, with fixed text
// rather than an encoder error that could quote it.
func TestHelperRelayClientRefusesANonJSONBody(t *testing.T) {
	c := newClient()
	c.http.Transport = localTransport{api: newLocalAPI(&backend.LocalBackend{}, false)}
	_, err := c.HelperRelay(context.Background(), "invites", []byte("not json secret"))
	assert.EqualError(t, err, "helper relay: body is not JSON")
}

// In-process calls carry the caller's span into the handler chain. The logger
// must not mark it with a /helper/ route, which would show the device uses
// helper invites; other routes are still annotated.
func TestLoggerSkipsHelperRoutes(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	api := newLocalAPI(&backend.LocalBackend{}, false)
	routeOf := func(method, path string) (string, bool) {
		mem.Reset()
		ctx, span := tp.Tracer("caller").Start(context.Background(), "caller")
		r := httptest.NewRequest(method, path, strings.NewReader(`{"op":"pairings"}`)).WithContext(ctx)
		api.ServeHTTP(httptest.NewRecorder(), r)
		span.End()
		for _, s := range mem.GetSpans() {
			for _, kv := range s.Attributes {
				if kv.Key == semconv.HTTPRouteKey {
					return kv.Value.AsString(), true
				}
			}
		}
		return "", false
	}
	_, ok := routeOf(http.MethodPost, helperRelayEndpoint)
	assert.False(t, ok, "relay")
	_, ok = routeOf(http.MethodGet, helperActivityEndpoint)
	assert.False(t, ok, "activity")
	_, ok = routeOf(http.MethodGet, helperPersonalProxiesEndpoint)
	assert.False(t, ok, "personal proxies")
	_, ok = routeOf(http.MethodGet, helperLiveEndpoint)
	assert.False(t, ok, "live")
	_, ok = routeOf(http.MethodPost, helperPairingKeysEndpoint)
	assert.False(t, ok, "pairing keys")
	route, ok := routeOf(http.MethodGet, "/not-a-route")
	assert.True(t, ok)
	assert.Equal(t, "/not-a-route", route)
}

// A connection gets one event as soon as it subscribes, covering a save made
// before it connected, and then one per save.
func TestSelectionEventsStream(t *testing.T) {
	events.Emit(vpn.SelectionSavedEvent{}) // a save no one hears
	srv := httptest.NewServer(newLocalAPI(&backend.LocalBackend{}, false))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+serverSelectionEventsEndpoint, nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	body := bufio.NewReader(resp.Body)
	requireEvent := func() {
		t.Helper()
		line, err := body.ReadString('\n')
		require.NoError(t, err)
		data, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
		require.True(t, ok, line)
		require.NoError(t, json.Unmarshal([]byte(data), &vpn.SelectionSavedEvent{}))
		_, err = body.ReadString('\n')
		require.NoError(t, err)
	}
	requireEvent()

	events.Emit(vpn.SelectionSavedEvent{})
	requireEvent()
}
