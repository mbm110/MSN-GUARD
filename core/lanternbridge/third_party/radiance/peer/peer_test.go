package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	box "github.com/getlantern/lantern-box"
	"github.com/getlantern/lantern-box/tracker/peerconn"

	"github.com/getlantern/lantern-box/portforward"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/internal/hostaccess"
)

// minimalValidLaunchCfg returns a launch_cfg JSON that passes
// peerrules.ValidateAbuseRules: the four abuse rule_set tags (each as a
// "remote" rule_set + a matching unconditional reject rule), plus
// one RFC1918 and one SMTP canary in reject rules. Shared by the
// stub server used in Start-path tests so the existing tests do not
// regress on the new check.
const minimalValidLaunchCfg = `{
	"inbounds":[{"type":"samizdat","tag":"samizdat-in"}],
	"route":{
		"rule_set":[
			{"type":"remote","tag":"geosite-malware","format":"binary","url":"https://example/geosite-malware.srs","download_detour":"direct"},
			{"type":"remote","tag":"geoip-malware","format":"binary","url":"https://example/geoip-malware.srs","download_detour":"direct"},
			{"type":"remote","tag":"geosite-phishing","format":"binary","url":"https://example/geosite-phishing.srs","download_detour":"direct"},
			{"type":"remote","tag":"geosite-cryptominers","format":"binary","url":"https://example/geosite-cryptominers.srs","download_detour":"direct"}
		],
		"rules":[
			{"action":"reject","rule_set":["geosite-malware"]},
			{"action":"reject","rule_set":["geoip-malware"]},
			{"action":"reject","rule_set":["geosite-phishing"]},
			{"action":"reject","rule_set":["geosite-cryptominers"]},
			{"action":"reject","ip_cidr":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","::1/128","fc00::/7","fe80::/10"]},
			{"action":"reject","port":[25,465,587,2525,6660,6661,6662,6663,6664,6665,6666,6667,6668,6669,6697]}
		]
	}
}`

type fakeForwarder struct {
	mu       sync.Mutex
	mapErr   error
	extIPErr error
	unmapErr error
	mapped   bool
	unmapped bool
	renewals int
	// renewStopped is set when UnmapPort stops renewal, as the real
	// Forwarder's does.
	renewStopped bool
	externalIP   string
	mapping      *portforward.Mapping
	cancelRenew  context.CancelFunc
}

func (f *fakeForwarder) MapPort(_ context.Context, _ string, internalPort uint16, _ string) (*portforward.Mapping, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mapErr != nil {
		return nil, f.mapErr
	}
	f.mapped = true
	f.mapping = &portforward.Mapping{
		ExternalPort:  internalPort,
		InternalPort:  internalPort,
		InternalIP:    "192.168.1.10",
		Protocol:      "TCP",
		LeaseDuration: time.Hour,
		Method:        "fake",
	}
	return f.mapping, nil
}

func (f *fakeForwarder) UnmapPort(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmapped = true
	if f.cancelRenew != nil {
		f.cancelRenew()
		f.cancelRenew = nil
		f.renewStopped = true
	}
	return f.unmapErr
}

func (f *fakeForwarder) StartRenewal(ctx context.Context) {
	f.mu.Lock()
	f.renewals++
	rctx, cancel := context.WithCancel(ctx)
	f.cancelRenew = cancel
	f.mu.Unlock()
	go func() { <-rctx.Done() }()
}

func (f *fakeForwarder) ExternalIP(_ context.Context) (string, error) {
	if f.extIPErr != nil {
		return "", f.extIPErr
	}
	if f.externalIP == "" {
		return "203.0.113.99", nil
	}
	return f.externalIP, nil
}

func (f *fakeForwarder) wasUnmapped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unmapped
}

func (f *fakeForwarder) wasMapped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mapped
}

// slowMapForwarder blocks MapPort on a gate channel and signals via entered
// when the call is in flight. Used to race two concurrent Starts so the
// test can observe the serialization invariant.
type slowMapForwarder struct {
	gate    chan struct{}
	entered chan struct{}
}

func (f *slowMapForwarder) MapPort(_ context.Context, _ string, internalPort uint16, _ string) (*portforward.Mapping, error) {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.gate
	return &portforward.Mapping{
		ExternalPort: internalPort, InternalPort: internalPort,
		InternalIP: "192.168.1.10", Protocol: "TCP",
		LeaseDuration: time.Hour, Method: "fake",
	}, nil
}
func (f *slowMapForwarder) UnmapPort(context.Context) error { return nil }
func (f *slowMapForwarder) StartRenewal(context.Context)    {}
func (f *slowMapForwarder) ExternalIP(context.Context) (string, error) {
	return "203.0.113.99", nil
}

type fakeBoxService struct {
	startErr  error
	closeErr  error
	started   atomic.Bool
	closed    atomic.Bool
	gotConfig string

	idsMu     sync.Mutex
	shortIDs  [][]string
	updateErr error
	// idsAtStart is the set the inbound held when Start was called, nil for
	// its base ID only.
	idsAtStart []string
	// afterUpdate, if set, runs after a set is applied, as connections on
	// its IDs could arrive then. Set before the box is in use.
	afterUpdate func()
}

func (b *fakeBoxService) Start() error {
	if b.startErr != nil {
		return b.startErr
	}
	b.idsMu.Lock()
	if len(b.shortIDs) > 0 {
		b.idsAtStart = b.shortIDs[len(b.shortIDs)-1]
	}
	b.idsMu.Unlock()
	b.started.Store(true)
	return nil
}

// shortIDsAtStart is the set the inbound held when Start was called.
func (b *fakeBoxService) shortIDsAtStart() []string {
	b.idsMu.Lock()
	defer b.idsMu.Unlock()
	return b.idsAtStart
}

func (b *fakeBoxService) Close() error {
	b.closed.Store(true)
	return b.closeErr
}

// UpdateShortIDs records each set, as the samizdat inbound would apply it.
// With updateErr set it refuses the set and records nothing.
func (b *fakeBoxService) UpdateShortIDs(ids []string) error {
	b.idsMu.Lock()
	defer b.idsMu.Unlock()
	if b.updateErr != nil {
		return b.updateErr
	}
	b.shortIDs = append(b.shortIDs, append([]string(nil), ids...))
	if b.afterUpdate != nil {
		b.idsMu.Unlock()
		b.afterUpdate()
		b.idsMu.Lock()
	}
	return nil
}

func (b *fakeBoxService) setUpdateErr(err error) {
	b.idsMu.Lock()
	defer b.idsMu.Unlock()
	b.updateErr = err
}

// lastShortIDs is the set most recently applied, or nil.
func (b *fakeBoxService) lastShortIDs() []string {
	b.idsMu.Lock()
	defer b.idsMu.Unlock()
	if len(b.shortIDs) == 0 {
		return nil
	}
	return b.shortIDs[len(b.shortIDs)-1]
}

// shortIDUpdates is every set applied, oldest first.
func (b *fakeBoxService) shortIDUpdates() [][]string {
	b.idsMu.Lock()
	defer b.idsMu.Unlock()
	return append([][]string(nil), b.shortIDs...)
}

type stubServer struct {
	t              *testing.T
	server         *httptest.Server
	registerStatus int
	registerResp   RegisterResponse
	verifyStatus   int
	// registerRespFn lets a test return a different response per
	// register call (e.g. cred-rotation tests need a fresh route_id
	// each time). When non-nil, takes precedence over registerResp.
	registerRespFn  func() RegisterResponse
	heartbeatStatus int
	// onRegister, onHeartbeat and onDeregister run before the request is
	// answered.
	onRegister   func()
	onHeartbeat  func()
	onDeregister func()
	// onVerify, when set, runs before verify is answered; a non-zero return
	// replaces the status.
	onVerify         func(LifecycleRequest) int
	deregisterStatus int
	// heartbeatShortIDs, when set, is returned as the heartbeat response's
	// pairing_short_ids with pairing_short_ids_known true. Unset, the
	// heartbeat answers with an empty body, as servers that predate the
	// fields do.
	heartbeatShortIDs atomic.Pointer[[]string]
	// heartbeatRevision is sent as pairing_short_ids_revision with
	// heartbeatShortIDs. Zero means the next of revisions, which, as the
	// server's clock does, increases with each known set the stub sends,
	// in register responses too. noRevisions sends 0 instead.
	heartbeatRevision  atomic.Int64
	revisions          atomic.Int64
	noRevisions        bool
	registerCount      atomic.Int64
	verifyCount        atomic.Int64
	heartbeatCount     atomic.Int64
	deregisterCount    atomic.Int64
	registerDeviceID   atomic.Value // string
	verifyDeviceID     atomic.Value // string
	heartbeatDeviceID  atomic.Value // string
	deregisterDeviceID atomic.Value // string
	lastRegisterReq    atomic.Value // RegisterRequest
	lastVerifyReq      atomic.Value // LifecycleRequest

	// heartbeatShortIDSets, when set, is sent as pairing_short_id_sets with
	// heartbeatShortIDs.
	heartbeatShortIDSets atomic.Pointer[[]PairingShortIDSet]
}

func newStubServer(t *testing.T) *stubServer {
	t.Helper()
	s := &stubServer{
		t:                t,
		registerStatus:   http.StatusOK,
		verifyStatus:     http.StatusOK,
		heartbeatStatus:  http.StatusOK,
		deregisterStatus: http.StatusOK,
		registerResp: RegisterResponse{
			RouteID:                  "00000000-0000-0000-0000-000000000123",
			ServerConfig:             minimalValidLaunchCfg,
			HeartbeatIntervalSeconds: 60,
		},
	}
	// Mount handlers under /v1 so the test mirrors production's versioned
	// baseURL (common.GetBaseURL returns a URL ending in /v1 or /api/v1).
	// Without this prefix, a regression that accidentally re-adds the
	// version segment when composing endpoint URLs would still pass.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/peer/register", func(w http.ResponseWriter, r *http.Request) {
		s.registerCount.Add(1)
		s.registerDeviceID.Store(r.Header.Get("X-Lantern-Device-Id"))
		var req RegisterRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.lastRegisterReq.Store(req)
		if s.onRegister != nil {
			s.onRegister()
		}
		if s.registerStatus != http.StatusOK {
			http.Error(w, "register failed", s.registerStatus)
			return
		}
		resp := s.registerResp
		if s.registerRespFn != nil {
			resp = s.registerRespFn()
		}
		if resp.PairingShortIDsKnown && resp.PairingShortIDsRevision == 0 && !s.noRevisions {
			resp.PairingShortIDsRevision = Revision(s.revisions.Add(1))
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/peer/verify", func(w http.ResponseWriter, r *http.Request) {
		s.verifyCount.Add(1)
		s.verifyDeviceID.Store(r.Header.Get("X-Lantern-Device-Id"))
		var req LifecycleRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.lastVerifyReq.Store(req)
		if s.onVerify != nil {
			if status := s.onVerify(req); status != 0 {
				http.Error(w, "verify failed", status)
				return
			}
		}
		if s.verifyStatus != http.StatusOK {
			http.Error(w, "verify failed", s.verifyStatus)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/peer/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		s.heartbeatCount.Add(1)
		s.heartbeatDeviceID.Store(r.Header.Get("X-Lantern-Device-Id"))
		// Read on arrival, so a response onHeartbeat delays carries what the
		// server knew when the heartbeat was sent.
		ids, rev := s.heartbeatShortIDs.Load(), s.heartbeatRevision.Load()
		if ids != nil && rev == 0 && !s.noRevisions {
			rev = s.revisions.Add(1)
		}
		if s.onHeartbeat != nil {
			s.onHeartbeat()
		}
		if s.heartbeatStatus != http.StatusOK {
			http.Error(w, "heartbeat failed", s.heartbeatStatus)
			return
		}
		if ids != nil {
			resp := HeartbeatResponse{PairingShortIDs: *ids, PairingShortIDsKnown: true, PairingShortIDsRevision: Revision(rev)}
			if sets := s.heartbeatShortIDSets.Load(); sets != nil {
				resp.PairingShortIDSets = *sets
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/peer/deregister", func(w http.ResponseWriter, r *http.Request) {
		s.deregisterCount.Add(1)
		s.deregisterDeviceID.Store(r.Header.Get("X-Lantern-Device-Id"))
		if s.onDeregister != nil {
			s.onDeregister()
		}
		if s.deregisterStatus != http.StatusOK {
			http.Error(w, "deregister failed", s.deregisterStatus)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// newTestClient builds a Client wired to the supplied test doubles. The
// HeartbeatInterval default of 0 leaves the production floor in place
// (caller can override per test).
func newTestClient(t *testing.T, fwd portForwarder, box *fakeBoxService, srv *stubServer, opts ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		// Production baseURL always includes a version segment. Mirror that
		// here so the test catches any future regression in how endpoint
		// URLs are composed from baseURL.
		API: NewAPI(srv.server.Client(), srv.server.URL+"/v1", "test-device"),
		NewForwarder: func(_ context.Context) (portForwarder, error) {
			return fwd, nil
		},
		BuildBoxService: func(_ context.Context, options string) (boxService, error) {
			box.gotConfig = options
			return box, nil
		},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	c, err := NewClient(cfg)
	require.NoError(t, err)
	return c
}

func TestClient_Start_HappyPath(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Stop(ctx) })

	assert.True(t, c.IsActive())
	assert.True(t, fwd.wasMapped())
	assert.True(t, box.started.Load())
	assert.Equal(t, int64(1), srv.registerCount.Load())
	assert.Equal(t, "test-device", srv.registerDeviceID.Load())

	req := srv.lastRegisterReq.Load().(RegisterRequest)
	assert.Equal(t, "203.0.113.42", req.ExternalIP)
	assert.NotZero(t, req.ExternalPort)
	assert.NotZero(t, req.InternalPort)

	// Start must call /peer/verify exactly once after bringing sing-box up,
	// with the route_id returned from Register. Without this the server
	// never confirms the peer is actually reachable from the public side.
	assert.Equal(t, int64(1), srv.verifyCount.Load(), "Start must invoke /peer/verify")
	assert.Equal(t, "test-device", srv.verifyDeviceID.Load())
	verifyReq := srv.lastVerifyReq.Load().(LifecycleRequest)
	assert.Equal(t, "00000000-0000-0000-0000-000000000123", verifyReq.RouteID,
		"/peer/verify must echo the route_id from Register")

	status := c.CurrentStatus()
	assert.True(t, status.Active)
	assert.Equal(t, "203.0.113.42", status.ExternalIP)
	assert.Equal(t, "00000000-0000-0000-0000-000000000123", status.RouteID)
}

// A server-side Verify failure means the listener we just brought up isn't
// reachable through the routed external endpoint. Start must unwind every
// resource it set up so we don't leave a registered route + open box +
// router mapping behind in that bad state.
func TestClient_Start_VerifyFailureUnwinds(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	srv.verifyStatus = http.StatusInternalServerError
	c := newTestClient(t, fwd, box, srv)

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "verify")

	assert.False(t, c.IsActive())
	assert.True(t, fwd.wasUnmapped(), "Verify failure must unmap the port forward")
	assert.True(t, box.closed.Load(), "Verify failure must close the sing-box service")
	assert.Equal(t, int64(1), srv.deregisterCount.Load(),
		"Verify failure must deregister the route we just registered")
	assert.Equal(t, int64(1), srv.verifyCount.Load(), "Verify was attempted exactly once")
}

func TestClient_Start_DoubleStartIsError(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	err := c.Start(context.Background())
	assert.ErrorContains(t, err, "already active")
}

// Two goroutines hitting Start at the same time must not both run setup —
// the second one would overwrite the first's state, leaving the first
// session orphaned with no way to Stop it through this Client.
func TestClient_Start_ConcurrentStartsAreSerialized(t *testing.T) {
	fwd := &slowMapForwarder{
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 1),
	}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	results := make(chan error, 2)
	for range 2 {
		go func() { results <- c.Start(context.Background()) }()
	}
	// Wait for one Start to be inside MapPort holding starting=true; release
	// it once the second Start has had a chance to observe the contended
	// state and reject.
	<-fwd.entered
	close(fwd.gate)

	var nilCount, errCount int
	for range 2 {
		if err := <-results; err == nil {
			nilCount++
		} else {
			errCount++
			assert.ErrorContains(t, err, "already active")
		}
	}
	assert.Equal(t, 1, nilCount, "exactly one Start must succeed")
	assert.Equal(t, 1, errCount, "the racing Start must be rejected")
	assert.Equal(t, int64(1), srv.registerCount.Load())
}

// A Stop that arrives while Start is still in flight must wait for that
// Start to finish — otherwise it returns nil and the racing Start happily
// leaves the client active afterward, which produces the exact orphaned-
// session shape Start's own rollback path is designed to prevent.
func TestClient_Stop_WaitsForInflightStart(t *testing.T) {
	fwd := &slowMapForwarder{
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 1),
	}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	startErr := make(chan error, 1)
	go func() { startErr <- c.Start(context.Background()) }()

	// Wait until Start is blocked inside MapPort (starting=true, active=false).
	<-fwd.entered

	stopErr := make(chan error, 1)
	go func() { stopErr <- c.Stop(context.Background()) }()

	// Stop must not return while Start is still in flight.
	select {
	case <-stopErr:
		t.Fatal("Stop returned before Start finished — would orphan the session")
	case <-time.After(50 * time.Millisecond):
	}

	// Let Start complete. Stop should unblock and tear down what Start set up.
	close(fwd.gate)

	require.NoError(t, <-startErr)
	require.NoError(t, <-stopErr)

	// Client must be in clean post-Stop state — not active and ready to be
	// Started again.
	assert.False(t, c.IsActive())
	assert.Equal(t, int64(1), srv.registerCount.Load(), "Start completed once")
	assert.Equal(t, int64(1), srv.deregisterCount.Load(), "Stop tore down what Start set up")
}

// A Stop with an already-canceled ctx that races a slow Start should give
// up promptly rather than wait forever.
func TestClient_Stop_RespectsCtxWhileWaitingForStart(t *testing.T) {
	fwd := &slowMapForwarder{
		gate:    make(chan struct{}),
		entered: make(chan struct{}, 1),
	}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)
	t.Cleanup(func() {
		close(fwd.gate)
		// Drain the in-flight Start so the test goroutines don't leak.
		_ = c.Stop(context.Background())
	})

	go func() { _ = c.Start(context.Background()) }()
	<-fwd.entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.Stop(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestClient_Start_PortForwardFailureUnwinds(t *testing.T) {
	fwd := &fakeForwarder{mapErr: portforward.ErrNoPortForwarding}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.False(t, c.IsActive())
	assert.Equal(t, int64(0), srv.registerCount.Load())
	assert.False(t, box.started.Load())
}

func TestClient_Start_ExternalIPFailureUnwinds(t *testing.T) {
	fwd := &fakeForwarder{extIPErr: errors.New("gateway returned empty")}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.False(t, c.IsActive())
	assert.True(t, fwd.wasUnmapped(), "port must be unmapped after external-ip failure")
	assert.Equal(t, int64(0), srv.registerCount.Load())
	assert.False(t, box.started.Load())
}

func TestClient_Start_RegisterFailureUnwinds(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	srv.registerStatus = http.StatusUnprocessableEntity
	c := newTestClient(t, fwd, box, srv)

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.False(t, c.IsActive())
	assert.True(t, fwd.wasUnmapped())
	assert.False(t, box.started.Load())
}

// Renewal starts as soon as the port is mapped, before registering: a PCP or
// NAT-PMP gateway can grant a lease shorter than the rest of Start takes. A
// failed Start stops it when it unmaps.
func TestClient_Start_RenewsFromMappingAndStopsOnRollback(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	srv.registerStatus = http.StatusUnprocessableEntity
	var renewingWhileRegistering atomic.Bool
	srv.onRegister = func() {
		fwd.mu.Lock()
		defer fwd.mu.Unlock()
		renewingWhileRegistering.Store(fwd.renewals == 1)
	}
	c := newTestClient(t, fwd, box, srv)

	require.Error(t, c.Start(context.Background()))
	assert.True(t, renewingWhileRegistering.Load(), "renewal must already run while registering")
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	assert.True(t, fwd.renewStopped, "rollback must stop renewal")
}

func TestClient_Start_BoxStartFailureUnwinds(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{startErr: errors.New("boom")}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.False(t, c.IsActive())
	assert.True(t, fwd.wasUnmapped())
	assert.True(t, box.closed.Load())
	assert.Equal(t, int64(1), srv.deregisterCount.Load())
}

// A launch_cfg that fails the abuse-rule sanity check must unwind
// every resource Start has taken so far — port forward, registration
// — without ever building or starting the box. This is the
// defence-in-depth gate that keeps a server-side regression from
// turning every peer into an open proxy.
func TestClient_Start_AbuseRuleValidationFailureUnwinds(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	// Strip the abuse rules from the launch_cfg the stub returns —
	// just the inbound, no route block. peerrules.ValidateAbuseRules will reject
	// this as "missing route block".
	srv.registerResp.ServerConfig = `{"inbounds":[{"type":"samizdat","tag":"samizdat-in"}]}`
	c := newTestClient(t, fwd, box, srv)

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "abuse-rule sanity check")

	assert.False(t, c.IsActive())
	assert.True(t, fwd.wasUnmapped(), "validation failure must unmap the port forward")
	assert.False(t, box.started.Load(), "validation must run before box.Start")
	assert.False(t, box.closed.Load(), "box was never started, nothing to close")
	assert.Equal(t, int64(1), srv.deregisterCount.Load(), "validation failure must deregister the route we just registered")
}

func TestClient_Stop_HappyPath(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	require.NoError(t, c.Stop(ctx))

	assert.False(t, c.IsActive())
	assert.True(t, fwd.wasUnmapped())
	assert.True(t, box.closed.Load())
	assert.Equal(t, int64(1), srv.deregisterCount.Load())
	assert.Equal(t, "test-device", srv.deregisterDeviceID.Load())
}

func TestClient_Stop_IsIdempotent(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	require.NoError(t, c.Stop(ctx))
	require.NoError(t, c.Stop(ctx))
	assert.Equal(t, int64(1), srv.deregisterCount.Load())
}

// Stop continues teardown even if individual steps fail. The first error is
// returned; the others are logged. All resources still get released.
func TestClient_Stop_ContinuesPastIndividualErrors(t *testing.T) {
	fwd := &fakeForwarder{unmapErr: errors.New("router said no")}
	box := &fakeBoxService{closeErr: errors.New("box close failed")}
	srv := newStubServer(t)
	srv.deregisterStatus = http.StatusInternalServerError
	c := newTestClient(t, fwd, box, srv)

	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	err := c.Stop(ctx)
	require.Error(t, err)
	assert.ErrorContains(t, err, "deregister")

	assert.False(t, c.IsActive())
	assert.True(t, fwd.wasUnmapped())
	assert.True(t, box.closed.Load())
	assert.Equal(t, int64(1), srv.deregisterCount.Load())
}

// Drives the loop with a 50ms interval (overridden via Config.HeartbeatInterval)
// against a server that always 404s, then waits for the auto-stop goroutine to
// flip IsActive() false and run teardown.
func TestClient_Heartbeat_404TriggersAutoStop(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	srv.heartbeatStatus = http.StatusNotFound
	c := newTestClient(t, fwd, box, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = 50 * time.Millisecond
		cfg.HeartbeatTimeout = 1 * time.Second
	})

	require.NoError(t, c.Start(context.Background()))

	deadline := time.After(3 * time.Second)
	for c.IsActive() {
		select {
		case <-deadline:
			t.Fatal("client did not auto-stop within 3s")
		case <-time.After(20 * time.Millisecond):
		}
	}

	assert.GreaterOrEqual(t, srv.heartbeatCount.Load(), int64(1))
	assert.Equal(t, "test-device", srv.heartbeatDeviceID.Load())
	assert.Equal(t, int64(1), srv.deregisterCount.Load())
	assert.True(t, fwd.wasUnmapped())
	assert.True(t, box.closed.Load())
}

// Non-404 heartbeat errors must not tear the client down — they're logged
// and the loop keeps trying.
func TestClient_Heartbeat_TransientErrorDoesNotStop(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	srv.heartbeatStatus = http.StatusInternalServerError
	c := newTestClient(t, fwd, box, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = 50 * time.Millisecond
		cfg.HeartbeatTimeout = 1 * time.Second
	})

	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	// Wait long enough for several heartbeats to fire.
	deadline := time.After(500 * time.Millisecond)
	for srv.heartbeatCount.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d heartbeats fired in 500ms", srv.heartbeatCount.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}
	assert.True(t, c.IsActive())
	assert.Equal(t, int64(0), srv.deregisterCount.Load())
}

// The peer's sing-box must bypass the user's own VPN TUN — verify both the
// "no route block at all" and "existing route block" cases get the flag set,
// and that other route-level keys are preserved.
func TestEnsurePeerOutboundsBypassVPN(t *testing.T) {
	ctx := box.Context(context.Background())
	parseOptions := func(t *testing.T, s string) option.Options {
		t.Helper()
		opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, []byte(s))
		require.NoError(t, err)
		return opts
	}

	t.Run("adds route block when missing", func(t *testing.T) {
		in := `{"inbounds":[{"type":"samizdat","tag":"samizdat-in"}]}`
		out, err := ensurePeerOutboundsBypassVPN(in)
		require.NoError(t, err)
		opts := parseOptions(t, out)
		require.NotNil(t, opts.Route)
		assert.True(t, opts.Route.AutoDetectInterface)
		assert.NotEmpty(t, opts.Inbounds, "must preserve other top-level fields")
	})
	t.Run("preserves existing route fields", func(t *testing.T) {
		in := `{"route":{"rules":[{"action":"sniff"}],"final":"direct"}}`
		out, err := ensurePeerOutboundsBypassVPN(in)
		require.NoError(t, err)
		opts := parseOptions(t, out)
		require.NotNil(t, opts.Route)
		assert.True(t, opts.Route.AutoDetectInterface)
		assert.Equal(t, "direct", opts.Route.Final)
		assert.NotEmpty(t, opts.Route.Rules)
	})
	t.Run("rejects malformed json", func(t *testing.T) {
		_, err := ensurePeerOutboundsBypassVPN(`{not json`)
		assert.Error(t, err)
	})
}

func TestPickInternalPort_InRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		p := pickInternalPort()
		assert.GreaterOrEqual(t, int(p), internalPortMin)
		assert.Less(t, int(p), internalPortMax)
	}
}

// pickManualForwarder is the default-NewForwarder factory's first
// branch: setting → env-var → nil (= caller falls through to UPnP).
// Tests each resolution path and the out-of-range / unparseable
// fallthrough behavior. Out-of-range setting + unset env returns nil
// — peer.NewClient's caller treats that as "use UPnP discovery."
func TestPickManualForwarder(t *testing.T) {
	tests := []struct {
		name       string
		setting    int    // 0 means unset
		envVar     string // "" means unset
		wantManual bool
		wantPort   uint16
	}{
		{"setting takes precedence over env", 5698, "1234", true, 5698},
		{"setting only", 5698, "", true, 5698},
		{"env only", 0, "5698", true, 5698},
		{"both unset → fall through", 0, "", false, 0},
		{"setting out of range, env unset → fall through", 70000, "", false, 0},
		{"setting negative, env unset → fall through", -5, "", false, 0},
		{"setting out of range, env valid → env wins", 70000, "5698", true, 5698},
		{"setting unset, env unparseable → fall through", 0, "abc", false, 0},
		{"setting valid low boundary", 1, "", true, 1},
		{"setting valid high boundary", 65535, "", true, 65535},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, settings.InitSettings(t.TempDir()))
			t.Cleanup(settings.Reset)
			if tc.setting != 0 {
				require.NoError(t, settings.Set(settings.PeerManualPortKey, tc.setting))
			}
			t.Setenv("RADIANCE_PEER_EXTERNAL_PORT", tc.envVar)

			fwd := pickManualForwarder()
			if !tc.wantManual {
				assert.Nil(t, fwd, "expected fall-through (nil) but got a forwarder")
				return
			}
			require.NotNil(t, fwd, "expected manual forwarder, got nil")
			// Verify the chosen port via the public MapPort surface —
			// ManualForwarder.port is unexported, MapPort echoes it.
			mapping, err := fwd.MapPort(context.Background(), portforward.TCP, 0, "")
			require.NoError(t, err)
			assert.Equal(t, tc.wantPort, mapping.ExternalPort)
			assert.Equal(t, tc.wantPort, mapping.InternalPort)
		})
	}
}

func TestAPIError_StringFormat(t *testing.T) {
	e := &APIError{Status: 422, Body: "could not connect to peer port"}
	assert.Contains(t, e.Error(), "422")
	assert.Contains(t, e.Error(), "could not connect")
}

// TestClient_RotatesCredentialsAtInterval pins the rotation invariant:
// the peer client must re-register and rebuild its libbox inbound on
// a schedule so a leaked credential's blast radius is bounded by
// CredRotationInterval rather than peer process lifetime.
//
// Drives a short rotation interval (50ms) and asserts:
//  1. Multiple registers happen (start + ≥2 rotations within 250ms).
//  2. Each rotation deregisters the prior route_id.
//  3. The peer's exposed RouteID changes — clients freshly assigned
//     after a rotation see the new ID; the bandit catalog stops
//     handing out the old one once Deregister lands.
//  4. Multiple distinct boxes were built (the rotation actually
//     rebuilt libbox; not just a no-op).
//  5. The first box was closed (the old listener released its port).
func TestClient_RotatesCredentialsAtInterval(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	srv := newStubServer(t)

	// Each rotation needs a register response with a distinct
	// route_id so we can verify the swap actually changed identifiers
	// rather than re-registering the same id.
	var registerSeq atomic.Int64
	srv.registerRespFn = func() RegisterResponse {
		n := registerSeq.Add(1)
		return RegisterResponse{
			RouteID:                  fmt.Sprintf("00000000-0000-0000-0000-00000000000%d", n),
			ServerConfig:             minimalValidLaunchCfg,
			HeartbeatIntervalSeconds: 60,
		}
	}

	// Each BuildBoxService call gets a fresh fakeBoxService so we can
	// see how many boxes were built and which ones got closed.
	var (
		boxesMu sync.Mutex
		boxes   []*fakeBoxService
	)
	c := newTestClient(t, fwd, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = 50 * time.Millisecond
		// Long heartbeat so heartbeat ticks don't compete with the
		// register/deregister counters that we're asserting on.
		cfg.HeartbeatInterval = time.Hour
		cfg.BuildBoxService = func(_ context.Context, options string) (boxService, error) {
			b := &fakeBoxService{gotConfig: options}
			boxesMu.Lock()
			boxes = append(boxes, b)
			boxesMu.Unlock()
			return b, nil
		}
	})

	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	// Wait for at least 2 rotations on top of the initial register.
	require.Eventually(t, func() bool {
		return srv.registerCount.Load() >= 3
	}, 1*time.Second, 25*time.Millisecond,
		"expected ≥3 registers (initial + 2 rotations) within 1s; got %d",
		srv.registerCount.Load())

	// Each rotation deregisters the prior route — N rotations =>
	// N deregisters (initial register is not preceded by one). Wait
	// briefly for the deregister to catch up to the most recent
	// rotation; rotation issues the deregister after the swap-lock
	// completes, so there's a small race window between observing the
	// new register and the corresponding deregister landing.
	rotations := srv.registerCount.Load() - 1
	require.Eventually(t, func() bool {
		return srv.deregisterCount.Load() >= rotations
	}, 500*time.Millisecond, 25*time.Millisecond,
		"each rotation should deregister the prior route_id (got %d deregs vs %d rotations)",
		srv.deregisterCount.Load(), rotations)

	// RouteID exposed via Status should reflect the latest rotation.
	// Asserting against CurrentStatus() rather than the internal field
	// pins the observable contract: a future change that updates the
	// route used by heartbeats but forgets to mirror it into
	// Status.RouteID would fail this assertion.
	assert.NotEqual(t, "00000000-0000-0000-0000-000000000001", c.CurrentStatus().RouteID,
		"current route_id should have advanced past the initial register")

	// Multiple boxes built; first one closed.
	boxesMu.Lock()
	defer boxesMu.Unlock()
	require.GreaterOrEqual(t, len(boxes), 2,
		"expected ≥2 libbox builds (initial + ≥1 rotation)")
	assert.True(t, boxes[0].closed.Load(),
		"first box should be closed by the first rotation")
}

// TestClient_StatusEventEmittedOnStartAndStop pins the full lifecycle
// phase sequence: Start fires one StatusEvent per stage so the UI can
// render granular progress (mapping port → registering → verifying →
// serving) instead of a single active/inactive flip. Stop fires
// stopping → idle on the way back down.
//
// Subscribers (the IPC SSE handler in production) need every edge so the
// UI can render fresh state without polling.
func TestClient_StatusEventEmittedOnStartAndStop(t *testing.T) {
	fwd := &fakeForwarder{}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	// Buffer must exceed total emit count (6 on Start: mapping → detecting
	// → registering → starting_proxy → verifying → serving; 2 on Stop:
	// stopping → idle) or the subscriber's send blocks and emits drop.
	got := make(chan StatusEvent, 16)
	sub := events.Subscribe(func(evt StatusEvent) {
		got <- evt
	})
	defer sub.Unsubscribe()

	require.NoError(t, c.Start(context.Background()))

	// events.Emit dispatches each callback in a separate goroutine, so
	// the order events land on the channel isn't deterministic — assert
	// set-membership of the expected phases + the final-state contract
	// (the only state observers actually care about) rather than the
	// sequence.
	wantStartPhases := map[Phase]bool{
		PhaseMappingPort: true,
		PhaseDetectingIP: true,
		PhaseRegistering: true,
		PhaseStartingBox: true,
		PhaseVerifying:   true,
		PhaseServing:     true,
	}
	startEvents := drainPhases(t, got, len(wantStartPhases))
	for want := range wantStartPhases {
		assert.Contains(t, startEvents, want, "Start sequence missing phase %q", want)
	}
	servingEvt, ok := startEvents[PhaseServing]
	require.True(t, ok, "Start sequence must reach PhaseServing")
	assert.True(t, servingEvt.Status.Active, "active must be true on serving")
	assert.NotEmpty(t, servingEvt.Status.RouteID, "route_id must be set on serving")
	for phase, evt := range startEvents {
		if phase == PhaseServing {
			continue
		}
		assert.False(t, evt.Status.Active, "active must be false on intermediate phase %q", phase)
	}

	require.NoError(t, c.Stop(context.Background()))
	wantStopPhases := map[Phase]bool{
		PhaseStopping: true,
		PhaseIdle:     true,
	}
	stopEvents := drainPhases(t, got, len(wantStopPhases))
	for want := range wantStopPhases {
		assert.Contains(t, stopEvents, want, "Stop sequence missing phase %q", want)
	}
	for phase, evt := range stopEvents {
		assert.False(t, evt.Status.Active, "active must be false during stop (phase %q)", phase)
	}
}

// drainPhases reads up to n StatusEvents from got and returns them
// keyed by Phase (last event per phase wins). Used by tests that care
// which phases occurred rather than in what order. The bus does deliver
// them in order now, so those tests could assert the sequence instead;
// they do not, because the phase a given step emits is not what they are
// pinning.
func drainPhases(t *testing.T, got <-chan StatusEvent, n int) map[Phase]StatusEvent {
	t.Helper()
	out := make(map[Phase]StatusEvent, n)
	deadline := time.After(2 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case evt := <-got:
			out[evt.Status.Phase] = evt
		case <-deadline:
			t.Fatalf("received only %d/%d status events within 2s; got phases: %v",
				i, n, mapKeys(out))
		}
	}
	return out
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestClient_StatusEventOnStartError surfaces a Start failure to the UI
// via PhaseError with the wrapped error message. Without this, a user
// who clicks SmC-on and hits e.g. a UPnP failure sees the toggle silently
// flip back without any diagnostic.
func TestClient_StatusEventOnStartError(t *testing.T) {
	fwd := &fakeForwarder{mapErr: errors.New("upnp gateway refused mapping")}
	box := &fakeBoxService{}
	srv := newStubServer(t)
	c := newTestClient(t, fwd, box, srv)

	got := make(chan StatusEvent, 16)
	sub := events.Subscribe(func(evt StatusEvent) { got <- evt })
	defer sub.Unsubscribe()

	err := c.Start(context.Background())
	require.Error(t, err)

	var sawError bool
	deadline := time.After(time.Second)
	for !sawError {
		select {
		case evt := <-got:
			if evt.Status.Phase == PhaseError {
				sawError = true
				assert.False(t, evt.Status.Active)
				assert.Contains(t, evt.Status.Error, "upnp gateway refused mapping",
					"error message must surface so the UI can render a real diagnostic")
			}
		case <-deadline:
			t.Fatal("no PhaseError status event within 1s")
		}
	}
}

var _ portForwarder = (*fakeForwarder)(nil)
var _ boxService = (*fakeBoxService)(nil)

// samizdatInboundJSON is a minimal but complete samizdat inbound: every field
// option.SamizdatInboundOptions's json tags require to round-trip. Values are
// placeholders; the box is never started.
const samizdatInboundJSON = `{
	"type": "samizdat",
	"tag": "samizdat-in",
	"listen": "127.0.0.1",
	"listen_port": 5698,
	"private_key": "0000000000000000000000000000000000000000000000000000000000000000",
	"short_ids": ["0000000000000000"],
	"cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBhTCCASugAwIBAgIQCHOFXAcuEzPfyHK6LdwxwzAKBggqhkjOPQQDAjATMREw\nDwYDVQQKEwhJbnRlcm5ldDAeFw0yNjA1MDYwMDAwMDBaFw0yNzA1MDYwMDAwMDBa\nMBMxETAPBgNVBAoTCEludGVybmV0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\nb6xQ7UDl11wL/8mZwLxrNqx6JJ+FczIw9V0a9Q3CYUYFGu5DzVyDUwmfVTZiQ+wR\nkQXjrkAwsOWK99JsM3R2bqNIMEYwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG\nCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwEQYDVR0RBAowCIIGdGVzdC5xMAoGCCqG\nSM49BAMCA0kAMEYCIQCqhyaQaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaIh\nAOaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n-----END CERTIFICATE-----\n",
	"key_pem": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaoAoGCCqGSM49\nAwEHoUQDQgAEb6xQ7UDl11wL/8mZwLxrNqx6JJ+FczIw9V0a9Q3CYUYFGu5DzVyD\nUwmfVTZiQ+wRkQXjrkAwsOWK99JsM3R2bg==\n-----END EC PRIVATE KEY-----\n",
	"masquerade_domain": "example.com"
}`

// TestDefaultBuildBoxService_DecodesSamizdatInbound is the regression net
// for the "missing inbound fields registry in context" failure that bit
// us live: the peer box was built from a ctx that didn't have the
// lantern-box protocol registries (samizdat, reflex, …) plumbed in, so the
// JSON decoder couldn't resolve inbounds[0].type="samizdat" → the build
// failed → applyPeerShare rolled the toggle back. The integration tests
// stub BuildBoxService entirely, so the samizdat decode path was never
// exercised in CI.
//
// Calling defaultBuildBoxService directly with a minimal samizdat-inbound
// options JSON walks the actual decode path. If the registries are missing
// from the ctx it produces, the decode fails with the "missing inbound
// fields registry" error and this test fails before any of the runtime
// cycle (rebuild, redeploy, toggle UI, dial-back) — what used to take a
// 5-minute round-trip is now a 0.1s test failure.
func TestDefaultBuildBoxService_DecodesSamizdatInbound(t *testing.T) {
	bs, err := defaultBuildBoxService(context.Background(), `{"inbounds":[`+samizdatInboundJSON+`]}`)
	require.NoError(t, err, "defaultBuildBoxService must decode a samizdat inbound — "+
		"the lantern-box protocol registries have to be in ctx")
	require.NotNil(t, bs)
	// We never call Start; just verifying the decode path. Close drops
	// any background structures the box might have stood up.
	_ = bs.Close()
}

func TestDefaultBuildBoxService_BuildsAbuseBlockingLaunchCfg(t *testing.T) {
	// Building binds the inbound, and an unstarted box keeps it bound after Close.
	inbound := strings.Replace(samizdatInboundJSON, `"listen_port": 5698`, `"listen_port": 0`, 1)
	cfg := strings.Replace(minimalValidLaunchCfg, `{"type":"samizdat","tag":"samizdat-in"}`, inbound, 1)
	require.NotEqual(t, minimalValidLaunchCfg, cfg)
	bs, err := defaultBuildBoxService(context.Background(), cfg)
	require.NoError(t, err)
	_ = bs.Close()
}

func TestDefaultBuildBoxService_DeniesHostAccess(t *testing.T) {
	denied := map[string]string{
		"outbound":     `{"outbounds":[{"type":"bridge","tag":"bridge"}]}`,
		"route action": `{"route":{"rules":[{"action":"route-options","tls_spoof":"example.com"}]}}`,
		"http client":  `{"http_clients":[{"tag":"client","netns":"/proc/1/ns/net"}]}`,
		"certificate provider": `{"certificate_providers":[{"type":"cloudflare-origin-ca","tag":"origin-ca",` +
			`"domain":["example.com"],"api_token":"token","data_directory":"/etc"}]}`,
	}
	for name, cfg := range denied {
		_, err := defaultBuildBoxService(context.Background(), cfg)
		assert.ErrorIs(t, err, hostaccess.ErrDenied, name)
	}
}

func TestNewPeerBoxContext_LogFactoryIsRetrievable(t *testing.T) {
	ctx := newPeerBoxContext(context.Background())
	require.NotNil(t, service.FromContext[sblog.Factory](ctx),
		"the registered log factory must be readable from the box's context, "+
			"or this box logs only to stderr")
}

func TestNewPeerBoxContext_ResolvesInboundRegistry(t *testing.T) {
	ctx := newPeerBoxContext(context.Background())
	assert.NotNil(t, service.FromContext[option.InboundOptionsRegistry](ctx),
		"registering the log factory must not displace the protocol registries "+
			"sing-box needs to decode the samizdat inbound")
}

func TestNewPeerBoxContext_InheritsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	boxCtx := newPeerBoxContext(ctx)
	require.NoError(t, boxCtx.Err())

	cancel()

	select {
	case <-boxCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("peer box context did not observe the caller's cancel")
	}
	assert.ErrorIs(t, boxCtx.Err(), context.Canceled)
}

func TestNewPeerBoxContext_RegistryStableAcrossLookups(t *testing.T) {
	// service.MustRegister mutates whichever registry the context hands back, so
	// a per-lookup rebuild would write the log factory into an object discarded
	// before sing-box reads it. Pin that both lookups resolve to one registry.
	ctx := newPeerBoxContext(context.Background())
	first := service.RegistryFromContext(ctx)
	second := service.RegistryFromContext(ctx)
	require.NotNil(t, first)
	assert.True(t, first == second, "every lookup must resolve to one registry")
}

// All four peer endpoints must carry the same standard header set as
// /config-new (X-Lantern-Config-Client-IP in particular). The server's
// util.ClientIPWithAddr prefers that header over X-Forwarded-For and
// RemoteAddr; without it, register/verify resolve a different IP than
// radiance has detected, and the server's verifier dials an address the
// peer's listener isn't bound to.
func TestAPI_ForwardsCommonHeaders(t *testing.T) {
	const fakePublicIP = "198.51.100.7"
	common.SetPublicIP(fakePublicIP)
	t.Cleanup(func() { common.SetPublicIP("") })

	type capture struct {
		clientIP  string
		deviceID  string
		platform  string
		appName   string
		userAgent string
	}
	captured := make(map[string]capture)
	var mu sync.Mutex
	record := func(path string, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		captured[path] = capture{
			clientIP:  r.Header.Get(common.ClientIPHeader),
			deviceID:  r.Header.Get(common.DeviceIDHeader),
			platform:  r.Header.Get(common.PlatformHeader),
			appName:   r.Header.Get(common.AppNameHeader),
			userAgent: r.Header.Get("User-Agent"),
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/peer/register", func(w http.ResponseWriter, r *http.Request) {
		record("/peer/register", r)
		_ = json.NewEncoder(w).Encode(RegisterResponse{
			RouteID:                  "00000000-0000-0000-0000-000000000123",
			ServerConfig:             `{}`,
			HeartbeatIntervalSeconds: 60,
		})
	})
	mux.HandleFunc("/peer/verify", func(w http.ResponseWriter, r *http.Request) {
		record("/peer/verify", r)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/peer/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		record("/peer/heartbeat", r)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/peer/deregister", func(w http.ResponseWriter, r *http.Request) {
		record("/peer/deregister", r)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	api := NewAPI(srv.Client(), srv.URL, "test-device-id")
	ctx := context.Background()

	_, err := api.Register(ctx, RegisterRequest{ExternalIP: "203.0.113.42", ExternalPort: 5698, InternalPort: 35698})
	require.NoError(t, err)
	require.NoError(t, api.Verify(ctx, "00000000-0000-0000-0000-000000000123"))
	_, err = api.Heartbeat(ctx, "00000000-0000-0000-0000-000000000123", 0, RelayUsage{})
	require.NoError(t, err)
	require.NoError(t, api.Deregister(ctx, "00000000-0000-0000-0000-000000000123"))

	for _, path := range []string{"/peer/register", "/peer/verify", "/peer/heartbeat", "/peer/deregister"} {
		mu.Lock()
		c, ok := captured[path]
		mu.Unlock()
		require.True(t, ok, "no request captured for %s", path)
		assert.Equal(t, fakePublicIP, c.clientIP,
			"%s must forward radiance's detected public IP via %s "+
				"so server-side ClientIPWithAddr resolves the same IP it does for /config-new",
			path, common.ClientIPHeader)
		assert.Equal(t, "test-device-id", c.deviceID, "%s must carry %s", path, common.DeviceIDHeader)
		assert.NotEmpty(t, c.platform, "%s must carry %s", path, common.PlatformHeader)
		assert.NotEmpty(t, c.appName, "%s must carry %s", path, common.AppNameHeader)
	}
}

// Rotation installs a freshly fetched launch_cfg on an already-running peer,
// so it has to re-apply the same abuse-rule gate Start does. Validating only
// at Start would let a server-side regression reach every long-lived peer on
// its next hourly rotation — the exact scenario the gate exists to prevent.
// A rejected rotation must leave the current, already validated box serving.
func TestClient_RotationRejectsLaunchCfgMissingAbuseRules(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	srv := newStubServer(t)

	var registerSeq atomic.Int64
	srv.registerRespFn = func() RegisterResponse {
		n := registerSeq.Add(1)
		cfg := minimalValidLaunchCfg
		if n > 1 {
			// The rotation response drops the route block entirely.
			cfg = `{"inbounds":[{"type":"samizdat","tag":"samizdat-in"}]}`
		}
		return RegisterResponse{
			RouteID:                  fmt.Sprintf("00000000-0000-0000-0000-00000000000%d", n),
			ServerConfig:             cfg,
			HeartbeatIntervalSeconds: 60,
		}
	}

	var (
		boxesMu sync.Mutex
		boxes   []*fakeBoxService
	)
	c := newTestClient(t, fwd, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = 30 * time.Millisecond
		cfg.HeartbeatInterval = time.Hour
		cfg.BuildBoxService = func(_ context.Context, _ string) (boxService, error) {
			b := &fakeBoxService{}
			boxesMu.Lock()
			boxes = append(boxes, b)
			boxesMu.Unlock()
			return b, nil
		}
	})

	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	// Give the rotation loop several chances to attempt the bad config.
	require.Eventually(t, func() bool { return srv.registerCount.Load() >= 2 },
		3*time.Second, 10*time.Millisecond, "rotation never re-registered")
	time.Sleep(100 * time.Millisecond)

	boxesMu.Lock()
	built := len(boxes)
	firstClosed := boxes[0].closed.Load()
	boxesMu.Unlock()

	assert.Equal(t, 1, built,
		"a launch_cfg missing abuse rules must be rejected before a new box is built")
	assert.False(t, firstClosed,
		"the original validated box must keep serving when a rotation is rejected")
	assert.True(t, c.IsActive(), "the peer must stay active after a rejected rotation")
	assert.Positive(t, srv.deregisterCount.Load(),
		"the orphan route created for the rejected rotation must be deregistered")
}

// TestTrackConn_CountsDistinctIPsNotConnections pins the reason ActiveClients
// keys on IP: samizdat multiplexes many H2 streams over one TCP conn and a
// client may hold several, so counting events would report more people helped
// than there are people.
func TestTrackConn_CountsDistinctIPsNotConnections(t *testing.T) {
	c := &Client{}

	c.trackConn(1, "203.0.113.7:44001")
	c.trackConn(1, "203.0.113.7:44002")
	c.trackConn(1, "203.0.113.7:44003")
	assert.Equal(t, 1, c.ActiveClients(), "one device with three connections is one client")

	c.trackConn(1, "198.51.100.9:55001")
	assert.Equal(t, 2, c.ActiveClients())

	// The device stays counted until its LAST connection closes.
	c.trackConn(-1, "203.0.113.7:44001")
	c.trackConn(-1, "203.0.113.7:44002")
	assert.Equal(t, 2, c.ActiveClients(), "still holding one connection")
	c.trackConn(-1, "203.0.113.7:44003")
	assert.Equal(t, 1, c.ActiveClients())
}

// TestTrackConn_IgnoresUnmatchedClose guards the count against going negative.
// peerconn is process-wide, so a close for a connection accepted before this
// Client registered its listener can still arrive.
func TestTrackConn_IgnoresUnmatchedClose(t *testing.T) {
	c := &Client{}

	c.trackConn(-1, "203.0.113.7:44001")
	assert.Equal(t, 0, c.ActiveClients())

	c.trackConn(1, "203.0.113.7:44001")
	c.trackConn(-1, "203.0.113.7:44001")
	c.trackConn(-1, "203.0.113.7:44001")
	assert.Equal(t, 0, c.ActiveClients(), "an extra close must not drive the tally below zero")

	c.trackConn(1, "198.51.100.9:55001")
	assert.Equal(t, 1, c.ActiveClients(), "and must not corrupt later counting")
}

// TestIsVerifierConn_PairsCloseWithAccept pins that a verifier close, which
// carries no destination, is matched by the source its accept recorded, and
// that an ordinary connection from the same IP is not swept up with it.
func TestIsVerifierConn_PairsCloseWithAccept(t *testing.T) {
	c := &Client{}

	assert.True(t, c.isVerifierConn(1, "35.233.177.182:33792", "api.iantem.io:443", nil))
	assert.True(t, c.isVerifierConn(1, "35.233.177.183:1000", "API.staging.iantem.io:443", nil))
	assert.False(t, c.isVerifierConn(1, "35.233.177.182:33793", "google.com:443", nil))

	assert.True(t, c.isVerifierConn(-1, "35.233.177.182:33792", "", nil))
	assert.False(t, c.isVerifierConn(-1, "35.233.177.182:33792", "", nil),
		"a second close for the same source is not the verifier's")
	assert.False(t, c.isVerifierConn(-1, "35.233.177.182:33793", "", nil))

	c.resetConnTracking()
	assert.False(t, c.isVerifierConn(-1, "35.233.177.183:1000", "", nil),
		"a reset forgets verifier connections from the old session")
}

// TestClient_VerifierStreamsSharingASource covers samizdat multiplexing: a
// client's ordinary stream and two api.iantem.io streams share one source.
// Both hidden accepts must hide a close each, so the ordinary stream stays
// counted until its own close.
func TestClient_VerifierStreamsSharingASource(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	c := newTestClient(t, fwd, &fakeBoxService{}, newStubServer(t))
	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	defer func() { require.NoError(t, c.Stop(ctx)) }()

	const src = "5.119.14.105:10304"
	peerconn.Notify(peerconn.Event{State: +1, Source: src, Destination: "google.com:443"})
	peerconn.Notify(peerconn.Event{State: +1, Source: src, Destination: "api.iantem.io:443"})
	peerconn.Notify(peerconn.Event{State: +1, Source: src, Destination: "api.iantem.io:443"})
	require.Equal(t, 1, c.ActiveClients())

	peerconn.Notify(peerconn.Event{State: -1, Source: src})
	peerconn.Notify(peerconn.Event{State: -1, Source: src})
	assert.Equal(t, 1, c.ActiveClients(), "two hidden accepts absorb two closes")
	peerconn.Notify(peerconn.Event{State: -1, Source: src})
	assert.Equal(t, 0, c.ActiveClients())
}

// TestClient_HidesVerifierConnections covers lantern-cloud's verify callback,
// which reaches api.iantem.io through the peer: it must not reach the UI as a
// person helped nor be reported to the server as a client.
func TestClient_HidesVerifierConnections(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	c := newTestClient(t, fwd, &fakeBoxService{}, newStubServer(t))
	ctx := context.Background()

	got := make(chan ConnectionEvent, 8)
	sub := events.Subscribe(func(evt ConnectionEvent) { got <- evt })
	defer sub.Unsubscribe()

	require.NoError(t, c.Start(ctx))
	peerconn.Notify(peerconn.Event{State: +1, Source: "35.233.177.182:33792", Destination: "api.iantem.io:443"})
	peerconn.Notify(peerconn.Event{State: +1, Source: "5.119.14.105:10304", Destination: "google.com:443"})
	assert.Equal(t, 1, c.ActiveClients(), "the verifier is not a client")
	peerconn.Notify(peerconn.Event{State: -1, Source: "35.233.177.182:33792"})
	peerconn.Notify(peerconn.Event{State: -1, Source: "5.119.14.105:10304"})

	var sources []string
	for len(sources) < 2 {
		select {
		case evt := <-got:
			sources = append(sources, evt.Source)
		case <-time.After(2 * time.Second):
			t.Fatalf("got %d connection events, want 2", len(sources))
		}
	}
	assert.Equal(t, []string{"5.119.14.105:10304", "5.119.14.105:10304"}, sources)
	select {
	case evt := <-got:
		t.Fatalf("unexpected connection event for %s", evt.Source)
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, c.Stop(ctx))
}

// TestResetConnTracking_ClearsAcrossSessions covers Stop → Start: the new
// session's box has its own connections, so inheriting the old tally would
// report load that no longer exists.
func TestResetConnTracking_ClearsAcrossSessions(t *testing.T) {
	c := &Client{}
	c.trackConn(1, "203.0.113.7:44001")
	c.trackConn(1, "198.51.100.9:55001")
	require.Equal(t, 2, c.ActiveClients())

	c.resetConnTracking()
	assert.Equal(t, 0, c.ActiveClients())

	c.trackConn(1, "203.0.113.7:44001")
	assert.Equal(t, 1, c.ActiveClients(), "tracking still works after a reset")
}

// TestTrackConn_DropsCountsWhileDraining covers the race the drain flag exists
// for. A peerconn callback that passed the listener wrapper's check before Stop
// set the flag can still reach trackConn after resetConnTracking cleared the
// map; without a second check under connsMu it would repopulate the map and
// leak a stale count into the next Start.
func TestTrackConn_DropsCountsWhileDraining(t *testing.T) {
	c := &Client{}
	c.trackConn(1, "203.0.113.7:44001")
	require.Equal(t, 1, c.ActiveClients())

	// Teardown ordering: flag first, then the reset.
	c.listenerDraining.Store(true)
	c.resetConnTracking()

	// The straggler callback lands here.
	c.trackConn(1, "198.51.100.9:55001")
	assert.Equal(t, 0, c.ActiveClients(),
		"a callback outliving Stop must not repopulate the tally")

	// A subsequent Start clears the flag and counting resumes.
	c.listenerDraining.Store(false)
	c.trackConn(1, "198.51.100.9:55001")
	assert.Equal(t, 1, c.ActiveClients())
}

func TestAPI_HeartbeatReturnsPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	api := NewAPI(srv.server.Client(), srv.server.URL+"/v1", "test-device")
	resp, err := api.Heartbeat(context.Background(), "00000000-0000-0000-0000-000000000123", 0, RelayUsage{})
	require.NoError(t, err, "an empty body is a heartbeat from a server that predates pairings")
	assert.Empty(t, resp.PairingShortIDs)
	assert.False(t, resp.PairingShortIDsKnown)

	srv.heartbeatShortIDs.Store(&[]string{"1111111111111111"})
	srv.heartbeatRevision.Store(1761004800000)
	resp, err = api.Heartbeat(context.Background(), "00000000-0000-0000-0000-000000000123", 0, RelayUsage{})
	require.NoError(t, err)
	assert.Equal(t, []string{"1111111111111111"}, resp.PairingShortIDs)
	assert.True(t, resp.PairingShortIDsKnown)
	assert.Equal(t, Revision(1761004800000), resp.PairingShortIDsRevision)
}

func TestAPI_HeartbeatToleratesMissingPairingFields(t *testing.T) {
	cases := map[string]struct {
		body      string
		wantIDs   []string
		wantKnown bool
		wantRev   Revision
	}{
		// lantern-cloud's protojson encodes int64 as a JSON string.
		"string revision": {
			body:    `{"pairing_short_ids":["1111111111111111"],"pairing_short_ids_known":true,"pairing_short_ids_revision":"1800000450000"}`,
			wantIDs: []string{"1111111111111111"}, wantKnown: true, wantRev: 1800000450000,
		},
		"number revision": {
			body:    `{"pairing_short_ids":["1111111111111111"],"pairing_short_ids_known":true,"pairing_short_ids_revision":1800000450000}`,
			wantIDs: []string{"1111111111111111"}, wantKnown: true, wantRev: 1800000450000,
		},
		"revision not a number": {
			body: `{"pairing_short_ids":["1111111111111111"],"pairing_short_ids_known":true,"pairing_short_ids_revision":"soon"}`,
		},
		"empty body":          {body: ""},
		"empty object":        {body: "{}"},
		"ids without known":   {body: `{"pairing_short_ids":["1111111111111111"]}`, wantIDs: []string{"1111111111111111"}},
		"known false":         {body: `{"pairing_short_ids":[],"pairing_short_ids_known":false}`, wantIDs: []string{}},
		"known with no pairs": {body: `{"pairing_short_ids":[],"pairing_short_ids_known":true}`, wantIDs: []string{}, wantKnown: true},
		"malformed json":      {body: `{"pairing_short_ids":["1111`},
		"known wrong type":    {body: `{"pairing_short_ids":["1111111111111111"],"pairing_short_ids_known":"yes"}`},
		"ids wrong type":      {body: `{"pairing_short_ids":"1111111111111111","pairing_short_ids_known":true}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/peer/heartbeat", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			api := NewAPI(srv.Client(), srv.URL, "test-device")
			resp, err := api.Heartbeat(context.Background(), "00000000-0000-0000-0000-000000000123", 0, RelayUsage{})
			require.NoError(t, err)
			assert.Equal(t, tc.wantIDs, resp.PairingShortIDs)
			assert.Equal(t, tc.wantKnown, resp.PairingShortIDsKnown)
			assert.Equal(t, tc.wantRev, resp.PairingShortIDsRevision)
		})
	}
}

func TestAPI_RegisterDecodesStringRevision(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/peer/register", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"route_id":"00000000-0000-0000-0000-000000000123","server_config":"{}",` +
			`"heartbeat_interval_seconds":60,"pairing_short_ids":["2222222222222222"],` +
			`"pairing_short_ids_known":true,"pairing_short_ids_revision":"1800000450000"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	api := NewAPI(srv.Client(), srv.URL, "test-device")
	resp, err := api.Register(context.Background(), RegisterRequest{ExternalIP: "203.0.113.42", ExternalPort: 5698})
	require.NoError(t, err)
	assert.Equal(t, Revision(1800000450000), resp.PairingShortIDsRevision)
	assert.True(t, resp.PairingShortIDsKnown)
}

func TestAPI_RegisterReturnsPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.PairingShortIDs = []string{"2222222222222222"}
	srv.registerResp.PairingShortIDsKnown = true
	srv.registerResp.PairingShortIDsRevision = 1761004800000
	api := NewAPI(srv.server.Client(), srv.server.URL+"/v1", "test-device")
	resp, err := api.Register(context.Background(), RegisterRequest{ExternalIP: "203.0.113.42", ExternalPort: 5698})
	require.NoError(t, err)
	assert.Equal(t, []string{"2222222222222222"}, resp.PairingShortIDs)
	assert.True(t, resp.PairingShortIDsKnown)
	assert.Equal(t, Revision(1761004800000), resp.PairingShortIDsRevision)
}

func TestRegisterRequest_ServePoolOmittedUnlessSet(t *testing.T) {
	buf, err := json.Marshal(RegisterRequest{ExternalIP: "203.0.113.42"})
	require.NoError(t, err)
	assert.NotContains(t, string(buf), "serve_pool")

	off := false
	buf, err = json.Marshal(RegisterRequest{ExternalIP: "203.0.113.42", ServePool: &off})
	require.NoError(t, err)
	assert.Contains(t, string(buf), `"serve_pool":false`)
}

func TestClient_RegisterSendsServePool(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	srv := newStubServer(t)
	c := newTestClient(t, &fakeForwarder{}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = time.Hour
	})
	ctx := context.Background()

	require.NoError(t, c.Start(ctx))
	assert.Nil(t, srv.lastRegisterReq.Load().(RegisterRequest).ServePool,
		"unset means help others too, which the server assumes when the field is absent")
	require.NoError(t, c.Stop(ctx))

	require.NoError(t, settings.Set(settings.PeerServePoolKey, false))
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Stop(ctx) })
	sp := srv.lastRegisterReq.Load().(RegisterRequest).ServePool
	require.NotNil(t, sp, "a volunteer serving only its pairings must say so")
	assert.False(t, *sp)
}

// TestClient_PairingsOnlyRegistersWithoutThePool checks that a run for pairings only registers serve_pool=false even when "help others
// too" is on, and follows the setting again once it isn't pairings-only.
func TestClient_PairingsOnlyRegistersWithoutThePool(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.Set(settings.PeerServePoolKey, true))
	var pairingsOnly atomic.Bool
	pairingsOnly.Store(true)
	srv := newStubServer(t)
	c := newTestClient(t, &fakeForwarder{}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = time.Hour
		cfg.PairingsOnly = pairingsOnly.Load
	})
	ctx := context.Background()

	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Stop(ctx) })
	sp := srv.lastRegisterReq.Load().(RegisterRequest).ServePool
	require.NotNil(t, sp)
	assert.False(t, *sp)
	assert.False(t, c.MayServePool())
	assert.True(t, c.CurrentStatus().PairingsOnly, "the status names the run it describes")

	pairingsOnly.Store(false)
	c.RetagStatus()
	assert.False(t, c.CurrentStatus().PairingsOnly, "a hand-off re-tags it")
	require.NoError(t, c.Reregister(ctx))
	assert.Nil(t, srv.lastRegisterReq.Load().(RegisterRequest).ServePool,
		"sharing takes over the same run and serves the pool again")
	assert.True(t, c.MayServePool())
}

// TestClient_MayServePoolErrsTowardThePool checks that MayServePool errs toward true while a box serves: a registration in flight
// reads true, a failed pool registration leaves it true and a pool-free one
// can't add it. A committed pool-free registration clears it, as does no box
// serving: a stop or a failed Start.
func TestClient_MayServePoolErrsTowardThePool(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	var pairingsOnly atomic.Bool
	srv := newStubServer(t)
	// holdRegister, when set, holds the next register until it is closed;
	// inRegister says a register is being held.
	var holdRegister atomic.Pointer[chan struct{}]
	inRegister := make(chan struct{}, 1)
	srv.onRegister = func() {
		if hold := holdRegister.Swap(nil); hold != nil {
			inRegister <- struct{}{}
			<-*hold
		}
	}
	var c *Client
	held := func(f func() error) {
		release := make(chan struct{})
		holdRegister.Store(&release)
		// A late register mustn't park the stub's handler past the test.
		var once sync.Once
		releaseNow := func() { once.Do(func() { close(release) }) }
		defer func() {
			holdRegister.Store(nil)
			releaseNow()
		}()
		done := make(chan error, 1)
		go func() { done <- f() }()
		select {
		case <-inRegister:
		case err := <-done:
			t.Fatalf("returned before registering: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("never registered")
		}
		assert.True(t, c.MayServePool(), "a registration in flight on a route that may serve the pool")
		releaseNow()
		require.NoError(t, <-done)
	}
	c = newTestClient(t, &fakeForwarder{}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = time.Hour
		cfg.PairingsOnly = pairingsOnly.Load
	})
	ctx := context.Background()
	assert.False(t, c.MayServePool(), "a new client has registered nothing")

	srv.registerStatus = http.StatusInternalServerError
	require.Error(t, c.Start(ctx))
	assert.False(t, c.MayServePool(), "a failed Start leaves no box serving")
	srv.registerStatus = http.StatusOK

	held(func() error { return c.Start(ctx) })
	t.Cleanup(func() { _ = c.Stop(ctx) })
	require.True(t, c.MayServePool())

	pairingsOnly.Store(true)
	held(func() error { return c.Reregister(ctx) })
	require.False(t, c.MayServePool(), "a committed pool-free registration")

	srv.registerStatus = http.StatusInternalServerError
	require.Error(t, c.Reregister(ctx))
	assert.False(t, c.MayServePool(), "a failed pool-free registration can't add the pool")

	pairingsOnly.Store(false)
	require.Error(t, c.Reregister(ctx))
	assert.True(t, c.MayServePool(), "a failed pool registration may still have registered the pool")

	pairingsOnly.Store(true)
	require.Error(t, c.Reregister(ctx))
	assert.True(t, c.MayServePool(), "only a committed pool-free registration clears it")

	srv.registerStatus = http.StatusOK
	require.NoError(t, c.Stop(ctx))
	assert.False(t, c.MayServePool(), "a stopped client serves nobody")
}

func TestAPI_RegisterRejectsEmptyBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/peer/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	api := NewAPI(srv.Client(), srv.URL, "test-device")
	_, err := api.Register(context.Background(), RegisterRequest{ExternalIP: "203.0.113.42", ExternalPort: 5698})
	require.Error(t, err, "a register without a route or config is unusable")
}

func TestHeartbeatReportsUsageUntilDelivered(t *testing.T) {
	var fail atomic.Bool
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		var m map[string]any
		if !assert.NoError(t, json.Unmarshal(b, &m)) {
			return
		}
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &Client{cfg: Config{API: NewAPI(srv.Client(), srv.URL, "dev")}}
	gen := c.relay.begin()
	c.relay.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, counter(1000, 24))
	c.relay.recordPairingFor(gen, 1, "203.0.113.9:1000", "", counter(76, 0))
	ctx := context.Background()

	fail.Store(true)
	_, err := c.sendHeartbeat(ctx, "route")
	require.Error(t, err)
	fail.Store(false)
	_, err = c.sendHeartbeat(ctx, "route")
	require.NoError(t, err)
	_, err = c.sendHeartbeat(ctx, "route")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 3)
	want := map[string]any{"route_id": "route", "active_clients": 0.0, "relayed_bytes": 1100.0,
		"paired_bytes": []any{map[string]any{"pairing_id": usagePairingA, "bytes": 1024.0}}}
	assert.Equal(t, want, bodies[0], "only the pairing ID and bytes are sent")
	assert.Equal(t, want, bodies[1], "a failed heartbeat's usage goes out again")
	assert.Equal(t, map[string]any{"route_id": "route", "active_clients": 0.0}, bodies[2],
		"a delivered report is cleared, and zero usage sends no fields")
}

// usageRejectingServer answers like a server that predates the usage fields:
// 400 for a body that carries them, and status otherwise.
func usageRejectingServer(t *testing.T, status int) (*httptest.Server, func() []map[string]any) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		var m map[string]any
		if !assert.NoError(t, json.Unmarshal(b, &m)) {
			return
		}
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		_, relayed := m["relayed_bytes"]
		_, paired := m["paired_bytes"]
		if relayed || paired {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(bodies)
	}
}

func TestHeartbeatDropsUsageTheServerRejects(t *testing.T) {
	srv, bodies := usageRejectingServer(t, http.StatusOK)
	c := &Client{cfg: Config{API: NewAPI(srv.Client(), srv.URL, "dev")}}
	gen := c.relay.begin()
	a := counter(1000, 24)
	c.relay.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, a)
	ctx := context.Background()

	_, err := c.sendHeartbeat(ctx, "route")
	require.NoError(t, err, "the heartbeat goes through without the usage")
	a.AddDown(6)
	_, err = c.sendHeartbeat(ctx, "route")
	require.NoError(t, err)

	got := bodies()
	require.Len(t, got, 4)
	bare := map[string]any{"route_id": "route", "active_clients": 0.0}
	assert.Equal(t, 1024.0, got[0]["relayed_bytes"])
	assert.Equal(t, bare, got[1], "resent once without the usage")
	assert.Equal(t, map[string]any{"route_id": "route", "active_clients": 0.0, "relayed_bytes": 6.0,
		"paired_bytes": []any{map[string]any{"pairing_id": usagePairingA, "bytes": 6.0}}}, got[2],
		"rejected usage is dropped, not sent again")
	assert.Equal(t, bare, got[3])
}

func TestHeartbeatWithoutUsageIsNotResentOn400(t *testing.T) {
	srv, bodies := usageRejectingServer(t, http.StatusBadRequest)
	c := &Client{cfg: Config{API: NewAPI(srv.Client(), srv.URL, "dev")}}
	c.relay.begin()

	_, err := c.sendHeartbeat(context.Background(), "route")
	require.Error(t, err)
	assert.Len(t, bodies(), 1)
}

func TestHeartbeatKeepsUsageOnServerError(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
		var fail atomic.Bool
		var mu sync.Mutex
		var relayed []any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var m map[string]any
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&m)) {
				return
			}
			mu.Lock()
			relayed = append(relayed, m["relayed_bytes"])
			mu.Unlock()
			if fail.Load() {
				w.WriteHeader(status)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		}))
		c := &Client{cfg: Config{API: NewAPI(srv.Client(), srv.URL, "dev")}}
		gen := c.relay.begin()
		c.relay.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, counter(1000, 24))
		ctx := context.Background()

		fail.Store(true)
		_, err := c.sendHeartbeat(ctx, "route")
		require.Error(t, err, "status %d", status)
		fail.Store(false)
		_, err = c.sendHeartbeat(ctx, "route")
		require.NoError(t, err)
		srv.Close()

		mu.Lock()
		assert.Equal(t, []any{1024.0, 1024.0}, relayed, "status %d is not resent, and keeps the usage for the next heartbeat", status)
		mu.Unlock()
	}
}

// A heartbeat carries pairing IDs, so a redirect to another origin must not
// replay it there.
func TestHeartbeatRefusesCrossOriginRedirects(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var other atomic.Int32
			elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				other.Add(1)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer elsewhere.Close()
			var redirect atomic.Bool
			redirect.Store(true)
			var mu sync.Mutex
			var bodies []map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if redirect.Load() {
					http.Redirect(w, r, elsewhere.URL+r.URL.Path, code)
					return
				}
				var m map[string]any
				if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&m)) {
					return
				}
				mu.Lock()
				bodies = append(bodies, m)
				mu.Unlock()
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			c := &Client{cfg: Config{API: NewAPI(srv.Client(), srv.URL, "dev")}}
			gen := c.relay.begin()
			c.relay.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, counter(1000, 24))
			ctx := context.Background()

			_, err := c.sendHeartbeat(ctx, "route")
			require.Error(t, err)
			assert.Zero(t, other.Load(), "the other origin never receives the heartbeat")
			redirect.Store(false)
			_, err = c.sendHeartbeat(ctx, "route")
			require.NoError(t, err)

			mu.Lock()
			defer mu.Unlock()
			require.Len(t, bodies, 1)
			assert.Equal(t, map[string]any{"route_id": "route", "active_clients": 0.0, "relayed_bytes": 1024.0,
				"paired_bytes": []any{map[string]any{"pairing_id": usagePairingA, "bytes": 1024.0}}}, bodies[0],
				"the refused heartbeat's usage goes out again")
		})
	}
}

func TestAPIFollowsSameOriginRedirects(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/peer/heartbeat" {
			http.Redirect(w, r, "/v2/peer/heartbeat", http.StatusPermanentRedirect)
			return
		}
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&got)) {
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := NewAPI(srv.Client(), srv.URL+"/v1", "dev").Heartbeat(context.Background(), "route", 2, RelayUsage{})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"route_id": "route", "active_clients": 2.0}, got)
}

// TestErrorTypes_WalksJoinedErrors checks that errorTypes names every error in a wrap tree, through joins and multi-%w, so
// an unclassified failure can be classified from its log without its text.
func TestErrorTypes_WalksJoinedErrors(t *testing.T) {
	leaf := &APIError{}
	err := fmt.Errorf("start: %w", errors.Join(context.DeadlineExceeded, leaf))
	got := errorTypes(err)
	assert.Contains(t, got, "*errors.joinError")
	assert.Contains(t, got, "*peer.APIError")
	assert.Contains(t, got, "context.deadlineExceededError")
}

// TestClient_MayServePoolHoldsThroughTeardown checks that MayServePool stays
// true until the box is closed: Stop clears active first, and a hand-off racing
// the teardown must still see the pool and wait for it rather than return while
// the old box may relay.
func TestClient_MayServePoolHoldsThroughTeardown(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	srv := newStubServer(t)
	inDeregister, release := make(chan struct{}), make(chan struct{})
	srv.onDeregister = func() {
		close(inDeregister)
		<-release
	}
	c := newTestClient(t, &fakeForwarder{}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = time.Hour
	})
	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	require.True(t, c.MayServePool())

	stopped := make(chan error, 1)
	go func() { stopped <- c.Stop(ctx) }()
	select {
	case <-inDeregister:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("never deregistered")
	}
	assert.False(t, c.IsActive(), "Stop has cleared active")
	assert.True(t, c.MayServePool(), "the box hasn't closed yet")
	close(release)
	require.NoError(t, <-stopped)
	assert.False(t, c.MayServePool())
}
