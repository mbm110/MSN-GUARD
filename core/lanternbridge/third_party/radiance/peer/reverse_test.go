package peer

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lbA "github.com/getlantern/lantern-box/adapter"
	"github.com/getlantern/lantern-box/portforward"
	"github.com/getlantern/lantern-box/protocol/samizdatreverse"
	"github.com/getlantern/samizdat"

	"github.com/getlantern/broflake/common/helperticket"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/helper/reverse"
)

type revLog struct {
	mu     sync.Mutex
	events []string
}

func (l *revLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *revLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev := l.events
	l.events = nil
	return ev
}

type revClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *revClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *revClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type revKeys struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func (k *revKeys) Get(id string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[id]
	return slices.Clone(key), ok
}

func (k *revKeys) IDs(role string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if role != string(helperticket.RoleInviter) {
		return nil
	}
	var ids []string
	for id := range k.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (k *revKeys) set(id string) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys == nil {
		k.keys = map[string][]byte{}
	}
	sum := sha256.Sum256([]byte("key-" + id))
	k.keys[id] = sum[:]
	return slices.Clone(sum[:])
}

func (k *revKeys) remove(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keys, id)
}

type revBox struct {
	mu           sync.Mutex
	log          *revLog
	portals      []*samizdatreverse.PortalConfig
	masquerades  []string
	outbounds    [][]string
	rebinds      int
	portalErr    error
	outboundsErr error
	rebindErr    error
	// serving is the last portal configured without error, and down says
	// it lost its listener to a failed rebind.
	serving *samizdatreverse.PortalConfig
	down    bool
}

func (b *revBox) SetReversePortal(cfg *samizdatreverse.PortalConfig, masqueradeDomain string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cfg == nil {
		b.log.add("clear-portal")
	} else {
		b.log.add("portal")
	}
	b.portals = append(b.portals, cfg)
	b.masquerades = append(b.masquerades, masqueradeDomain)
	if b.portalErr == nil {
		b.serving, b.down = cfg, false
	}
	return b.portalErr
}

func (b *revBox) SetReverseOutbounds(tags []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log.add(fmt.Sprintf("outbounds:%d", len(tags)))
	b.outbounds = append(b.outbounds, slices.Clone(tags))
	return b.outboundsErr
}

func (b *revBox) RebindReversePortal() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log.add("rebind")
	b.rebinds++
	if b.rebindErr != nil {
		b.down = true
	}
	return b.rebindErr
}

func (b *revBox) ReversePortalListening() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.serving != nil && len(b.serving.Pairings) > 0 && !b.down
}

func (b *revBox) lastPortal() *samizdatreverse.PortalConfig {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.portals) == 0 {
		return nil
	}
	return b.portals[len(b.portals)-1]
}

func (b *revBox) lastOutbounds() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.outbounds) == 0 {
		return nil
	}
	return b.outbounds[len(b.outbounds)-1]
}

func (b *revBox) setErrs(portal, outbounds error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.portalErr, b.outboundsErr = portal, outbounds
}

// revForwarder is a fakeForwarder whose router hands out an external port
// different from the internal one.
type revForwarder struct {
	*fakeForwarder
	log      *revLog
	mu       sync.Mutex
	internal []uint16
}

const revExternalOffset = 7

func (f *revForwarder) MapPort(ctx context.Context, protocol string, internalPort uint16, desc string) (*portforward.Mapping, error) {
	m, err := f.fakeForwarder.MapPort(ctx, protocol, internalPort, desc)
	if err != nil {
		f.log.add("map-failed")
		return nil, err
	}
	f.log.add("map")
	f.mu.Lock()
	f.internal = append(f.internal, internalPort)
	f.mu.Unlock()
	mapped := *m
	mapped.ExternalPort = internalPort + revExternalOffset
	return &mapped, nil
}

func (f *revForwarder) UnmapPort(ctx context.Context) error {
	f.log.add("unmap")
	return f.fakeForwarder.UnmapPort(ctx)
}

func (f *revForwarder) mappedPorts() []uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.internal)
}

type revResponse struct {
	status     int
	observedIP string
	// tags overrides the default of a tag for every named pairing.
	tags map[string]string
}

type revServer struct {
	srv *httptest.Server
	log *revLog

	mu          sync.Mutex
	registers   [][]helper.ReverseBlob
	deregisters int
	// next answers register calls in order; once used up, every call gets
	// fallback.
	next        []revResponse
	fallback    revResponse
	deregStatus int
	block       chan struct{}
	// arrived counts requests, blocked or not.
	arrived atomic.Int32
}

func revTag(pairingID string) string {
	sum := sha256.Sum256([]byte(pairingID))
	return lbA.HelperTagPrefix + hex.EncodeToString(sum[:6])
}

func newRevServer(t *testing.T, log *revLog) *revServer {
	s := &revServer{log: log, fallback: revResponse{observedIP: "198.51.100.7"}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.arrived.Add(1)
		s.mu.Lock()
		block := s.block
		s.mu.Unlock()
		if block != nil {
			<-block
		}
		switch r.URL.Path {
		case "/v1/helper/reverse/register":
			var req struct {
				Routes []helper.ReverseBlob `json:"routes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.registers = append(s.registers, req.Routes)
			resp := s.fallback
			if len(s.next) > 0 {
				resp, s.next = s.next[0], s.next[1:]
			}
			s.mu.Unlock()
			log.add(fmt.Sprintf("register:%d", len(req.Routes)))
			if resp.status != 0 && resp.status != http.StatusOK {
				w.WriteHeader(resp.status)
				return
			}
			tags := resp.tags
			if tags == nil {
				tags = map[string]string{}
				for _, b := range req.Routes {
					tags[b.PairingID] = revTag(b.PairingID)
				}
			}
			_ = json.NewEncoder(w).Encode(helper.ReverseRegisterResponse{ObservedIP: resp.observedIP, Tags: tags})
		case "/v1/helper/reverse/deregister":
			s.mu.Lock()
			s.deregisters++
			status := s.deregStatus
			s.mu.Unlock()
			log.add("deregister")
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *revServer) queue(rs ...revResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = append(s.next, rs...)
}

func (s *revServer) setFallback(r revResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fallback = r
}

func (s *revServer) lastRegister() []helper.ReverseBlob {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.registers) == 0 {
		return nil
	}
	return s.registers[len(s.registers)-1]
}

func (s *revServer) registerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.registers)
}

type revEnv struct {
	c     *ReverseClient
	log   *revLog
	clock *revClock
	keys  *revKeys
	box   *revBox
	fwd   *revForwarder
	srv   *revServer
	// forwarders counts NewForwarder calls.
	forwarders int
}

func newRevEnv(t *testing.T) *revEnv {
	t.Helper()
	log := &revLog{}
	e := &revEnv{
		log:   log,
		clock: &revClock{t: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
		keys:  &revKeys{},
		box:   &revBox{log: log},
		fwd:   &revForwarder{fakeForwarder: &fakeForwarder{}, log: log},
		srv:   newRevServer(t, log),
	}
	e.c = NewReverseClient(ReverseConfig{
		API:  helper.NewReverseAPI(e.srv.srv.Client(), e.srv.srv.URL+"/v1", "test-device"),
		Keys: e.keys,
		Box:  e.box,
		NewForwarder: func(context.Context) (portForwarder, error) {
			e.forwarders++
			return e.fwd, nil
		},
		Now: e.clock.Now,
	})
	return e
}

func (e *revEnv) cycle(t *testing.T) time.Duration {
	t.Helper()
	return e.c.cycle(context.Background())
}

func openBlob(t *testing.T, key []byte, b helper.ReverseBlob, now time.Time) reverse.Route {
	t.Helper()
	assert.Equal(t, reverse.BlobVersion, b.Version)
	r, err := reverse.Open(key, b.PairingID, b.Blob, now)
	require.NoError(t, err)
	return r
}

func x25519Public(t *testing.T, priv []byte) [32]byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(priv)
	require.NoError(t, err)
	var pub [32]byte
	copy(pub[:], k.PublicKey().Bytes())
	return pub
}

func TestReverseIdleWithoutKeys(t *testing.T) {
	e := newRevEnv(t)
	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Zero(t, e.forwarders)
	assert.Empty(t, e.log.take())
}

func TestReverseRegistersSealedRoute(t *testing.T) {
	e := newRevEnv(t)
	key := e.keys.set("p1")
	e.srv.queue(revResponse{observedIP: "198.51.100.7"})

	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Equal(t, []string{"register:0", "map", "portal", "outbounds:0", "register:1", "portal", "outbounds:1"}, e.log.take())

	ports := e.fwd.mappedPorts()
	require.Len(t, ports, 1)
	internal := ports[0]
	portal := e.box.lastPortal()
	require.NotNil(t, portal)
	assert.Equal(t, internal, portal.ListenPort)

	blobs := e.srv.lastRegister()
	require.Len(t, blobs, 1)
	r := openBlob(t, key, blobs[0], e.clock.Now())
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("198.51.100.7:%d", internal+revExternalOffset))}, r.Addrs)
	assert.Equal(t, x25519Public(t, portal.PrivateKey), r.PublicKey)
	assert.Equal(t, e.c.coverDomain, r.CoverDomain)
	assert.Equal(t, e.c.coverDomain, e.box.masquerades[len(e.box.masquerades)-1])
	block, _ := pem.Decode(portal.CertPEM)
	require.NotNil(t, block)
	spki, err := samizdat.SPKISHA256(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, spki, r.CertSPKISHA256)

	wantTag := lbA.ReverseHelperTag(revTag("p1"))
	assert.Equal(t, []string{wantTag}, e.box.lastOutbounds())
	want := map[[8]byte]string{}
	for _, sid := range reverse.AcceptedShortIDs(key, e.clock.Now()) {
		want[sid] = wantTag
	}
	assert.Equal(t, want, portal.Pairings)

	// A steady tick reseals with a fresh issued_at and leaves the box alone.
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:1"}, e.log.take())
	r2 := openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
	assert.Equal(t, e.clock.Now().Unix(), r2.IssuedAt.Unix())
}

func TestReverseObservedIPChangeRegistersAgain(t *testing.T) {
	e := newRevEnv(t)
	key := e.keys.set("p1")
	e.cycle(t)
	e.log.take()

	e.clock.Advance(defaultReverseRegisterInterval)
	e.srv.setFallback(revResponse{observedIP: "203.0.113.5"})
	e.cycle(t)
	assert.Equal(t, []string{"register:1", "register:1"}, e.log.take())
	r := openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
	require.Len(t, r.Addrs, 1)
	assert.Equal(t, netip.MustParseAddr("203.0.113.5"), r.Addrs[0].Addr())
}

func TestReverseKeepsOneAddressPerFamily(t *testing.T) {
	e := newRevEnv(t)
	key := e.keys.set("p1")
	e.srv.queue(revResponse{observedIP: "198.51.100.7"}, revResponse{observedIP: "2001:db8::7"})
	e.srv.setFallback(revResponse{observedIP: "2001:db8::7"})

	e.cycle(t)
	assert.Equal(t, []string{"register:0", "map", "portal", "outbounds:0", "register:1", "portal", "outbounds:1", "register:1"}, e.log.take())
	internal := e.fwd.mappedPorts()[0]
	r := openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
	assert.ElementsMatch(t, []netip.AddrPort{
		netip.MustParseAddrPort(fmt.Sprintf("198.51.100.7:%d", internal+revExternalOffset)),
		netip.MustParseAddrPort(fmt.Sprintf("[2001:db8::7]:%d", internal)),
	}, r.Addrs)

	// Only the IPv6 address is seen again, so the IPv4 one expires an hour
	// after it was last seen.
	e.clock.Advance(30 * time.Minute)
	e.cycle(t)
	r = openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
	assert.Len(t, r.Addrs, 2)

	e.clock.Advance(31 * time.Minute)
	e.cycle(t)
	r = openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("[2001:db8::7]:%d", internal))}, r.Addrs)
}

func TestReverseNoAddressDeregisters(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.srv.setFallback(revResponse{observedIP: ""})

	e.cycle(t)
	assert.Equal(t, []string{"register:0", "outbounds:0"}, e.log.take())
	assert.False(t, e.fwd.wasMapped(), "no port is mapped without an address to advertise")

	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:0"}, e.log.take())

	// An address learned later brings the route back.
	e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "map", "portal", "register:1", "portal", "outbounds:1"}, e.log.take())

	// Losing every address withdraws the registered route and the outbounds.
	e.c.NetworkChanged()
	e.srv.setFallback(revResponse{observedIP: ""})
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"deregister", "rebind", "unmap", "register:0", "outbounds:0"}, e.log.take())
}

func TestReverseRotationKeepsPortAndCoverDomain(t *testing.T) {
	e := newRevEnv(t)
	key := e.keys.set("p1")
	e.cycle(t)
	first := e.box.lastPortal()
	r1 := openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())

	e.clock.Advance(defaultReverseRotateInterval)
	e.log.take()
	e.cycle(t)
	// The last portal cuts how long the replaced identity is kept.
	assert.Equal(t, []string{"portal", "register:1", "portal"}, e.log.take())
	second := e.box.lastPortal()
	r2 := openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())

	assert.Equal(t, first.ListenPort, second.ListenPort)
	assert.NotEqual(t, first.PrivateKey, second.PrivateKey)
	assert.NotEqual(t, r1.PublicKey, r2.PublicKey)
	assert.Equal(t, x25519Public(t, second.PrivateKey), r2.PublicKey)
	assert.Equal(t, r1.CoverDomain, r2.CoverDomain)
	assert.Equal(t, r1.Addrs, r2.Addrs)
	assert.Equal(t, 1, len(e.fwd.mappedPorts()))
}

func TestReverseNetworkChangedRemaps(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)
	e.log.take()

	e.c.NetworkChanged()
	select {
	case <-e.c.kick:
	default:
		t.Fatal("NetworkChanged did not ask for a cycle")
	}
	e.cycle(t)
	assert.Equal(t, []string{"deregister", "rebind", "unmap", "register:0", "map", "register:1"}, e.log.take())
	ports := e.fwd.mappedPorts()
	require.Len(t, ports, 2)
	assert.Equal(t, ports[0], ports[1], "the portal keeps its port across a remap")
}

func TestReversePairingsChangedDeregistersRemoved(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	k2 := e.keys.set("p2")
	e.cycle(t)
	e.log.take()

	e.keys.remove("p1")
	e.c.PairingsChanged()
	e.cycle(t)
	assert.Equal(t, []string{"portal", "outbounds:1", "deregister", "register:1"}, e.log.take())
	blobs := e.srv.lastRegister()
	require.Len(t, blobs, 1)
	assert.Equal(t, "p2", blobs[0].PairingID)
	openBlob(t, k2, blobs[0], e.clock.Now())
	assert.Equal(t, []string{lbA.ReverseHelperTag(revTag("p2"))}, e.box.lastOutbounds())

	// The last pairing gone: clear the box, deregister and unmap.
	e.keys.remove("p2")
	e.cycle(t)
	assert.Equal(t, []string{"clear-portal", "deregister", "unmap"}, e.log.take())
	e.cycle(t)
	assert.Empty(t, e.log.take())
}

func TestReverseCapsRoutes(t *testing.T) {
	e := newRevEnv(t)
	var ids []string
	for i := range 25 {
		id := fmt.Sprintf("p%02d", i)
		e.keys.set(id)
		ids = append(ids, id)
	}
	e.cycle(t)
	blobs := e.srv.lastRegister()
	require.Len(t, blobs, maxReverseRoutes)
	var got []string
	for _, b := range blobs {
		got = append(got, b.PairingID)
		assert.LessOrEqual(t, len(b.Blob), reverse.MaxBlobLen)
	}
	assert.Equal(t, ids[:maxReverseRoutes], got)
	assert.Len(t, e.box.lastOutbounds(), maxReverseRoutes)
}

func TestReverseSkipsInvalidTags(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.keys.set("p2")
	e.srv.setFallback(revResponse{observedIP: "198.51.100.7", tags: map[string]string{"p1": revTag("p1"), "p2": "not-a-helper-tag"}})
	e.cycle(t)
	assert.Equal(t, []string{lbA.ReverseHelperTag(revTag("p1"))}, e.box.lastOutbounds())
	for _, tag := range e.box.lastPortal().Pairings {
		assert.Equal(t, lbA.ReverseHelperTag(revTag("p1")), tag)
	}
}

func TestReverseDisabledIdlesAnHour(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.srv.setFallback(revResponse{status: http.StatusNotFound})

	assert.Equal(t, reverseDisabledWait, e.cycle(t))
	assert.Equal(t, []string{"register:0"}, e.log.take(), "a disabled feature maps no port")

	e.clock.Advance(30 * time.Minute)
	e.c.PairingsChanged()
	assert.Equal(t, 30*time.Minute, e.cycle(t))
	assert.Empty(t, e.log.take())

	e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
	e.clock.Advance(30 * time.Minute)
	e.cycle(t)
	assert.Contains(t, e.log.take(), "register:1")
}

func TestReverseBacksOffOnOverload(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e.srv.setFallback(revResponse{status: status})
			want := defaultReverseRegisterInterval
			for range 6 {
				want = min(2*want, maxReverseBackoff)
				assert.Equal(t, want, e.cycle(t))
				e.clock.Advance(want)
			}
			assert.Equal(t, maxReverseBackoff, want)

			e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
			assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
			e.clock.Advance(defaultReverseRegisterInterval)
		})
	}
}

// Stopping and starting the client, as a VPN toggle does, makes no
// lantern-cloud call while it is held off.
func TestReverseRestartKeepsTheHoldOff(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := newRevEnv(t)
			e.keys.set("p1")
			e.cycle(t)
			e.srv.setFallback(revResponse{status: status})
			e.clock.Advance(defaultReverseRegisterInterval)
			e.cycle(t)
			e.log.take()
			arrived := e.srv.arrived.Load()
			cycled := make(chan struct{}, 1)
			e.c.cycled = func() {
				select {
				case cycled <- struct{}{}:
				default:
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for range 3 {
				require.NoError(t, e.c.Start(context.Background()))
				select {
				case <-cycled:
				case <-ctx.Done():
					t.Fatal("the client never finished a cycle")
				}
				e.c.Stop(ctx)
			}
			assert.Equal(t, arrived, e.srv.arrived.Load(), "a restart called lantern-cloud while held off")
		})
	}
}

func TestReverseOtherErrorsRetryNextTick(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Equal(t, 2, e.srv.registerCount())
}

func TestReverseMapFailureRetriesNextTick(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.fwd.mapErr = errors.New("no gateway at 192.168.1.1")
	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Equal(t, []string{"register:0", "map-failed", "unmap"}, e.log.take())
	assert.Empty(t, e.srv.lastRegister(), "no route is registered without a mapping")

	e.fwd.mapErr = nil
	e.cycle(t)
	assert.Contains(t, e.log.take(), "register:1")
}

// controlForwarder is a revForwarder that takes a local IP control, as
// *portforward.Forwarder does, and fails MapPort with ErrNoLocalIP while
// noLocalIP is set.
type controlForwarder struct {
	*revForwarder
	control   control.Func
	noLocalIP bool
}

func (f *controlForwarder) SetLocalIPControl(fn control.Func) { f.control = fn }

func (f *controlForwarder) MapPort(ctx context.Context, protocol string, internalPort uint16, desc string) (*portforward.Mapping, error) {
	if f.noLocalIP {
		f.log.add("map-failed")
		return nil, fmt.Errorf("determine local ip: %w", portforward.ErrNoLocalIP)
	}
	return f.revForwarder.MapPort(ctx, protocol, internalPort, desc)
}

func TestReverseMapsThroughTheTunnelBypass(t *testing.T) {
	e := newRevEnv(t)
	fwd := &controlForwarder{revForwarder: e.fwd}
	var bound atomic.Bool
	tunnelUp := true
	e.c.cfg.NewForwarder = func(context.Context) (portForwarder, error) { return fwd, nil }
	e.c.cfg.LocalIPControl = func() control.Func {
		if !tunnelUp {
			return nil
		}
		return func(string, string, syscall.RawConn) error {
			bound.Store(true)
			return nil
		}
	}
	e.keys.set("p1")

	fwd.noLocalIP = true
	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Equal(t, []string{"register:0", "map-failed", "unmap"}, e.log.take())
	assert.Nil(t, e.box.lastPortal(), "no portal without a mapping")
	require.NotNil(t, fwd.control)
	require.NoError(t, fwd.control("udp", "", nil))
	assert.True(t, bound.Load())

	fwd.noLocalIP = false
	e.cycle(t)
	assert.Contains(t, e.log.take(), "register:1")

	// With no tunnel, the control binds nothing, and binds again once one
	// runs: the forwarder can outlive either.
	tunnelUp = false
	bound.Store(false)
	fwd.control = nil
	e.c.NetworkChanged()
	e.cycle(t)
	require.NotNil(t, fwd.control)
	require.NoError(t, fwd.control("udp", "", nil))
	assert.False(t, bound.Load(), "no binding with no tunnel")
	tunnelUp = true
	require.NoError(t, fwd.control("udp", "", nil))
	assert.True(t, bound.Load(), "bound once a tunnel runs")
}

type quietForwarder struct {
	*revForwarder
	quiet bool
}

func (f *quietForwarder) SetQuietLogs(quiet bool) { f.quiet = quiet }

func TestReverseMapsQuietly(t *testing.T) {
	e := newRevEnv(t)
	fwd := &quietForwarder{revForwarder: e.fwd}
	e.c.cfg.NewForwarder = func(context.Context) (portForwarder, error) { return fwd, nil }
	e.keys.set("p1")
	e.cycle(t)
	assert.Contains(t, e.log.take(), "map")
	assert.True(t, fwd.quiet)
}

// Discovery logs the gateway, so only the reverse client's discovery is quiet.
func TestOnlyTheReverseClientDiscoversQuietly(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	var opts []int
	prev := discoverForwarder
	discoverForwarder = func(_ context.Context, o ...portforward.Option) (*portforward.Forwarder, error) {
		opts = append(opts, len(o))
		return nil, portforward.ErrNoPortForwarding
	}
	t.Cleanup(func() { discoverForwarder = prev })

	_, err := NewReverseClient(ReverseConfig{}).cfg.NewForwarder(context.Background())
	require.ErrorIs(t, err, portforward.ErrNoPortForwarding)
	_, err = newDefaultForwarder(context.Background())
	require.ErrorIs(t, err, portforward.ErrNoPortForwarding)
	assert.Equal(t, []int{1, 0}, opts)
}

// Both clients' forwarders are bound whenever there is a physical control to
// ask, whether or not a tunnel runs when they are made, since one may start
// while they renew; with none, discovery is as before.
func TestForwardersAreBoundToThePhysicalInterface(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	var opts []int
	prev := discoverForwarder
	discoverForwarder = func(_ context.Context, o ...portforward.Option) (*portforward.Forwarder, error) {
		opts = append(opts, len(o))
		return nil, portforward.ErrNoPortForwarding
	}
	t.Cleanup(func() { discoverForwarder = prev })
	var tunnel control.Func
	physical := func() control.Func { return tunnel }

	for _, physical := range []func() control.Func{nil, physical} {
		peerClient, err := NewClient(Config{API: &API{}, PhysicalControl: physical})
		require.NoError(t, err)
		_, err = peerClient.cfg.NewForwarder(context.Background())
		require.ErrorIs(t, err, portforward.ErrNoPortForwarding)
		_, err = NewReverseClient(ReverseConfig{LocalIPControl: physical}).cfg.NewForwarder(context.Background())
		require.ErrorIs(t, err, portforward.ErrNoPortForwarding)
	}
	assert.Equal(t, []int{0, 1, 1, 2}, opts, "BoundTo is added when there is a physical control, even with no tunnel yet")
}

// The control a forwarder binds through follows the tunnel running at each
// socket, not the one it was made under: a forwarder renews its mappings
// across a VPN connect, restart or disconnect.
func TestCurrentPhysicalFollowsTheTunnel(t *testing.T) {
	assert.Nil(t, currentPhysical(nil))
	var tunnel control.Func
	physical := func() control.Func { return tunnel }
	// Made with the VPN off, as a forwarder can be.
	fn := currentPhysical(physical)
	require.NotNil(t, fn)

	var calls []string
	tunnelNamed := func(name string) control.Func {
		return func(string, string, syscall.RawConn) error {
			calls = append(calls, name)
			return nil
		}
	}
	require.NoError(t, fn("udp4", "192.168.1.1:5351", nil))
	tunnel = tunnelNamed("first")
	require.NoError(t, fn("udp4", "192.168.1.1:5351", nil))
	tunnel = tunnelNamed("second")
	require.NoError(t, fn("udp4", "192.168.1.1:5351", nil))
	tunnel = nil
	require.NoError(t, fn("udp4", "192.168.1.1:5351", nil))
	assert.Equal(t, []string{"first", "second"}, calls)
}

func TestReverseBoxErrorsRetryNextTick(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.box.setErrs(errors.New("bind failed"), nil)
	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Equal(t, []string{"register:0", "map", "portal"}, e.log.take(), "no route while no portal serves it")

	e.box.setErrs(nil, errors.New("outbounds failed"))
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"portal", "outbounds:0", "register:1", "portal", "outbounds:1"}, e.log.take())

	e.box.setErrs(nil, nil)
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"outbounds:1", "register:1"}, e.log.take())

	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:1"}, e.log.take())
}

func TestReverseStartReturnsAtOnceAndStopTearsDownInOrder(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	gate := make(chan struct{})
	e.srv.mu.Lock()
	e.srv.block = gate
	e.srv.mu.Unlock()

	start := time.Now()
	require.NoError(t, e.c.Start(context.Background()))
	require.NoError(t, e.c.Start(context.Background()), "Start is idempotent")
	assert.Less(t, time.Since(start), time.Second)

	e.srv.mu.Lock()
	e.srv.block = nil
	e.srv.mu.Unlock()
	close(gate)
	require.Eventually(t, func() bool {
		return slices.Contains(e.box.lastOutbounds(), lbA.ReverseHelperTag(revTag("p1")))
	}, 5*time.Second, 10*time.Millisecond)
	e.log.take()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.c.Stop(ctx)
	assert.Equal(t, []string{"clear-portal", "unmap", "deregister"}, e.log.take())
	assert.True(t, e.fwd.renewStopped)

	// A restart serves again.
	require.NoError(t, e.c.Start(context.Background()))
	require.Eventually(t, func() bool {
		return slices.Contains(e.log.take(), "register:1")
	}, 5*time.Second, 10*time.Millisecond)
	e.c.Stop(ctx)
}

func TestReverseKickRunsACycle(t *testing.T) {
	e := newRevEnv(t)
	require.NoError(t, e.c.Start(context.Background()))
	defer e.c.Stop(context.Background())

	e.keys.set("p1")
	e.c.PairingsChanged()
	require.Eventually(t, func() bool { return e.srv.registerCount() >= 2 }, 5*time.Second, 10*time.Millisecond)
}

func TestReverseCredsAreConsistent(t *testing.T) {
	creds, err := newReverseCreds("www.example.com")
	require.NoError(t, err)
	assert.Equal(t, x25519Public(t, creds.PrivateKey[:]), creds.PublicKey)

	block, _ := pem.Decode(creds.CertPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, []string{"www.example.com"}, cert.DNSNames)
	assert.True(t, cert.NotBefore.Before(time.Now().Add(-23*time.Hour)))
	assert.True(t, cert.NotAfter.After(time.Now().Add(364*24*time.Hour)))
	spki, err := samizdat.SPKISHA256(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, spki, creds.SPKI)

	keyBlock, _ := pem.Decode(creds.KeyPEM)
	require.NotNil(t, keyBlock)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(cert.PublicKey))

	other, err := newReverseCreds("www.example.com")
	require.NoError(t, err)
	assert.NotEqual(t, creds.PrivateKey, other.PrivateKey)
}

func TestReverseCoverDomainsFit(t *testing.T) {
	for _, d := range reverseCoverDomains {
		assert.LessOrEqual(t, len(d), reverse.MaxDomainLen)
		assert.False(t, strings.ContainsAny(d, " /:"))
	}
}

func TestReverseFailedRotationKeepsAdvertisingTheRunningPortal(t *testing.T) {
	e := newRevEnv(t)
	key := e.keys.set("p1")
	e.cycle(t)
	running := e.box.lastPortal()

	e.box.setErrs(errors.New("bind failed"), nil)
	e.clock.Advance(defaultReverseRotateInterval)
	e.log.take()
	e.cycle(t)
	assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
	r := openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
	assert.Equal(t, x25519Public(t, running.PrivateKey), r.PublicKey)

	e.box.setErrs(nil, nil)
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"portal", "register:1", "portal"}, e.log.take())
	r = openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
	assert.Equal(t, x25519Public(t, e.box.lastPortal().PrivateKey), r.PublicKey)
	assert.NotEqual(t, x25519Public(t, running.PrivateKey), r.PublicKey)
}

func TestReverseDisabledTearsDown(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)
	e.log.take()

	e.srv.setFallback(revResponse{status: http.StatusNotFound})
	e.clock.Advance(defaultReverseRegisterInterval)
	assert.Equal(t, reverseDisabledWait, e.cycle(t))
	assert.Equal(t, []string{"register:1", "clear-portal", "unmap"}, e.log.take())

	e.c.NetworkChanged()
	e.clock.Advance(59 * time.Minute)
	e.cycle(t)
	assert.Empty(t, e.log.take())

	// Stop has nothing left to withdraw.
	e.c.teardown(make(chan struct{}))
	assert.Empty(t, e.log.take())
}

func TestReverseDeregisterErrorsBackOff(t *testing.T) {
	for _, tc := range []struct {
		status int
		wait   time.Duration
	}{
		{http.StatusNotFound, reverseDisabledWait},
		{http.StatusTooManyRequests, 2 * defaultReverseRegisterInterval},
		{http.StatusServiceUnavailable, 2 * defaultReverseRegisterInterval},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			e := newRevEnv(t)
			e.keys.set("p1")
			e.cycle(t)
			e.keys.remove("p1")
			e.srv.mu.Lock()
			e.srv.deregStatus = tc.status
			e.srv.mu.Unlock()
			e.log.take()

			assert.Equal(t, tc.wait, e.cycle(t))
			assert.Equal(t, []string{"clear-portal", "deregister", "unmap"}, e.log.take())
			for range 3 {
				e.clock.Advance(tc.wait / 4)
				e.cycle(t)
			}
			assert.Empty(t, e.log.take(), "no calls while held off")

			e.clock.Advance(tc.wait)
			e.cycle(t)
			if tc.status == http.StatusNotFound {
				assert.Empty(t, e.log.take(), "a disabled server keeps no route to withdraw")
			} else {
				assert.Equal(t, []string{"deregister"}, e.log.take())
			}
		})
	}
}

func TestReverseNeverLogsTheManualPort(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.Set(settings.PeerManualPortKey, 41234))
	var buf strings.Builder
	var bufMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		bufMu.Lock()
		defer bufMu.Unlock()
		return buf.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug}))

	e := newRevEnv(t)
	e.c = NewReverseClient(ReverseConfig{API: e.c.cfg.API, Keys: e.keys, Box: e.box, Now: e.clock.Now, Logger: logger})
	e.c.st.manualPort = reverseManualPort(logger)
	e.keys.set("p1")
	e.cycle(t)
	e.c.NetworkChanged()
	e.cycle(t)
	require.Equal(t, uint16(41234), e.box.lastPortal().ListenPort)

	bufMu.Lock()
	defer bufMu.Unlock()
	assert.Contains(t, buf.String(), "manual port forward")
	assert.NotContains(t, buf.String(), "41234")
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestReverseReportsTagsBeforeTheBox(t *testing.T) {
	e := newRevEnv(t)
	var got []map[string]string
	var outboundsAtReport [][]string
	e.c.cfg.OnTags = func(tags map[string]string) {
		got = append(got, tags)
		outboundsAtReport = append(outboundsAtReport, e.box.lastOutbounds())
	}
	e.keys.set("p1")
	e.srv.setFallback(revResponse{observedIP: "198.51.100.7", tags: map[string]string{"p1": revTag("p1")}})
	e.cycle(t)
	require.Equal(t, []map[string]string{{"p1": revTag("p1")}}, got)
	assert.Empty(t, outboundsAtReport[0])
	assert.Equal(t, []string{lbA.ReverseHelperTag(revTag("p1"))}, e.box.lastOutbounds())

	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Len(t, got, 1, "an unchanged map is not reported again")
}

// A revoked pairing leaves the portal and reverse outbounds on the next
// cycle even while lantern-cloud fails or is backed off from; the rest stay.
func TestReverseDropsARevokedPairingWhileTheAPIFails(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e := newRevEnv(t)
			e.keys.set("p1")
			k2 := e.keys.set("p2")
			e.cycle(t)
			tag1, tag2 := lbA.ReverseHelperTag(revTag("p1")), lbA.ReverseHelperTag(revTag("p2"))
			require.ElementsMatch(t, []string{tag1, tag2}, e.box.lastOutbounds())

			e.srv.setFallback(revResponse{status: status})
			e.clock.Advance(defaultReverseRegisterInterval)
			e.cycle(t)
			e.log.take()
			registers := e.srv.registerCount()

			e.keys.remove("p1")
			e.c.PairingsChanged()
			e.cycle(t)
			assert.Equal(t, []string{tag2}, e.box.lastOutbounds())
			want := map[[8]byte]string{}
			for _, sid := range reverse.AcceptedShortIDs(k2, e.clock.Now()) {
				want[sid] = tag2
			}
			assert.Equal(t, want, e.box.lastPortal().Pairings)
			if status == http.StatusServiceUnavailable {
				assert.Equal(t, registers, e.srv.registerCount(), "held off")
			}
		})
	}
}

func TestReverseNetworkChangedMarksThePublicIPStale(t *testing.T) {
	common.SetPublicIP("198.51.100.9")
	t.Cleanup(func() { common.SetPublicIP("") })
	e := newRevEnv(t)
	require.False(t, common.PublicIPStale())
	e.c.NetworkChanged()
	assert.True(t, common.PublicIPStale())
}

func (e *revEnv) startManual(t *testing.T, sharing *atomic.Bool) {
	t.Helper()
	e.c = NewReverseClient(ReverseConfig{
		API: e.c.cfg.API, Keys: e.keys, Box: e.box, Now: e.clock.Now,
		PeerShareActive: sharing.Load,
		NewForwarder: func(context.Context) (portForwarder, error) {
			e.forwarders++
			return e.fwd, nil
		},
	})
}

func (e *revEnv) portalOn(port uint16, manual bool) func() bool {
	return func() bool {
		p := e.box.lastPortal()
		return p != nil && (p.ListenPort == port) == manual
	}
}

// A run keeps the forwarding its Start chose: the manual port while peer
// sharing is off, and a mapped port of its own, never the manual one, while
// peer sharing holds it.
func TestReverseChoosesItsForwardingAtStart(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.Set(settings.PeerManualPortKey, 41234))
	var sharing atomic.Bool
	e := newRevEnv(t)
	e.startManual(t, &sharing)
	e.keys.set("p1")
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e.c.Stop(ctx)
	}
	t.Cleanup(stop)

	require.NoError(t, e.c.Start(context.Background()))
	require.Eventually(t, e.portalOn(41234, true), 5*time.Second, 5*time.Millisecond)
	assert.False(t, e.c.YieldedManualPort())

	// Peer sharing turning on mid-run changes nothing until a restart.
	sharing.Store(true)
	e.c.PairingsChanged()
	assert.Never(t, e.portalOn(41234, false), 100*time.Millisecond, 10*time.Millisecond)

	stop()
	assert.Nil(t, e.box.lastPortal(), "the portal is cleared on Stop")
	assert.False(t, e.c.YieldedManualPort(), "a stopped client yields nothing")
	require.NoError(t, e.c.Start(context.Background()))
	require.Eventually(t, e.portalOn(41234, false), 5*time.Second, 5*time.Millisecond)
	assert.True(t, e.c.YieldedManualPort())
	port := e.box.lastPortal().ListenPort

	// A network change remaps, still off the manual port.
	e.c.NetworkChanged()
	require.Eventually(t, func() bool { return len(e.fwd.mappedPorts()) == 2 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, []uint16{port, port}, e.fwd.mappedPorts())

	e.log.take()
	stop()
	assert.Equal(t, []string{"clear-portal", "unmap", "deregister"}, e.log.take(), "Stop releases the mapped port")
	sharing.Store(false)
	e.c.NetworkChanged()
	require.NoError(t, e.c.Start(context.Background()))
	require.Eventually(t, e.portalOn(41234, true), 5*time.Second, 5*time.Millisecond)
	assert.False(t, e.c.YieldedManualPort())
}

func TestReverseNeverMapsTheManualPortAutomatically(t *testing.T) {
	for _, avoid := range []uint16{internalPortMin, internalPortMin + 1, 41234, internalPortMax - 1} {
		seen := make(map[uint16]bool)
		for i := range internalPortMax - internalPortMin - 1 {
			port := internalPortSkipping(i, avoid)
			require.NotEqual(t, avoid, port)
			require.GreaterOrEqual(t, int(port), internalPortMin)
			require.Less(t, int(port), internalPortMax)
			seen[port] = true
		}
		assert.Len(t, seen, internalPortMax-internalPortMin-1, "every other port can be picked")
		for range 1000 {
			require.NotEqual(t, avoid, pickInternalPortExcept(avoid))
		}
	}
	p := pickInternalPortExcept(80)
	assert.GreaterOrEqual(t, int(p), internalPortMin)
	assert.Less(t, int(p), internalPortMax)
}

// Release returns once the portal and port are free, without waiting for
// lantern-cloud to answer the deregister.
func TestReverseReleaseDoesNotWaitForTheDeregister(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	require.NoError(t, e.c.Start(context.Background()))
	require.Eventually(t, func() bool {
		return slices.Contains(e.box.lastOutbounds(), lbA.ReverseHelperTag(revTag("p1")))
	}, 5*time.Second, 10*time.Millisecond)
	e.log.take()

	gate := make(chan struct{})
	e.srv.mu.Lock()
	e.srv.block = gate
	e.srv.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	e.c.Release(ctx)
	assert.Less(t, time.Since(start), time.Second)
	assert.NoError(t, ctx.Err())
	assert.Nil(t, e.box.lastPortal())
	assert.Equal(t, []string{"clear-portal", "unmap"}, e.log.take())

	close(gate)
	e.c.Stop(ctx)
	assert.Equal(t, []string{"deregister"}, e.log.take())
}

// A revocation leaves the portal at once even while a register is stuck.
func TestReverseRevocationDoesNotWaitForARegisterInFlight(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.keys.set("p2")
	require.NoError(t, e.c.Start(context.Background()))
	gate := make(chan struct{})
	t.Cleanup(func() {
		e.srv.mu.Lock()
		e.srv.block = nil
		e.srv.mu.Unlock()
		close(gate)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e.c.Stop(ctx)
	})
	tag := func(id string) string { return lbA.ReverseHelperTag(revTag(id)) }
	serves := func(id string) bool {
		p := e.box.lastPortal()
		return p != nil && slices.Contains(slices.Collect(maps.Values(p.Pairings)), tag(id))
	}
	require.Eventually(t, func() bool { return serves("p1") && serves("p2") }, 5*time.Second, 5*time.Millisecond)

	e.srv.mu.Lock()
	e.srv.block = gate
	e.srv.mu.Unlock()
	arrived := e.srv.arrived.Load()
	e.c.wake()
	require.Eventually(t, func() bool { return e.srv.arrived.Load() > arrived }, 5*time.Second, 5*time.Millisecond)

	e.keys.remove("p1")
	e.c.PairingsChanged()
	require.Eventually(t, func() bool { return !serves("p1") }, time.Second, 5*time.Millisecond)
	assert.True(t, serves("p2"))
	assert.NotContains(t, e.box.lastOutbounds(), tag("p1"))
}

func inUseError(t *testing.T) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	_, err = net.Listen("tcp", ln.Addr().String())
	require.Error(t, err)
	require.True(t, portInUse(err))
	return fmt.Errorf("portal: listen: %w", err)
}

// A mapped port another socket holds is given up, so the next cycle maps
// another instead of retrying it forever.
func TestReverseMovesOffAnOccupiedPort(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.box.setErrs(inUseError(t), nil)
	assert.Equal(t, defaultReverseRegisterInterval, e.cycle(t))
	assert.Equal(t, []string{"register:0", "map", "portal", "unmap"}, e.log.take())
	assert.Zero(t, e.c.st.lastPort)

	e.box.setErrs(nil, nil)
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "map", "portal", "outbounds:0", "register:1", "portal", "outbounds:1"}, e.log.take())
	assert.Len(t, e.fwd.mappedPorts(), 2)
}

// Only a bind failure on a port the client picked moves it: not another
// error, not the manual port, and not while a portal serves.
func TestReverseKeepsItsPortOnOtherPortalErrors(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.box.setErrs(errors.New("bad certificate"), nil)
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "map", "portal"}, e.log.take())

	e.box.setErrs(nil, nil)
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	e.log.take()
	e.box.setErrs(inUseError(t), nil)
	e.clock.Advance(defaultReverseRotateInterval)
	e.cycle(t)
	log := e.log.take()
	assert.Contains(t, log, "portal")
	assert.NotContains(t, log, "unmap", "a serving portal keeps its mapping")

	e = newRevEnv(t)
	e.c.st.manualPort = 41234
	e.keys.set("p1")
	e.box.setErrs(inUseError(t), nil)
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "portal"}, e.log.take(), "the manual port is never given up")
}

// A portal that lost its listener, to a failed rebind or a tunnel that came
// up without it, is configured again, and no route is published until it
// listens.
func TestReverseRestoresAPortalThatLostItsListener(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)
	require.True(t, e.box.ReversePortalListening())
	e.log.take()

	e.box.mu.Lock()
	e.box.rebindErr = errors.New("listen failed")
	e.box.mu.Unlock()
	e.box.setErrs(errors.New("listen failed"), nil)
	e.c.NetworkChanged()
	e.clock.Advance(time.Second)
	e.cycle(t)
	assert.Equal(t, []string{"deregister", "rebind", "unmap", "register:0", "map", "portal"}, e.log.take(),
		"no route is published for a portal without a listener")
	assert.True(t, e.c.st.portal == nil)

	e.box.setErrs(nil, nil)
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
	assert.True(t, e.box.ReversePortalListening())

	// A tunnel restart whose restore failed.
	e.box.mu.Lock()
	e.box.down = true
	e.box.mu.Unlock()
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
}

// The first bind happens when the pairings arrive, after a portal with none
// was configured, and an occupied port moves the client off it then too.
func TestReverseMovesOffAPortOccupiedWhenThePairingsArrive(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	var configures int
	e.c.cfg.Box = portalErrAfter{revBox: e.box, err: inUseError(t), n: 1, count: &configures}
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "map", "portal", "outbounds:0", "register:1", "portal", "unmap"}, e.log.take())
	assert.Zero(t, e.c.st.lastPort)
	assert.True(t, e.c.st.portal == nil)
}

// portalErrAfter fails every portal configure after the first n.
type portalErrAfter struct {
	*revBox
	err   error
	n     int
	count *int
}

func (b portalErrAfter) SetReversePortal(cfg *samizdatreverse.PortalConfig, masqueradeDomain string) error {
	*b.count++
	if *b.count > b.n {
		b.revBox.setErrs(b.err, nil)
	}
	return b.revBox.SetReversePortal(cfg, masqueradeDomain)
}

// prevKey returns the previous identity's private key the portal was
// configured with, or nil.
func prevKey(cfg *samizdatreverse.PortalConfig) []byte {
	if cfg == nil || cfg.Previous == nil {
		return nil
	}
	return cfg.Previous.PrivateKey
}

// A rotation keeps the registered identity as the portal's previous one, for
// at most a rotate interval while the new route is not registered, and for one
// more helper poll once it is.
func TestReverseRotationKeepsThePublishedIdentity(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)
	published := e.box.lastPortal()
	require.Nil(t, published.Previous)

	e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
	e.clock.Advance(defaultReverseRotateInterval)
	rotated := e.clock.Now()
	e.log.take()
	e.cycle(t)
	assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
	portal := e.box.lastPortal()
	assert.NotEqual(t, published.PrivateKey, portal.PrivateKey)
	require.NotNil(t, portal.Previous)
	assert.Equal(t, published.PrivateKey, portal.Previous.PrivateKey)
	assert.Equal(t, published.CertPEM, portal.Previous.CertPEM)
	assert.Equal(t, published.KeyPEM, portal.Previous.KeyPEM)
	assert.Equal(t, rotated.Add(defaultReverseRotateInterval), portal.Previous.Until)

	// Registers still failing leave it alone. The address is forgotten by
	// now, so the client asks for it again first.
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:0"}, e.log.take())

	e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
	e.clock.Advance(defaultReverseRegisterInterval)
	registered := e.clock.Now()
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "register:1", "portal"}, e.log.take())
	portal = e.box.lastPortal()
	require.NotNil(t, portal.Previous)
	assert.Equal(t, published.PrivateKey, portal.Previous.PrivateKey)
	assert.Equal(t, registered.Add(defaultReverseRegisterInterval+reversePrevGrace), portal.Previous.Until)

	// Later registers do not extend it.
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:1"}, e.log.take())

	// Once it has passed, the portal drops it.
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
	assert.Nil(t, e.box.lastPortal().Previous)
	assert.Equal(t, portal.PrivateKey, e.box.lastPortal().PrivateKey)
	e.clock.Advance(defaultReverseRegisterInterval)
	e.cycle(t)
	assert.Equal(t, []string{"register:1"}, e.log.take())
}

// The cut never outlasts the rotate interval after the rotation.
func TestReversePreviousNeverOutlastsTheRotateInterval(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)

	e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
	e.clock.Advance(defaultReverseRotateInterval)
	rotated := e.clock.Now()
	e.cycle(t)

	e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
	e.clock.Advance(defaultReverseRotateInterval - time.Minute)
	e.log.take()
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "register:1"}, e.log.take(), "the cap is the Until the portal holds")
	portal := e.box.lastPortal()
	require.NotNil(t, portal.Previous)
	assert.Equal(t, rotated.Add(defaultReverseRotateInterval), portal.Previous.Until)
}

func TestReverseRotationRegisteredAtOnceCutsThePrevious(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)
	published := e.box.lastPortal()

	e.clock.Advance(defaultReverseRotateInterval)
	now := e.clock.Now()
	e.log.take()
	e.cycle(t)
	assert.Equal(t, []string{"portal", "register:1", "portal"}, e.log.take())
	n := len(e.box.portals)
	long, short := e.box.portals[n-2], e.box.portals[n-1]
	require.NotNil(t, long.Previous)
	require.NotNil(t, short.Previous)
	assert.Equal(t, published.PrivateKey, long.Previous.PrivateKey)
	assert.Equal(t, now.Add(defaultReverseRotateInterval), long.Previous.Until)
	assert.Equal(t, published.PrivateKey, short.Previous.PrivateKey)
	assert.Equal(t, now.Add(defaultReverseRegisterInterval+reversePrevGrace), short.Previous.Until)
	assert.Equal(t, long.PrivateKey, short.PrivateKey)
}

func TestReverseNoPreviousForAnUnregisteredIdentity(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.srv.queue(revResponse{observedIP: "198.51.100.7"})
	e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
	e.cycle(t)
	first := e.box.lastPortal()
	require.NotNil(t, first)

	e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
	e.clock.Advance(defaultReverseRotateInterval)
	e.cycle(t)
	assert.NotEqual(t, first.PrivateKey, e.box.lastPortal().PrivateKey)
	for _, p := range e.box.portals {
		if p != nil {
			assert.Nil(t, p.Previous)
		}
	}
}

func TestReversePreviousDroppedOnClear(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)

	e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
	e.clock.Advance(defaultReverseRotateInterval)
	e.cycle(t)
	rotated := e.box.lastPortal()
	require.NotNil(t, rotated.Previous)

	e.keys.remove("p1")
	e.c.PairingsChanged()
	e.clock.Advance(time.Second)
	e.log.take()
	e.cycle(t)
	assert.Equal(t, []string{"clear-portal", "deregister", "unmap"}, e.log.take())
	assert.Nil(t, e.c.st.prev)
	assert.Nil(t, e.c.st.published, "a cleared identity could come back as Previous")

	e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
	e.keys.set("p1")
	e.clock.Advance(time.Second)
	e.cycle(t)
	portal := e.box.lastPortal()
	require.NotNil(t, portal)
	assert.Equal(t, rotated.PrivateKey, portal.PrivateKey)
	assert.Nil(t, portal.Previous)
}

// A portal moved to another port drops the previous identity: helpers holding
// it dial the old port.
func TestReversePreviousDroppedOnAPortChange(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.cycle(t)

	e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
	e.clock.Advance(defaultReverseRotateInterval)
	e.cycle(t)
	rotated := e.box.lastPortal()
	require.NotNil(t, rotated.Previous)

	e.srv.setFallback(revResponse{observedIP: "198.51.100.7"})
	e.c.unmap(context.Background())
	e.c.st.lastPort = rotated.ListenPort + 1
	e.clock.Advance(defaultReverseRegisterInterval)
	e.log.take()
	e.cycle(t)
	assert.Equal(t, []string{"register:0", "map", "portal", "register:1"}, e.log.take())
	portal := e.box.lastPortal()
	require.NotEqual(t, rotated.ListenPort, portal.ListenPort)
	assert.Nil(t, portal.Previous)
	assert.Nil(t, e.c.st.prev)
}

func TestReverseDoubleRotationKeepsTheLastPublished(t *testing.T) {
	t.Run("second identity registered", func(t *testing.T) {
		e := newRevEnv(t)
		e.keys.set("p1")
		e.cycle(t)
		first := e.box.lastPortal()

		e.clock.Advance(defaultReverseRotateInterval)
		e.cycle(t)
		second := e.box.lastPortal()

		e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
		e.clock.Advance(defaultReverseRotateInterval)
		e.cycle(t)
		third := e.box.lastPortal()
		require.NotNil(t, third.Previous)
		assert.Equal(t, second.PrivateKey, third.Previous.PrivateKey)
		assert.NotEqual(t, first.PrivateKey, third.Previous.PrivateKey)
		assert.Equal(t, e.clock.Now().Add(defaultReverseRotateInterval), third.Previous.Until)
	})
	// The published identity keeps its first deadline, and once that has
	// passed it is never brought back.
	t.Run("second identity never registered", func(t *testing.T) {
		e := newRevEnv(t)
		e.keys.set("p1")
		e.cycle(t)
		first := e.box.lastPortal()

		e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
		e.clock.Advance(defaultReverseRotateInterval)
		rotated := e.clock.Now()
		e.cycle(t)
		second := e.box.lastPortal()
		require.NotNil(t, second.Previous)
		assert.Equal(t, first.PrivateKey, second.Previous.PrivateKey)

		// The address is forgotten by now: the empty register answers, the
		// route register fails.
		e.srv.queue(revResponse{observedIP: "198.51.100.7"}, revResponse{status: http.StatusInternalServerError})
		e.clock.Advance(defaultReverseRotateInterval / 2)
		e.cycle(t)
		require.NotNil(t, e.box.lastPortal().Previous)
		assert.Equal(t, rotated.Add(defaultReverseRotateInterval), e.box.lastPortal().Previous.Until)

		// The address is still remembered, so the one register is the
		// route register, which fails.
		e.clock.Advance(defaultReverseRotateInterval / 2)
		e.log.take()
		e.cycle(t)
		assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
		third := e.box.lastPortal()
		assert.NotEqual(t, second.PrivateKey, third.PrivateKey)
		assert.Nil(t, third.Previous, "an expired identity came back as Previous")
		assert.Nil(t, e.c.st.published)

		e.srv.queue(revResponse{observedIP: "198.51.100.7"}, revResponse{status: http.StatusInternalServerError})
		e.clock.Advance(defaultReverseRotateInterval)
		e.cycle(t)
		assert.Nil(t, e.box.lastPortal().Previous, "an expired identity came back as Previous")
	})
}

// A failed configure leaves the client holding what the box serves, and the
// next cycle tries again.
func TestReverseFailedPreviousConfigureKeepsStateConsistent(t *testing.T) {
	t.Run("rotation", func(t *testing.T) {
		e := newRevEnv(t)
		key := e.keys.set("p1")
		e.cycle(t)
		published := e.box.lastPortal()
		creds := e.c.st.portalCreds

		e.box.setErrs(errors.New("bind failed"), nil)
		e.clock.Advance(defaultReverseRotateInterval)
		rotated := e.clock.Now()
		e.log.take()
		e.cycle(t)
		assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
		assert.Same(t, published, e.c.st.portal)
		assert.Same(t, creds, e.c.st.portalCreds)
		assert.Nil(t, e.c.st.portalPrev)
		r := openBlob(t, key, e.srv.lastRegister()[0], e.clock.Now())
		assert.Equal(t, x25519Public(t, published.PrivateKey), r.PublicKey)

		e.box.setErrs(nil, nil)
		e.clock.Advance(defaultReverseRegisterInterval)
		registered := e.clock.Now()
		e.cycle(t)
		assert.Equal(t, []string{"portal", "register:1", "portal"}, e.log.take())
		n := len(e.box.portals)
		assert.Equal(t, published.PrivateKey, prevKey(e.box.portals[n-2]))
		assert.Equal(t, rotated.Add(defaultReverseRotateInterval), e.box.portals[n-2].Previous.Until)
		assert.Equal(t, published.PrivateKey, prevKey(e.box.portals[n-1]))
		assert.Equal(t, registered.Add(defaultReverseRegisterInterval+reversePrevGrace), e.box.portals[n-1].Previous.Until)
	})
	t.Run("cut", func(t *testing.T) {
		e := newRevEnv(t)
		e.keys.set("p1")
		e.cycle(t)
		published := e.box.lastPortal()
		var configures int
		e.c.cfg.Box = portalErrAfter{revBox: e.box, err: errors.New("configure failed"), n: len(e.box.portals) + 1, count: &configures}

		e.clock.Advance(defaultReverseRotateInterval)
		rotated := e.clock.Now()
		e.log.take()
		configures = len(e.box.portals)
		e.cycle(t)
		assert.Equal(t, []string{"portal", "register:1", "portal"}, e.log.take())
		serving := e.box.portals[len(e.box.portals)-2]
		assert.Same(t, serving, e.c.st.portal, "the client holds the configuration the box serves")
		assert.Equal(t, rotated.Add(defaultReverseRotateInterval), e.c.st.portal.Previous.Until)
		assert.Equal(t, published.PrivateKey, prevKey(e.c.st.portal))
		assert.Same(t, e.c.st.prev, e.c.st.portalPrev)

		e.c.cfg.Box = e.box
		e.box.setErrs(nil, nil)
		e.clock.Advance(defaultReverseRegisterInterval)
		e.cycle(t)
		assert.Equal(t, []string{"portal", "register:1"}, e.log.take())
		portal := e.box.lastPortal()
		assert.Equal(t, published.PrivateKey, prevKey(portal))
		assert.Equal(t, rotated.Add(defaultReverseRegisterInterval+reversePrevGrace), portal.Previous.Until)
	})
}

// Revoking a pairing edits the pairings and keeps the previous identity.
func TestReverseRevocationKeepsThePrevious(t *testing.T) {
	e := newRevEnv(t)
	e.keys.set("p1")
	e.keys.set("p2")
	e.cycle(t)
	published := e.box.lastPortal()

	e.srv.setFallback(revResponse{status: http.StatusInternalServerError})
	e.clock.Advance(defaultReverseRotateInterval)
	e.cycle(t)
	rotated := e.box.lastPortal()
	require.NotNil(t, rotated.Previous)

	e.keys.remove("p1")
	e.log.take()
	e.c.dropRevoked(e.keys.IDs(string(helperticket.RoleInviter)))
	assert.Equal(t, []string{"portal", "outbounds:1"}, e.log.take())
	portal := e.box.lastPortal()
	assert.Less(t, len(portal.Pairings), len(rotated.Pairings))
	assert.Equal(t, rotated.PrivateKey, portal.PrivateKey)
	assert.Equal(t, published.PrivateKey, prevKey(portal))
	assert.Equal(t, rotated.Previous.Until, portal.Previous.Until)
}
