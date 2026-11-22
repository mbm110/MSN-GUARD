package peer

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/broflake/common/helperticket"
	lbA "github.com/getlantern/lantern-box/adapter"
	"github.com/getlantern/lantern-box/portforward"
	"github.com/getlantern/lantern-box/protocol/samizdatreverse"
	"github.com/sagernet/sing/common/control"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/helper/reverse"
)

const (
	defaultReverseRegisterInterval = 150 * time.Second
	defaultReverseRotateInterval   = time.Hour
	defaultReverseAddrMemory       = time.Hour
	reverseDisabledWait            = time.Hour
	maxReverseBackoff              = 10 * time.Minute
	// maxReverseRoutes is the most routes lantern-cloud accepts in one
	// register call.
	maxReverseRoutes = 20
	// maxReverseReregisters bounds the registers a cycle repeats because the
	// observed address changed, so two addresses alternating between calls
	// cannot loop.
	maxReverseReregisters  = 2
	reversePortDescription = "Lantern personal proxy"
	// reversePrevGrace is how long past one register interval the portal
	// keeps the previous identity once the new one is registered, so helpers
	// poll the new route once more before the old identity stops working.
	reversePrevGrace = 30 * time.Second
)

// ReverseBox is the VPN box the reverse client serves through; vpn.VPNClient
// implements it.
type ReverseBox interface {
	SetReversePortal(cfg *samizdatreverse.PortalConfig, masqueradeDomain string) error
	SetReverseOutbounds(tags []string) error
	RebindReversePortal() error
	// ReversePortalListening reports whether a running portal holds a
	// listener. A failed bind or rebind leaves it without one.
	ReversePortalListening() bool
}

// PairingKeySource returns this device's helper pairing keys; helper.PairingKeys
// implements it.
type PairingKeySource interface {
	Get(pairingID string) ([]byte, bool)
	IDs(role string) []string
}

// ReverseConfig plumbs in a ReverseClient's dependencies. Zero durations and a
// nil Now, NewForwarder or Logger fall back to production defaults.
type ReverseConfig struct {
	API  *helper.ReverseAPI
	Keys PairingKeySource
	Box  ReverseBox
	// NewForwarder returns a forwarder that discovers the gateway. It is not
	// used while the client maps the manual port.
	NewForwarder func(ctx context.Context) (portForwarder, error)
	// OnTags, if set, is given a copy of the pairing ID to helper tag map each
	// time a register changes it, on the client's goroutine before the box
	// hears of the change. It must not block.
	OnTags func(tags map[string]string)
	// PeerShareActive, if set, reports whether peer sharing is on. Start
	// reads it once: a run started while it is on maps a port of its own
	// rather than the manual port, which peer sharing binds.
	PeerShareActive func() bool
	// LocalIPControl, if set, returns the socket control that keeps port
	// mapping off the VPN tunnel, from discovering the gateway to every
	// request to it and the LAN address mapped to, or nil with no tunnel.
	LocalIPControl   func() control.Func
	Now              func() time.Time
	RegisterInterval time.Duration
	RotateInterval   time.Duration
	// AddrMemory is how long an observed address of one family is kept
	// without being observed again.
	AddrMemory time.Duration
	Logger     *slog.Logger
}

// ReverseClient lets this device's paired helpers reach it as an inviter: it
// maps a TCP port for the VPN box's reverse portal and keeps a sealed route to
// it registered with lantern-cloud for each inviter pairing. It is safe for
// concurrent use.
type ReverseClient struct {
	cfg         ReverseConfig
	coverDomain string
	kick        chan struct{}
	netChanged  atomic.Bool
	pairing     helper.PairingWatch

	mu     sync.Mutex
	cancel context.CancelFunc
	// done closes when the last started run has torn down.
	done chan struct{}
	// released closes when the last started run has removed its portal and
	// unmapped its port, before it deregisters.
	released chan struct{}
	// yielded says the running client skipped the manual port for peer
	// sharing.
	yielded bool
	// cycled, when set by a test before Start, runs after each cycle.
	cycled func()

	// st is owned by the run goroutine; a run starts only after the previous
	// one's done closes.
	st reverseState
}

type observedAddr struct {
	ip netip.Addr
	at time.Time
}

type reverseState struct {
	fwd     portForwarder
	mapping *portforward.Mapping
	// manualPort is the manual port configured when the run started, or 0.
	// The run maps it unless yielded, and never picks it as a discovered
	// mapping's internal port.
	manualPort uint16
	yielded    bool
	// lastPort is the internal port of the last mapping, tried again on a
	// remap so the portal keeps its listener.
	lastPort uint16
	creds    *reverseCreds
	credsAt  time.Time
	v4, v6   observedAddr
	tags     map[string]string
	// registered says lantern-cloud may hold routes this client sent.
	registered    bool
	registeredIDs []string
	// boxSet says the box may hold a portal this client configured.
	boxSet      bool
	portal      *samizdatreverse.PortalConfig
	portalCreds *reverseCreds
	// portalPrev is the identity the portal was configured with as
	// Previous, set exactly when portal.Previous is.
	portalPrev *reverseCreds
	// published is the identity sealed into the last route a register
	// accepted, served on publishedPort: the one helpers may hold.
	published     *reverseCreds
	publishedPort uint16
	// prev is the published identity a rotation replaced, which the portal
	// keeps accepting new sessions under until prevUntil, if it still
	// listens on prevPort. prevRotated is when the rotation happened.
	prev           *reverseCreds
	prevPort       uint16
	prevRotated    time.Time
	prevUntil      time.Time
	outbounds      []string
	outboundsKnown bool
	apiNotBefore   time.Time
	backoff        time.Duration
	warnedRouteCap bool
}

// NewReverseClient returns a stopped ReverseClient.
func NewReverseClient(cfg ReverseConfig) *ReverseClient {
	if cfg.NewForwarder == nil {
		cfg.NewForwarder = func(ctx context.Context) (portForwarder, error) {
			return newForwarder(ctx, nil, append([]portforward.Option{portforward.QuietLogs()}, boundTo(cfg.LocalIPControl)...)...)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RegisterInterval == 0 {
		cfg.RegisterInterval = defaultReverseRegisterInterval
	}
	if cfg.RotateInterval == 0 {
		cfg.RotateInterval = defaultReverseRotateInterval
	}
	if cfg.AddrMemory == 0 {
		cfg.AddrMemory = defaultReverseAddrMemory
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &ReverseClient{
		cfg:         cfg,
		coverDomain: pickReverseCoverDomain(),
		kick:        make(chan struct{}, 1),
	}
}

// Start starts serving in the background and returns at once; it does no
// network I/O itself. Starting a started client does nothing. It returns an
// error only when API, Keys or Box is nil.
//
// The run keeps the forwarding chosen here: the manual port if one is
// configured and peer sharing is off, and a mapped port otherwise.
func (c *ReverseClient) Start(context.Context) error {
	if c.cfg.API == nil || c.cfg.Keys == nil || c.cfg.Box == nil {
		return errors.New("peer: ReverseConfig needs API, Keys and Box")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		return nil
	}
	manual := reverseManualPort(c.cfg.Logger)
	yielded := manual != 0 && c.cfg.PeerShareActive != nil && c.cfg.PeerShareActive()
	if yielded {
		c.cfg.Logger.Info("reverse: peer sharing holds the manual port, mapping another")
	}
	ctx, cancel := context.WithCancel(context.Background())
	prev, done, released := c.done, make(chan struct{}), make(chan struct{})
	c.cancel, c.done, c.released, c.yielded = cancel, done, released, yielded
	go c.run(ctx, prev, done, released, manual, yielded)
	return nil
}

// YieldedManualPort reports whether the running client maps a port of its own
// because peer sharing was on when it started.
func (c *ReverseClient) YieldedManualPort() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancel != nil && c.yielded
}

// Stop removes the portal and its reverse outbounds from the box, unmaps the
// port, and deregisters this device's routes, in that order. It waits for that
// teardown or for ctx, whichever ends first; the teardown has its own
// deadlines and finishes either way.
func (c *ReverseClient) Stop(ctx context.Context) {
	done, _ := c.halt()
	waitOrDone(ctx, done)
}

// Release is Stop, but waits only until the portal is removed and the port
// unmapped; the deregister finishes in the background.
func (c *ReverseClient) Release(ctx context.Context) {
	_, released := c.halt()
	waitOrDone(ctx, released)
}

func (c *ReverseClient) halt() (done, released <-chan struct{}) {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	done, released = c.done, c.released
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return done, released
}

func waitOrDone(ctx context.Context, ch <-chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

// NetworkChanged forgets the observed addresses, deregisters, rebinds the
// portal, maps the port again and registers at once. It marks the public IP
// stale, so reverse requests stop carrying it.
func (c *ReverseClient) NetworkChanged() {
	common.MarkPublicIPStale()
	c.netChanged.Store(true)
	c.wake()
}

// PairingsChanged registers at once for the current inviter pairings.
func (c *ReverseClient) PairingsChanged() {
	c.pairing.Changed()
	c.wake()
}

func (c *ReverseClient) wake() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *ReverseClient) run(ctx context.Context, prev <-chan struct{}, done, released chan struct{}, manual uint16, yielded bool) {
	defer close(done)
	if prev != nil {
		<-prev
	}
	// The last run's port may be the manual port this run must not map.
	c.st.manualPort, c.st.yielded, c.st.lastPort = manual, yielded, 0
	defer c.teardown(released)
	for {
		wait := c.cycle(ctx)
		if c.cycled != nil {
			c.cycled()
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-c.kick:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// teardown releases the portal and port before it deregisters, so released
// never waits on lantern-cloud.
func (c *ReverseClient) teardown(released chan struct{}) {
	s := &c.st
	c.clearBox()
	c.unmap(context.Background())
	close(released)
	// While held off the routes are left to expire, so a restart loop
	// cannot cut the hold-off short.
	if now := c.cfg.Now(); !now.Before(s.apiNotBefore) {
		c.deregister(context.Background(), now)
	}
	s.v4, s.v6 = observedAddr{}, observedAddr{}
	s.tags = nil
	s.creds, s.credsAt = nil, time.Time{}
	s.published, s.prev = nil, nil
}

// cycle does one round of work and returns how long to wait before the next.
func (c *ReverseClient) cycle(runCtx context.Context) time.Duration {
	s := &c.st
	// lantern-cloud calls end when the pairings change, so a revocation
	// never waits on one.
	ctx, release := c.pairing.Watch(runCtx, c.pairing.Snapshot())
	defer release()
	now := c.cfg.Now()
	ids := c.cfg.Keys.IDs(string(helperticket.RoleInviter))
	c.dropRevoked(ids)
	gated := now.Before(s.apiNotBefore)
	if c.netChanged.Swap(false) {
		s.v4, s.v6 = observedAddr{}, observedAddr{}
		if !gated {
			c.deregister(ctx, now)
		}
		if s.boxSet {
			if err := c.cfg.Box.RebindReversePortal(); err != nil {
				c.cfg.Logger.Warn("reverse: could not rebind the portal")
			}
		}
		c.unmap(ctx)
		gated = now.Before(s.apiNotBefore)
	}
	if len(ids) == 0 {
		if !gated {
			c.deregister(ctx, now)
		}
		c.clearBox()
		c.unmap(ctx)
		s.tags = nil
		return c.untilNextCycle(now)
	}
	if gated {
		return s.apiNotBefore.Sub(now)
	}
	if len(ids) > maxReverseRoutes && !s.warnedRouteCap {
		s.warnedRouteCap = true
		c.cfg.Logger.Info("reverse: more inviter pairings than routes allowed, registering a subset",
			"pairings", len(ids), "routes", maxReverseRoutes)
	}
	if len(ids) > maxReverseRoutes {
		ids = ids[:maxReverseRoutes]
	}
	for id := range s.tags {
		if !slices.Contains(ids, id) {
			delete(s.tags, id)
		}
	}
	s.expire(now, c.cfg.AddrMemory)
	// The empty register comes before any mapping, so a disabled feature
	// never opens a port.
	if s.mapping == nil || !s.hasAddr() {
		resp, err := c.cfg.API.Register(ctx, nil)
		if err != nil {
			return c.apiFailed(ctx, err, now)
		}
		s.backoff = 0
		s.observe(resp.ObservedIP, now)
		if !s.hasAddr() {
			c.withdraw(ctx, now)
			return c.untilNextCycle(now)
		}
	}
	if s.mapping == nil && !c.mapPort(runCtx) {
		return c.cfg.RegisterInterval
	}
	if s.creds == nil || now.Sub(s.credsAt) >= c.cfg.RotateInterval {
		creds, err := newReverseCreds(c.coverDomain)
		if err != nil {
			c.cfg.Logger.Error("reverse: could not make listener credentials", "err", err)
			return c.cfg.RegisterInterval
		}
		// A previous identity that is still the one published keeps the
		// deadline it got when it was first rotated out.
		if s.prev == nil || s.prev != s.published {
			s.prev = nil
			if s.creds != nil && s.published != nil {
				s.prev, s.prevPort = s.published, s.publishedPort
				s.prevRotated, s.prevUntil = now, now.Add(c.cfg.RotateInterval)
			}
		}
		s.creds, s.credsAt = &creds, now
	}
	if slices.ContainsFunc(s.registeredIDs, func(id string) bool { return !slices.Contains(ids, id) }) {
		if c.deregister(ctx, now); now.Before(s.apiNotBefore) {
			return s.apiNotBefore.Sub(now)
		}
	}
	c.applyBox(ids, now)
	for range 1 + maxReverseReregisters {
		// Routes advertise the identity the running portal holds, which a
		// failed reconfigure leaves at the previous credentials.
		if s.portal == nil || s.portal.ListenPort != s.mapping.InternalPort || c.portalDown() {
			return c.cfg.RegisterInterval
		}
		blobs := c.seal(ids, now)
		if len(blobs) == 0 {
			return c.cfg.RegisterInterval
		}
		s.registered = true
		resp, err := c.cfg.API.Register(ctx, blobs)
		if err != nil {
			return c.apiFailed(ctx, err, now)
		}
		s.backoff = 0
		s.registeredIDs = s.registeredIDs[:0]
		for _, b := range blobs {
			s.registeredIDs = append(s.registeredIDs, b.PairingID)
		}
		shortened := c.markPublished(c.cfg.Now())
		if c.updateTags(blobs, resp.Tags) || shortened {
			c.applyBox(ids, now)
		}
		if !s.observe(resp.ObservedIP, now) {
			break
		}
	}
	return c.cfg.RegisterInterval
}

// markPublished records that a register accepted routes for the portal's
// identity at now. Once the identity a rotation replaced is no longer the one
// published, it reports whether the previous identity's time was cut to one
// more helper poll.
func (c *ReverseClient) markPublished(now time.Time) bool {
	s := &c.st
	s.published, s.publishedPort = s.portalCreds, s.portal.ListenPort
	if s.prev == nil || s.prev == s.portalCreds {
		return false
	}
	until := now.Add(c.cfg.RegisterInterval + reversePrevGrace)
	if capped := s.prevRotated.Add(c.cfg.RotateInterval); capped.Before(until) {
		until = capped
	}
	if !until.Before(s.prevUntil) {
		return false
	}
	s.prevUntil = until
	return true
}

// dropRevoked takes the pairings not in ids, or whose key is gone, out of the
// portal and reverse outbounds, so a revocation never waits on lantern-cloud.
func (c *ReverseClient) dropRevoked(ids []string) {
	s := &c.st
	authorized := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := c.cfg.Keys.Get(id); ok {
			authorized[id] = true
		}
	}
	held := len(s.tags)
	maps.DeleteFunc(s.tags, func(id, _ string) bool { return !authorized[id] })
	if len(authorized) == 0 {
		c.clearBox()
		return
	}
	if !s.boxSet {
		return
	}
	allowed := make(map[string]bool, len(s.tags))
	for _, tag := range s.tags {
		allowed[lbA.ReverseHelperTag(tag)] = true
	}
	if s.portal != nil {
		pairings := maps.Clone(s.portal.Pairings)
		maps.DeleteFunc(pairings, func(_ [8]byte, tag string) bool { return !allowed[tag] })
		if len(pairings) != len(s.portal.Pairings) {
			cfg := *s.portal
			cfg.Pairings = pairings
			if err := c.cfg.Box.SetReversePortal(&cfg, c.coverDomain); err != nil {
				c.cfg.Logger.Warn("reverse: could not configure the portal")
			} else {
				s.portal = &cfg
			}
		}
	}
	kept := slices.DeleteFunc(slices.Clone(s.outbounds), func(tag string) bool { return !allowed[tag] })
	// After a failed set the box may hold a dropped pairing's outbound that
	// s.outbounds lacks.
	if len(kept) != len(s.outbounds) || (!s.outboundsKnown && len(s.tags) < held) {
		c.setOutbounds(kept)
	}
}

// untilNextCycle is the register interval, or longer while API calls are
// held off.
func (c *ReverseClient) untilNextCycle(now time.Time) time.Duration {
	if wait := c.st.apiNotBefore.Sub(now); wait > c.cfg.RegisterInterval {
		return wait
	}
	return c.cfg.RegisterInterval
}

type localIPControlSetter interface {
	SetLocalIPControl(control.Func)
}

type quietLogSetter interface {
	SetQuietLogs(bool)
}

func (c *ReverseClient) mapPort(ctx context.Context) bool {
	s := &c.st
	var fwd portForwarder
	if s.mapsManualPort() {
		fwd = portforward.NewManualForwarder(s.manualPort)
	} else {
		var err error
		if fwd, err = c.cfg.NewForwarder(ctx); err != nil {
			// Gateway errors name local addresses.
			c.cfg.Logger.Info("reverse: no port forwarding",
				"unsupported", errors.Is(err, portforward.ErrNoPortForwarding))
			return false
		}
	}
	// Its log lines would otherwise carry the mapped ports and LAN address.
	if q, ok := fwd.(quietLogSetter); ok {
		q.SetQuietLogs(true)
	}
	if lf, ok := fwd.(localIPControlSetter); ok && c.cfg.LocalIPControl != nil {
		if fn := currentPhysical(c.cfg.LocalIPControl); fn != nil {
			lf.SetLocalIPControl(fn)
		}
	}
	port := s.lastPort
	if port == 0 {
		port = pickInternalPortExcept(s.manualPort)
	}
	mapping, err := fwd.MapPort(ctx, portforward.TCP, port, reversePortDescription)
	if err != nil {
		c.cfg.Logger.Info("reverse: could not map a port",
			"unsupported", errors.Is(err, portforward.ErrNoPortForwarding),
			"no_local_ip", errors.Is(err, portforward.ErrNoLocalIP))
		cleanupCtx, cancel := context.WithTimeout(context.Background(), peerCleanupTimeout)
		_ = fwd.UnmapPort(cleanupCtx)
		cancel()
		s.lastPort = 0
		return false
	}
	// Renewal runs until UnmapPort, which outlives the run's ctx in teardown.
	fwd.StartRenewal(context.Background())
	s.fwd, s.mapping, s.lastPort = fwd, mapping, mapping.InternalPort
	return true
}

func (c *ReverseClient) unmap(ctx context.Context) {
	s := &c.st
	if s.fwd == nil {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), peerCleanupTimeout)
	defer cancel()
	if err := s.fwd.UnmapPort(cleanupCtx); err != nil {
		c.cfg.Logger.Info("reverse: could not unmap the port")
	}
	s.fwd, s.mapping = nil, nil
}

func (c *ReverseClient) deregister(ctx context.Context, now time.Time) {
	s := &c.st
	if !s.registered {
		return
	}
	// A cancelled run's deregister ends at once; teardown deregisters again.
	ctx, cancel := context.WithTimeout(ctx, peerCleanupTimeout)
	defer cancel()
	if err := c.cfg.API.Deregister(ctx); err != nil {
		c.apiFailed(ctx, err, now)
		return
	}
	s.registered = false
	s.registeredIDs = nil
}

// withdraw takes this device's routes and reverse outbounds down while it
// knows no address to reach it at, keeping the mapping and portal.
func (c *ReverseClient) withdraw(ctx context.Context, now time.Time) {
	c.deregister(ctx, now)
	c.setOutbounds(nil)
}

func (c *ReverseClient) clearBox() {
	s := &c.st
	if !s.boxSet {
		return
	}
	if err := c.cfg.Box.SetReversePortal(nil, ""); err != nil {
		c.cfg.Logger.Warn("reverse: could not remove the portal")
		return
	}
	s.boxSet = false
	s.portal, s.portalCreds, s.portalPrev = nil, nil, nil
	// A cleared portal's identity is never brought back as Previous.
	s.published, s.prev = nil, nil
	s.outbounds, s.outboundsKnown = nil, true
}

func (c *ReverseClient) apiFailed(ctx context.Context, err error, now time.Time) time.Duration {
	s := &c.st
	if ctx.Err() != nil {
		return c.cfg.RegisterInterval
	}
	var apiErr *helper.ReverseAPIError
	switch {
	case errors.Is(err, helper.ErrReverseDisabled):
		c.cfg.Logger.Info("reverse: routes disabled by lantern-cloud")
		s.apiNotBefore = now.Add(reverseDisabledWait)
		// A disabled server serves no routes, and the rows it holds expire.
		s.registered, s.registeredIDs = false, nil
		c.clearBox()
		c.unmap(ctx)
		s.creds, s.credsAt = nil, time.Time{}
		s.published, s.prev = nil, nil
		return reverseDisabledWait
	case errors.As(err, &apiErr) &&
		(apiErr.Status == http.StatusTooManyRequests || apiErr.Status == http.StatusServiceUnavailable):
		s.backoff = min(2*max(s.backoff, c.cfg.RegisterInterval), maxReverseBackoff)
		c.cfg.Logger.Info("reverse: lantern-cloud is busy, backing off", "wait", s.backoff)
		s.apiNotBefore = now.Add(s.backoff)
		return s.backoff
	}
	c.cfg.Logger.Warn("reverse: lantern-cloud call failed", "err", err)
	return c.cfg.RegisterInterval
}

// seal returns a fresh blob for each pairing in ids, for the portal's
// credentials.
func (c *ReverseClient) seal(ids []string, now time.Time) []helper.ReverseBlob {
	s := &c.st
	route := reverse.Route{
		PublicKey:      s.portalCreds.PublicKey,
		CertSPKISHA256: s.portalCreds.SPKI,
		CoverDomain:    s.portalCreds.CoverDomain,
		IssuedAt:       now,
	}
	// The router forwards only IPv4, to the internal port; IPv6 reaches the
	// listener directly.
	if s.v4.ip.IsValid() {
		route.Addrs = append(route.Addrs, netip.AddrPortFrom(s.v4.ip, s.mapping.ExternalPort))
	}
	if s.v6.ip.IsValid() {
		route.Addrs = append(route.Addrs, netip.AddrPortFrom(s.v6.ip, s.mapping.InternalPort))
	}
	blobs := make([]helper.ReverseBlob, 0, len(ids))
	failed := 0
	for _, id := range ids {
		key, ok := c.cfg.Keys.Get(id)
		if !ok {
			continue
		}
		blob, err := reverse.Seal(key, id, route)
		if err != nil || len(blob) == 0 || len(blob) > reverse.MaxBlobLen || blob[0] != reverse.BlobVersion {
			failed++
			continue
		}
		blobs = append(blobs, helper.ReverseBlob{PairingID: id, Blob: blob, Version: reverse.BlobVersion})
	}
	if failed > 0 {
		c.cfg.Logger.Error("reverse: could not seal routes", "failed", failed)
	}
	return blobs
}

// updateTags takes the tags of the registered pairings from a register
// response and reports whether any changed.
func (c *ReverseClient) updateTags(blobs []helper.ReverseBlob, tags map[string]string) bool {
	s := &c.st
	before := maps.Clone(s.tags)
	if s.tags == nil {
		s.tags = make(map[string]string)
	}
	for _, b := range blobs {
		if tag := tags[b.PairingID]; tag != "" {
			s.tags[b.PairingID] = tag
		} else {
			delete(s.tags, b.PairingID)
		}
	}
	if maps.Equal(before, s.tags) {
		return false
	}
	if c.cfg.OnTags != nil {
		c.cfg.OnTags(maps.Clone(s.tags))
	}
	return true
}

// applyBox brings the portal and reverse outbounds in line with the current
// credentials, port and tags, retrying whatever failed last time.
func (c *ReverseClient) applyBox(ids []string, now time.Time) {
	s := &c.st
	pairings := make(map[[8]byte]string)
	var tags []string
	for _, id := range ids {
		tag := lbA.ReverseHelperTag(s.tags[id])
		if tag == "" {
			continue
		}
		key, ok := c.cfg.Keys.Get(id)
		if !ok {
			continue
		}
		for _, sid := range reverse.AcceptedShortIDs(key, now) {
			pairings[sid] = tag
		}
		tags = append(tags, tag)
	}
	slices.Sort(tags)
	tags = slices.Compact(tags)

	// Helpers that hold the previous identity's route dial the port it was
	// published on, and a portal moved to another port takes nothing there.
	if s.prev != nil && (!now.Before(s.prevUntil) || s.prevPort != s.mapping.InternalPort || s.prev == s.creds) {
		// Once dropped, it is never brought back as Previous.
		if s.published == s.prev {
			s.published = nil
		}
		s.prev = nil
	}

	if s.portal == nil || s.portalCreds != s.creds || s.portal.ListenPort != s.mapping.InternalPort ||
		!maps.Equal(s.portal.Pairings, pairings) || c.portalDown() || s.portalPrev != s.prev ||
		(s.prev != nil && !s.portal.Previous.Until.Equal(s.prevUntil)) {
		cfg := &samizdatreverse.PortalConfig{
			ListenPort: s.mapping.InternalPort,
			PrivateKey: s.creds.PrivateKey[:],
			CertPEM:    s.creds.CertPEM,
			KeyPEM:     s.creds.KeyPEM,
			Pairings:   pairings,
		}
		if s.prev != nil {
			cfg.Previous = &samizdatreverse.PreviousIdentity{
				PrivateKey: s.prev.PrivateKey[:],
				CertPEM:    s.prev.CertPEM,
				KeyPEM:     s.prev.KeyPEM,
				Until:      s.prevUntil,
			}
		}
		s.boxSet = true
		if err := c.cfg.Box.SetReversePortal(cfg, c.coverDomain); err != nil {
			// The error can name the port or a tag.
			c.cfg.Logger.Warn("reverse: could not configure the portal")
			if s.portal == nil || len(s.portal.Pairings) == 0 || c.portalDown() {
				// Nothing serves: no route is published until a configure
				// succeeds.
				s.portal, s.portalPrev = nil, nil
				// Another socket holds the port the client picked, so the
				// next cycle maps a different one.
				if !s.mapsManualPort() && portInUse(err) {
					c.unmap(context.Background())
					s.lastPort = 0
				}
			}
			return
		}
		s.portal, s.portalCreds, s.portalPrev = cfg, s.creds, s.prev
	}
	c.setOutbounds(tags)
}

// portalDown reports whether the portal configured with pairings has lost its
// listener, to a failed rebind or a tunnel that came up without it.
func (c *ReverseClient) portalDown() bool {
	s := &c.st
	return s.portal != nil && len(s.portal.Pairings) > 0 && !c.cfg.Box.ReversePortalListening()
}

func (c *ReverseClient) setOutbounds(tags []string) {
	s := &c.st
	if s.outboundsKnown && slices.Equal(s.outbounds, tags) {
		return
	}
	if err := c.cfg.Box.SetReverseOutbounds(tags); err != nil {
		// The error can name a tag.
		c.cfg.Logger.Warn("reverse: could not set the reverse outbounds")
		s.outboundsKnown = false
		return
	}
	s.outbounds, s.outboundsKnown = tags, true
}

func (s *reverseState) mapsManualPort() bool { return s.manualPort != 0 && !s.yielded }

func (s *reverseState) hasAddr() bool { return s.v4.ip.IsValid() || s.v6.ip.IsValid() }

func (s *reverseState) expire(now time.Time, memory time.Duration) {
	if s.v4.ip.IsValid() && now.Sub(s.v4.at) > memory {
		s.v4 = observedAddr{}
	}
	if s.v6.ip.IsValid() && now.Sub(s.v6.at) > memory {
		s.v6 = observedAddr{}
	}
}

// observe records ip for its family and reports whether it differs from the
// address held for that family.
func (s *reverseState) observe(ip string, now time.Time) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.Zone() != "" {
		return false
	}
	held := &s.v6
	if addr.Is4() {
		held = &s.v4
	}
	changed := held.ip != addr
	*held = observedAddr{ip: addr, at: now}
	return changed
}
