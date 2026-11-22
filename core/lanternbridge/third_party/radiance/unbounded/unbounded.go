// Package unbounded manages the broflake / Unbounded widget-proxy lifecycle.
//
// Unbounded is the WebRTC-based donor mode for Lantern's Share My Connection
// feature: the local user contributes bandwidth to censored users via short-
// lived WebRTC sessions brokered through a discovery server, without exposing
// a long-lived inbound port the way the samizdat-over-UPnP "Share My
// Connection" mode does. It's the lower-bandwidth, lower-risk, universally-
// applicable alternative to SmC — works on networks where UPnP is disabled
// or unavailable, and the peer's residential IP isn't tied to a single
// long-lived inbound listener.
//
// Three conditions must all hold for the widget proxy to actually run:
//
//  1. settings.UnboundedKey is true (local opt-in via the UI toggle)
//  2. server-side cfg.Features[UNBOUNDED] is enabled (server says go)
//  3. server-side cfg.Unbounded provides discovery + egress URLs
//
// The manager subscribes to config.NewConfigEvent and recomputes the
// running state on every config update; it also re-evaluates when
// SetEnabled flips the local toggle. Each consumer connection change
// (accept / disconnect) emits a ConnectionEvent on the radiance event
// bus so the same Flutter globe used for SmC can render arcs without
// caring which protocol produced them.
package unbounded

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/getlantern/common"

	"github.com/getlantern/broflake/clientcore"
	"github.com/getlantern/broflake/common"
	"github.com/getlantern/broflake/common/helperticket"
	"github.com/sagernet/sing-box/experimental/libbox"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/common/sameorigin"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
)

// ConnectionEvent fires every time a consumer (i.e. a censored client
// being routed through this widget proxy) connects or disconnects via
// the broflake mesh.
//
//	State     +1 on accept, -1 on close
//	Source    consumer's IP if broflake exposes it, otherwise empty
//	Timestamp emit time in Unix milliseconds
//
// JSON shape is identical to peer.ConnectionEvent so a consumer
// reading both SSE streams can deserialize each frame with the
// same struct. The in-process event bus, however, keys
// subscriptions by concrete Go type, so subscribing to
// peer.ConnectionEvent does NOT also deliver unbounded
// ConnectionEvents — in-process consumers that want a unified
// view of all peer activity must subscribe to both. Broflake's
// internal worker-slot identifier is not surfaced; a consumer
// that needs to pair accept/close events for the same arc keys
// off Source (or arrival sequence within a single connection
// lifetime).
type ConnectionEvent struct {
	events.Event
	State     int    `json:"state"`
	Source    string `json:"source"`
	Timestamp int64  `json:"timestamp"`
}

// connSources tracks the source addr of each live consumer slot so a close
// event — which broflake delivers with a nil addr — can be re-tagged with the
// addr its accept carried. Keyed by broflake's workerIdx (the consumer slot),
// stable across a single connection's accept→close. Without this, a close
// carries an empty Source, downstream consumers (the Flutter globe + helped
// counter) can't match it to the accept, and the connection's arc/count leaks.
// Concurrency-safe: broflake fires connection-change callbacks from per-worker
// goroutines.
type connSources struct {
	mu    sync.Mutex
	addrs map[int]string
}

func newConnSources() *connSources {
	return &connSources{addrs: make(map[int]string)}
}

// resolve records the addr on accept (state > 0) or restores it on close
// (state < 0, where broflake's addr is nil), returning the Source the
// ConnectionEvent should carry. An accept with an empty addr is left
// untracked, so its close stays empty too — neither is counted, which is the
// right behavior when broflake can't surface the consumer IP at all.
func (c *connSources) resolve(state, workerIdx int, addrStr string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case state > 0:
		if addrStr != "" {
			c.addrs[workerIdx] = addrStr
		}
	case state < 0:
		if addrStr == "" {
			addrStr = c.addrs[workerIdx]
		}
		delete(c.addrs, workerIdx)
	}
	return addrStr
}

var manager = &unboundedManager{}

// widget is the minimum interface the manager needs from a running
// broflake instance. Defined locally (vs using clientcore.UI) so
// tests can supply a tiny fake without implementing the full
// clientcore.UI surface area.
type widget interface {
	Stop()
}

// bypassHTTPClient makes the widget's HTTP requests: its signaling with
// freddie and its WebSocket handshake to the egress. With the VPN on, the
// widget runs in the VPN's own process, whose sockets bypass the tunnel while
// the system resolver points into it, so a default dial can't resolve either
// host. The bypass proxy resolves and routes around the tunnel, and
// bypass.DialContext dials directly when the VPN isn't running.
var bypassHTTPClient = newBypassHTTPClient(bypass.DialContext)

func newBypassHTTPClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dial
	return &http.Client{Transport: transport}
}

// newWidget builds the live broflake widget. Package var so unit
// tests can swap it for a fake that records start/stop calls
// without spinning up real WebRTC.
var newWidget = func(bfOpt *clientcore.BroflakeOptions, rtcOpt *clientcore.WebRTCOptions, egOpt *clientcore.EgressOptions) (widget, error) {
	// BroflakeConn is for clients routing traffic *through* the mesh.
	// A widget proxy only donates bandwidth, so the conn is unused —
	// discard it.
	_, ui, err := clientcore.NewBroflake(bfOpt, rtcOpt, egOpt)
	if err != nil {
		return nil, err
	}
	return ui, nil
}

type unboundedManager struct {
	// transitionMu serializes start/stop. It's held for the full
	// duration of a stop (including the wait for the worker goroutine
	// to actually exit) and for the full duration of a start. Without
	// it, stop's signal-then-return path could race a concurrent start
	// — the worker is still running ui.Stop while cancel/done get
	// re-armed under a fresh worker, leaving two broflake widgets
	// alive simultaneously.
	transitionMu sync.Mutex

	// mu protects the fields below. Held only for the brief window of
	// reading or mutating manager state; never held across the wait on
	// done or any broflake call.
	mu sync.Mutex
	// armed gates every start path. InitSubscription flips it true;
	// public Stop flips it false. Without this gate, a config event
	// (or any other applyConfig caller) racing the public Stop's
	// transitionMu hold could observe cancel==nil after Stop's wait,
	// pile up at transitionMu, and start a new widget *after* the
	// shutdown caller has already returned — the LocalBackend.Close
	// docstring is explicit that Stop is the final teardown, so a
	// post-Stop revival breaks that contract. start() and applyConfig
	// re-check armed under mu (inside transitionMu for start) so a
	// concurrent flip is honored even when the caller has been queued
	// at transitionMu the whole time.
	armed  bool
	cancel context.CancelFunc
	// done is closed by the worker goroutine when it actually exits
	// (after NewBroflake returns and ui.Stop runs). stop and Stop wait
	// on this under transitionMu so backend shutdown blocks until the
	// broflake widget is actually torn down. Nil when nothing is
	// running.
	done chan struct{}
	// lastCfg + lastFeatureOn cache the server-side half of the
	// three-condition predicate so SetEnabled can re-evaluate
	// immediately when the local toggle flips, without waiting for
	// the next NewConfigEvent. Both are updated atomically when a
	// new config arrives.
	lastCfg       *C.UnboundedConfig
	lastFeatureOn bool
	// lastBlocked is the reason noteBlocked last logged, "" while the
	// widget runs.
	lastBlocked string
	// stopping is set once stop has cancelled the worker, until the worker
	// exits, so a worker still tearing down isn't taken for one starting.
	stopping bool
	// noteMu serializes noteBlocked. It's never held with transitionMu
	// waiting on it, and m.mu is only taken inside it.
	noteMu sync.Mutex
	// noteQueued is set while a noteBlockedAsync evaluation is pending.
	noteQueued atomic.Bool

	// tickets supplies the volunteer tickets for this device's helper
	// pairings. nil: the widget joins no rooms.
	tickets roomTickets

	// vpnStatus reports the VPN tunnel's state, which the widget sends
	// freddie with its STUN preflights. nil: it reports none.
	vpnStatus func() string

	// boxCtx returns the running VPN tunnel's sing-box context, or nil with
	// none. The widget's WebRTC sockets follow it (see tunnelNet). nil: they
	// use the host stack.
	boxCtx func() context.Context

	// runningCfg is the snapshot of UnboundedConfig the live worker
	// was started with. broflake consumes its discovery/egress
	// options once in clientcore.NewBroflake, so a server-side config
	// change while the worker is alive would otherwise leave it
	// running on stale parameters. applyConfig compares this against
	// the freshly-cached lastCfg and triggers stop+start when they
	// differ, with the predicate still otherwise satisfied. Nil
	// whenever cancel is nil.
	runningCfg *C.UnboundedConfig
	running    bool
	peers      map[int]string
	arrivals   uint64

	// slots receives per-chunk byte counts from the live worker; it is
	// folded into bytesDown/bytesUp and peerBytes (keyed by consumer IP)
	// whenever a slot's connection changes or a snapshot is taken.
	slots     *slotTable
	bytesDown uint64
	bytesUp   uint64
	peerBytes map[string]*peerTally
	// lastOwner keeps a closed slot's tally so bytes broflake reports after the
	// close are still credited to it.
	lastOwner map[int]*peerTally
	// slotPairing is each slot's helper pairing, kept after the slot closes
	// until its next accept, the same as lastOwner.
	slotPairing map[int]string
	// retired holds stopped runs' tables still absorbing late bytes.
	retired []retiredRun
	// now overrides time.Now for peer retention tests.
	now func() time.Time
	// live receives slots serving helper pairings. Nil means
	// helper.DefaultLive.
	live *helper.LiveTracker
	// usage receives the bytes relayed for each helper pairing. Nil counts
	// nothing.
	usage *helper.Usage
	// runHook hears each start and stop of the worker, under mu.
	runHook func(running bool)

	// exitFlag is config-new's direct_exit, debounced.
	exitFlag exitFlag
	// exitAllowed reports whether this device may exit users' traffic at
	// all (SetDirectExitAllowed). nil: never.
	exitAllowed func() bool
	// exitPlatform is the platform interface the exit's boxes run on
	// (SetPlatformInterface). nil: sing-box's own.
	exitPlatform libbox.PlatformInterface
	// exitRun is the running widget's direct exit. nil with none.
	exitRun *exitRun
	// exitNotBefore is the hold-off lantern-cloud last asked the exit for,
	// kept across widget runs so a restart can't cut it short.
	exitNotBefore time.Time
}

// shouldStart reports whether all three start conditions hold. Caller
// must hold m.mu.
func (m *unboundedManager) shouldStart() bool {
	return settings.GetBool(settings.UnboundedKey) && m.lastFeatureOn && cfgUsable(m.lastCfg)
}

// cfgUsable reports whether the cached UnboundedConfig supplies the
// minimum fields broflake needs to route real consumer traffic:
// discovery (server + endpoint) and egress (address + endpoint). The
// server contract is that all four are required; broflake's
// clientcore defaults exist for unit-test convenience and point at
// the upstream maintainer's infra — running them in a Lantern build
// would bypass the server's per-environment endpoint selection and
// the "is this user opted in?" feature-flag gate, so a partially-
// populated config is treated as "not yet ready to start" rather
// than "fall back to defaults".
//
// CTableSize / PTableSize are not required; defaults are reasonable
// and the server sends them only when it wants to override.
func cfgUsable(cfg *C.UnboundedConfig) bool {
	if cfg == nil {
		return false
	}
	return cfg.DiscoverySrv != "" && cfg.DiscoveryEndpoint != "" &&
		cfg.EgressAddr != "" && cfg.EgressEndpoint != ""
}

// natFailTimeoutKey sets how long the widget waits, once signaling completes,
// for a consumer's data channel to open. broflake also checks ICE pairs for
// that whole window, so raising it lengthens both.
const natFailTimeoutKey = "nat_fail_timeout_ms"

const (
	minNATFailTimeout = time.Second
	maxNATFailTimeout = 30 * time.Second
)

// volunteerSocketKey, set to "true", has the widget send its signaling to
// freddie over one persistent WebSocket rather than a POST per message,
// falling back to POSTs whenever it can't have the socket (see
// clientcore.WebRTCOptions.VolunteerSocket).
const volunteerSocketKey = "volunteer_socket"

// widgetVolunteerSocket reports whether the server's widget tuning turns on
// the volunteer socket. A value that isn't a bool is ignored, leaving it off.
func widgetVolunteerSocket(opts map[string]string) (on bool, ignored []string) {
	raw, ok := opts[volunteerSocketKey]
	if !ok {
		return false, nil
	}
	on, err := strconv.ParseBool(raw)
	if err != nil {
		return false, []string{fmt.Sprintf("%s=%q", volunteerSocketKey, raw)}
	}
	return on, nil
}

// widgetTuning splits the server's widget tuning map into the NAT fail timeout,
// which isn't WebRTC tuning, and everything clientcore.ParseWebRTCTuning reads.
// A zero timeout means the key was absent or invalid; keep broflake's default.
// It skips volunteerSocketKey, which widgetVolunteerSocket reads.
func widgetTuning(opts map[string]string) (natFail time.Duration, tuning clientcore.WebRTCTuning, ignored []string) {
	raw, ok := opts[natFailTimeoutKey]
	if _, socket := opts[volunteerSocketKey]; ok || socket {
		opts = maps.Clone(opts)
		delete(opts, natFailTimeoutKey)
		delete(opts, volunteerSocketKey)
	}
	tuning, ignored = clientcore.ParseWebRTCTuning(opts)
	if !ok {
		return 0, tuning, ignored
	}
	ms, err := strconv.ParseUint(raw, 10, 32)
	natFail = time.Duration(ms) * time.Millisecond
	if err != nil || natFail < minNATFailTimeout || natFail > maxNATFailTimeout {
		return 0, tuning, append(ignored, fmt.Sprintf("%s=%q", natFailTimeoutKey, raw))
	}
	return natFail, tuning, ignored
}

func donorSTUNBatch(servers []string) func(uint32) ([]string, error) {
	pool := C.NormalizeDonorSTUNServers(servers)
	return func(size uint32) ([]string, error) {
		batch := slices.Clone(pool)
		rand.Shuffle(len(batch), func(i, j int) { batch[i], batch[j] = batch[j], batch[i] })
		if uint64(size) < uint64(len(batch)) {
			batch = batch[:size]
		}
		return batch, nil
	}
}

// roomTickets is where the widget gets its helper pairing tickets;
// helper.Source in production.
type roomTickets interface {
	Volunteer() []string
	AnsweredVolunteer() []string
}

// ticketWaiter is a roomTickets that can wait for its first fetch, as
// helper.Source can.
type ticketWaiter interface {
	WaitFetched(ctx context.Context) bool
}

// ticketWait bounds how long a starting widget waits for its first ticket
// fetch. A variable so tests can shorten it.
var ticketWait = 10 * time.Second

// waitForTickets gives tickets' first fetch up to ticketWait to finish before
// the widget starts. broflake's room slot serves the pool until it has
// tickets, and a pool consumer can then hold it for as long as it stays, so
// a widget that started before its tickets came could keep its inviter out.
// A source that can't wait, or a fetch that takes too long, starts the widget
// anyway. It reports whether ctx was done during the wait, so the widget
// shouldn't start at all.
func waitForTickets(ctx context.Context, tickets roomTickets) (stopped bool) {
	w, ok := tickets.(ticketWaiter)
	if !ok {
		return false
	}
	waitCtx, cancel := context.WithTimeout(ctx, ticketWait)
	defer cancel()
	if w.WaitFetched(waitCtx) || ctx.Err() != nil {
		return ctx.Err() != nil
	}
	slog.Info("Unbounded: starting before the first pairing ticket fetch finished")
	return false
}

// SetTicketSource sets where the widget gets its volunteer tickets. A widget
// already running keeps its source until it restarts.
func SetTicketSource(src roomTickets) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.tickets = src
}

// SetPairedUsage sets where the widget counts the bytes it relays for each
// helper pairing. A take from u first folds the widget's pending slot bytes.
func SetPairedUsage(u *helper.Usage) {
	manager.mu.Lock()
	manager.usage = u
	manager.mu.Unlock()
	u.SetFlush(manager.foldPending)
}

// SetRunHook sets f to hear true when the widget's worker starts and false
// when it is stopped or fails to build the widget. f runs with the manager's
// lock held, so it must not block or call into this package.
func SetRunHook(f func(running bool)) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.runHook = f
}

// fireRunLocked tells the run hook, if any, whether the worker runs. Caller
// must hold m.mu.
func (m *unboundedManager) fireRunLocked(running bool) {
	if m.runHook != nil {
		m.runHook(running)
	}
}

// SetVPNStatus sets where the widget reads the VPN tunnel's state, which it
// reports to freddie with its STUN preflights, so freddie can tell whether
// STUN failures follow the tunnel. A widget already running keeps its source
// until it restarts.
func SetVPNStatus(status func() string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.vpnStatus = status
}

// SetBoxContext sets where the widget finds the running VPN tunnel's
// sing-box context, so its WebRTC sockets stay off the tunnel. A widget
// already running keeps its source until it restarts.
func SetBoxContext(boxCtx func() context.Context) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.boxCtx = boxCtx
}

// roomSyncInterval is how often a running widget re-reads its tickets and the
// serve-pool setting. The source is a cache that renews tickets every 10
// minutes, so this costs nothing. A variable so tests can shorten it.
var roomSyncInterval = 30 * time.Second

// servePool is the "help others too" setting, shared with direct mode: unset
// means on.
func servePool() bool {
	return settings.PeerServesPool()
}

// applyRooms points a new widget's options at the volunteer tickets and sets
// the serve-pool setting. broflake calls the source at every genesis message,
// so fresh tickets reach the widget as soon as the source has them; the source
// is a cache whose reads never block. The returned set records each pairing
// whose tickets reach signaling, for syncRooms. Call it before NewBroflake.
func applyRooms(rtcOpt *clientcore.WebRTCOptions, tickets roomTickets) *servedPairings {
	served := &servedPairings{ids: make(map[string]bool)}
	if tickets != nil {
		rtcOpt.RoomTicketSource = func() []string {
			tks := tickets.Volunteer()
			served.add(tks)
			return tks
		}
	}
	rtcOpt.SetServePool(servePool())
	return served
}

// servedPairings is the set of pairing IDs whose tickets a widget has handed
// to signaling. Recording them as they go out, from the widget's first
// genesis, means a pairing that ends before syncRooms first looks still ends
// its sessions. Like volunteerPairings, it is never logged.
type servedPairings struct {
	mu  sync.Mutex
	ids map[string]bool
}

func (s *servedPairings) add(tickets []string) {
	ids := volunteerPairings(tickets)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range ids {
		s.ids[id] = true
	}
}

// endedIn reports whether a served pairing is missing from the tickets answered
// returns. It copies the served set before calling answered: a pairing served
// by then was in an earlier answer, so missing from this one it has ended,
// while one served only afterwards may come from a newer answer than this.
func (s *servedPairings) endedIn(answered func() []string) bool {
	s.mu.Lock()
	served := make([]string, 0, len(s.ids))
	for id := range s.ids {
		served = append(served, id)
	}
	s.mu.Unlock()
	cur := volunteerPairings(answered())
	for _, id := range served {
		if !cur[id] {
			return true
		}
	}
	return false
}

// volunteerPairings is the set of pairing IDs tickets claim. It is unverified
// and is used only to notice a pairing disappearing; it is never logged.
func volunteerPairings(tickets []string) map[string]bool {
	out := make(map[string]bool, len(tickets))
	for _, tk := range tickets {
		if _, id := helperticket.Peek(tk); id != "" {
			out[id] = true
		}
	}
	return out
}

// syncRooms keeps a running widget's pool setting current and watches for
// changes that must end its open sessions, until ctx ends. done identifies the
// run. Two changes restart the widget:
//
//   - a pairing it has served is missing from the tickets lantern-cloud last
//     answered with: the pairing has ended. freddie stops new matches by
//     itself, but a WebRTC session already open outlives the tickets, and the
//     widget cannot tell which session came through which room. Tickets that
//     only expired, say while lantern-cloud is unreachable, end nothing;
//   - "help others too" turned off: sessions already open with strangers
//     must end too.
func (m *unboundedManager) syncRooms(ctx context.Context, done chan struct{}, rtcOpt *clientcore.WebRTCOptions, tickets roomTickets, served *servedPairings, interval time.Duration) {
	prevPool := rtcOpt.ServesPool()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pool := servePool()
		rtcOpt.SetServePool(pool)
		if pool != prevPool {
			// The exit's next registration says whether it serves the pool.
			m.reregisterExit()
		}
		reason := ""
		if prevPool && !pool {
			reason = "Unbounded: helping others turned off; restarting the widget to close its sessions"
		}
		if tickets != nil && served.endedIn(tickets.AnsweredVolunteer) {
			reason = "Unbounded: a helper pairing ended; restarting the widget to close its sessions"
		}
		if reason != "" {
			slog.Info(reason)
			go m.restartIfCurrent(done)
			return
		}
		prevPool = pool
	}
}

// restartIfCurrent stops and restarts the widget if the run done identifies
// is still the live one. The check and the restart hold transitionMu
// together, so a run that something else already stopped or replaced is
// never bounced.
func (m *unboundedManager) restartIfCurrent(done chan struct{}) {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	m.mu.Lock()
	current := done != nil && m.done == done
	m.mu.Unlock()
	if !current {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), internalStopTimeout)
	defer cancel()
	if err := m.stopLocked(ctx, false); err != nil {
		slog.Warn("Unbounded: internal stop timed out before worker exited",
			"error", err, "timeout", internalStopTimeout)
		// The old worker still holds the run, so startLocked would do
		// nothing. Start once it exits; start re-checks that the manager is
		// armed and nothing else started, so a public Stop meanwhile wins.
		go func() {
			<-done
			m.start()
		}()
		return
	}
	m.startLocked()
}

// Enabled reports whether the local opt-in is set. Doesn't say whether
// the proxy is currently running (server flag and config can override).
func Enabled() bool {
	return settings.GetBool(settings.UnboundedKey)
}

// SetEnabled persists the local opt-in (if it differs from the current
// persisted value) and re-evaluates the manager. Use this from direct
// callers (FFI, programmatic use) where the new toggle value hasn't
// been written to settings yet.
//
// PatchSettings persists settings itself before calling into the
// unbounded package, so it should use Apply() directly instead of
// going through SetEnabled — otherwise SetEnabled's no-change short-
// circuit (Enabled() == enable) returns before Apply runs and the
// manager never re-evaluates.
func SetEnabled(enable bool) error {
	if Enabled() != enable {
		if err := settings.Set(settings.UnboundedKey, enable); err != nil {
			return err
		}
		slog.Info("Unbounded widget proxy local opt-in changed", "enabled", enable)
	}
	return Apply()
}

// Apply re-evaluates the three-condition predicate (local toggle +
// server feature flag + server config cached) against the currently
// persisted setting and starts or stops the manager accordingly. Used
// by PatchSettings (which already persisted UnboundedKey itself) and
// by SetEnabled (after its persist step). Safe to call when nothing
// has changed — start is a no-op if the worker is already running and
// stop is a no-op if it isn't.
//
// No-op once Stop has disarmed the manager (post-shutdown): the
// armed gate is also checked inside start, so even a queued
// transition stays a no-op after Stop.
func Apply() error {
	if h := applyHook; h != nil {
		h()
	}
	defer manager.noteBlocked()
	if !Enabled() {
		manager.stop()
		return nil
	}
	manager.mu.Lock()
	armed := manager.armed
	shouldStart := manager.shouldStart()
	running := manager.cancel != nil
	manager.mu.Unlock()
	if armed && shouldStart && !running {
		manager.start()
	}
	return nil
}

// InitSubscription wires the manager into radiance's config event bus
// and applies any already-cached config. Called once at LocalBackend
// startup; the underlying subscription lives for the process lifetime
// (sync.Once-guarded), but the armed flag is set on every call so a
// Start-after-Close re-enables the manager that public Stop had
// disarmed.
//
// initial is the config that ConfigHandler has already loaded by the
// time Start reaches this line — typically the previously-persisted
// config from disk. Without seeding the manager state from it, the
// three-condition predicate stays stuck at lastCfg=nil/lastFeatureOn=
// false until the next config refresh arrives, and an already-opted-in
// user wouldn't auto-start the widget proxy until then. Pass nil if
// no config is available yet.
func InitSubscription(initial *config.Config) {
	initOnce.Do(func() {
		events.Subscribe(func(evt config.NewConfigEvent) {
			if evt.New == nil {
				return
			}
			applyConfig(*evt.New)
		})
	})
	manager.mu.Lock()
	manager.armed = true
	manager.mu.Unlock()
	if initial != nil {
		applyConfig(*initial)
		return
	}
	manager.noteBlocked()
}

// applyConfig ignores updates after Stop so late events cannot restart the widget.
func applyConfig(cfg config.Config) {
	defer manager.noteBlocked()
	manager.mu.Lock()
	if !manager.armed {
		manager.mu.Unlock()
		return
	}
	manager.lastCfg = cfg.Unbounded
	if cfg.Unbounded != nil {
		copied := *cfg.Unbounded
		copied.STUNServers = slices.Clone(cfg.Unbounded.STUNServers)
		copied.Tuning = maps.Clone(cfg.Unbounded.Tuning)
		manager.lastCfg = &copied
	}
	manager.lastFeatureOn = cfg.Features[C.UNBOUNDED]
	if manager.exitFlag.update(cfg.Features[directExitFeature], time.Now()) {
		// Identical configs bring no further events, so the off comes from a timer. A stale
		// one only re-checks.
		time.AfterFunc(directExitOffDelay, RecheckDirectExit)
	}
	run := manager.exitRun
	shouldRun := manager.shouldStart()
	running := manager.cancel != nil
	ucfg := manager.lastCfg
	cfgChanged := running && !manager.runningCfg.Equal(ucfg)
	manager.mu.Unlock()

	// The exit turns on and off without restarting the widget.
	if run != nil {
		run.sync()
	}

	switch {
	case shouldRun && !running:
		manager.start()
	case shouldRun && cfgChanged:
		// Broflake consumed its options at construction time and has
		// no live-reconfigure API; the only way to pick up new
		// discovery/egress endpoints or table sizes is to tear the
		// worker down and bring it back up with the new config.
		// stop blocks until the prior worker fully exits, so start
		// always sees a clean slate.
		manager.stop()
		manager.start()
	case !shouldRun && running:
		manager.stop()
	}
}

var initOnce sync.Once

// Stop tears down a running widget proxy and waits for the worker
// goroutine to actually exit (or the supplied ctx to expire). Used
// as a LocalBackend shutdown hook — without the wait, Close would
// return as soon as the cancel signal was queued and the broflake
// goroutine could still be inside NewBroflake or ui.Stop when the
// rest of the process tears down.
//
// Stop also disarms the manager: any subsequent start path (Apply,
// applyConfig from a config event, manager.start directly) becomes
// a no-op until InitSubscription re-arms. The config subscription
// callback stays installed but short-circuits via the armed gate,
// so a late config event arriving during or after Stop can't
// revive the widget. Future Start (after Close) re-arms via
// InitSubscription.
//
// Idempotent: no-op if no worker is running. Returns ctx.Err() if
// the wait deadline expires before the worker exits — in that case
// the worker has been signalled to cancel and will exit on its own
// schedule, but the caller has given up waiting. m.cancel and
// m.done stay set until the worker eventually clears them, so a
// subsequent start observes "already running" and is a no-op.
func Stop(ctx context.Context) error {
	return manager.stopCtx(ctx, true)
}

// internalStopTimeout bounds how long Apply / applyConfig wait for
// the worker to exit after signalling cancel. broflake's ui.Stop
// should drain in well under this; a longer-than-expected ui.Stop
// must not block a settings PATCH or a config-event handler
// indefinitely. Variable (not const) so tests can install a short
// timeout to exercise the timeout path without holding up the
// suite. Production code reads this on every call, so the override
// applies for the duration of the test.
var internalStopTimeout = 5 * time.Second

// applyHook is invoked at the top of Apply, before any state check
// or transition. nil in production; backend tests install a counter
// or assertion to verify that PatchSettings actually dispatches the
// UnboundedKey diff to this package. Keep this minimal — exposing
// the manager's internals across packages just for test wiring
// would be a much bigger surface.
var applyHook func()

// SetApplyHookForTest installs h to be invoked at the start of
// every Apply call. Pass nil to remove. Test-only; production code
// must not call this. The hook fires regardless of the Enabled()
// gate so callers can verify dispatch happened even when no
// transition results.
func SetApplyHookForTest(h func()) {
	applyHook = h
}

// stopCtx is the shared implementation for both the public Stop
// (disarm=true) and internal manager.stop (disarm=false). Holds
// transitionMu for the entire signal+wait so a concurrent start
// cannot interleave. On ctx expiration the cancel signal has been
// delivered and the worker will exit on its own schedule; manager
// state is left intact so future transitions see "already running"
// until the worker clears it.
func (m *unboundedManager) stopCtx(ctx context.Context, disarm bool) error {
	// Deferred first so it runs after transitionMu is released: a public
	// Stop disarms, which nothing else would log.
	defer m.noteBlocked()
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	return m.stopLocked(ctx, disarm)
}

// stopLocked is stopCtx for a caller that holds transitionMu.
func (m *unboundedManager) stopLocked(ctx context.Context, disarm bool) error {
	m.mu.Lock()
	if disarm {
		m.armed = false
	}
	cancel := m.cancel
	done := m.done
	m.mu.Unlock()
	if cancel == nil {
		return nil
	}
	// Published with the cancel, under one hold of m.mu: a worker that exits
	// at once can't evaluate the gate while it still reads as running, and a
	// worker that finishes starting can't set running after this clears it,
	// since it reads ctx under m.mu. cancel doesn't block or call back in.
	m.mu.Lock()
	m.running = false
	m.stopping = true
	cancel()
	m.fireRunLocked(false)
	m.releaseAllPeers()
	m.peers = nil
	m.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// start brings up the broflake worker if all preconditions hold at
// the moment it acquires the locks: manager armed, no worker already
// running, and the three-condition predicate (toggle + feature flag +
// cached config) still satisfied. Every check is done INSIDE
// transitionMu so a caller queued behind a stop or another start
// observes the freshest state rather than a snapshot from when it
// decided to start — a concurrent SetEnabled(false) or config update
// between the caller's predicate read and start's lock acquisition
// is honored.
//
// The config used by the worker is the LIVE m.lastCfg, not a snapshot
// captured by the caller. applyConfig updates m.lastCfg before
// calling start, so this gives identical behavior for the normal
// path; for the race case (config updated after caller decided to
// start), the worker comes up with the latest parameters.
func (m *unboundedManager) start() {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	m.startLocked()
}

// startLocked is start for a caller that holds transitionMu.
func (m *unboundedManager) startLocked() {
	m.mu.Lock()
	if !m.armed {
		// Disarmed by public Stop. Re-check inside transitionMu so a
		// start that got queued at transitionMu while Stop was waiting
		// for the worker still bails out instead of reviving the widget
		// after Stop's caller has returned.
		m.mu.Unlock()
		return
	}
	if m.cancel != nil {
		m.mu.Unlock()
		return // already running; transitionMu prevents overlap with stop
	}
	if !m.shouldStart() {
		// Predicate flipped while we were queued at transitionMu — a
		// SetEnabled(false), a config event that cleared the feature
		// flag or unset the cfg, or any other concurrent change. Bail
		// rather than start a worker that's already been decided
		// against.
		m.mu.Unlock()
		return
	}
	ucfg := m.lastCfg
	tickets := m.tickets
	vpnStatus := m.vpnStatus
	boxCtx := m.boxCtx
	syncInterval := roomSyncInterval
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.cancel = cancel
	m.done = done
	m.stopping = false
	// Retain the immutable config snapshot to detect changes while this worker runs.
	m.runningCfg = ucfg
	m.peers = make(map[int]string)
	slots := &slotTable{}
	m.slots = slots
	m.fireRunLocked(true)
	m.mu.Unlock()

	go func() {
		defer close(done)
		// However the worker ends, say why nothing is running now: a stop that
		// timed out leaves this as the only evaluation after the worker exits.
		defer m.noteBlocked()
		slog.Info("Unbounded: starting broflake widget proxy")

		bfOpt := clientcore.NewDefaultBroflakeOptions()
		bfOpt.ClientType = "widget"
		if ucfg != nil {
			if ucfg.CTableSize > 0 {
				bfOpt.CTableSize = ucfg.CTableSize
			}
			if ucfg.PTableSize > 0 {
				bfOpt.PTableSize = ucfg.PTableSize
			}
			// Empty, the default, reports nothing. Set, the widget reports its
			// connected consumers, IP addresses included, to netstated for the
			// network visualizations, as the browser widget does.
			bfOpt.Netstated = ucfg.Netstated
		}

		// Wire the broflake connection callback into the radiance event
		// bus so the Flutter globe (and any future abuse aggregation)
		// sees consumer connect/disconnect.
		//
		// Cancellation drain: broflake's per-worker connection-change
		// goroutines can fire callbacks concurrently with ui.Stop, and
		// the broflake API doesn't promise no-callbacks-after-Stop.
		// Check ctx.Err() at the top so callbacks delivered after stop
		// signals cancel — but before broflake's internal teardown
		// drained — short-circuit instead of pushing a stale connection
		// event onto the bus after the consumer thinks Unbounded is
		// off. broflake exposes no registration point we could
		// disarm directly (the callback IS the registration), so the
		// inline ctx check is the next-best place.
		// Close callbacks omit the address; preserve it for connection-event subscribers.
		sources := newConnSources()
		bfOpt.OnConnectionChangeFunc = func(state int, workerIdx int, addr net.IP) {
			if ctx.Err() != nil {
				return
			}
			addrStr := ""
			if addr != nil {
				addrStr = addr.String()
			}
			addrStr = sources.resolve(state, workerIdx, addrStr)
			m.recordConnection(ctx, state, workerIdx, addrStr)
			slog.Debug("Unbounded: consumer connection change",
				"state", state, "workerIdx", workerIdx, "source", addrStr)
			events.Emit(ConnectionEvent{
				State:     state,
				Source:    addrStr,
				Timestamp: time.Now().UnixMilli(),
			})
		}

		// broflake calls this just after OnConnectionChangeFunc, with the
		// helper pairing the consumer came through, which the producer has
		// checked against its own tickets. The pairing is never logged.
		bfOpt.OnConnectionChangeInfoFunc = func(state int, workerIdx int, info common.ConsumerInfo) {
			m.recordPairing(ctx, slots, state, workerIdx, info.Pairing)
		}

		// Downstream chunks fire per chunk on broflake's data path, so the
		// counters stay lock-free and attribution to an IP happens later
		// under m.mu. Chunks arriving after stop land in the retired run,
		// credited to the slot owners at stop.
		bfOpt.OnDownstreamChunkFunc = chunkCounter(slots, true)
		bfOpt.OnUpstreamChunkFunc = chunkCounter(slots, false)

		rtcOpt := clientcore.NewDefaultWebRTCOptions()
		// A genesis POST carries this widget's room tickets; never let a
		// redirect replay it to another origin.
		rtcOpt.HTTPClient = sameorigin.Client(bypassHTTPClient, "unbounded: signaling")
		rtcOpt.STUNBatch = donorSTUNBatch(nil)
		rtcOpt.VPNStatus = vpnStatus
		rtcOpt.Net = newTunnelNet(boxCtx)
		// freddie counts outcomes for each kind of volunteer, so the apps can be
		// compared with the browser widget and lantern-box nodes.
		rtcOpt.VolunteerKind = common.VolunteerKindApp
		if ucfg != nil {
			rtcOpt.STUNBatch = donorSTUNBatch(ucfg.STUNServers)
			if ucfg.DiscoverySrv != "" {
				rtcOpt.DiscoverySrv = ucfg.DiscoverySrv
			}
			if ucfg.DiscoveryEndpoint != "" {
				rtcOpt.Endpoint = ucfg.DiscoveryEndpoint
			}
			natFail, tuning, ignored := widgetTuning(ucfg.Tuning)
			rtcOpt.Tuning = tuning
			if natFail > 0 {
				rtcOpt.NATFailTimeout = natFail
			}
			socket, socketIgnored := widgetVolunteerSocket(ucfg.Tuning)
			rtcOpt.VolunteerSocket = socket
			ignored = append(ignored, socketIgnored...)
			if len(ignored) > 0 {
				slog.Warn("Unbounded: ignoring widget tuning", "ignored", ignored)
			}
		}
		// Helper pairing rooms: freddie offers this widget's genesis messages
		// to its paired consumers first, and with "help others too" off to
		// nobody else.
		if stopped := waitForTickets(ctx, tickets); stopped {
			// Stopped while waiting: don't build a widget only to tear it down.
			m.mu.Lock()
			m.cancel = nil
			m.stopping = false
			m.done = nil
			m.runningCfg = nil
			m.mu.Unlock()
			slog.Info("Unbounded: broflake widget proxy stopped before it started")
			return
		}
		served := applyRooms(rtcOpt, tickets)
		// The exit is offered to broflake off, and turned on and off later
		// with direct_exit: broflake reads WebRTCOptions.Exit only here.
		exitRun := m.startExit()
		if exitRun != nil {
			rtcOpt.Exit = exitRun.e.Options()
		}

		egOpt := clientcore.NewDefaultEgressOptions()
		egOpt.HTTPClient = bypassHTTPClient
		if ucfg != nil {
			if ucfg.EgressAddr != "" {
				egOpt.Addr = ucfg.EgressAddr
			}
			if ucfg.EgressEndpoint != "" {
				egOpt.Endpoint = ucfg.EgressEndpoint
			}
		}

		ui, err := newWidget(bfOpt, rtcOpt, egOpt)
		if err != nil {
			slog.Error("Unbounded: failed to create broflake widget", "error", err)
			if exitRun != nil {
				exitRun.close()
			}
			cancel()
			m.mu.Lock()
			m.fireRunLocked(false)
			m.cancel = nil
			m.stopping = false
			m.done = nil
			m.runningCfg = nil
			m.mu.Unlock()
			return
		}

		m.mu.Lock()
		m.running = ctx.Err() == nil
		m.exitRun = exitRun
		m.mu.Unlock()
		// Through noteBlocked, not by clearing lastBlocked here: a reason an
		// earlier evaluation chose but hasn't logged yet is then logged before
		// this, so it can't be the last line once the widget runs.
		m.noteBlocked()
		if exitRun != nil {
			exitRun.sync()
		}
		slog.Info("Unbounded: broflake widget proxy started")
		// The worker waits for syncRooms before reporting done, so a stopped
		// run leaves nothing behind.
		syncDone := make(chan struct{})
		go func() {
			defer close(syncDone)
			m.syncRooms(ctx, done, rtcOpt, tickets, served, syncInterval)
		}()
		<-ctx.Done()
		slog.Info("Unbounded: stopping broflake widget proxy")
		ui.Stop()
		<-syncDone
		if exitRun != nil {
			exitRun.close()
		}
		m.mu.Lock()
		m.cancel = nil
		m.stopping = false
		m.done = nil
		m.runningCfg = nil
		m.exitRun = nil
		m.mu.Unlock()
		slog.Info("Unbounded: broflake widget proxy stopped")
	}()
}

// stop is the internal (no-arg) variant called by Apply and
// applyConfig. It wraps stopCtx with a default timeout so a hung
// ui.Stop doesn't block settings PATCHes or config-event handling
// indefinitely. The timeout error is logged because the call site
// has no useful action to take; subsequent transitions observe
// "already running" until the worker eventually exits.
func (m *unboundedManager) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), internalStopTimeout)
	defer cancel()
	if err := m.stopCtx(ctx, false); err != nil {
		slog.Warn("Unbounded: internal stop timed out before worker exited",
			"error", err, "timeout", internalStopTimeout)
	}
}
