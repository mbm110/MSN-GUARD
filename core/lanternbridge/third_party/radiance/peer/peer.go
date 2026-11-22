package peer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	box "github.com/getlantern/lantern-box"
	lblog "github.com/getlantern/lantern-box/log"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/getlantern/lantern-box/tracker/peerconn"

	"github.com/getlantern/lantern-box/peerrules"
	"github.com/getlantern/lantern-box/portforward"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/internal/hostaccess"
	rlog "github.com/getlantern/radiance/log"
)

// StatusEvent fires whenever the Client's session state changes — successful
// Start, user Stop, or auto-Stop on a 404 heartbeat. Status is a full snapshot
// of session state at emit time, not a delta.
type StatusEvent struct {
	events.Event
	Status Status `json:"status"`
}

// ConnectionEvent fires every time a remote client opens or closes a
// samizdat session against the local peer's inbound. Source is the remote
// "ip:port" string; Timestamp is the emit time in Unix milliseconds.
//
//	State     +1 on accept, -1 on close
//	Source    remote peer "ip:port"
//	Timestamp emit time in Unix milliseconds
//	Pairing   the helper pairing the client came through, "" for the pool or not yet known
//
// Pairing identifies a friend relationship. It goes to the local app only:
// it must never be logged, traced or persisted.
type ConnectionEvent struct {
	events.Event
	State     int    `json:"state"`
	Source    string `json:"source"`
	Timestamp int64  `json:"timestamp"`
	Pairing   string `json:"pairing,omitempty"`
}

// Port range chosen to minimize collision risk on the typical home network,
// not to guarantee one. 30000–50000 sits above the well-known/system range
// (0–1023) and above the ports most services use by default (web/dev/dbs
// usually <30000). It overlaps both the IANA registered range (1024–49151)
// and the OS ephemeral range on some platforms (Linux's default
// net.ipv4.ip_local_port_range starts at 32768, Windows uses 49152+), so
// a collision is still possible. AddPortMapping surfaces the conflict and
// the peer.Client caller can retry with a fresh pick.
const (
	internalPortMin = 30000
	internalPortMax = 50000
)

type portForwarder interface {
	MapPort(ctx context.Context, protocol string, internalPort uint16, description string) (*portforward.Mapping, error)
	UnmapPort(ctx context.Context) error
	StartRenewal(ctx context.Context)
	ExternalIP(ctx context.Context) (string, error)
}

type boxService interface {
	Start() error
	Close() error
}

type boxFactory func(ctx context.Context, options string) (boxService, error)

// Phase is the peer.Client lifecycle stage surfaced to the UI. Granular
// enough that "Share My Connection" can render a real progress sequence
// (mapping port → registering → verifying → serving) instead of a single
// active/inactive boolean. Values are stable strings so Flutter / web
// consumers can switch on them without depending on Go enum ordering.
type Phase string

const (
	PhaseIdle        Phase = "idle"
	PhaseMappingPort Phase = "mapping_port"
	PhaseDetectingIP Phase = "detecting_ip"
	PhaseRegistering Phase = "registering"
	PhaseStartingBox Phase = "starting_proxy"
	PhaseVerifying   Phase = "verifying"
	PhaseServing     Phase = "serving"
	PhaseStopping    Phase = "stopping"
	PhaseError       Phase = "error"
)

type Status struct {
	Phase Phase `json:"phase"`
	// Error is the human-readable failure reason when Phase == PhaseError.
	// Empty for every other phase.
	Error string `json:"error,omitempty"`
	// Reason classifies Error for consumers that need to branch on the cause
	// or localize it. Empty when the failure could not be named, in which
	// case Error is the raw Go error and is not worth translating.
	Reason Reason `json:"reason,omitempty"`
	// Active is true only when Phase == PhaseServing; kept as a separate
	// field so a boolean "is sharing?" check need not switch on the phase
	// enum.
	Active       bool      `json:"active"`
	SharingSince time.Time `json:"sharing_since,omitempty"`
	ExternalIP   string    `json:"external_ip,omitempty"`
	ExternalPort uint16    `json:"external_port,omitempty"`
	RouteID      string    `json:"route_id,omitempty"`
	// PairingsOnly is whether the run this status describes served only the
	// device's helper pairings (Config.PairingsOnly), rather than Share My
	// Connection.
	PairingsOnly bool `json:"pairings_only,omitempty"`
}

// Config plumbs in dependencies. Zero-valued fields fall back to production
// defaults; HeartbeatInterval, HeartbeatTimeout, and CredRotationInterval
// exist so tests can drive the loops without sleeping a full minute / hour.
type Config struct {
	API          *API
	NewForwarder func(ctx context.Context) (portForwarder, error)
	// PhysicalControl, if set, returns the socket control that keeps port
	// mapping off the VPN tunnel, from discovering the gateway to every
	// request to it and the LAN address mapped to, or nil with no tunnel. It
	// applies to the default NewForwarder.
	PhysicalControl      func() control.Func
	BuildBoxService      boxFactory
	HeartbeatInterval    time.Duration
	HeartbeatTimeout     time.Duration
	CredRotationInterval time.Duration
	// RejectionsPath is where the tally of refused destinations persists.
	// Empty keeps the tally in memory only.
	RejectionsPath string
	// BoxCloseTimeout bounds how long teardown waits for a sing-box Close.
	// Zero means defaultBoxCloseTimeout.
	BoxCloseTimeout time.Duration
	// Now is the clock for pairing-set expiry. Nil means time.Now.
	Now func() time.Time
	// OnSelfStop is called after the client stops itself, rather than on a
	// caller's Stop: the server dropped its route, or a credential rotation
	// left nothing serving what the server advertises. It runs on its own
	// goroutine after Stop returns, with the reason.
	OnSelfStop func(reason error)
	// Live receives the connections that came through a helper pairing, for
	// the volunteer's live per-friend status. Nil means helper.DefaultLive.
	Live *helper.LiveTracker
	// PairingsOnly, if set, reports whether this run serves only the device's
	// helper pairings, whatever "help others too" says: the volunteer runs
	// for its pairings with Share My Connection off. It is read at each
	// registration, like the setting.
	PairingsOnly func() bool
}

// liveOwner groups this package's connections in the LiveTracker.
const liveOwner = "peer"

// defaultBoxCloseTimeout: samizdat's Close releases the listening port at once
// but then waits for every open client connection to end, which with
// long-lived clients has taken 18 minutes. Nothing teardown does next depends
// on that drain.
const defaultBoxCloseTimeout = 5 * time.Second

// Client orchestrates one peer-proxy session: open UPnP port → register with
// lantern-cloud → run a sing-box samizdat inbound on the forwarded port →
// heartbeat → on shutdown: deregister + close inbound + unmap.
//
// Re-Starting a stopped Client is allowed.
type Client struct {
	cfg Config

	// poolMaybe backs MayServePool.
	poolMaybe atomic.Bool

	mu sync.Mutex
	// startingDone is created when Start sets starting=true and closed when
	// the same Start clears it (success or fail). Stop callers that arrive
	// mid-Start block on this channel rather than racing the in-flight
	// setup. Nil whenever no Start is in flight.
	startingDone chan struct{}
	// starting and active together serialize Start: starting is true while a
	// Start call is in flight, active is true once it succeeds. Without
	// starting, two concurrent Start calls could both pass the !active check
	// and run setup in parallel — the second's state would overwrite the
	// first's, orphaning a registered route + open box that this Client can
	// no longer Stop.
	starting  bool
	active    bool
	status    Status
	cancelRun context.CancelFunc
	runDone   chan struct{}
	forwarder portForwarder
	box       boxService
	routeID   string

	// listenerDraining short-circuits the peerconn listener wrapper while
	// box.Close is firing per-connection disconnect callbacks. peerconn.Notify
	// reads its registered listener under an RLock and then releases the lock
	// before invoking it, so SetListener(nil) alone races against in-flight
	// Notify calls — under load (real client traffic), Close fires N disconnect
	// callbacks from N goroutines that have already snapshotted the listener,
	// each then emitting an event to every subscriber. The
	// Flutter-side subscriber posts main-thread tasks per event, and a
	// hundred-task flood against a Flutter engine that's simultaneously
	// processing the SmC-off state change is the Flutter mutex crash we hit.
	// Setting this flag before box.Close drops the cascade inline.
	listenerDraining atomic.Bool

	// connsByIP counts open connections per remote IP so ActiveClients can
	// report distinct devices. Keyed by IP rather than the "ip:port" Source
	// because samizdat multiplexes many H2 streams over one TCP conn and a
	// client may open several, so counting events or ports would report more
	// people than are actually being helped. Guarded by its own mutex: the
	// peerconn listener fires from box's accept/close goroutines and must not
	// contend with Start/Stop holding c.mu.
	connsMu   sync.Mutex
	connsByIP map[string]int
	// verifierConns counts open verifier streams per "ip:port" source, so
	// their closes, which carry no destination, are hidden like their
	// accepts. A count rather than a set because samizdat multiplexes
	// streams over one TCP conn, so several can share a source. Guarded by
	// connsMu.
	verifierConns map[string]int
	// verifierCounters holds the byte counters of open verifier streams. When
	// events carry a counter it identifies the stream, so a close is hidden
	// exactly when its own accept was; verifierConns is the fallback for
	// events without one. Guarded by connsMu.
	verifierCounters map[*peerconn.Counter]struct{}

	// relay totals the bytes each session relays, for RelaySnapshot.
	relay relayStats

	// rejections tallies destinations refused by reject rules, across
	// sessions, so allowlist gaps are visible. Flushed on each heartbeat and
	// at Stop.
	rejections *rejectionTally

	// externalPort / internalPort persist the port mapping picked at
	// Start so the cred-rotation loop can re-register against the same
	// (address, port) tuple without re-probing UPnP / re-mapping. The
	// router-side mapping itself stays put across rotations; only the
	// samizdat creds and route_id rotate.
	externalPort uint16
	internalPort uint16
	// boxOptions is the fresh options string passed to BuildBoxService,
	// kept for diagnostics and so the rotation path doesn't need to
	// re-derive it from the (also-stored) box reference.
	boxOptions string
	// baseShortIDs are the inbound's short IDs from the current launch config.
	// They are always kept when pairing short IDs are applied, because
	// lantern-cloud's verifier and pool clients authenticate with them.
	baseShortIDs []string
	// pairingShortIDs is the newest pairing set the server vouched for;
	// pairingKnown says there is one. A response that does not vouch for a
	// set leaves both alone, so a server that cannot tell never revokes, and
	// a rotated box gets this set again. pairingApplied says the current box
	// holds it; when a push failed it does not, and each heartbeat retries.
	pairingShortIDs []string
	pairingKnown    bool
	pairingApplied  bool
	// pairingRevision is the server's revision of the newest set accepted,
	// the highest seen this session, 0 before any. It survives expiry, so a
	// set older than one already accepted is never taken.
	pairingRevision int64
	// pairingConfirmedAt is when a known set was last accepted. A rotation
	// that reuses the record keeps it.
	pairingConfirmedAt time.Time
	// pairingByShortID maps a short ID to its pairing ID for every grouped
	// set a serving box may accept: heldGroups, prevGroups, and
	// pendingGroups while a push of them is in flight. Written under c.mu,
	// read lock-free by the connection listener.
	pairingByShortID atomic.Pointer[map[[8]byte]string]
	// heldGroups are the groups of the newest grouped set pushed to the
	// inbound, and prevGroups those it replaced, which a box built during a
	// rotation may still hold. pendingGroups are the recorded set's groups
	// until a push of that set succeeds. Guarded by c.mu.
	heldGroups    map[[8]byte]string
	prevGroups    map[[8]byte]string
	pendingGroups *map[[8]byte]string
	// liveMu orders the listener's LiveTracker updates against a session's
	// end. liveGen identifies the running session and changes at every
	// begin and end, so a listener callback that resumes after its session
	// ended adds nothing that the end would have had to close.
	liveMu  sync.Mutex
	liveGen uint64
	// conns holds this session's open connections by byte counter, so a
	// close reports the pairing the connection was attributed to, at accept
	// or by a grouped set that arrived later. Cleared at the session's begin
	// and end. Guarded by liveMu, which is taken after c.mu.
	conns map[*peerconn.Counter]liveConn
	// beforeTrackLive, if set, runs in the listener just before its
	// LiveTracker update, so tests can interleave it with Stop.
	beforeTrackLive func()
	// shortIDsMu serializes recording a set with pushing it onto the box,
	// so the box and pairingApplied agree. It is held across those local
	// pushes only, never across network I/O or a box's Start or Close.
	// Taken before c.mu, never while holding it.
	shortIDsMu sync.Mutex
	// warnedNoBaseShortIDs and warnedNoUpdater keep their warnings to one
	// per client, since every heartbeat would otherwise repeat them.
	warnedNoBaseShortIDs atomic.Bool
	warnedNoUpdater      atomic.Bool
	// runCtx is captured here for the cred-rotation goroutine to bind
	// the new libbox lifetime to the same context as the original Start.
	// Stop's cancelRun() teardown still applies to the rebuilt box.
	runCtx context.Context
	// registration counts successful registrations. The server reuses a
	// peer's route_id across re-registrations, so a heartbeat 404 is only
	// attributable to the current registration by this, not by route_id.
	registration uint64

	// lifecycle is held for the whole of Start, Stop and each rotation, so
	// none of them interleave. A register is an upsert on the peer's
	// (address, port) that reuses its route_id, so interleaving lets one
	// operation deregister, overwrite or stop another's route. A one-slot
	// channel rather than a mutex, so acquiring can give up on a ctx.
	lifecycle chan struct{}
}

// peerCredRotationInterval bounds how long a leaked samizdat
// credential remains usable. At each tick the peer re-registers with
// lantern-cloud (new route_id, new keypair, new shortID), rebuilds the
// libbox service against the new options, and deregisters the prior
// route. Caps blast radius from credential leakage (logs, telemetry,
// memory dumps, H2 leakage paths) to ~1h regardless of peer process
// lifetime.
//
// Cost per rotation: one API.Register + Deregister round trip, one
// libbox build + start + close cycle. Brief (~hundreds-of-ms) port-
// rebind window during the swap; samizdat clients see TCP RST and
// reconnect via the bandit. Acceptable trade-off vs. holding the same
// cred for the full peer process lifetime.
const peerCredRotationInterval = 1 * time.Hour

// peerCleanupTimeout caps how long Start's rollback path waits for
// Deregister / UnmapPort. Cleanup uses a fresh Background context (not the
// caller's ctx) so an already-canceled or expired Start ctx doesn't skip
// teardown and leak the registered route or router rule.
const peerCleanupTimeout = 30 * time.Second

// peerVerifyTimeout bounds the post-rotation Verify, which runs holding the
// lifecycle slot.
const peerVerifyTimeout = 30 * time.Second

func NewClient(cfg Config) (*Client, error) {
	if cfg.API == nil {
		return nil, errors.New("peer: Config.API is required")
	}
	if cfg.NewForwarder == nil {
		physical := cfg.PhysicalControl
		cfg.NewForwarder = func(ctx context.Context) (portForwarder, error) {
			return newDefaultForwarder(ctx, boundTo(physical)...)
		}
	}
	if cfg.BuildBoxService == nil {
		cfg.BuildBoxService = defaultBuildBoxService
	}
	if cfg.BoxCloseTimeout == 0 {
		cfg.BoxCloseTimeout = defaultBoxCloseTimeout
	}
	if cfg.HeartbeatTimeout == 0 {
		cfg.HeartbeatTimeout = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{
		cfg:        cfg,
		rejections: newRejectionTally(cfg.RejectionsPath),
		lifecycle:  make(chan struct{}, 1),
	}, nil
}

// acquireLifecycle takes the lifecycle slot, or gives up when ctx is done.
func (c *Client) acquireLifecycle(ctx context.Context) error {
	select {
	case c.lifecycle <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) releaseLifecycle() { <-c.lifecycle }

// Start opens the peer-proxy session. On success a background heartbeat
// goroutine is running; on error any partial setup is torn down before
// returning.
func (c *Client) Start(ctx context.Context) (retErr error) {
	if err := c.acquireLifecycle(ctx); err != nil {
		return err
	}
	defer c.releaseLifecycle()
	c.mu.Lock()
	if c.active || c.starting {
		c.mu.Unlock()
		return errors.New("peer client already active")
	}
	c.starting = true
	c.startingDone = make(chan struct{})
	c.mu.Unlock()

	// Re-arm the listener wrapper. Stop / rollback flips this to true to
	// silence the disconnect cascade during box.Close; if we don't reset
	// here, a Stop→Start cycle would leave the wrapper permanently muted.
	c.listenerDraining.Store(false)
	relayGen := c.relay.begin()
	liveGen := c.beginLive()

	var (
		success   bool
		fwd       portForwarder
		regResp   *RegisterResponse
		regPool   bool
		box       boxService
		runCtx    context.Context
		cancelRun context.CancelFunc
	)
	defer func() {
		c.mu.Lock()
		c.starting = false
		done := c.startingDone
		c.startingDone = nil
		c.mu.Unlock()
		close(done) // unblocks any Stop call that arrived mid-Start
		if success {
			return
		}
		// A fresh ctx — the caller's may already be canceled by the time we
		// roll back, which would skip Deregister and UnmapPort and leak the
		// registered route + router rule.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), peerCleanupTimeout)
		defer cancel()
		// Always clear the connection listener on rollback: it is registered
		// before box.Start and Verify, either of which can fail. Drain-flag
		// first so any in-flight Notify callbacks short-circuit even if
		// SetListener races (see Stop).
		c.listenerDraining.Store(true)
		peerconn.SetListener(nil)
		c.resetConnTracking()
		c.relay.end()
		c.endLive()
		c.mu.Lock()
		c.clearGroupsLocked()
		c.mu.Unlock()
		if box != nil {
			_ = c.closeBox(box)
		}
		if cancelRun != nil {
			cancelRun()
		}
		if regResp != nil {
			_ = c.cfg.API.Deregister(cleanupCtx, regResp.RouteID)
		}
		c.poolMaybe.Store(false)
		if fwd != nil {
			_ = fwd.UnmapPort(cleanupCtx)
		}
		// Surface the failure to the UI. Emitted AFTER cleanup so the UI
		// sees the error phase as the terminal state of this Start attempt,
		// not as a transient between phases.
		//
		// This is the one place that sees both the failure and the phase it
		// happened in, which is what makes the error nameable — so it is
		// also the place that logs the full tree. Nothing downstream of here
		// has the detail any more: the UI renders Error verbatim, and a
		// named StartError's Error() is deliberately one sentence.
		var errMsg string
		var reason Reason
		if retErr != nil {
			failedPhase := c.currentPhase()
			var manualPort uint16
			if m, ok := fwd.(*portforward.ManualForwarder); ok {
				manualPort = m.Port()
			}
			if named := classifyStartFailure(failedPhase, retErr, manualPort); named != nil {
				if named.Reason == ReasonCanceled {
					// Not a failure: the user toggled sharing back off while
					// it was still coming up. At Error this would put an
					// expected click into the error rate, and the rate is
					// only useful if everything in it is worth looking at.
					slog.Info("peer: start canceled before it finished",
						"phase", failedPhase, "err", retErr)
				} else {
					if c.pairingsOnly() {
						// A background attempt that is retried and that
						// routers without UPnP fail routinely; the error can
						// quote an API body, so it's left out.
						slog.Warn("peer: pairings-only start failed", "phase", failedPhase,
							"reason", named.Reason)
					} else {
						slog.Error("peer: start failed", "phase", failedPhase,
							"reason", named.Reason, "err", retErr)
					}
				}
				reason = named.Reason
				retErr = named
			} else {
				// Unnamed, so the raw wrap is all the user gets — worth a
				// log line of its own, since a reason we cannot classify is
				// the signal that this list needs another entry.
				if c.pairingsOnly() {
					// The types, not the text, which can quote an API body.
					slog.Warn("peer: pairings-only start failed with an unclassified error",
						"phase", failedPhase, "error_types", errorTypes(retErr))
				} else {
					slog.Error("peer: start failed with an unclassified error",
						"phase", failedPhase, "err", retErr)
				}
			}
			errMsg = retErr.Error()
		}
		c.emitError(reason, errMsg)
	}()

	c.emitPhase(PhaseMappingPort, "")
	fwd, err := c.cfg.NewForwarder(ctx)
	if err != nil {
		return fmt.Errorf("discover gateway: %w", err)
	}
	internalPort := pickInternalPort()
	mapping, err := fwd.MapPort(ctx, portforward.TCP, internalPort, "Lantern Share My Connection")
	if err != nil {
		return fmt.Errorf("map port %d: %w", internalPort, err)
	}
	// Renew from the moment the port is mapped: a PCP or NAT-PMP gateway can
	// grant a lease shorter than registering, starting the box and verifying
	// take. Not tied to the caller's ctx, which ends with Start: UnmapPort,
	// which both rollback and Stop call, stops the renewal.
	fwd.StartRenewal(context.Background())

	c.emitPhase(PhaseDetectingIP, "")
	externalIP, err := fwd.ExternalIP(ctx)
	if err != nil {
		return fmt.Errorf("get external ip: %w", err)
	}

	c.emitPhase(PhaseRegistering, "")
	regResp, regPool, err = c.register(ctx, RegisterRequest{
		ExternalIP:   externalIP,
		ExternalPort: mapping.ExternalPort,
		InternalPort: mapping.InternalPort,
	})
	if err != nil {
		return fmt.Errorf("register with lantern-cloud: %w", err)
	}

	// Defence-in-depth: refuse to start the box if the server-supplied
	// launch_cfg is missing the expected abuse-handling rules. A
	// server-side regression that silently shipped an open-proxy
	// config would otherwise turn every peer in the field into one
	// until the next deploy. The peer prefers failing to share over
	// sharing unsafely.
	if err := peerrules.ValidateAbuseRules(regResp.ServerConfig); err != nil {
		return fmt.Errorf("launch_cfg failed abuse-rule sanity check: %w", err)
	}

	// The peer's outbound traffic must bypass any TUN device the user's own
	// VPN may have installed — otherwise censored clients' traffic would
	// egress through the local user's Lantern proxy instead of their
	// residential connection, defeating the whole point of peer-sharing.
	// auto_detect_interface tells sing-box to bind outbound dials to the
	// underlying physical interface rather than whatever the OS routing
	// table picks (which would be the VPN TUN if the VPN is up).
	c.emitPhase(PhaseStartingBox, "")
	options, err := ensurePeerOutboundsBypassVPN(regResp.ServerConfig)
	if err != nil {
		return fmt.Errorf("patch sing-box options: %w", err)
	}

	// runCtx must outlive Start, so it derives from Background() rather than
	// the caller's ctx — otherwise libbox's stored ctx would die when Start
	// returns and take the box's internal goroutines with it.
	runCtx, cancelRun = context.WithCancel(context.Background())
	box, err = c.cfg.BuildBoxService(runCtx, options)
	if err != nil {
		cancelRun()
		return fmt.Errorf("build sing-box: %w", err)
	}

	// Paired inviters authenticate with per-pairing short IDs that
	// lantern-cloud rotates. The launch config's own ID stays. Only a set the
	// server vouches for is applied, and before Start, so the box never
	// serves without it; otherwise the box keeps its base ID.
	baseShortIDs := inboundShortIDs(options)
	var startPairing []string
	var startRevision int64
	startPairingKnown := regResp.PairingShortIDsKnown && regResp.PairingShortIDsRevision > 0
	startPairingApplied := false
	if startPairingKnown {
		startPairing = slices.Clone(regResp.PairingShortIDs)
		startRevision = int64(regResp.PairingShortIDsRevision)
		startPairingApplied = c.applyShortIDs(box, baseShortIDs, startPairing)
	}
	var startGroups *map[[8]byte]string
	if startPairingKnown {
		if g, ok := groupPairingShortIDs(startPairing, regResp.PairingShortIDSets, baseShortIDs); ok {
			startGroups = &g
		}
	}

	// Published before serving, so connections accepted from the start
	// resolve their pairing.
	c.mu.Lock()
	c.heldGroups, c.prevGroups, c.pendingGroups = nil, nil, startGroups
	if startPairingApplied {
		c.commitPendingGroupsLocked()
	} else {
		c.publishGroupsLocked(false)
	}
	c.mu.Unlock()

	// Forward inbound accept/close events from lantern-box's samizdat
	// inbound to the radiance event bus. Consumers (lantern-core's
	// FlutterEventEmitter, future abuse aggregation) subscribe via
	// events.Subscribe[ConnectionEvent]. Listener is process-wide
	// single-active; cleared on Stop and in the rollback defer so
	// post-teardown accept-loop callbacks land on a no-op rather than
	// emit events to a torn-down consumer.
	// Registered before box.Start: samizdat binds each connection to the
	// listener at accept, so registering any later would never report a
	// connection accepted in between, such as one during Verify.
	peerconn.SetListener(func(evt peerconn.Event) {
		state, source := evt.State, evt.Source
		if c.listenerDraining.Load() {
			// Diagnostic: if Notify reaches this point but we drop because
			// the drain flag is set, that's the post-Stop racing-Notify case
			// the flag was added to silence. Logging makes its frequency
			// observable instead of "events silently vanish."
			slog.Debug("peer listener: dropping post-Stop Notify",
				"state", state, "source", source)
			return
		}
		// Per-connection breadcrumb correlates samizdat-in activity with
		// peer-connection FlutterEvents on the consumer side. Debug-level
		// so prod logs aren't flooded under real traffic and so the
		// remote ip:port doesn't land in routinely-collected client logs;
		// operators investigating "no globe arcs despite samizdat traffic"
		// can flip the level. The listener-registration line below stays
		// at Info — that's a once-per-session lifecycle event, not a
		// per-connection breadcrumb.
		if evt.Rejected {
			c.rejections.record(evt.Destination)
		}
		if c.isVerifierConn(state, source, evt.Destination, evt.Bytes) {
			slog.Debug("peer listener: hiding verifier connection",
				"state", state, "source", source)
			return
		}
		// The pairing is deliberately absent from this line and every other.
		slog.Debug("peer listener: forwarding connection event",
			"state", state, "source", source)
		c.trackConn(state, source)
		if c.beforeTrackLive != nil {
			c.beforeTrackLive()
		}
		pairing := c.trackPairing(liveGen, relayGen, state, source, evt.ShortID, evt.Bytes)
		events.Emit(ConnectionEvent{State: state, Source: source, Timestamp: time.Now().UnixMilli(), Pairing: pairing})
	})
	slog.Info("peer listener: registered with peerconn", "route_id", regResp.RouteID)

	if err := box.Start(); err != nil {
		cancelRun()
		return fmt.Errorf("start sing-box: %w", err)
	}

	c.emitPhase(PhaseVerifying, "")
	// Now that sing-box is listening with the just-built creds, ask the
	// server to dial back through them. Splitting verify out of Register
	// into this explicit follow-up avoids the chicken-and-egg where the
	// server tried to verify before the peer could possibly be listening
	// (the cert/key only arrive in the Register response). Failure here
	// is fatal — the server has already deprecated the row, so the
	// deferred cleanup tears the rest of the session down.
	if err := c.cfg.API.Verify(ctx, regResp.RouteID); err != nil {
		cancelRun()
		return fmt.Errorf("verify with lantern-cloud: %w", err)
	}

	// HeartbeatIntervalSeconds is server-driven so lantern-cloud can dial up
	// the cadence on registrations it wants to expire faster. Honor any
	// positive value verbatim — clamping short intervals up would defeat
	// that and risk the server reaping the route between our heartbeats.
	// A non-positive value means the field was unset (e.g., older server,
	// JSON omitted); fall back to a sane default.
	heartbeat := c.cfg.HeartbeatInterval
	if heartbeat == 0 {
		heartbeat = time.Duration(regResp.HeartbeatIntervalSeconds) * time.Second
		if heartbeat <= 0 {
			heartbeat = 5 * time.Minute
		}
	}
	runDone := make(chan struct{})

	c.mu.Lock()
	c.active = true
	c.commitPool(regPool)
	c.registration++
	c.forwarder = fwd
	c.box = box
	c.routeID = regResp.RouteID
	c.externalPort = mapping.ExternalPort
	c.internalPort = mapping.InternalPort
	c.boxOptions = options
	c.baseShortIDs = baseShortIDs
	c.pairingShortIDs = startPairing
	c.pairingKnown = startPairingKnown
	// With no known set the new box holds what it should: its base ID.
	c.pairingApplied = !startPairingKnown || startPairingApplied
	c.pairingRevision = startRevision
	if startPairingKnown {
		c.pairingConfirmedAt = c.cfg.Now()
	}
	c.runCtx = runCtx
	c.cancelRun = cancelRun
	c.runDone = runDone
	c.status = Status{
		Phase:        PhaseServing,
		Active:       true,
		SharingSince: time.Now(),
		ExternalIP:   externalIP,
		ExternalPort: mapping.ExternalPort,
		RouteID:      regResp.RouteID,
	}
	c.tagStatusLocked()
	statusSnapshot := c.status
	c.mu.Unlock()

	rotation := c.cfg.CredRotationInterval
	if rotation == 0 {
		rotation = peerCredRotationInterval
	}

	go c.heartbeatLoop(runCtx, heartbeat, runDone)
	go c.credRotationLoop(runCtx, rotation)

	slog.Info("peer client started",
		"external_port", mapping.ExternalPort,
		"internal_port", mapping.InternalPort,
		"method", mapping.Method,
		"route_id", regResp.RouteID,
		"heartbeat", heartbeat,
	)
	success = true
	c.publishStatus(statusSnapshot)
	return nil
}

// Stop tears down the session running when it is called. Idempotent.
//
// With a session running, Stop always completes. It cancels that session
// first, so a rotation holding the lifecycle slot aborts its network calls,
// then waits for the slot however long ctx allows or not: giving up would
// leave a session whose loops are cancelled but which is still registered
// and listening. Only work bounded by that cancelled session can hold the
// slot then. Teardown runs on its own bounded context.
//
// With no session yet, because a Start is in flight, Stop waits for that
// Start and stops what it started, but honors ctx while waiting, so a caller
// has an exit if the Start hangs (UPnP discovery, say). Giving up then
// leaves nothing half-cancelled.
//
// Stop targets the session it cancelled, so it never tears down a session a
// later Start begins.
func (c *Client) Stop(ctx context.Context) error {
	c.mu.Lock()
	cancelRun, session := c.cancelRun, c.runCtx
	c.mu.Unlock()
	if session != nil {
		cancelRun()
		c.lifecycle <- struct{}{}
	} else if err := c.acquireLifecycle(ctx); err != nil {
		return err
	}
	defer c.releaseLifecycle()
	teardownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), peerCleanupTimeout)
	defer cancel()
	_, err := c.stopHeld(teardownCtx, stopTarget{session: session})
	return err
}

// stopTarget identifies what a stop is for. A zero field matches anything, so
// the zero stopTarget stops whatever is running.
type stopTarget struct {
	// session is the runCtx of the session to stop.
	session context.Context
	// routeID and registration identify the registration the stop was decided
	// on. The server reuses a route_id across re-registrations, and a rotation
	// advances registration before it swaps in a different route_id, so both
	// are needed.
	routeID      string
	registration uint64
}

// stopTarget stops the client if it still matches target, checked under the
// lifecycle slot so no rotation or Start can change it before the stop. It
// reports whether it stopped anything.
func (c *Client) stopTarget(ctx context.Context, target stopTarget) (bool, error) {
	if err := c.acquireLifecycle(ctx); err != nil {
		return false, err
	}
	defer c.releaseLifecycle()
	return c.stopHeld(ctx, target)
}

// stopHeld is stopTarget for a caller already holding the lifecycle slot.
func (c *Client) stopHeld(ctx context.Context, target stopTarget) (bool, error) {
	c.mu.Lock()
	for c.starting {
		done := c.startingDone
		c.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		c.mu.Lock()
	}
	if !c.active ||
		target.session != nil && c.runCtx != target.session ||
		target.routeID != "" && c.routeID != target.routeID ||
		target.registration != 0 && c.registration != target.registration {
		c.mu.Unlock()
		return false, nil
	}
	cancel := c.cancelRun
	done := c.runDone
	fwd := c.forwarder
	box := c.box
	routeID := c.routeID
	c.active = false
	c.cancelRun = nil
	c.runDone = nil
	c.forwarder = nil
	c.box = nil
	c.routeID = ""
	c.externalPort = 0
	c.internalPort = 0
	c.boxOptions = ""
	c.baseShortIDs = nil
	c.pairingShortIDs = nil
	c.pairingKnown = false
	c.pairingApplied = false
	c.pairingRevision = 0
	c.pairingConfirmedAt = time.Time{}
	c.clearGroupsLocked()
	c.runCtx = nil
	c.status = Status{Phase: PhaseStopping}
	c.tagStatusLocked()
	stoppingSnapshot := c.status
	c.mu.Unlock()
	c.publishStatus(stoppingSnapshot)

	// Suppress the connection listener BEFORE box.Close. peerconn.Notify
	// reads its registered listener under an RLock and releases it before
	// invoking — SetListener(nil) alone races against in-flight Notify
	// goroutines that have already snapshotted the listener (one per live
	// inbound connection at Close time). Flipping listenerDraining first
	// short-circuits the wrapper inline so even the racing invocations
	// become no-ops. SetListener(nil) is still called for cleanliness and
	// to release the listener closure's reference to this Client.
	c.listenerDraining.Store(true)
	peerconn.SetListener(nil)
	c.resetConnTracking()
	c.relay.end()
	// Stop drops the closes of connections still open, so end them here.
	c.endLive()

	cancel()
	<-done

	var firstErr error
	if err := c.cfg.API.Deregister(ctx, routeID); err != nil {
		firstErr = fmt.Errorf("deregister: %w", err)
		slog.Warn("peer client deregister failed (continuing teardown)", "err", err)
	}
	if err := c.closeBox(box); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("close sing-box: %w", err)
		}
		slog.Warn("peer client sing-box close failed", "err", err)
	}
	// Only now does no box serve: a hand-off racing this teardown must still
	// see the pool, and re-register or wait for it.
	c.poolMaybe.Store(false)
	if err := fwd.UnmapPort(ctx); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("unmap port: %w", err)
		}
		slog.Warn("peer client unmap port failed", "err", err)
	}
	c.rejections.flush()
	slog.Info("peer client stopped", "route_id", routeID)
	c.mu.Lock()
	c.status = Status{Phase: PhaseIdle}
	c.tagStatusLocked()
	idleSnapshot := c.status
	c.mu.Unlock()
	c.publishStatus(idleSnapshot)
	return true, firstErr
}

func (c *Client) IsActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *Client) CurrentStatus() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// MayServePool reports whether this client's box may be serving the general
// pool, erring toward true: false means it is known not to be.
func (c *Client) MayServePool() bool {
	return c.poolMaybe.Load()
}

// register registers the route with lantern-cloud, with serve_pool as this run
// wants it, and reports whether that registration serves the pool. The caller
// commits the result with commitPool.
func (c *Client) register(ctx context.Context, req RegisterRequest) (*RegisterResponse, bool, error) {
	// Set before the setting is read, so a caller racing this registration
	// sees the pool it may register.
	was := c.poolMaybe.Swap(true)
	req.ServePool = c.servePool()
	pool := req.ServePool == nil || *req.ServePool
	if !pool {
		// A pool-free registration can't add the pool, failed or not.
		c.poolMaybe.Store(was)
	}
	resp, err := c.cfg.API.Register(ctx, req)
	return resp, pool, err
}

// commitPool records the pool setting of the registration the running box now
// serves.
func (c *Client) commitPool(pool bool) {
	if !pool {
		c.poolMaybe.Store(false)
	}
}

// pairingsOnly reports whether this run serves only the device's helper
// pairings (Config.PairingsOnly).
func (c *Client) pairingsOnly() bool {
	return c.cfg.PairingsOnly != nil && c.cfg.PairingsOnly()
}

// errorTypes lists the dynamic types in err's wrap tree, breadth first and
// following joined and multi-%w errors too: enough to tell which error to
// classify without its text.
func errorTypes(err error) string {
	var types []string
	queue := []error{err}
	for len(queue) > 0 && len(types) < 12 {
		e := queue[0]
		queue = queue[1:]
		if e == nil {
			continue
		}
		types = append(types, fmt.Sprintf("%T", e))
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			queue = append(queue, u.Unwrap()...)
		case interface{ Unwrap() error }:
			queue = append(queue, u.Unwrap())
		}
	}
	return strings.Join(types, ", ")
}

// tagStatusLocked records on c.status which kind of run it describes. The
// caller holds c.mu.
func (c *Client) tagStatusLocked() {
	c.status.PairingsOnly = c.pairingsOnly()
}

// RetagStatus re-records which kind of run the current status describes,
// after a hand-off between sharing and pairings-only changed it without a new
// phase.
func (c *Client) RetagStatus() {
	c.mu.Lock()
	c.tagStatusLocked()
	c.mu.Unlock()
}

// publishStatus emits s for the sharing UI, unless it describes a run that
// serves only the device's helper pairings: Share My Connection is off then,
// and a background pairings-only run must not show as sharing, or as failing
// to.
func (c *Client) publishStatus(s Status) {
	if s.PairingsOnly {
		return
	}
	events.Emit(StatusEvent{Status: s})
}

// emitPhase updates c.status.Phase under the lock and emits a snapshot.
// Used at each lifecycle boundary in Start / Stop so the UI sees progress
// instead of a binary active/inactive flip. Active is recomputed here:
// only PhaseServing implies active=true; every other phase clears it so
// subscribers using just the Active flag don't see e.g. "active=true with
// Phase=verifying" mid-Start.
func (c *Client) emitPhase(p Phase, errMsg string) {
	c.emitStatus(p, errMsg, "")
}

func (c *Client) emitError(reason Reason, errMsg string) {
	c.emitStatus(PhaseError, errMsg, reason)
}

func (c *Client) emitStatus(p Phase, errMsg string, reason Reason) {
	c.mu.Lock()
	c.status.Phase = p
	c.status.Error = errMsg
	// Cleared on every non-error phase, so a stale classification from a
	// previous failed Start cannot ride along on the next attempt's progress
	// events.
	c.status.Reason = reason
	c.status.Active = (p == PhaseServing)
	c.tagStatusLocked()
	snapshot := c.status
	c.mu.Unlock()
	c.publishStatus(snapshot)
}

// currentPhase reports the phase Start had reached, which is the phase a
// failure happened in — read before emitError overwrites it.
func (c *Client) currentPhase() Phase {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status.Phase
}

// trackConn maintains the per-IP open-connection tally behind ActiveClients.
// A -1 for an IP with no recorded connection is ignored rather than allowed to
// go negative: peerconn is process-wide and a disconnect for a connection
// accepted before this Client registered its listener can still arrive.
func (c *Client) trackConn(state int, source string) {
	ip, _, err := net.SplitHostPort(source)
	if err != nil {
		ip = source
	}
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	// Re-check the drain flag here, not just in the listener wrapper. A
	// callback that passed the wrapper's check before Stop set the flag can
	// reach this point after resetConnTracking has already cleared the map,
	// repopulating it and leaking a stale count into the next Start. Checking
	// under connsMu is what makes this airtight rather than merely narrower:
	// Stop sets the flag before taking connsMu to reset, so any call that
	// acquires the lock after the reset necessarily observes the flag.
	if c.listenerDraining.Load() {
		return
	}
	if c.connsByIP == nil {
		c.connsByIP = make(map[string]int)
	}
	switch {
	case state > 0:
		c.connsByIP[ip]++
	case state < 0:
		if n, ok := c.connsByIP[ip]; ok {
			if n <= 1 {
				delete(c.connsByIP, ip)
			} else {
				c.connsByIP[ip] = n - 1
			}
		}
	}
}

// ActiveClients reports how many distinct remote IPs currently hold at least
// one connection. Reported to the server on each heartbeat so it can stop
// assigning new clients to a peer that is already carrying its share.
func (c *Client) ActiveClients() int {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	return len(c.connsByIP)
}

// resetConnTracking drops the tally on teardown so a subsequent Start doesn't
// inherit connections belonging to the previous session's box.
func (c *Client) resetConnTracking() {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	c.connsByIP = nil
	c.verifierConns = nil
	c.verifierCounters = nil
}

// verifierCallbackHosts are the hosts lantern-cloud's verifier fetches through
// a peer to prove it can proxy: "api." + the environment's public domain, per
// defaultPeerVerifyCallbackURL in lantern-cloud's cmd/api/peer_verify.go. They
// are lantern-cloud itself checking the route, not a person being helped.
var verifierCallbackHosts = []string{"api.iantem.io", "api.staging.iantem.io"}

// isVerifierConn reports whether a connection event belongs to lantern-cloud's
// verifier, which re-verifies serving peers too, so that it is neither shown
// as a person helped nor reported to the server as a client. An accept is
// matched by destination. A close carries no destination, so it is matched by
// its byte counter, which identifies the stream. Without a counter, each
// hidden accept hides one later close from the same source; when ordinary and
// verifier streams share a source that may not be the verifier's own close,
// but the per-IP totals still balance.
func (c *Client) isVerifierConn(state int, source, destination string, bytes *peerconn.Counter) bool {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	// Same reason as trackConn: a late accept must not repopulate the set
	// after resetConnTracking has cleared it.
	if c.listenerDraining.Load() {
		return false
	}
	if state < 0 {
		if bytes != nil {
			if _, ok := c.verifierCounters[bytes]; !ok {
				return false
			}
			delete(c.verifierCounters, bytes)
			return true
		}
		n := c.verifierConns[source]
		if n == 0 {
			return false
		}
		if n == 1 {
			delete(c.verifierConns, source)
		} else {
			c.verifierConns[source] = n - 1
		}
		return true
	}
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
	}
	if !slices.ContainsFunc(verifierCallbackHosts, func(h string) bool {
		return strings.EqualFold(h, host)
	}) {
		return false
	}
	if bytes != nil {
		if c.verifierCounters == nil {
			c.verifierCounters = make(map[*peerconn.Counter]struct{})
		}
		c.verifierCounters[bytes] = struct{}{}
		return true
	}
	if c.verifierConns == nil {
		c.verifierConns = make(map[string]int)
	}
	c.verifierConns[source]++
	return true
}

// sendHeartbeat sends one heartbeat carrying the traffic relayed since the
// last one that succeeded. A heartbeat that fails keeps that traffic for the
// next, except on a 400 for a heartbeat that carried traffic: a server that
// predates the usage fields rejects them, so the traffic is dropped and the
// heartbeat sent again without it.
func (c *Client) sendHeartbeat(ctx context.Context, routeID string) (*HeartbeatResponse, error) {
	usage := c.relay.takeUsage()
	resp, err := c.cfg.API.Heartbeat(ctx, routeID, c.ActiveClients(), usage)
	if err == nil {
		return resp, nil
	}
	if (usage.RelayedBytes > 0 || len(usage.PairedBytes) > 0) && isBadRequest(err) {
		return c.cfg.API.Heartbeat(ctx, routeID, c.ActiveClients(), RelayUsage{})
	}
	c.relay.restoreUsage(usage)
	return resp, err
}

// heartbeatLoop closes done on exit so Stop can wait for the loop before
// tearing down resources. The channel is passed in rather than read off the
// Client because Stop nils c.runDone before waiting on its local copy.
func (c *Client) heartbeatLoop(ctx context.Context, interval time.Duration, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.rejections.flush()
			c.mu.Lock()
			routeID, registration := c.routeID, c.registration
			c.mu.Unlock()
			if routeID == "" {
				return
			}
			hbCtx, cancel := context.WithTimeout(ctx, c.cfg.HeartbeatTimeout)
			resp, err := c.sendHeartbeat(hbCtx, routeID)
			cancel()
			if err == nil && resp.PairingShortIDsKnown {
				// Replaces the pairing set, so an ended pairing stops working
				// here, unless a newer set was accepted while it was in
				// flight.
				c.offerPairingShortIDs(resp.PairingShortIDs, resp.PairingShortIDSets, true, int64(resp.PairingShortIDsRevision))
			} else {
				// A failed heartbeat, or one that does not vouch for a set,
				// says nothing about pairings, so the last set stays, and is
				// pushed again if the box does not hold it.
				c.applyPairingShortIDs(nil, false, 0)
			}
			c.expireUnconfirmedPairing()
			if err != nil {
				// A single transient blip shouldn't kill the registration —
				// the server-side reaper will deprecate the row if heartbeats
				// stay missing past expiration, and we'll observe that on a
				// later heartbeat as a 404.
				slog.Warn("peer heartbeat failed", "err", err, "route_id", routeID)
				if isNotRegistered(err) {
					// Re-check current routeID under lock. If credRotationLoop
					// swapped routeID + deregistered the prior route between
					// our heartbeat-prepare and heartbeat-response, the 404
					// applies to a stale route and is expected, not a reason
					// to stop. Skip the auto-Stop and let the next tick
					// heartbeat the new route.
					// A rotation may have re-registered while this heartbeat was
					// in flight; stopSelf stops only if this registration is
					// still current, and the loop keeps running otherwise.
					slog.Info("peer heartbeat 404; stopping unless a re-registration replaced the route", "route_id", routeID)
					c.stopSelf(stopTarget{session: ctx, routeID: routeID, registration: registration},
						fmt.Errorf("route %s no longer registered: %w", routeID, err))
					continue
				}
			}
		}
	}
}

// isNotRegistered reports whether an error from the heartbeat is a 404 from
// the server (deprecated / reaped / wrong owner). On 404 the registration is
// gone and we stop ourselves; on any other error we keep trying.
func isNotRegistered(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == 404
}

func isBadRequest(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == 400
}

// credRotationLoop periodically rotates the peer's samizdat credentials
// (X25519 keypair, shortID, masquerade) by re-registering with
// lantern-cloud, rebuilding the libbox inbound, and deregistering the
// prior route. Caps blast radius from credential leakage to ~interval
// regardless of peer process lifetime — see peerCredRotationInterval.
//
// Closes done is the responsibility of heartbeatLoop; this loop just
// exits when ctx is cancelled. We deliberately don't add another close
// channel: heartbeatLoop's done already gates Stop, and rotation
// failures are non-fatal (log + retry next tick), so there's nothing
// the Stop path needs to wait on from this goroutine.
func (c *Client) credRotationLoop(ctx context.Context, interval time.Duration) {
	// Non-positive interval would panic time.NewTicker. Treat it the same
	// as the zero case Start handles when CredRotationInterval is unset:
	// fall back to the default cap rather than disabling rotation
	// silently (an unset value still wants rotation; a negative value is
	// almost certainly a test/config bug).
	if interval <= 0 {
		interval = peerCredRotationInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.runRotation(ctx)
		}
	}
}

// runRotation wraps rotateCreds with a panic recover. libbox.Start can
// panic — the main tunnel start path already wraps it with recover for
// the same reason — and an unrecovered panic here would crash the host
// process during a background rotation, taking the user's main VPN
// with it. Treat a panic the same as any other rotation failure: log,
// keep the existing box serving, try again next tick.
func (c *Client) runRotation(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("peer cred rotation panicked; current creds remain in use",
				"panic", r, "stack", string(debug.Stack()))
		}
	}()
	if err := c.rotateCreds(ctx); err != nil {
		// A failure that left nothing serving has already stopped the
		// client; otherwise the current box and route still serve and the
		// next tick retries.
		if c.IsActive() {
			slog.Warn("peer cred rotation failed; current creds remain in use", "err", err)
		} else {
			slog.Warn("peer cred rotation failed; client stopped", "err", err)
		}
	}
}

// ErrNotActive is Reregister's error when no session runs.
var ErrNotActive = errors.New("peer: no session is running")

// Reregister re-registers the running session now rather than at its next
// rotation, so a change to what registration sends, such as peer_serve_pool,
// takes effect at once. It rotates the credentials exactly as the hourly
// rotation does, and like it turns a libbox panic into an error. The new
// credentials plus closing the old box, which ends its sessions, cut off
// strangers when "help others too" turns off; paired clients reconnect with
// their pairing IDs.
func (c *Client) Reregister(ctx context.Context) (err error) {
	c.mu.Lock()
	active, session := c.active, c.runCtx
	c.mu.Unlock()
	if !active || session == nil {
		return ErrNotActive
	}
	defer func() {
		if r := recover(); r != nil {
			//logleak:ok recovered panic value
			err = fmt.Errorf("peer re-register panicked: %v", r)
		}
	}()
	// Bound to the session too, as the hourly rotation is: Stop cancels the
	// session and then waits for the lifecycle slot, so a re-register hung
	// in ExternalIP or Register must end with it.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(session, cancel)()
	return c.rotateCreds(ctx)
}

// rotateCreds swaps the peer's samizdat credentials by re-registering and
// rebuilding the libbox inbound against the new launch config.
//
// The server keys a peer's route on (address, port) and upserts it, so a
// re-register from the same peer returns the same route_id with new
// credentials. Rotation therefore never deregisters a route_id it is still
// using: that would unregister the live route. Once the re-register succeeds
// on the same route_id the server advertises only the new credentials, so any
// failure after that point leaves nothing serving what clients are handed, and
// the client stops itself (see stopSelf) rather than keep heartbeating a dead
// route. A different route_id keeps the older behavior: the new route is
// deregistered on failure and the old box keeps serving.
//
// The old box is closed before the new one is built, because building the
// samizdat inbound binds the listening port. Close releases the port at once
// and ends the box's sessions; closeBox bounds the wait as a safety net.
func (c *Client) rotateCreds(ctx context.Context) error {
	if err := c.acquireLifecycle(ctx); err != nil {
		return err
	}
	defer c.releaseLifecycle()
	c.mu.Lock()
	if !c.active {
		c.mu.Unlock()
		return ErrNotActive
	}
	fwd := c.forwarder
	extPort := c.externalPort
	intPort := c.internalPort
	oldRouteID := c.routeID
	oldBox := c.box
	// Capture sessionRunCtx upfront so the final swap can detect a
	// Stop→Start cycle that happened mid-rotation. Just checking
	// c.active at the swap isn't enough: Stop clears active, then a
	// new Start can set it back to true before this rotation reaches
	// the swap, and the old rotation would clobber the new session's
	// state. The runCtx is unique per session, so a pointer-identity
	// check at the swap is sufficient.
	sessionRunCtx := c.runCtx
	c.mu.Unlock()

	if fwd == nil || oldBox == nil {
		return errors.New("rotateCreds: client state inconsistent")
	}

	externalIP, err := fwd.ExternalIP(ctx)
	if err != nil {
		return fmt.Errorf("get external ip: %w", err)
	}
	regResp, regPool, err := c.register(ctx, RegisterRequest{
		ExternalIP:   externalIP,
		ExternalPort: extPort,
		InternalPort: intPort,
	})
	if err != nil {
		return fmt.Errorf("re-register: %w", err)
	}
	// The server now advertises this registration's creds, so any heartbeat
	// 404 from before it no longer describes the route.
	c.mu.Lock()
	c.registration++
	registration := c.registration
	c.mu.Unlock()
	if regResp.PairingShortIDsKnown {
		// Offered like a heartbeat's set: taken only if newer than the
		// one held, and pushed onto the box serving now.
		c.offerPairingShortIDs(regResp.PairingShortIDs, regResp.PairingShortIDSets, true, int64(regResp.PairingShortIDsRevision))
	}
	sameRoute := regResp.RouteID == oldRouteID
	// abandon undoes a registration this rotation can no longer use. A new
	// route_id is deregistered so the bandit doesn't hand out creds for a box
	// that never came up. The same route_id is the live route, now advertising
	// the new creds, so it is left to stopSelf.
	abandon := func(reason error) {
		if sameRoute {
			return
		}
		// Use a fresh ctx so a cancelled rotation ctx doesn't skip the
		// cleanup we just made necessary.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), peerCleanupTimeout)
		defer cancel()
		if dErr := c.cfg.API.Deregister(cleanupCtx, regResp.RouteID); dErr != nil {
			slog.Warn("deregister orphan route after rotation failure",
				"reason", reason, "err", dErr, "orphan_route_id", regResp.RouteID)
		}
	}
	// fail reports a rotation failure. servingOld says whether the old box
	// still serves creds the server hands out.
	fail := func(err error, servingOld bool) error {
		abandon(err)
		if sameRoute || !servingOld {
			// Stopped here, while this rotation still holds the lifecycle
			// slot: a stop queued behind it could lose the slot to the next
			// rotation, whose re-register would make it look stale.
			reason := fmt.Errorf("credential rotation left nothing serving the advertised route: %w", err)
			stopCtx, cancel := context.WithTimeout(context.Background(), peerCleanupTimeout)
			stopped, _ := c.stopHeld(stopCtx, stopTarget{session: sessionRunCtx, routeID: oldRouteID, registration: registration})
			cancel()
			if stopped && c.cfg.OnSelfStop != nil {
				go c.cfg.OnSelfStop(reason)
			}
		}
		return err
	}

	// Same defence-in-depth gate Start applies, because rotation installs a
	// freshly fetched launch_cfg on an already-running peer. Validating only
	// at Start would let a server-side regression reach every long-lived peer
	// on its next hourly rotation.
	if err := peerrules.ValidateAbuseRules(regResp.ServerConfig); err != nil {
		return fail(fmt.Errorf("rotated launch_cfg failed abuse-rule sanity check: %w", err), true)
	}

	options, err := ensurePeerOutboundsBypassVPN(regResp.ServerConfig)
	if err != nil {
		return fail(fmt.Errorf("patch sing-box options: %w", err), true)
	}

	c.mu.Lock()
	currentRunCtx := c.runCtx
	c.mu.Unlock()
	if currentRunCtx == nil || currentRunCtx != sessionRunCtx {
		// Stop ran (runCtx==nil), or a Stop→Start cycle replaced the
		// session (runCtx pointer differs from the one captured at the
		// top). The session this rotation belongs to is gone, so there is
		// nothing to stop; only a separate new route needs cleaning up.
		abandon(errors.New("client stopped during rotation"))
		return errors.New("client stopped during rotation")
	}

	if closeErr := c.closeBox(oldBox); closeErr != nil {
		slog.Warn("close old box during rotation", "err", closeErr)
	}
	// The new box is built with its base ID only. Before it starts it is
	// given the newest recorded set, which includes this register's if it
	// was newer, so paired users reconnecting after the old box closed are
	// never refused. A heartbeat that records a newer set before the swap
	// pushes it onto the old box; the swap below gives the new box it.
	newBase := inboundShortIDs(options)
	var (
		rotPairing []string
		rotKnown   bool
		rotApplied bool
	)
	newBox, err := buildAndStartWithRetry(ctx, func() (boxService, error) {
		b, err := c.cfg.BuildBoxService(sessionRunCtx, options)
		if err != nil {
			return b, err
		}
		c.mu.Lock()
		rotPairing, rotKnown = slices.Clone(c.pairingShortIDs), c.pairingKnown
		if rotKnown {
			c.publishGroupsLocked(true)
		}
		c.mu.Unlock()
		rotApplied = rotKnown && c.applyShortIDs(b, newBase, rotPairing)
		return b, nil
	}, c.closeBox)
	if err != nil {
		// The old box is closed and the new one isn't up: nothing listens.
		// Leave c.box pointing at oldBox so Stop's close stays idempotent.
		return fail(fmt.Errorf("start new sing-box: %w", err), false)
	}

	// Final swap under lock. Re-check that the session is still the
	// one we started against. Per-session runCtx identity is a stricter
	// check than c.active alone: a Stop→Start cycle between the
	// runCtx-check above and now would have cleared active AND set it
	// back true, but the new session's runCtx differs from sessionRunCtx
	// — so we'd otherwise resurrect old-session state into the new one.
	// shortIDsMu orders the swap against a heartbeat's record and push.
	c.shortIDsMu.Lock()
	c.mu.Lock()
	if !c.active || c.runCtx != sessionRunCtx {
		c.mu.Unlock()
		c.shortIDsMu.Unlock()
		// Either Stop cleared state, or Stop→Start replaced the session.
		// Close the new box we just brought up (the current session has
		// no reference to it) and clean up a separate new route. Don't
		// touch the prior route: in the Stop-only case, Stop already
		// deregistered it; in the Stop→Start case, deregistering it
		// would defeat the rotation point of cutting off the old creds.
		if err := c.closeBox(newBox); err != nil {
			slog.Warn("close new box after session changed during rotation", "err", err)
		}
		abandon(errors.New("session changed during rotation swap"))
		return errors.New("session changed during rotation")
	}
	c.box = newBox
	c.routeID = regResp.RouteID
	c.commitPool(regPool)
	c.boxOptions = options
	c.baseShortIDs = newBase
	// Reconcile the new box with the current record, which a heartbeat may
	// have replaced, or expiry cleared, since the push before Start. The
	// box holds the pairing set that push took, or none; the record wants
	// its set, or none when it is not known. If they differ, the box is
	// given the record now, base ID only when there is none, and a failure
	// leaves pairingApplied false for the next heartbeat to retry.
	var pushed, want []string
	if rotKnown && rotApplied {
		pushed = rotPairing
	}
	if c.pairingKnown {
		want = slices.Clone(c.pairingShortIDs)
	}
	held := slices.Equal(pushed, want)
	c.pairingApplied = held
	if held {
		c.commitPendingGroupsLocked()
	} else {
		c.publishGroupsLocked(true)
	}
	c.status.RouteID = regResp.RouteID
	c.status.ExternalIP = externalIP
	c.mu.Unlock()
	if !held {
		ok := c.applyShortIDs(newBox, newBase, want)
		c.mu.Lock()
		if c.box == newBox {
			if ok {
				c.pairingApplied = true
				c.commitPendingGroupsLocked()
			} else {
				c.publishGroupsLocked(false)
			}
		}
		c.mu.Unlock()
	}
	c.shortIDsMu.Unlock()

	if !sameRoute {
		// Deregister the prior route so the bandit stops handing the old
		// (now-invalid) creds to clients. Use a fresh ctx so a Stop that
		// races us between the swap above and the deregister doesn't
		// cancel the cleanup.
		deregCtx, cancelDereg := context.WithTimeout(context.Background(), peerCleanupTimeout)
		if err := c.cfg.API.Deregister(deregCtx, oldRouteID); err != nil {
			slog.Warn("deregister prior route after rotation",
				"err", err, "old_route_id", oldRouteID)
		}
		cancelDereg()
	}

	// The re-register reset the route's verification, and the server hands
	// clients only verified peers.
	verifyCtx, cancelVerify := context.WithTimeout(ctx, peerVerifyTimeout)
	verifyErr := c.cfg.API.Verify(verifyCtx, regResp.RouteID)
	cancelVerify()
	if verifyErr != nil && ctx.Err() == nil {
		slog.Warn("verify after rotation failed; box left running",
			"err", verifyErr, "route_id", regResp.RouteID)
	}

	slog.Info("peer cred rotation succeeded",
		"new_route_id", regResp.RouteID,
		"old_route_id", oldRouteID,
	)
	return nil
}

// buildAndStartWithRetry builds and starts a box, retrying a handful of times
// with a short backoff to absorb EADDRINUSE while the old box's listening port
// is released. Building is retried along with starting because building the
// samizdat inbound is what binds the port. Inter-attempt backoff totals 750ms
// (50+100+200+400 across 4 sleeps; no sleep after the final attempt).
//
// Building or starting libbox can panic; that is converted to an error so the
// caller's failure handling still runs. A box that was built but failed or
// panicked on Start holds the port, so it is closed with closeBox.
func buildAndStartWithRetry(ctx context.Context, build func() (boxService, error), closeBox func(boxService) error) (box boxService, retErr error) {
	var inFlight boxService
	defer func() {
		if r := recover(); r != nil {
			if inFlight != nil {
				_ = closeBox(inFlight)
			}
			//logleak:ok recovered panic value
			box, retErr = nil, fmt.Errorf("build or start new sing-box panicked: %v", r)
		}
	}()
	const attempts = 5
	backoff := 50 * time.Millisecond
	var lastErr error
	for i := 0; i < attempts; i++ {
		b, err := build()
		if err == nil {
			inFlight = b
			if err = b.Start(); err == nil {
				return b, nil
			}
			_ = closeBox(b)
			inFlight = nil
		}
		lastErr = err
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("ctx cancelled after %d attempts: %w", i+1, lastErr)
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("%d attempts: %w", attempts, lastErr)
}

// closeBox closes box, waiting at most cfg.BoxCloseTimeout for it to return.
// A Close still draining client connections keeps running in the background;
// by then the listening port is already released, so the peer can rebind it.
func (c *Client) closeBox(box boxService) error {
	done := make(chan error, 1)
	go func() { done <- box.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(c.cfg.BoxCloseTimeout):
		slog.Warn("peer sing-box close still draining client connections; continuing",
			"timeout", c.cfg.BoxCloseTimeout)
		return nil
	}
}

// stopSelf stops target from inside one of the client's own loops, then reports
// the reason to Config.OnSelfStop. It stops nothing, and reports nothing, if a
// Stop→Start or a re-registration has replaced target by then. Stop runs on a new goroutine
// because it waits for those loops to exit.
func (c *Client) stopSelf(target stopTarget, reason error) {
	go func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), peerCleanupTimeout)
		defer cancel()
		if stopped, _ := c.stopTarget(stopCtx, target); stopped {
			slog.Info("peer client stopped itself", "reason", reason)
			if c.cfg.OnSelfStop != nil {
				c.cfg.OnSelfStop(reason)
			}
		}
	}()
}

// ensurePeerOutboundsBypassVPN guarantees the peer sing-box's outbound dials
// bind to the physical interface rather than whatever the OS routing table
// picks. Without this, when the user's own Lantern VPN is up its TUN holds
// the default route and the peer's outbound traffic — i.e. the censored
// client's destination requests — would egress through Lantern's proxy
// network instead of the user's residential connection. That defeats the
// whole point of using the user's home IP as a circumvention exit.
//
// We splice the flag into whatever sing-box options the server supplied
// rather than relying on the server-side track config to set it, since the
// VPN-bypass requirement is a property of the *client's* environment, not
// the proxy track config.
func ensurePeerOutboundsBypassVPN(options string) (string, error) {
	ctx := box.Context(context.Background())
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(options))
	if err != nil {
		return "", fmt.Errorf("decode options: %w", err)
	}
	if opts.Route == nil {
		opts.Route = &option.RouteOptions{}
	}
	opts.Route.AutoDetectInterface = true
	out, err := json.MarshalContext(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("encode options: %w", err)
	}
	return string(out), nil
}

// pickManualForwarder resolves the manual port override against the
// two configured sources and returns a ManualForwarder, or nil if
// neither source supplies a valid port. The default NewForwarder
// factory in NewClient calls this first; nil means "fall through to
// UPnP discovery."
//
// Resolution order:
//
//  1. "peer_manual_port" setting (Advanced UI)
//  2. RADIANCE_PEER_EXTERNAL_PORT env var (developer / power-user)
//  3. nil — caller falls through to UPnP
//
// Persisted names are quoted so the comment stays accurate if Go
// identifiers move or rename.
//
// The setting is range-checked before casting to uint16 — a raw cast
// silently wraps negative values (-5 → 65531) and values above the
// port space (70000 → 4464), which would register a port the peer
// doesn't listen on (or, worse, one it does listen on for another
// service). Out-of-range / unparseable values are logged at Warn and
// the resolution falls through to the next source as if unset.
func pickManualForwarder() portForwarder { return chooseManualForwarder(slog.Default(), true) }

// chooseManualForwarder is pickManualForwarder logging to log; with logPort
// false its log lines carry neither the port nor a rejected value.
func chooseManualForwarder(log *slog.Logger, logPort bool) portForwarder {
	attr := func(key string, value any) []any {
		if !logPort {
			return nil
		}
		return []any{key, value}
	}
	if raw := settings.GetInt(settings.PeerManualPortKey); raw != 0 {
		if raw < 1 || raw > 65535 {
			log.Warn("ignoring out-of-range peer_manual_port setting; falling through to env / UPnP",
				attr("value", raw)...)
		} else {
			port := uint16(raw)
			log.Info("peer client using manual port forward",
				append(attr("port", port), "source", "setting")...)
			return portforward.NewManualForwarder(port)
		}
	}
	if raw := env.GetString(env.PeerExternalPort); raw != "" {
		port, err := portforward.ParseManualPort(raw)
		if err != nil {
			log.Warn("ignoring invalid "+env.PeerExternalPort.String(),
				append(attr("value", raw), attr("err", err)...)...)
		} else {
			log.Info("peer client using manual port forward",
				append(attr("port", port), "source", env.PeerExternalPort.String())...)
			return portforward.NewManualForwarder(port)
		}
	}
	return nil
}

func newDefaultForwarder(ctx context.Context, opts ...portforward.Option) (portForwarder, error) {
	return newForwarder(ctx, pickManualForwarder(), opts...)
}

// boundTo is the option that keeps a forwarder's sockets off the VPN tunnel,
// or none without a way to find the physical interface.
func boundTo(physical func() control.Func) []portforward.Option {
	if fn := currentPhysical(physical); fn != nil {
		return []portforward.Option{portforward.BoundTo(fn)}
	}
	return nil
}

// currentPhysical is a control that binds each socket through the control
// physical returns when the socket is made, or nil with no physical. A
// forwarder outlives the VPN state it was made under, renewing its mappings
// through a connect, restart or disconnect: one made with the VPN off must
// bind once it connects, and a control kept from an earlier tunnel reads
// that tunnel's closed interface monitor. With no tunnel running, a socket
// needs no binding.
func currentPhysical(physical func() control.Func) control.Func {
	if physical == nil {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		if fn := physical(); fn != nil {
			return fn(network, address, conn)
		}
		return nil
	}
}

// ManualPort is the manual port the peer and reverse clients bind, from the
// setting or the environment, or 0 if there is none. Both clients resolve it
// this way, so a caller deciding whether they would collide must too.
func ManualPort() uint16 {
	// Quietly: chooseManualForwarder logs its choice, which Start logs again.
	return reverseManualPort(discardLog)
}

var discardLog = slog.New(slog.DiscardHandler)

// reverseManualPort is the configured manual port, or 0, found without the
// port in the log.
func reverseManualPort(log *slog.Logger) uint16 {
	if m, ok := chooseManualForwarder(log, false).(*portforward.ManualForwarder); ok {
		return m.Port()
	}
	return 0
}

// discoverForwarder is portforward.NewForwarder, a var so tests can see the
// options it is given.
var discoverForwarder = portforward.NewForwarder

func newForwarder(ctx context.Context, manual portForwarder, opts ...portforward.Option) (portForwarder, error) {
	if manual != nil {
		return manual, nil
	}
	// Return an untyped nil on error: a typed-nil *Forwarder would pass the
	// caller's fwd != nil check and panic in UnmapPort.
	fwd, err := discoverForwarder(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return fwd, nil
}

func pickInternalPort() uint16 {
	return uint16(internalPortMin + rand.IntN(internalPortMax-internalPortMin))
}

// pickInternalPortExcept is pickInternalPort, never returning avoid.
func pickInternalPortExcept(avoid uint16) uint16 {
	if int(avoid) < internalPortMin || int(avoid) >= internalPortMax {
		return pickInternalPort()
	}
	return internalPortSkipping(rand.IntN(internalPortMax-internalPortMin-1), avoid)
}

// internalPortSkipping is the i-th port of the internal range without avoid,
// which must be in the range.
func internalPortSkipping(i int, avoid uint16) uint16 {
	if port := uint16(internalPortMin + i); port < avoid {
		return port
	}
	return uint16(internalPortMin + i + 1)
}

// servePool returns nil when this peer also serves the general pool, so the
// register request leaves serve_pool out and the server applies its default,
// and a pointer to false when it serves only helper pairings: the user limited
// it to them, or it runs only for them (Config.PairingsOnly). It is read at
// each registration, so a change takes effect at the next one: the next Start
// or the hourly credential rotation.
func (c *Client) servePool() *bool {
	if !c.pairingsOnly() && settings.PeerServesPool() {
		return nil
	}
	off := false
	return &off
}

// peerInboundTag is the tag lantern-cloud gives the peer's samizdat inbound.
const peerInboundTag = "samizdat-in"

// shortIDUpdater is lantern-box's samizdat inbound's runtime short-ID setter.
type shortIDUpdater interface {
	UpdateShortIDs(ids []string) error
}

// samizdatInbound finds b's samizdat inbound. A test double can implement
// shortIDUpdater itself; a real box is searched by tag.
func samizdatInbound(b boxService) (shortIDUpdater, bool) {
	if u, ok := b.(shortIDUpdater); ok {
		return u, true
	}
	sb, ok := b.(interface{ Inbound() adapter.InboundManager })
	if !ok {
		return nil, false
	}
	in, found := sb.Inbound().Get(peerInboundTag)
	if !found {
		return nil, false
	}
	u, ok := in.(shortIDUpdater)
	return u, ok
}

// inboundShortIDs returns the samizdat inbound's short IDs from a launch
// config, or nil if it has none or cannot be read.
func inboundShortIDs(options string) []string {
	opts, err := json.UnmarshalExtendedContext[option.Options](box.Context(context.Background()), []byte(options))
	if err != nil {
		return nil
	}
	for _, in := range opts.Inbounds {
		if in.Tag != peerInboundTag {
			continue
		}
		if o, ok := in.Options.(*lbO.SamizdatInboundOptions); ok {
			return o.ShortIDs
		}
	}
	return nil
}

// mergeShortIDs is base followed by the valid pairing IDs not already
// present, lowercased. An invalid ID is dropped rather than passed on,
// because lantern-box refuses a whole set over one bad entry.
func mergeShortIDs(base, pairing []string) []string {
	out := append([]string(nil), base...)
	seen := make(map[string]bool, len(base)+len(pairing))
	for _, id := range base {
		seen[strings.ToLower(id)] = true
	}
	for _, id := range pairing {
		id = strings.ToLower(id)
		if b, err := hex.DecodeString(id); err != nil || len(b) != 8 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// applyShortIDs sets b's inbound to accept base plus the pairing short IDs,
// and reports whether it did. Without a base ID it changes nothing:
// replacing the set would cut off lantern-cloud's verifier and every pool
// client. The IDs are credentials, so neither they nor their number are
// logged.
func (c *Client) applyShortIDs(b boxService, base, pairing []string) bool {
	if len(base) == 0 {
		if !c.warnedNoBaseShortIDs.Swap(true) {
			slog.Warn("peer: launch config has no samizdat short IDs; not applying pairing short IDs")
		}
		return false
	}
	u, ok := samizdatInbound(b)
	if !ok {
		if !c.warnedNoUpdater.Swap(true) {
			slog.Warn("peer: samizdat inbound cannot update short IDs; paired clients cannot connect")
		}
		return false
	}
	if err := u.UpdateShortIDs(mergeShortIDs(base, pairing)); err != nil {
		slog.Warn("peer: updating samizdat short IDs failed; keeping the previous set", "err", err)
		return false
	}
	slog.Debug("peer: samizdat short IDs updated")
	return true
}

// acceptsPairingRevision reports whether a known set at revision rev is newer
// than the one held, so that a response computed earlier but answered later
// (a heartbeat in flight across a rotation's register, say) never replaces
// it. The server sends known and the revision together, so a known set with
// revision 0 is never taken. Called with c.mu held.
func (c *Client) acceptsPairingRevision(rev int64) bool {
	return rev > c.pairingRevision
}

// applyPairingShortIDs offers a pairing set to the box serving now. With
// known true it is the server's set at revision rev: if newer than the one
// held, it is recorded, confirmed now, and pushed. Whether or not it was,
// if the box does not hold the record (its set, or the base ID only when
// none is known) because a push failed, it is pushed again; with known
// false that is all it does.
func (c *Client) applyPairingShortIDs(pairing []string, known bool, rev int64) {
	c.offerPairingShortIDs(pairing, nil, known, rev)
}

// offerPairingShortIDs is applyPairingShortIDs with the set's per-pairing
// groups, taken only when their IDs, joined in order, equal the set held at
// that revision. Groups are also taken at the revision already held, since a
// replica that predates groups answers that revision without them. A newer
// set without matching groups keeps the previous mapping.
func (c *Client) offerPairingShortIDs(pairing []string, groups []PairingShortIDSet, known bool, rev int64) {
	c.shortIDsMu.Lock()
	defer c.shortIDsMu.Unlock()
	c.mu.Lock()
	b, base := c.box, c.baseShortIDs
	if b == nil {
		c.mu.Unlock()
		return
	}
	if known && c.acceptsPairingRevision(rev) {
		c.pairingShortIDs = slices.Clone(pairing)
		c.pairingKnown = true
		c.pairingRevision = rev
		c.pairingConfirmedAt = c.cfg.Now()
		c.pairingApplied = false
		c.pendingGroups = nil
		if g, ok := groupPairingShortIDs(pairing, groups, base); ok {
			c.pendingGroups = &g
		}
	} else if known && c.pairingKnown && rev == c.pairingRevision {
		if g, ok := groupPairingShortIDs(c.pairingShortIDs, groups, base); ok {
			c.pendingGroups = &g
			if c.pairingApplied {
				c.commitPendingGroupsLocked()
			}
		}
	}
	if c.pairingApplied {
		c.mu.Unlock()
		return
	}
	// Base ID only when no set is known: a rotation's box may still hold
	// a set that expired before its swap.
	var record []string
	if c.pairingKnown {
		record = slices.Clone(c.pairingShortIDs)
	}
	// Staged before the push, so a stream the inbound accepts on a new ID
	// resolves its pairing at once.
	c.publishGroupsLocked(true)
	c.mu.Unlock()
	ok := c.applyShortIDs(b, base, record)
	c.mu.Lock()
	if c.box == b {
		if ok {
			c.pairingApplied = true
			c.commitPendingGroupsLocked()
		} else {
			c.publishGroupsLocked(false)
		}
	}
	c.mu.Unlock()
}

// commitPendingGroupsLocked makes pendingGroups the held groups, keeping
// the groups they replace, and publishes the map. Pending groups equal to the
// held ones replace nothing, so a repeated response keeps prevGroups. With
// none pending it only publishes. The box must already hold the recorded
// set, and c.mu must be held.
func (c *Client) commitPendingGroupsLocked() {
	if c.pendingGroups != nil {
		if !maps.Equal(*c.pendingGroups, c.heldGroups) {
			c.prevGroups, c.heldGroups = c.heldGroups, *c.pendingGroups
		}
		c.pendingGroups = nil
	}
	c.publishGroupsLocked(false)
}

// publishGroupsLocked sets the pairing map to the held and previous groups,
// and the pending ones too when staged is true. Called with c.mu held.
func (c *Client) publishGroupsLocked(staged bool) {
	sets := []map[[8]byte]string{c.prevGroups, c.heldGroups}
	if staged && c.pendingGroups != nil {
		sets = append(sets, *c.pendingGroups)
	}
	m := make(map[[8]byte]string)
	for _, set := range sets {
		maps.Copy(m, set)
	}
	c.setPairingByShortID(m)
}

// clearGroupsLocked forgets every group and empties the pairing map.
// Called with c.mu held.
func (c *Client) clearGroupsLocked() {
	c.heldGroups, c.prevGroups, c.pendingGroups = nil, nil, nil
	c.setPairingByShortID(nil)
}

// pairingMaxUnconfirmed is how long a pairing set is kept without the server
// vouching for it again. A pairing short ID is valid for epochs e-1..e+1 of
// 24 hours, so none in a set is still valid this long after it was issued.
// Without the bound, a server that keeps answering without a set (replicas
// without the ticket key, say) would keep an ended pairing working forever.
const pairingMaxUnconfirmed = 48 * time.Hour

// expireUnconfirmedPairing drops the pairing set, leaving the box with its
// base ID only, once the server has not vouched for it for
// pairingMaxUnconfirmed. A failed push keeps the record so the next heartbeat
// tries again.
func (c *Client) expireUnconfirmedPairing() {
	c.shortIDsMu.Lock()
	defer c.shortIDsMu.Unlock()
	c.mu.Lock()
	if !c.pairingKnown || c.cfg.Now().Sub(c.pairingConfirmedAt) < pairingMaxUnconfirmed {
		c.mu.Unlock()
		return
	}
	b, base := c.box, c.baseShortIDs
	c.mu.Unlock()
	if b == nil {
		return
	}
	// Without a base ID no pairing ID was ever pushed, so there is nothing
	// to take off the box.
	if len(base) > 0 && !c.applyShortIDs(b, base, nil) {
		return
	}
	c.mu.Lock()
	if c.box == b {
		c.pairingShortIDs = nil
		c.pairingKnown = false
		c.pairingApplied = true
		c.pairingConfirmedAt = time.Time{}
		c.clearGroupsLocked()
	}
	c.mu.Unlock()
	slog.Info("peer: pairing short IDs unconfirmed for too long; dropped")
}

// groupPairingShortIDs maps each short ID in groups to its pairing, and
// reports whether groups describe flat: their IDs, joined in order, equal
// flat's, ignoring case. A short ID in base is the launch config's own, which
// pool clients and the verifier use, so it never maps to a pairing.
func groupPairingShortIDs(flat []string, groups []PairingShortIDSet, base []string) (map[[8]byte]string, bool) {
	if len(groups) == 0 {
		return nil, false
	}
	var joined []string
	for _, g := range groups {
		for _, id := range g.ShortIDs {
			joined = append(joined, strings.ToLower(id))
		}
	}
	if len(joined) != len(flat) {
		return nil, false
	}
	for i, id := range flat {
		if strings.ToLower(id) != joined[i] {
			return nil, false
		}
	}
	isBase := make(map[string]bool, len(base))
	for _, id := range base {
		isBase[strings.ToLower(id)] = true
	}
	out := make(map[[8]byte]string, len(joined))
	for _, g := range groups {
		if g.PairingID == "" {
			continue
		}
		for _, id := range g.ShortIDs {
			id = strings.ToLower(id)
			raw, err := hex.DecodeString(id)
			if err != nil || len(raw) != 8 || isBase[id] {
				continue
			}
			out[[8]byte(raw)] = g.PairingID
		}
	}
	return out, true
}

type liveConn struct {
	shortID [8]byte
	pairing string
}

// setPairingByShortID replaces the short ID to pairing map; nil clears it.
// Open connections the new map attributes are then followed in the
// LiveTracker and labelled in the relay snapshot.
func (c *Client) setPairingByShortID(m map[[8]byte]string) {
	if len(m) == 0 {
		c.pairingByShortID.Store(nil)
		return
	}
	c.pairingByShortID.Store(&m)
	// After the store, so a connection the listener records without a
	// pairing either sees the new map itself or is here to be resolved.
	c.liveMu.Lock()
	defer c.liveMu.Unlock()
	for bytes, lc := range c.conns {
		if lc.pairing != "" {
			continue
		}
		pairing := m[lc.shortID]
		if pairing == "" {
			continue
		}
		c.conns[bytes] = liveConn{shortID: lc.shortID, pairing: pairing}
		c.relay.setPairing(bytes, pairing)
		c.live().Open(liveOwner, bytes, pairing, func() uint64 { return bytes.Down() + bytes.Up() })
	}
}

// pairingFor is the pairing a connection with short ID id came through, or ""
// if none.
func (c *Client) pairingFor(id [8]byte) string {
	if id == ([8]byte{}) {
		return ""
	}
	m := c.pairingByShortID.Load()
	if m == nil {
		return ""
	}
	return (*m)[id]
}

func (c *Client) live() *helper.LiveTracker {
	if c.cfg.Live != nil {
		return c.cfg.Live
	}
	return helper.DefaultLive
}

// beginLive starts a session's live tracking and returns its generation.
func (c *Client) beginLive() uint64 {
	c.liveMu.Lock()
	defer c.liveMu.Unlock()
	c.liveGen++
	clear(c.conns)
	return c.liveGen
}

// endLive ends the session's live tracking: every connection it opened is
// closed, and its late callbacks are ignored.
func (c *Client) endLive() {
	c.liveMu.Lock()
	defer c.liveMu.Unlock()
	c.liveGen++
	clear(c.conns)
	c.live().CloseOwner(liveOwner)
}

// trackPairing records a connection event in the relay snapshot and the
// LiveTracker and returns its pairing, "" for the pool or not yet known.
// Events from an ended session are not live-tracked.
func (c *Client) trackPairing(liveGen, relayGen uint64, state int, source string, shortID [8]byte, bytes *peerconn.Counter) string {
	c.liveMu.Lock()
	defer c.liveMu.Unlock()
	pairing := c.pairingFor(shortID)
	lc, open := c.conns[bytes]
	if state < 0 && open {
		pairing = lc.pairing
	}
	c.relay.recordPairingFor(relayGen, state, source, pairing, bytes)
	if bytes == nil || liveGen != c.liveGen {
		return pairing
	}
	switch {
	case state > 0:
		if c.conns == nil {
			c.conns = make(map[*peerconn.Counter]liveConn)
		}
		c.conns[bytes] = liveConn{shortID: shortID, pairing: pairing}
		if pairing != "" {
			c.live().Open(liveOwner, bytes, pairing, func() uint64 { return bytes.Down() + bytes.Up() })
		}
	case state < 0:
		delete(c.conns, bytes)
		c.live().Close(bytes)
	}
	return pairing
}

// defaultBuildBoxService builds the sing-box service for one peer box.
//
// A peer-proxy box needs no TUN / platform-VPN integration the way the main
// VPN tunnel does: the samizdat inbound is just an HTTPS server bound to a
// TCP port, which sing-box's default network stack handles.
func defaultBuildBoxService(ctx context.Context, options string) (boxService, error) {
	ctx = newPeerBoxContext(ctx)
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(options))
	if err != nil {
		return nil, fmt.Errorf("decode sing-box options: %w", err)
	}
	// The registry checks don't see route rule actions.
	if err := hostaccess.CheckOptions(opts); err != nil {
		return nil, fmt.Errorf("check sing-box options: %w", err)
	}
	bs, err := sbox.New(sbox.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		return nil, fmt.Errorf("build sing-box: %w", err)
	}
	return bs, nil
}

// newPeerBoxContext augments ctx with everything one peer box needs: the
// sing-box and lantern-box protocol registries plus this box's own sing-box
// log factory. The caller's cancellation is preserved, so a Stop-induced
// cancel still reaches the box. The registries refuse outbounds, endpoints,
// DNS servers, services and certificate providers that [hostaccess] denies.
//
// The registries are what let sing-box decode custom inbounds like the
// samizdat stanza from /peer/register; without them the decode fails with
// "missing inbound fields registry in context". Registering the log factory
// routes this box's router and dial errors to lantern.log instead of
// sing-box's stderr default. Both are scoped to the fresh registry
// hostaccess.Context installs, so the peer and the main tunnel coexist without
// stomping on each other.
func newPeerBoxContext(ctx context.Context) context.Context {
	return newBoxContextLoggingTo(ctx, slog.Default().Handler())
}

// newBoxContextLoggingTo is newPeerBoxContext with the box logging to h.
func newBoxContextLoggingTo(ctx context.Context, h slog.Handler) context.Context {
	ctx = hostaccess.Context(ctx)
	service.MustRegister[sblog.Factory](ctx, lblog.NewFactory(rlog.RedactConnectionInfo(h)))
	return ctx
}
