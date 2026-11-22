package vpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	runtimeDebug "runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/libbox"
	sblog "github.com/sagernet/sing-box/log"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	lsync "github.com/getlantern/common/sync"
	lbA "github.com/getlantern/lantern-box/adapter"
	"github.com/getlantern/lantern-box/adapter/groups"
	lbC "github.com/getlantern/lantern-box/constant"
	lblog "github.com/getlantern/lantern-box/log"
	"github.com/getlantern/lantern-box/tracker/clientcontext"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/internal/hostaccess"
	"github.com/getlantern/radiance/kindling"
	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn/memmon"
)

const defaultCloseTimeout = 10 * time.Second

// devicePauseTimeout bounds an iOS device pause; iOS may never deliver a wake
// event to the extension.
const devicePauseTimeout = time.Minute

type tunnel struct {
	ctx                  context.Context
	boxInstance          *sbox.Box
	clashModeManager     *clashModeManager
	connTracker          *connTracker
	selectionHistory     lbA.AutoSelectHistoryStorage
	selectionHistorySeed map[string]lbA.TagHistory
	logFactory           sblog.ObservableFactory

	// announcedAuto is the auto selection AutoSelectedChangeListener last emitted for this tunnel.
	// It is stored before the emit, so a reader woken by the event sees that selection or a newer one.
	announcedAuto atomic.Pointer[string]

	dataPath string

	// optsMap is a map of current outbound/endpoint options JSON, used to deduplicate when adding
	// outbounds/endpoints
	optsMap     *lsync.TypedMap[string, []byte]
	mutGrpMgr   *groups.MutableGroupManager
	outboundMgr adapter.OutboundManager
	// nonSelectableTags is the set of non-selectable outbound tags the tunnel manages
	// directly through outboundMgr, never joined to a selection group, so a later
	// reconcile can remove the ones a config drops. Guarded by outboundMu.
	nonSelectableTags map[string]struct{}

	injector *clientcontext.Injector

	initialLanternTags []string
	// initialNonSelectable is the config's non-selectable tags at connect. It seeds
	// nonSelectableTags so an outbound dropped before the first reconcile is still
	// torn down rather than left dialable.
	initialNonSelectable []string
	initialMode          string

	// memoryMonitor starts during tunnel init in visibility-only mode.
	// On iOS, its executor is installed later, after the connection tracker exists.
	memoryMonitor *memmon.Monitor

	// connObserver, if non-nil, is attached to connTracker at connect to receive
	// connection-close pushes for telemetry.
	connObserver ConnObserver

	// inviterTickets, if non-nil, supplies the Unbounded consumer's helper
	// inviter tickets.
	inviterTickets InviterTickets
	// personalProxy is the friend tag the rooms consumer's tickets are
	// narrowed to, while the personal proxy group exists. Written under
	// outboundMu; read lock-free on the signaling path.
	personalProxy atomic.Pointer[string]
	// personalProxyFault, if set, can fail a personal proxy group step by
	// name. For tests.
	personalProxyFault func(step string) error
	// portalMasquerade is the masquerade domain the reverse portal inbound,
	// if any, was created with. Guarded by outboundMu.
	portalMasquerade string

	// outboundMu serializes the outbound mutators.
	outboundMu sync.Mutex
	// replacedHelpers holds the helper tags whose outbound addOutboundsLocked
	// replaced under the same tag since the last syncPersonalProxiesLocked,
	// which swaps them into the personal proxies group. Guarded by outboundMu.
	replacedHelpers map[string]struct{}

	// closeTimeout bounds how long close() waits for closers to finish; a zero
	// value uses defaultCloseTimeout.
	closeTimeout time.Duration

	cancel  context.CancelFunc
	closers []io.Closer

	// netRecovery re-seeds network state while the pause manager reports the
	// network paused. Nil when no pause manager is present.
	netRecovery *netRecovery

	// pauseManager, if non-nil, is retained so the device-lifecycle hooks can
	// pause and wake the tunnel.
	pauseManager pause.Manager
	// endPauseTimer force-wakes an iOS device pause; see devicePause. Guarded by pauseMu.
	endPauseTimer *time.Timer
	pauseMu       sync.Mutex

	// staleSource is the stale source restart state the client's tunnels
	// share, and restartForStaleSource starts a restart of this tunnel for
	// one; nil when the client has no restart path.
	staleSource           *staleSourceGuard
	restartForStaleSource func(failed func(started bool))
	// staleSourceUpdate starts the stale source check schedule over; nil
	// without a checker. Set before the tunnel is published.
	staleSourceUpdate func()
}

func (t *tunnel) start(ctx context.Context, options O.Options, platformIfce libbox.PlatformInterface, isRestart bool) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "tunnel.start",
		trace.WithAttributes(
			attribute.String("platform", common.Platform),
			attribute.Bool("is_restart", isRestart),
		))
	defer span.End()

	if err := t.init(ctx, options, platformIfce); err != nil {
		t.close()
		slog.Error("Failed to initialize tunnel", "error", err)
		return fmt.Errorf("initializing tunnel: %w", err)
	}

	if err := t.connect(ctx); err != nil {
		t.close()
		slog.Error("Failed to connect tunnel", "error", err)
		return fmt.Errorf("connecting tunnel: %w", err)
	}
	t.optsMap = makeOutboundOptsMap(t.ctx, options)
	t.nonSelectableTags = makeNonSelectableTagSet(t.initialNonSelectable, options)
	return nil
}

// traceSpan wraps fn in a child span of the caller's context and records any
// error on the child span so failures show up per-phase in the trace.
func traceSpan(ctx context.Context, name string, fn func() error) error {
	_, span := otel.Tracer(tracerName).Start(ctx, name)
	defer span.End()
	err := fn()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	return err
}

var lineBreakEscaper = strings.NewReplacer("\r", `\r`, "\n", `\n`)

func recoverToError(err *error, operation string) {
	if r := recover(); r != nil {
		common.WriteRecoveredPanic(operation, r)
		//logleak:ok recovered panic value
		*err = fmt.Errorf("panic %s: %s", operation, lineBreakEscaper.Replace(fmt.Sprint(r)))
	}
}

func (t *tunnel) init(ctx context.Context, options O.Options, platformIfce libbox.PlatformInterface) (err error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "tunnel.init")
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	// Must run before sbox.New, which acquires the cache flock.
	if err := consumeCacheClearMarker(t.dataPath); err != nil {
		slog.Warn("Failed to apply deferred tunnel cache clear", "path", t.dataPath, "error", err)
	}

	slog.Log(nil, rlog.LevelTrace, "Initializing tunnel")

	t.ctx, t.cancel = context.WithCancel(context.Background())
	if common.IsMobile() {
		var monitorCloser io.Closer
		t.memoryMonitor, monitorCloser = startMemoryMonitor(t.ctx)
		t.closers = append(t.closers, monitorCloser)

		if common.IsIOS() {
			// Pin GOMEMLIMIT before the allocation-heavy libbox bring-up so GC
			// gets its turn during it. Only iOS needs this: it silently kills the
			// extension past a hard cap; Android applies no such restriction.
			setMobileMemoryLimits()
		}
	}
	if common.IsAndroid() {
		libbox.Setup(&libbox.SetupOptions{FixAndroidStack: true})
	}

	boxCtx := hostaccess.ContextWithDNSTransport(t.ctx, platformIfce)
	if platformIfce != nil {
		boxCtx = service.ContextWith[adapter.PlatformInterface](boxCtx, libbox.NewPlatformInterfaceWrapper(platformIfce))
	}

	// Unbounded signaling must dial freddie outside the VPN tunnel or it
	// recursively re-enters itself. streamingRoundTripper forces kindling to
	// skip AMP (non-streamable) so freddie's long-poll genesis stream works.
	boxCtx = lbA.ContextWithDirectTransport(boxCtx, streamingRoundTripper{inner: kindling.HTTPClient().Transport})
	if !slices.ContainsFunc(options.Outbounds, func(o O.Outbound) bool { return o.Tag == PersonalProxyTag }) {
		t.personalProxy.Store(nil)
	}
	// An Unbounded consumer joins its helper pairings' rooms on freddie with
	// the inviter tickets lantern-cloud issues this device. lantern-box gives
	// the source only to helper-tagged Unbounded outbounds, which read it at
	// every subscribe; the source fetches on first use and renews in the
	// background, outside the tunnel like the signaling itself.
	boxCtx = withHelperRoomTickets(boxCtx, t)
	t.prefetchInviterTickets(options.Outbounds)

	t.ctx = boxCtx
	t.logFactory = lblog.NewFactory(rlog.RedactConnectionInfo(slog.Default().Handler()))
	service.MustRegister[sblog.Factory](t.ctx, t.logFactory)

	t.selectionHistory = lbA.NewAutoSelectHistoryStorage()
	for tag, h := range t.selectionHistorySeed {
		entry := h
		t.selectionHistory.Store(tag, &entry)
	}
	service.MustRegister[lbA.AutoSelectHistoryStorage](t.ctx, t.selectionHistory)
	t.closers = append(t.closers, t.selectionHistory)

	// Must install before sbox.New, which creates the outbounds.
	// Non-selectable outbounds are infrastructure, never user traffic, so they
	// never send client info.
	tags := filterNonSelectableTags(t.initialLanternTags, t.initialNonSelectable)
	t.injector = newClientInfoInjector(tags)
	if err := t.injector.Install(t.ctx); err != nil {
		return fmt.Errorf("install client info injector: %w", err)
	}

	slog.Log(nil, rlog.LevelTrace, "Creating box instance")
	var instance *sbox.Box
	if err := traceSpan(ctx, "sbox.New", func() (err error) {
		defer recoverToError(&err, "creating box instance")
		instance, err = sbox.New(sbox.Options{
			Context: t.ctx,
			Options: options,
		})
		return err
	}); err != nil {
		return fmt.Errorf("create box instance: %w", err)
	}
	cacheFile := service.FromContext[adapter.CacheFile](t.ctx)
	service.MustRegister[adapter.CacheFile](t.ctx, &cacheFileWrapper{CacheFile: cacheFile})

	t.closers = append(t.closers, instance)
	t.boxInstance = instance

	t.clashModeManager, err = newClashModeManager(t.ctx, t.logFactory.NewLogger("clash-mode"), t.initialMode)
	if err != nil {
		return fmt.Errorf("create clash mode manager: %w", err)
	}
	t.connTracker = startConnTracker(t.ctx, instance.Outbound())
	instance.Router().AppendTracker(t.connTracker)
	t.closers = append(t.closers, t.connTracker)

	slog.Info("Tunnel initialized")
	return nil
}

// Memory tuning for mobile devices, which have more constrained resources. iOS will silently
// kill the extension if it exceeds a hard cap (≈50 MB).
const (
	// mobileGCPercent is the soft cap for triggering the GC.
	mobileGCPercent = 50
	// mobileMemoryLimit is the GOMEMLIMIT soft cap. This needs to be below the iOS hard cap
	// to leave room for the non-Go side (Swift, cgo, etc.).
	mobileMemoryLimit = 40 * 1024 * 1024 // 40 MB
)

func setMobileMemoryLimits() {
	slog.Debug("Setting memory limits for mobile platform", "platform", common.Platform,
		"gc_percent", mobileGCPercent, "go_mem_limit", mobileMemoryLimit,
	)
	runtimeDebug.SetGCPercent(mobileGCPercent)
	runtimeDebug.SetMemoryLimit(mobileMemoryLimit)
}

func newClientInfoInjector(lanternTags []string) *clientcontext.Injector {
	lanternTags = slices.DeleteFunc(slices.Clone(lanternTags), isHelperOutboundTag)
	return clientcontext.NewInjector(func() clientcontext.ClientInfo {
		return clientcontext.ClientInfo{
			DeviceID:    settings.GetString(settings.DeviceIDKey),
			Platform:    common.Platform,
			IsPro:       settings.IsPro(),
			CountryCode: settings.GetString(settings.CountryCodeKey),
			Version:     common.GetVersion(),
		}
	}, lanternTags...)
}

// isHelperOutboundTag reports whether tag is a personal proxy's outbound, direct
// or reverse. It reaches a friend's peer box, not a Lantern server: the box
// doesn't strip client info, so a frame sent ahead of the stream reaches the
// destination and corrupts it (a TLS server answers "protocol version not
// supported").
func isHelperOutboundTag(tag string) bool {
	return lbA.IsHelperTag(tag) || lbA.IsReverseHelperTag(tag)
}

// updateInjectionLocked enables client info injection only for selectable
// Lantern outbounds that load successfully, and never for a personal proxy's
// (isHelperOutboundTag), though its servers come in the same config.
//
// The caller must hold t.outboundMu.
func (t *tunnel) updateInjectionLocked(tag string, lantern, loaded bool) {
	if t.injector == nil {
		return
	}
	_, nonSelectable := t.nonSelectableTags[tag]
	switch {
	case !lantern || nonSelectable || isHelperOutboundTag(tag):
		t.injector.RemoveOutboundTags(tag)
	case loaded:
		// Failed loads leave the tag unchanged.
		t.injector.AddOutboundTags(tag)
	}
}

func filterNonSelectableTags(tags, nonSelectable []string) []string {
	if len(nonSelectable) == 0 {
		return tags
	}
	var filtered []string
	for _, tag := range tags {
		if !slices.Contains(nonSelectable, tag) {
			filtered = append(filtered, tag)
		}
	}
	return filtered
}

func newMutableGroupManager(
	ctx context.Context,
	logger sblog.ContextLogger,
	connMgr groups.ConnectionManager,
) (*groups.MutableGroupManager, error) {
	oMgr := service.FromContext[adapter.OutboundManager](ctx)
	epMgr := service.FromContext[adapter.EndpointManager](ctx)
	if oMgr == nil || epMgr == nil {
		return nil, fmt.Errorf("outbound or endpoint manager not found in context")
	}

	var mutGroups []lbA.MutableOutboundGroup
	for _, out := range oMgr.Outbounds() {
		// The personal proxy groups stay out: the manager's map is fixed at
		// construction, and the tunnel removes and recreates them.
		if g, isMutGroup := out.(lbA.MutableOutboundGroup); isMutGroup &&
			g.Tag() != PersonalProxiesTag && g.Tag() != PersonalProxyTag {
			mutGroups = append(mutGroups, g)
		}
	}
	return groups.NewMutableGroupManager(logger, oMgr, epMgr, connMgr, mutGroups), nil
}

func (t *tunnel) connect(ctx context.Context) (err error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "tunnel.connect")
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	slog.Log(nil, rlog.LevelTrace, "Starting libbox service")

	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic starting libbox service", "panic", r)
			//logleak:ok recovered panic value
			err = fmt.Errorf("panic starting libbox service: %v", r)
		}
	}()
	if err := traceSpan(ctx, "libbox.BoxService.Start", func() error {
		return t.boxInstance.Start()
	}); err != nil {
		slog.Error("Failed to start libbox service", "error", err)
		return fmt.Errorf("starting libbox service: %w", err)
	}
	slog.Debug("Libbox service started")
	bypass.ProxyStateChanged()

	t.outboundMgr = service.FromContext[adapter.OutboundManager](t.ctx)
	t.connTracker.SetObserver(t.connObserver)
	dnsRouter := service.FromContext[adapter.DNSRouter](t.ctx)
	if unregister := resetOnSplitTunnelReload(t.boxInstance.Router(), dnsRouter, t.connTracker); unregister != nil {
		t.closers = append([]io.Closer{unregister}, t.closers...)
	}
	if pm := service.FromContext[pause.Manager](t.ctx); pm != nil {
		t.pauseManager = pm
		t.netRecovery = newNetRecovery(t.boxInstance.Network(), pm.IsNetworkPaused)
		go t.netRecovery.run(t.ctx)
		slog.Debug("Network recovery supervisor started")
		events.SubscribeContext(t.ctx, func(evt NetworkEvent) {
			switch evt.EventType {
			case NetworkEventPaused:
				t.netRecovery.pause()
			case NetworkEventWake:
				t.netRecovery.wake()
			}
		})

		cb := pm.RegisterCallback(t.onPauseUpdate)
		// A network pause can already be in effect before this registration, so
		// seed it once. Only the paused case is emitted: not emitting a wake keeps
		// this off-lock read from racing a real pause into the wrong final state.
		if pm.IsNetworkPaused() {
			events.Emit(NetworkEvent{EventType: NetworkEventPaused})
		}
		t.closers = append(t.closers, closerFunc(func() error {
			pm.UnregisterCallback(cb)
			// No further events arrive after unregister, so force a wake to release
			// a NetworkEvent consumer left paused at teardown. UnregisterCallback
			// serializes with in-flight callbacks via the manager lock, so this
			// wake lands last.
			events.Emit(NetworkEvent{EventType: NetworkEventWake})
			return nil
		}))
	}

	if checker := t.startStaleSourceChecker(); checker != nil {
		// Prepend: it resets the box's network, so it stops before the box closes.
		t.closers = append([]io.Closer{checker}, t.closers...)
	}

	if common.IsIOS() {
		// Only iOS enforces a hard memory cap, so only it gets reclaim and
		// admission control. Android runs the monitor for visibility only.
		initExecutor(t.memoryMonitor, t.connTracker, t.clashModeManager)
	}

	var mutGrpMgr *groups.MutableGroupManager
	if err := traceSpan(ctx, "newMutableGroupManager", func() error {
		var err error
		mutGrpMgr, err = newMutableGroupManager(
			t.ctx, t.logFactory.NewLogger("groupsManager"), t.connTracker,
		)
		return err
	}); err != nil {
		return fmt.Errorf("creating mutable group manager: %w", err)
	}
	t.mutGrpMgr = mutGrpMgr
	// Prepend: mgm's removalQueue reads from libbox-managed state, so close it first.
	t.closers = append([]io.Closer{
		closerFunc(func() error { mutGrpMgr.Close(); return nil }),
	}, t.closers...)

	t.subscribeExhaustionSignal()

	slog.Info("Tunnel connection established")
	return nil
}

// resetOnSplitTunnelReload clears the DNS cache and closes every tracked
// connection each time the split-tunnel rule set reloads, since DNS rules can
// match the rule set and a connection keeps the route it matched when it
// opened. It returns nil when the router has no split-tunnel rule set;
// otherwise closing the result unregisters the callback, and once Close returns,
// no reset is running or will run.
func resetOnSplitTunnelReload(router adapter.Router, dnsRouter adapter.DNSRouter, tracker *connTracker) io.Closer {
	ruleSet, ok := router.RuleSet(splitTunnelTag)
	if !ok {
		return nil
	}
	var (
		mu     sync.Mutex
		closed bool
	)
	cb := ruleSet.RegisterCallback(func(adapter.RuleSet) {
		mu.Lock()
		defer mu.Unlock()
		// A reload invokes a snapshot of its callbacks, so this can run after unregistering.
		if closed {
			return
		}
		slog.Info("Split-tunnel rules reloaded; clearing DNS cache and closing connections",
			"connections", tracker.activeConnectionCount())
		// Cleared first, so reconnecting flows don't resolve from the old cache.
		dnsRouter.ClearCache()
		tracker.closeAllTracked()
	})
	return closerFunc(func() error {
		ruleSet.UnregisterCallback(cb)
		mu.Lock()
		closed = true
		mu.Unlock()
		return nil
	})
}

// onPauseUpdate mirrors the pause manager's network-axis transitions onto
// NetworkEvent. Device-axis events are ignored: only a missing default route
// (NetworkPause) leaves the tunnel unable to dial, and on resume the box already
// resets the network itself.
func (t *tunnel) onPauseUpdate(evt int) {
	switch evt {
	case pause.EventNetworkPause:
		events.Emit(NetworkEvent{EventType: NetworkEventPaused})
	case pause.EventNetworkWake:
		events.Emit(NetworkEvent{EventType: NetworkEventWake})
	}
}

// subscribeExhaustionSignal bridges the auto group's exhaustion
// channel onto ExhaustionEvent so subscribers can react without the
// tunnel knowing about them.
func (t *tunnel) subscribeExhaustionSignal() {
	g, ok := t.mutGrpMgr.OutboundGroup(AutoSelectTag)
	if !ok {
		slog.Warn("auto group not found; exhaustion events disabled",
			"tag", AutoSelectTag)
		return
	}
	signaler, ok := g.(lbA.ExhaustionSignaler)
	if !ok {
		slog.Warn("auto group does not implement ExhaustionSignaler; exhaustion events disabled",
			"tag", AutoSelectTag)
		return
	}
	go t.emitExhaustionEvents(signaler.ExhaustionSignal())
}

func (t *tunnel) emitExhaustionEvents(ch <-chan struct{}) {
	for {
		select {
		case <-t.ctx.Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			events.Emit(ExhaustionEvent{})
		}
	}
}

func (t *tunnel) selectMode(mode string) error {
	if t.boxInstance == nil {
		return fmt.Errorf("tunnel not running")
	}

	prev, err := t.clashModeManager.SetMode(mode)
	if err != nil {
		return fmt.Errorf("switching mode: %w", err)
	}
	if prev != mode {
		// Flows matched to the outgoing mode keep its server until closed.
		// Auto mode routes to the proxyless hedge when it's built.
		t.connTracker.closeMatchedTo(prev)
		if prev == AutoSelectTag {
			t.connTracker.closeMatchedTo(ProxylessHedgeTag)
		}
		go func() {
			time.Sleep(time.Second)
			runtimeDebug.FreeOSMemory()
		}()
	}
	return nil
}

// ErrPersonalProxiesUnavailable is returned for a selection of
// PersonalProxiesTag while the device has no helper outbound.
var ErrPersonalProxiesUnavailable = errors.New("personal proxies unavailable")

func (t *tunnel) selectOutbound(tag string) error {
	// Held to the selection, so the personal proxies group cannot be removed
	// between its check and its selection, and a swap of a replaced outbound
	// in the manual selector, which restores its selection, cannot interleave.
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if friend, ok := ParsePersonalProxySelection(tag); ok {
		return t.selectPersonalProxyLocked(friend)
	}
	if tag == PersonalProxyTag {
		return ErrPersonalProxyUnavailable
	}
	// Checked before the mode switch, so a refused selection changes nothing.
	if tag == PersonalProxiesTag && !t.offersPersonalProxies() {
		return ErrPersonalProxiesUnavailable
	}
	if err := t.selectMode(ManualSelectTag); err != nil {
		return err
	}

	outboundMgr := service.FromContext[adapter.OutboundManager](t.ctx)
	outbound, loaded := outboundMgr.Outbound(ManualSelectTag)
	if !loaded {
		return fmt.Errorf("manual select group not found")
	}
	if !outbound.(Selector).SelectOutbound(tag) && tag == PersonalProxiesTag {
		return ErrPersonalProxiesUnavailable
	}
	return t.deselectPersonalProxyLocked()
}

// selectAuto switches the tunnel to auto-select, withdrawing a selected
// friend's group.
func (t *tunnel) selectAuto() error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if err := t.selectMode(AutoSelectTag); err != nil {
		return err
	}
	return t.deselectPersonalProxyLocked()
}

// offersPersonalProxies reports whether the manual selector offers the
// personal proxies group, which it does exactly while the group exists.
func (t *tunnel) offersPersonalProxies() bool {
	if t.mutGrpMgr == nil {
		return false
	}
	selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	return ok && slices.Contains(selector.All(), PersonalProxiesTag)
}

// personalProxiesGroup returns the personal proxies group, or nil while it
// does not exist.
func (t *tunnel) personalProxiesGroup() lbA.MutableOutboundGroup {
	if t.outboundMgr == nil {
		return nil
	}
	out, ok := t.outboundMgr.Outbound(PersonalProxiesTag)
	if !ok {
		return nil
	}
	g, _ := out.(lbA.MutableOutboundGroup)
	return g
}

// liveOutbound returns the outbound manager's outbound for tag, or nil.
func (t *tunnel) liveOutbound(tag string) adapter.Outbound {
	if t.outboundMgr == nil {
		return nil
	}
	out, _ := t.outboundMgr.Outbound(tag)
	return out
}

// swapIntoSelectionGroupsLocked points the manual selector and the auto
// group at the outbound now under tag, after it replaced the one they hold.
// The manual selector swaps it in place, keeping its selection and never
// dropping the tag. The auto group cannot replace a member, so the tag is
// removed and added again, directly on the group: through the group manager
// the removal would queue the new outbound for teardown. A sole auto member
// leaves the group empty in between, which it tolerates once started (it
// looks up its pause manager when it needs it). The caller must hold
// t.outboundMu.
func (t *tunnel) swapIntoSelectionGroupsLocked(tag string) error {
	if selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag); ok && slices.Contains(selector.All(), tag) {
		if err := t.mutGrpMgr.ReplaceInGroup(ManualSelectTag, tag); err != nil {
			return fmt.Errorf("swap %s in %s: %w", tag, ManualSelectTag, err)
		}
	}
	auto, ok := t.mutGrpMgr.OutboundGroup(AutoSelectTag)
	if !ok {
		return fmt.Errorf("group %s not found", AutoSelectTag)
	}
	if !slices.Contains(auto.All(), tag) {
		return t.mutGrpMgr.AddToGroup(AutoSelectTag, tag)
	}
	if _, err := auto.Remove(tag); err != nil {
		return fmt.Errorf("swap %s in %s: %w", tag, AutoSelectTag, err)
	}
	if n, err := auto.Add(tag); err != nil || n == 0 {
		if err == nil {
			err = errors.New("not added")
		}
		return fmt.Errorf("swap %s in %s: %w", tag, AutoSelectTag, err)
	}
	return nil
}

// syncPersonalProxiesLocked brings the personal proxies group and then the
// selected friend's group in line with the helper outbounds the tunnel now
// holds. The caller must hold t.outboundMu.
func (t *tunnel) syncPersonalProxiesLocked() error {
	replaced := t.replacedHelpers
	t.replacedHelpers = nil
	// The personal proxies group first: a friend's group that lost its last
	// member falls back to it.
	err := t.syncPersonalProxiesGroupLocked(replaced)
	return errors.Join(err, t.syncPersonalProxyLocked(replaced))
}

// syncPersonalProxiesGroupLocked makes the personal proxies group hold exactly
// the helper outbounds the manual selector offers, as the outbound manager now
// holds them, pointing those in replaced at their new outbounds. It creates the
// group with its first member and removes it with its last (a url-test group
// must never be empty), and keeps the selector offering it exactly while it
// exists. The caller must hold t.outboundMu.
func (t *tunnel) syncPersonalProxiesGroupLocked(replaced map[string]struct{}) error {
	if t.mutGrpMgr == nil || t.outboundMgr == nil {
		return nil
	}
	selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	if !ok {
		return errors.New("manual select group not found")
	}
	helpers := helperTags(selector.All())
	group := t.personalProxiesGroup()
	switch {
	case len(helpers) == 0 && group == nil:
		return nil
	case len(helpers) == 0:
		return t.withdrawPersonalProxiesLocked(selector)
	case group == nil:
		if err := t.createPersonalProxiesLocked(helpers); err != nil {
			return err
		}
	default:
		// Added before the stale members go, so the group is never empty.
		if _, err := group.Add(helpers...); err != nil {
			return fmt.Errorf("update personal proxies group: %w", err)
		}
		var stale, swap []string
		for _, tag := range group.All() {
			if !slices.Contains(helpers, tag) {
				stale = append(stale, tag)
			} else if _, ok := replaced[tag]; ok {
				swap = append(swap, tag)
			}
		}
		if len(stale) > 0 {
			if _, err := group.Remove(stale...); err != nil {
				return fmt.Errorf("update personal proxies group: %w", err)
			}
		}
		if err := swapPersonalProxiesLocked(group, swap); err != nil {
			return err
		}
	}
	if !slices.Contains(selector.All(), PersonalProxiesTag) {
		if _, err := selector.Add(PersonalProxiesTag); err != nil {
			return fmt.Errorf("offer personal proxies group: %w", err)
		}
	}
	return nil
}

// swapPersonalProxiesLocked points the group's members in swap at their
// replacement outbounds in place: the group never drops or empties, and the
// manual selector's choice of it never moves. The group is kept out of the
// group manager, so it is replaced on directly. The caller must hold
// t.outboundMu.
func swapPersonalProxiesLocked(group lbA.MutableOutboundGroup, swap []string) error {
	if len(swap) == 0 {
		return nil
	}
	replacer, ok := group.(lbA.MemberReplacer)
	if !ok {
		return errors.New("update personal proxies group: group cannot replace members")
	}
	if _, err := replacer.Replace(swap...); err != nil {
		return fmt.Errorf("update personal proxies group: %w", err)
	}
	return nil
}

// withdrawPersonalProxiesLocked removes the group from the selector and then
// from the outbound manager, so the selector never holds a closed group. The
// caller must hold t.outboundMu.
func (t *tunnel) withdrawPersonalProxiesLocked(selector lbA.MutableOutboundGroup) error {
	var errs []error
	// The selector falls back to an arbitrary member when its selection goes,
	// so a selected group first hands traffic to auto-select, which the
	// backend then persists.
	if selector.Now() == PersonalProxiesTag && t.boxInstance != nil {
		if err := t.selectMode(AutoSelectTag); err != nil {
			errs = append(errs, err)
		}
	}
	if _, err := selector.Remove(PersonalProxiesTag); err != nil {
		errs = append(errs, err)
	}
	if err := t.outboundMgr.Remove(PersonalProxiesTag); err != nil {
		errs = append(errs, fmt.Errorf("remove personal proxies group: %w", err))
	}
	return errors.Join(errs...)
}

// createPersonalProxiesLocked creates the group over helpers, which must not
// be empty. The caller must hold t.outboundMu.
func (t *tunnel) createPersonalProxiesLocked(helpers []string) error {
	out := personalProxiesOutbound(helpers)
	router := service.FromContext[adapter.Router](t.ctx)
	logger := t.logFactory.NewLogger("outbound/" + out.Tag + "[" + out.Type + "]")
	if err := t.outboundMgr.Create(t.ctx, router, logger, out.Tag, out.Type, out.Options); err != nil {
		return fmt.Errorf("create personal proxies group: %w", err)
	}
	return nil
}

func (t *tunnel) close() error {
	if t.cancel != nil {
		t.cancel()
	}
	t.pauseMu.Lock()
	if t.endPauseTimer != nil {
		t.endPauseTimer.Stop()
	}
	t.pauseMu.Unlock()

	closers := t.closers
	recovery := t.netRecovery
	t.closers = nil
	t.boxInstance = nil

	done := make(chan error, 1)
	go func() {
		if recovery != nil {
			recovery.stop()
		}
		var errs []error
		for _, closer := range closers {
			slog.Log(nil, rlog.LevelTrace, "Closing tunnel resource", "type", fmt.Sprintf("%T", closer))
			errs = append(errs, closer.Close())
		}
		err := errors.Join(errs...)
		bypass.ProxyStateChanged()
		done <- err
		slog.Log(nil, rlog.LevelTrace, "Tunnel closers finished", "error", err)
	}()

	timeout := t.closeTimeout
	if timeout == 0 {
		timeout = defaultCloseTimeout
	}
	select {
	case <-time.After(timeout):
		slog.Warn("Timed out waiting for tunnel to close; closers still running")
		return errors.New("timeout waiting for tunnel to close")
	case err := <-done:
		return err
	}
}

// devicePause pauses the tunnel for a device sleep. On iOS it also arms a timer to
// wake after devicePauseTimeout.
func (t *tunnel) devicePause() {
	if t.pauseManager == nil {
		return
	}
	t.pauseManager.DevicePause()
	if common.IsIOS() {
		t.pauseMu.Lock()
		if t.endPauseTimer == nil {
			t.endPauseTimer = time.AfterFunc(devicePauseTimeout, t.pauseManager.DeviceWake)
		} else {
			t.endPauseTimer.Reset(devicePauseTimeout)
		}
		t.pauseMu.Unlock()
	}
}

// deviceWake wakes the tunnel after a device sleep. On iOS the wake is driven by
// devicePause's timer, so this is a no-op there.
func (t *tunnel) deviceWake() {
	if t.pauseManager == nil {
		return
	}
	if !common.IsIOS() {
		t.pauseManager.DeviceWake()
	}
}

func (t *tunnel) resetNetwork() {
	if t.boxInstance != nil {
		t.boxInstance.Network().ResetNetwork(t.ctx)
	}
}

var errLibboxClosed = errors.New("libbox closed")

func (t *tunnel) addOutbounds(list servers.ServerList) error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	err := t.addOutboundsLocked(list)
	if errors.Is(err, errLibboxClosed) {
		return err
	}
	return errors.Join(err, t.syncPersonalProxiesLocked())
}

// addOutboundsLocked adds the servers in list to the tunnel. The caller must
// hold t.outboundMu.
func (t *tunnel) addOutboundsLocked(list servers.ServerList) error {
	return t.loadOutboundsLocked(list, true)
}

// applyProbeTimeoutsLocked sets the probe timeouts of list's auto-select
// options on the auto group. A list without options leaves them alone. The
// caller must hold t.outboundMu.
func (t *tunnel) applyProbeTimeoutsLocked(list servers.ServerList) {
	if list.AutoSelectOptions == nil {
		return
	}
	if err := t.mutGrpMgr.SetProbeTimeouts(AutoSelectTag, list.AutoSelectOptions.ProbeTimeoutsMs); err != nil {
		slog.Warn("Failed to set probe timeouts", "error", err)
	}
}

// loadOutboundsLocked adds the servers in list to the tunnel, or swaps in
// those whose options changed, and with applyOverrides sets list's bandit URL
// overrides on the auto group. The caller must hold t.outboundMu.
func (t *tunnel) loadOutboundsLocked(list servers.ServerList, applyOverrides bool) error {
	list = allowedServers(list)
	// Before any member joins the auto-select group: adding one probes it at
	// once, with whatever timeouts the group has then.
	if applyOverrides {
		t.applyProbeTimeoutsLocked(list)
	}
	outbounds := list.Outbounds()
	endpoints := list.Endpoints()
	if len(outbounds) == 0 && len(endpoints) == 0 {
		slog.Debug("No outbounds or endpoints to add")
		return nil
	}

	slog.Info("Adding servers", "tags", loggableTags(list.Tags()))
	// remove duplicates from list before adding to avoid unnecessary reloads
	newList := removeDuplicates(t.ctx, t.optsMap, list)
	newOutbounds := newList.Outbounds()
	newEndpoints := newList.Endpoints()

	ctx := t.ctx
	router := service.FromContext[adapter.Router](ctx)

	isLantern := make(map[string]bool, len(newList.Servers))
	for _, srv := range newList.Servers {
		isLantern[srv.Tag] = srv.IsLantern
	}

	t.prefetchInviterTickets(newOutbounds)

	var errs []error
	var (
		mutGrpMgr = t.mutGrpMgr
		added     = 0
	)
	for _, outbound := range newOutbounds {
		logger := t.logFactory.NewLogger("outbound/" + loggableTag(outbound.Tag) + "[" + outbound.Type + "]")
		prev := t.liveOutbound(outbound.Tag)
		err := mutGrpMgr.CreateOutboundForGroup(
			ctx, router, logger, ManualSelectTag, outbound.Tag, outbound.Type, outbound.Options,
		)
		// An outbound with new options replaces the one under its tag. The
		// selection groups skip a tag they already hold, so the manual
		// selector refused it; it is swapped into both groups below.
		// A failed create leaves no new outbound, even if a queued removal
		// took the old one meanwhile.
		cur := t.liveOutbound(outbound.Tag)
		replaced := prev != nil && cur != nil && cur != prev
		if replaced {
			err = nil
			if lbA.IsHelperTag(outbound.Tag) || lbA.IsReverseHelperTag(outbound.Tag) {
				if t.replacedHelpers == nil {
					t.replacedHelpers = make(map[string]struct{})
				}
				t.replacedHelpers[outbound.Tag] = struct{}{}
			}
		}
		// Before the auto-select group gets the outbound: it probes new members
		// immediately, and those probes must go through the exchange.
		t.updateInjectionLocked(outbound.Tag, isLantern[outbound.Tag], err == nil)
		if err == nil {
			if replaced {
				err = t.swapIntoSelectionGroupsLocked(outbound.Tag)
			} else {
				err = mutGrpMgr.AddToGroup(AutoSelectTag, outbound.Tag)
			}
		}
		if errors.Is(err, groups.ErrIsClosed) || errors.Is(err, lbA.ErrGroupClosed) {
			return errLibboxClosed
		}
		if err != nil {
			slog.Warn("Failed to load outbound",
				"tag", loggableTag(outbound.Tag),
				"type", outbound.Type,
				"error", loggableError(outbound.Tag, err),
			)
			errs = append(errs, err)
		} else {
			t.optsMap.Store(outbound.Tag, marshalOptions(ctx, outbound))
			added++
		}
	}

	if contextDone(ctx) {
		return ctx.Err()
	}

	for _, endpoint := range newEndpoints {
		logger := t.logFactory.NewLogger("endpoint/" + endpoint.Tag + "[" + endpoint.Type + "]")
		err := mutGrpMgr.CreateEndpointForGroup(
			ctx, router, logger, ManualSelectTag, endpoint.Tag, endpoint.Type, endpoint.Options,
		)
		if err == nil {
			err = mutGrpMgr.AddToGroup(AutoSelectTag, endpoint.Tag)
		}
		if errors.Is(err, groups.ErrIsClosed) {
			return errLibboxClosed
		}
		if err != nil {
			slog.Warn("Failed to load endpoint",
				"tag", endpoint.Tag,
				"type", endpoint.Type,
				"error", err,
			)
			errs = append(errs, err)
		} else {
			t.optsMap.Store(endpoint.Tag, marshalOptions(ctx, endpoint))
			added++
		}
	}

	if !applyOverrides {
		slog.Debug("Added servers", "added", added)
		return errors.Join(errs...)
	}
	if len(list.URLOverrides) > 0 {
		slog.Info("Applying bandit URL overrides to auto-select group",
			"override_count", len(list.URLOverrides),
		)
	}
	if err := t.mutGrpMgr.SetURLOverrides(AutoSelectTag, list.URLOverrides); err != nil {
		slog.Warn("Failed to set URL overrides", "error", err)
	} else if len(list.URLOverrides) > 0 {
		// Trigger an immediate probe cycle when we have bandit overrides so
		// callback probes are hit within seconds of config receipt rather than
		// waiting for the next scheduled interval (3 min).
		if err := t.mutGrpMgr.CheckOutbounds(AutoSelectTag); err != nil {
			slog.Warn("Failed to trigger immediate probe cycle after bandit overrides", "error", err)
		} else {
			slog.Info("Triggered immediate probe cycle for bandit callbacks")
		}
	}

	slog.Debug("Added servers", "added", added)
	return errors.Join(errs...)
}

// updateNonSelectableOutbounds reconciles the tunnel's non-selectable outbounds
// against list. Each is created directly through the outbound manager and never
// joined to a selection group, so it is dialable by tag but can never carry user
// traffic. Endpoints are out of scope; a non-selectable endpoint stays build-time
// only.
func (t *tunnel) updateNonSelectableOutbounds(list servers.ServerList) error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	return t.updateNonSelectableOutboundsLocked(list)
}

// updateNonSelectableOutboundsLocked implements updateNonSelectableOutbounds. The
// caller must hold t.outboundMu.
func (t *tunnel) updateNonSelectableOutboundsLocked(list servers.ServerList) error {
	list = allowedServers(list)
	ctx := t.ctx
	router := service.FromContext[adapter.Router](ctx)

	next := make(map[string]struct{}, len(list.Servers))
	for _, srv := range list.Servers {
		next[srv.Tag] = struct{}{}
	}

	var errs []error
	for tag := range t.nonSelectableTags {
		if _, keep := next[tag]; keep {
			continue
		}
		if err := t.outboundMgr.Remove(tag); err != nil {
			// Keep the tag tracked and its optsMap entry intact so the next
			// reconcile retries the removal instead of leaking a stale outbound.
			slog.Warn("Failed to remove non-selectable outbound", "tag", tag, "error", err)
			errs = append(errs, err)
			next[tag] = struct{}{}
			continue
		}
		t.optsMap.Delete(tag)
	}

	newOutbounds := removeDuplicates(ctx, t.optsMap, list).Outbounds()
	t.prefetchInviterTickets(newOutbounds)
	for _, outbound := range newOutbounds {
		logger := t.logFactory.NewLogger("outbound/" + outbound.Tag + "[" + outbound.Type + "]")
		if err := t.outboundMgr.Create(ctx, router, logger, outbound.Tag, outbound.Type, outbound.Options); err != nil {
			slog.Warn("Failed to load non-selectable outbound",
				"tag", outbound.Tag, "type", outbound.Type, "error", err)
			errs = append(errs, err)
			continue
		}
		t.optsMap.Store(outbound.Tag, marshalOptions(ctx, outbound))
	}

	t.nonSelectableTags = next
	return errors.Join(errs...)
}

// reconcileHelpers makes the tunnel's helper outbounds those in helpers:
// it removes the helpers in the selection groups that helpers does not name,
// adds the missing ones and swaps in those whose options changed, all under
// one hold of t.outboundMu. helpers must hold only helper servers. Reverse
// outbounds are left alone: setReverseOutbounds owns them.
func (t *tunnel) reconcileHelpers(helpers servers.ServerList) error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if t.mutGrpMgr == nil {
		return nil
	}
	keep := helpers.Tags()
	var stale []string
	for _, groupTag := range []string{ManualSelectTag, AutoSelectTag} {
		group, ok := t.mutGrpMgr.OutboundGroup(groupTag)
		if !ok {
			continue
		}
		for _, tag := range helperTags(group.All()) {
			if !lbA.IsReverseHelperTag(tag) && !slices.Contains(keep, tag) && !slices.Contains(stale, tag) {
				stale = append(stale, tag)
			}
		}
	}
	var errs []error
	if len(stale) > 0 {
		slog.Debug("Removing helpers that no longer have a pairing", "count", len(stale))
		err := t.removeOutboundsLocked(stale)
		if errors.Is(err, errLibboxClosed) {
			return err
		}
		errs = append(errs, err)
	}
	// Bandit URL overrides belong to the whole server list, so a helpers-only
	// load leaves them alone.
	err := t.loadOutboundsLocked(helpers, false)
	if errors.Is(err, errLibboxClosed) {
		return err
	}
	errs = append(errs, err, t.syncPersonalProxiesLocked())
	return errors.Join(errs...)
}

func (t *tunnel) removeOutbounds(tags []string) error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	err := t.removeOutboundsLocked(tags)
	if errors.Is(err, errLibboxClosed) {
		return err
	}
	return errors.Join(err, t.syncPersonalProxiesLocked())
}

// removeOutboundsLocked removes the outbounds with the given tags from the
// tunnel. The caller must hold t.outboundMu.
func (t *tunnel) removeOutboundsLocked(tags []string) error {
	var (
		mutGrpMgr = t.mutGrpMgr
		removed   []string
		errs      []error
	)
	for _, tag := range tags {
		if tag == PersonalProxiesTag || tag == PersonalProxyTag {
			continue // the tunnel's own groups: syncPersonalProxiesLocked manages them
		}
		if out, loaded := mutGrpMgr.OutboundGroup(tag); loaded {
			if _, isMutGroup := out.(lbA.MutableOutboundGroup); isMutGroup {
				continue // skip nested groups
			}
		}
		err := mutGrpMgr.RemoveFromGroup(ManualSelectTag, tag)
		if err == nil {
			err = mutGrpMgr.RemoveFromGroup(AutoSelectTag, tag)
		}
		if errors.Is(err, groups.ErrIsClosed) {
			return errLibboxClosed
		}
		if err != nil {
			errs = append(errs, err)
		} else {
			t.optsMap.Delete(tag)
			removed = append(removed, tag)
		}
	}
	if t.injector != nil {
		t.injector.RemoveOutboundTags(removed...)
	}
	slog.Debug("Removed servers", "removed", len(removed))
	return errors.Join(errs...)
}

func (t *tunnel) updateOutbounds(list servers.ServerList) error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()

	var errs []error
	outbounds := list.Outbounds()
	endpoints := list.Endpoints()
	if len(outbounds) == 0 && len(endpoints) == 0 && len(list.URLOverrides) == 0 {
		// A config with no servers still sets, or clears, the probe timeouts.
		t.applyProbeTimeoutsLocked(list)
		slog.Debug("No outbounds, endpoints, or bandit overrides to update, skipping")
		return nil
	}
	slog.Log(nil, rlog.LevelTrace, "Updating servers")

	selector, selectorExists := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	_, autoSelectExists := t.mutGrpMgr.OutboundGroup(AutoSelectTag)
	if !selectorExists || !autoSelectExists {
		slog.Error("Selector or auto-select group not found when updating outbounds")
		return errors.New("selector or auto-select group not found")
	}

	if contextDone(t.ctx) {
		return t.ctx.Err()
	}

	// collect tags present in the current group but absent from the new config
	// (reverse outbounds are never in a config: setReverseOutbounds owns them)
	newTags := list.Tags()
	var toRemove []string
	for _, tag := range selector.All() {
		if !lbA.IsReverseHelperTag(tag) && !slices.Contains(newTags, tag) {
			toRemove = append(toRemove, tag)
		}
	}

	// Add new outbounds first, before removing old ones. If all new
	// outbounds fail to load (e.g. invalid config), we keep the old
	// working outbounds to maintain connectivity.
	addErr := t.addOutboundsLocked(list)
	if errors.Is(addErr, errLibboxClosed) {
		return addErr
	}
	if addErr != nil {
		errs = append(errs, addErr)
	}

	// Check if any new outbound actually loaded
	hasNewOutbound := false
	for _, tag := range newTags {
		if slices.Contains(selector.All(), tag) {
			hasNewOutbound = true
			break
		}
	}

	if hasNewOutbound {
		if err := t.removeOutboundsLocked(toRemove); errors.Is(err, errLibboxClosed) {
			return err
		} else if err != nil {
			errs = append(errs, err)
		}
	} else {
		slog.Warn("All new outbounds failed to load, keeping old outbounds",
			"failed_tags", newTags, "would_remove_tags", toRemove)
	}

	if err := t.syncPersonalProxiesLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func removeDuplicates(ctx context.Context, curr *lsync.TypedMap[string, []byte], list servers.ServerList) servers.ServerList {
	slog.Log(nil, rlog.LevelTrace, "Removing duplicate outbounds/endpoints")
	var deduped []*servers.Server
	var dropped []string
	for _, srv := range list.Servers {
		if currOpts, exists := curr.Load(srv.Tag); exists {
			if bytes.Equal(currOpts, marshalOptions(ctx, srv.Options)) {
				dropped = append(dropped, srv.Tag)
				continue
			}
		}
		deduped = append(deduped, srv)
	}
	if len(dropped) > 0 {
		slog.Debug("Dropped duplicate outbounds/endpoints", "tags", loggableTags(dropped))
	}
	return servers.ServerList{
		Servers:           deduped,
		URLOverrides:      list.URLOverrides,
		AutoSelectOptions: list.AutoSelectOptions,
	}
}

func makeOutboundOptsMap(ctx context.Context, options O.Options) *lsync.TypedMap[string, []byte] {
	var optsMap lsync.TypedMap[string, []byte]
	for _, out := range options.Outbounds {
		optsMap.Store(out.Tag, marshalOptions(ctx, out))
	}
	for _, ep := range options.Endpoints {
		optsMap.Store(ep.Tag, marshalOptions(ctx, ep))
	}
	return &optsMap
}

func marshalOptions(ctx context.Context, opts any) []byte {
	switch o := opts.(type) {
	case O.Outbound:
		opts = &o
	case O.Endpoint:
		opts = &o
	}
	b, _ := json.MarshalContext(ctx, opts)
	return b
}

// makeNonSelectableTagSet returns the non-selectable tags that are outbounds in
// options. Endpoints are excluded because the reconcile manages outbounds only.
func makeNonSelectableTagSet(nonSelectable []string, options O.Options) map[string]struct{} {
	if len(nonSelectable) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(nonSelectable))
	for _, tag := range nonSelectable {
		want[tag] = struct{}{}
	}
	seeded := make(map[string]struct{})
	for _, out := range options.Outbounds {
		if _, ok := want[out.Tag]; ok {
			seeded[out.Tag] = struct{}{}
		}
	}
	return seeded
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// runUntilClosed runs run in a goroutine until Close cancels its context and
// waits for it to return.
func runUntilClosed(ctx context.Context, run func(context.Context)) io.Closer {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		run(ctx)
	}()

	return closerFunc(func() error {
		cancel()
		<-done
		return nil
	})
}

func contextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// streamingRoundTripper defaults Accept to text/event-stream so kindling's
// race pipeline drops non-streamable transports (AMP) that would otherwise
// buffer freddie's long-poll body and break broflake's genesis subscription.
type streamingRoundTripper struct {
	inner http.RoundTripper
}

func (s streamingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Accept") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("Accept", "text/event-stream")
	}
	resp, err := s.inner.RoundTrip(req)
	if err != nil {
		slog.Error("unbounded signaling RoundTrip error",
			"host", req.URL.Host, "path", req.URL.Path, "error", err,
		)
		return nil, err
	}
	return resp, nil
}

// cacheFileWrapper suppresses libbox's persistence of the selected outbound
// and the clash mode so BoxOptions.InitialServer controls them on each connect
// rather than stale values from disk. Persisting the mode would also restore
// reject mode after a crash.
type cacheFileWrapper struct {
	adapter.CacheFile
}

func (c *cacheFileWrapper) LoadSelected(_ string) string {
	return ""
}

func (c *cacheFileWrapper) StoreSelected(_, _ string) error {
	return nil
}

func (c *cacheFileWrapper) LoadMode() string {
	return ""
}

func (c *cacheFileWrapper) StoreMode(string) error {
	return nil
}

// prefetchInviterTickets starts the inviter ticket fetch, without waiting for
// it, when outbounds include a helper-tagged Unbounded outbound. The fetch then
// usually lands before that outbound's first subscribe, which would otherwise
// go out without tickets on a cold start and could settle on a pool volunteer
// for the session. Tunnels with no such outbound still never call the API.
func (t *tunnel) prefetchInviterTickets(outbounds []O.Outbound) {
	if t.inviterTickets == nil {
		return
	}
	for _, out := range outbounds {
		if out.Type == lbC.TypeUnbounded && lbA.IsHelperTag(out.Tag) {
			t.inviterTickets.Inviter()
			return
		}
	}
}

// withHelperRoomTickets gives the Unbounded outbound t's room tickets (see
// tunnel.roomTickets). With no ticket source, ctx is returned unchanged.
func withHelperRoomTickets(ctx context.Context, t *tunnel) context.Context {
	if t.inviterTickets == nil {
		return ctx
	}
	return lbA.ContextWithRoomTicketSource(ctx, t.roomTickets)
}
