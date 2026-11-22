// Package vpn provides high-level management of VPN tunnels, including connecting to the best
// available server, connecting to specific servers, disconnecting, reconnecting, and querying
// tunnel status.
package vpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	box "github.com/getlantern/lantern-box"
	lbA "github.com/getlantern/lantern-box/adapter"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/getlantern/lantern-box/protocol/samizdatreverse"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/internal/hostaccess"
	"github.com/getlantern/radiance/internal/redact"
	"github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/traces"
)

const (
	tracerName            = "github.com/getlantern/radiance/vpn"
	offlineURLTestTimeout = 30 * time.Second
)

var (
	ErrTunnelNotConnected     = errors.New("tunnel not connected")
	ErrTunnelAlreadyConnected = errors.New("tunnel already connected")
)

type VPNStatus string

// Possible VPN statuses
const (
	Connecting    VPNStatus = "connecting"
	Connected     VPNStatus = "connected"
	Disconnecting VPNStatus = "disconnecting"
	Disconnected  VPNStatus = "disconnected"
	Restarting    VPNStatus = "restarting"
	ErrorStatus   VPNStatus = "error"
)

func (s *VPNStatus) String() string {
	return string(*s)
}

// VPNClient manages the lifecycle of the VPN tunnel.
type VPNClient struct {
	tunnel *tunnel
	// boxCtx is tunnel's sing-box context, read lock-free so the Unbounded
	// widget's sockets never wait out a connect.
	boxCtx atomic.Pointer[context.Context]
	// currentTunnel is tunnel, read lock-free so an SSE frame never waits out a connect or
	// restart.
	currentTunnel atomic.Pointer[tunnel]

	platformIfce PlatformInterface
	// boxPlatform is the platform the tunnel's box runs on: platformIfce, or on Android shared.
	boxPlatform libbox.PlatformInterface
	// shared is platformIfce with its default interface monitor shared, for the tunnel's box and
	// the Unbounded direct exit's. Only Android has one, as only its exit runs on the platform.
	shared *sharedPlatform
	logger *slog.Logger

	offlineTestCancel context.CancelFunc
	offlineTestDone   chan struct{}

	status atomic.Value // VPNStatus

	// connObserver, if set, receives connection-close pushes. It outlives individual tunnels
	// and is re-attached to each tunnel's tracker at connect.
	connObserver ConnObserver

	// inviterTickets, if set, gives each tunnel's Unbounded consumer this
	// device's helper inviter tickets. Guarded by mu.
	inviterTickets InviterTickets

	// reversePortal, reverseMasquerade and reverseTags are the reverse direct
	// state each tunnel is given when it comes up. Written under mu;
	// reverseTags is read lock-free so the backend never waits out a connect.
	reversePortal     *samizdatreverse.PortalConfig
	reverseMasquerade string
	reverseTags       atomic.Pointer[[]string]
	// proxyless is the last state SetProxylessEnabled asked for, applied to
	// each tunnel as it starts; nil until the backend first sets it.
	proxyless atomic.Pointer[bool]
	// proxylessApplyMu orders applying the proxyless state to the tunnel.
	// Callers hold mu only for reading, which doesn't order them, so a
	// stale apply could otherwise land after a newer one.
	proxylessApplyMu sync.Mutex

	// staleSource is the stale source restart state, shared across tunnels
	// so a restart's rate limit and outcome outlive the tunnel it replaced.
	staleSource staleSourceGuard

	mu sync.RWMutex
}

// InviterTickets is where a tunnel's Unbounded consumer gets the inviter
// tickets for this device's helper pairings; helper.Source in production.
// Inviter is called on the signaling path, so it must not block.
type InviterTickets interface {
	Inviter() []string
	// InviterFor returns the inviter tickets for the pairing whose outbound
	// tag is tag, and whether the source has been answered: until then, no
	// tickets means only that none are known yet. Like Inviter, it is called
	// on the signaling path and must not block.
	InviterFor(tag string) (tickets []string, answered bool)
}

// SetInviterTickets sets the inviter ticket source for tunnels started from
// now on. Pass the process's one helper.Source, which the Unbounded widget
// shares, so the two draw on a single fetch budget.
func (c *VPNClient) SetInviterTickets(src InviterTickets) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inviterTickets = src
}

// newTunnel returns an unstarted tunnel for boxOptions. Caller holds c.mu.
func (c *VPNClient) newTunnel(boxOptions BoxOptions, initialMode string) *tunnel {
	t := &tunnel{
		dataPath:             boxOptions.BasePath,
		selectionHistorySeed: boxOptions.SelectionHistorySeed,
		initialLanternTags:   boxOptions.LanternServerTags,
		initialNonSelectable: boxOptions.NonSelectableOutbounds,
		initialMode:          initialMode,
		portalMasquerade:     boxOptions.reverseMasquerade,
		connObserver:         c.connObserver,
		inviterTickets:       c.inviterTickets,
		staleSource:          &c.staleSource,
	}
	t.restartForStaleSource = c.staleSourceRestart(t)
	if friend, ok := ParsePersonalProxySelection(boxOptions.InitialServer); ok {
		t.personalProxy.Store(&friend)
	}
	return t
}

// withPersonalProxyRooms records in boxOptions whether a rooms consumer may
// reach the friend its InitialServer selects. Caller holds c.mu.
func (c *VPNClient) withPersonalProxyRooms(boxOptions BoxOptions) BoxOptions {
	if friend, ok := ParsePersonalProxySelection(boxOptions.InitialServer); ok {
		boxOptions.personalProxyRooms = roomsReachable(c.inviterTickets, friend)
	}
	return boxOptions
}

// withReverse adds the kept reverse outbounds, and the portal when one is
// configured, to boxOptions, so a selection that depends on them can start.
// Caller holds c.mu.
func (c *VPNClient) withReverse(boxOptions BoxOptions) BoxOptions {
	tags := c.ReverseOutbounds()
	if len(tags) > 0 {
		outbounds := slices.Clone(boxOptions.Options.Outbounds)
		for _, tag := range tags {
			if !slices.ContainsFunc(outbounds, func(o option.Outbound) bool { return o.Tag == tag }) {
				outbounds = append(outbounds, reverseServer(tag).Options.(option.Outbound))
			}
		}
		boxOptions.Options.Outbounds = outbounds
	}
	if c.reversePortal != nil {
		boxOptions.reversePortal = true
		boxOptions.reverseMasquerade = c.reverseMasquerade
	}
	return boxOptions
}

// PlatformInterface defines the methods to interact with platform-specific services
type PlatformInterface interface {
	libbox.PlatformInterface
	// RestartService is called when the VPNClient wants to restart the tunnel instead of direct
	// disconnect/reconnect. This allows platforms to perform any necessary extra steps to restart
	// the tunnel. RestartService should block until the tunnel has been restarted and is ready for
	// use, or return an error if restart fails.
	RestartService() error
	// PostServiceClose is called after the tunnel has been closed. This allows platforms to perform
	// any necessary cleanup.
	PostServiceClose()
}

// NewVPNClient creates a new VPNClient instance with the given data path, logger, and
// platform interface.
func NewVPNClient(dataPath string, logger *slog.Logger, platformIfce PlatformInterface) *VPNClient {
	if logger == nil {
		logger = slog.Default()
	}
	done := make(chan struct{})
	close(done)
	c := &VPNClient{
		platformIfce:      platformIfce,
		logger:            logger,
		offlineTestCancel: func() {},
		offlineTestDone:   done,
	}
	if platformIfce != nil {
		c.boxPlatform = platformIfce
		if sharePlatformMonitor() {
			c.shared = newSharedPlatform(platformIfce)
			c.boxPlatform = c.shared
		}
	}
	c.status.Store(Disconnected)
	return c
}

func (c *VPNClient) Connect(ctx context.Context, boxOptions BoxOptions) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "connect")
	defer span.End()

	c.mu.Lock()
	c.offlineTestCancel()
	done := c.offlineTestDone
	c.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return traces.RecordError(ctx, ctx.Err())
	}

	// The bring-up below must outlive the request that triggered it, so detach
	// from the caller's cancellation while keeping trace context (span values).
	ctx = context.WithoutCancel(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel != nil {
		switch status := c.Status(); status {
		case Connected:
			return ErrTunnelAlreadyConnected
		case Restarting, Connecting, Disconnecting:
			return fmt.Errorf("tunnel is currently %s", status)
		case Disconnected, ErrorStatus:
			// Clean up the stale tunnel so we can reconnect.
			c.setTunnelLocked(nil)
		default:
			return fmt.Errorf("tunnel is in unexpected state: %s", status)
		}
	}

	c.logger.Info("Connecting VPN")
	boxOptions = c.withReverse(c.withPersonalProxyRooms(boxOptions))
	options, initialMode, err := buildOptions(boxOptions)
	if err != nil {
		return traces.RecordError(ctx, fmt.Errorf("failed to build options: %w", err))
	}
	if err := traces.RecordError(ctx, c.start(ctx, boxOptions, options, initialMode, false)); err != nil {
		c.logger.Error("Failed to connect VPN", "error", err)
		return err
	}
	c.logger.Info("VPN connected successfully")
	return nil
}

// Disconnect closes the tunnel and all active connections.
func (c *VPNClient) Disconnect() error {
	ctx, span := otel.Tracer(tracerName).Start(context.Background(), "disconnect")
	defer span.End()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel == nil {
		return nil
	}
	c.logger.Info("Disconnecting VPN")
	if err := traces.RecordError(ctx, c.close()); err != nil {
		c.logger.Error("Failed to disconnect VPN", "error", err)
		return err
	}
	c.logger.Info("VPN disconnected successfully")
	return nil
}

func (c *VPNClient) start(ctx context.Context, boxOptions BoxOptions, options option.Options, initialMode string, isRestart bool) error {
	configureBufPool()
	c.logger.Debug("Starting tunnel")
	c.setStatus(Connecting, nil)
	for attempt := 1; ; attempt++ {
		t := c.newTunnel(boxOptions, initialMode)
		err := t.start(ctx, options, c.boxPlatform, isRestart)
		if err == nil {
			c.setTunnelLocked(t)
			if err := c.restoreReverseLocked(); err != nil {
				// The error can name a reverse tag or the portal's port.
				c.logger.Warn("Failed to restore reverse direct state on the new tunnel")
			}
			if err := c.restoreProxylessLocked(boxOptions.Proxyless); err != nil {
				c.logger.Warn("Failed to restore the proxyless state on the new tunnel", "error", err)
			}
			c.setStatus(Connected, nil)
			c.logger.Debug("Tunnel started")
			return nil
		}
		// Wintun derives the adapter's device identity from its name, so only a new
		// name escapes the collision.
		if attempt > maxTUNIdentityRetries || !isTUNIdentityCollision(err) {
			c.setStatus(ErrorStatus, err)
			return err
		}
		name := tunIdentityName(attempt)
		if !setTUNInterfaceName(options, name) {
			c.setStatus(ErrorStatus, err)
			return err
		}
		c.logger.Warn("TUN adapter identity already exists, retrying under a new name",
			"interface_name", name, "attempt", attempt, "error", err)
	}
}

func (c *VPNClient) close() error {
	t := c.tunnel
	c.setTunnelLocked(nil)

	c.logger.Debug("Closing tunnel")
	c.setStatus(Disconnecting, nil)
	if err := t.close(); err != nil {
		c.setStatus(ErrorStatus, err)
		return err
	}
	c.setStatus(Disconnected, nil)
	if c.platformIfce != nil {
		c.platformIfce.PostServiceClose()
	}
	c.logger.Debug("Tunnel closed")
	runtime.GC()
	return nil
}

// Restart closes and restarts the tunnel if it is currently running. Returns an error if the tunnel
// is not running or restart fails.
func (c *VPNClient) Restart(boxOptions BoxOptions) error {
	return c.restart(boxOptions, nil)
}

// restart is Restart, limited to only when only is non-nil: a restart asked for by a tunnel that
// has since been replaced must not take down its replacement.
func (c *VPNClient) restart(boxOptions BoxOptions, only *tunnel) error {
	ctx, span := otel.Tracer(tracerName).Start(context.Background(), "VPNClient.Restart")
	defer span.End()

	c.mu.Lock()
	if c.tunnel == nil || c.Status() != Connected || only != nil && c.tunnel != only {
		c.mu.Unlock()
		return ErrTunnelNotConnected
	}

	c.setStatus(Restarting, nil)
	c.logger.Info("Restarting tunnel")

	if c.platformIfce != nil {
		span.SetAttributes(attribute.String("path", "platform_ifce"))
		c.mu.Unlock()
		if err := c.platformIfce.RestartService(); err != nil {
			c.logger.Error("Failed to restart tunnel via platform interface", "error", err)
			err = fmt.Errorf("platform interface restart failed: %w", err)
			c.setStatus(ErrorStatus, err)
			return traces.RecordError(ctx, err)
		}
		c.logger.Info("Tunnel restarted successfully")
		return nil
	}
	span.SetAttributes(attribute.String("path", "direct"))

	defer c.mu.Unlock()
	if err := c.close(); err != nil {
		return traces.RecordError(ctx, fmt.Errorf("closing tunnel: %w", err))
	}
	boxOptions = c.withReverse(c.withPersonalProxyRooms(boxOptions))
	options, initialMode, err := buildOptions(boxOptions)
	if err != nil {
		c.setStatus(ErrorStatus, err)
		return traces.RecordError(ctx, fmt.Errorf("failed to build options: %w", err))
	}
	if err := c.start(ctx, boxOptions, options, initialMode, true); err != nil {
		c.logger.Error("starting tunnel", "error", err)
		// c.start already set ErrorStatus; the guard lets Restarting→ErrorStatus through.
		return traces.RecordError(ctx, fmt.Errorf("starting tunnel: %w", err))
	}
	c.logger.Info("Tunnel restarted successfully")
	return nil
}

// ResetNetwork drops the tunnel's connections and re-seeds its interface state,
// for a platform to call on a network change, and starts the tunnel's stale
// source checks over. No-op if the tunnel is not running.
func (c *VPNClient) ResetNetwork() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel != nil {
		c.tunnel.resetNetwork()
		c.tunnel.restartStaleSourceSchedule()
	}
}

// ResetNetworkForMonitor resets connections, and starts the stale source checks
// over, only if listener belongs to the current tunnel. Nil or stale listeners
// are ignored.
func (c *VPNClient) ResetNetworkForMonitor(listener libbox.InterfaceUpdateListener) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if listener == nil || c.tunnel == nil || c.tunnel.boxInstance == nil {
		return
	}
	network := c.tunnel.boxInstance.Network()
	current, ok := network.InterfaceMonitor().(libbox.InterfaceUpdateListener)
	if !ok {
		return
	}
	// A shared platform holds its forwarder, not the tunnel's monitor.
	if current != listener && (c.shared == nil || !c.shared.forwardsTo(listener, current)) {
		return
	}
	network.ResetNetwork(c.tunnel.ctx)
	c.tunnel.restartStaleSourceSchedule()
}

// Pause pauses the tunnel for a device sleep. No-op if the tunnel is not running.
func (c *VPNClient) Pause() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel != nil {
		c.tunnel.devicePause()
	}
}

// Wake wakes the tunnel after a device sleep. No-op if the tunnel is not running.
func (c *VPNClient) Wake() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel != nil {
		c.tunnel.deviceWake()
	}
}

// isOpen returns true if the tunnel is open, false otherwise.
// Note, this does not check if the tunnel can connect to a server.
func (c *VPNClient) isOpen() bool {
	return c.Status() == Connected
}

func (c *VPNClient) Status() VPNStatus {
	s, _ := c.status.Load().(VPNStatus)
	return s
}

// setStatus stores and emits a status event. If the current status is Restarting, only allow
// transitions to Connected or ErrorStatus to avoid emitting intermediate states during a restart.
func (c *VPNClient) setStatus(s VPNStatus, err error) {
	if cur, _ := c.status.Load().(VPNStatus); cur == Restarting && s != Connected && s != ErrorStatus {
		return
	}
	c.status.Store(s)
	// Use c.logger (not slog.Info) so this respects the VPNClient's configured
	// logger — important for tests that pass NoOpLogger via WithLogger.
	c.logger.Info("[vpn-state-trace]", "hop", "daemon_setstatus", "status", s, "ts_ms", time.Now().UnixMilli())
	evt := StatusUpdateEvent{Status: s}
	if err != nil {
		// sing-box errors name the failing outbound, and a helper- tag must
		// not leave the client; the UI may forward this text.
		evt.Error = redact.Helper(err.Error())
	}
	events.Emit(evt)
}

// HistoryStorage returns the tunnel's auto-select history storage, or
// nil if the tunnel is not connected.
func (c *VPNClient) HistoryStorage() AutoSelectHistoryStorage {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return nil
	}
	return c.tunnel.selectionHistory
}

// SelectServer changes the currently selected server to the one specified by tag. If tag is
// AutoSelectTag or the empty string, the tunnel will switch to auto-select mode and automatically
// choose the best server.
func (c *VPNClient) SelectServer(tag string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel == nil || c.Status() != Connected {
		return ErrTunnelNotConnected
	}
	t := c.tunnel
	if tag == AutoSelectTag || tag == "" {
		return t.selectAuto()
	}

	c.logger.Info("Selecting server", "tag", tag)
	if err := t.selectOutbound(tag); err != nil {
		c.logger.Error("Failed to select server", "tag", tag, "error", err)
		return fmt.Errorf("failed to select server %s: %w", tag, err)
	}
	return nil
}

// SelectedPersonalProxy returns the friend whose personal proxy group the
// running tunnel has selected, or "" when it has none or no tunnel is up.
func (c *VPNClient) SelectedPersonalProxy() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil || c.Status() != Connected {
		return ""
	}
	return c.tunnel.selectedFriend()
}

// PersonalProxyMember reports what the running tunnel holds for the friend
// whose direct outbound tag is friend; the zero value while no tunnel is up.
func (c *VPNClient) PersonalProxyMember(friend string) PersonalProxyMember {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil || c.Status() != Connected {
		return PersonalProxyMember{}
	}
	return c.tunnel.personalProxyMember(friend)
}

func (c *VPNClient) UpdateOutbounds(list servers.ServerList) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return ErrTunnelNotConnected
	}
	return c.tunnel.updateOutbounds(list)
}

func (c *VPNClient) AddOutbounds(list servers.ServerList) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return ErrTunnelNotConnected
	}
	return c.tunnel.addOutbounds(list)
}

// UpdateNonSelectableOutbounds reconciles the non-selectable outbounds on the running
// tunnel. They are created directly through the outbound manager, never joined to a
// selection group, so they are dialable by tag but never carry user traffic. Returns
// ErrTunnelNotConnected when no tunnel is up.
func (c *VPNClient) UpdateNonSelectableOutbounds(list servers.ServerList) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return ErrTunnelNotConnected
	}
	return c.tunnel.updateNonSelectableOutbounds(list)
}

// ReconcileHelpers makes the running tunnel's helper outbounds (lbA.IsHelperTag)
// those in helpers: it removes the others, withdrawing the personal proxies
// group with the last, adds the missing ones and swaps in those whose options
// changed. A tunnel built from options captured before a pairing changed may
// still hold the old set; this brings it up to date.
func (c *VPNClient) ReconcileHelpers(helpers servers.ServerList) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return ErrTunnelNotConnected
	}
	return c.tunnel.reconcileHelpers(helpers)
}

// SetReversePortal configures the running tunnel's portal, creating it if the
// tunnel has none, with probes that fail authentication forwarded to
// masqueradeDomain. A portal created for another masqueradeDomain is replaced,
// ending its sessions. A nil cfg removes the portal and every reverse outbound,
// and forgets the tags SetReverseOutbounds kept. A copy of cfg, and
// masqueradeDomain, are kept and applied to each tunnel that comes up; with no
// tunnel running they are only kept, and SetReversePortal returns nil. A
// configure error leaves them kept.
func (c *VPNClient) SetReversePortal(cfg *samizdatreverse.PortalConfig, masqueradeDomain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg == nil {
		c.reversePortal, c.reverseMasquerade = nil, ""
		c.reverseTags.Store(nil)
	} else {
		kept := *cfg
		kept.Pairings = maps.Clone(cfg.Pairings)
		kept.PrivateKey = bytes.Clone(cfg.PrivateKey)
		kept.CertPEM = bytes.Clone(cfg.CertPEM)
		kept.KeyPEM = bytes.Clone(cfg.KeyPEM)
		if cfg.Previous != nil {
			prev := *cfg.Previous
			prev.PrivateKey = bytes.Clone(prev.PrivateKey)
			prev.CertPEM = bytes.Clone(prev.CertPEM)
			prev.KeyPEM = bytes.Clone(prev.KeyPEM)
			kept.Previous = &prev
		}
		c.reversePortal, c.reverseMasquerade = &kept, masqueradeDomain
	}
	if c.tunnel == nil {
		return nil
	}
	return c.tunnel.setReversePortal(c.reversePortal, c.reverseMasquerade)
}

// SetReverseOutbounds makes the reverse outbounds exactly this set of
// reverse tags (lbA.IsReverseHelperTag), adding and removing as needed, and
// resyncs the groups. Like SetReversePortal, it keeps tags for later tunnels
// and returns nil with no tunnel running. A set holding any other tag is
// refused and changes nothing.
func (c *VPNClient) SetReverseOutbounds(tags []string) error {
	for _, tag := range tags {
		if !lbA.IsReverseHelperTag(tag) {
			return errors.New("not a reverse helper tag")
		}
	}
	tags = slices.Compact(slices.Sorted(slices.Values(tags)))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reverseTags.Store(&tags)
	if c.tunnel == nil {
		return nil
	}
	return c.tunnel.setReverseOutbounds(tags)
}

// ReverseOutbounds returns the reverse tags last given to SetReverseOutbounds,
// whether or not a tunnel holds them.
func (c *VPNClient) ReverseOutbounds() []string {
	tags := c.reverseTags.Load()
	if tags == nil {
		return nil
	}
	return slices.Clone(*tags)
}

// RebindReversePortal rebinds the running portal's listener to the current
// default interface (see samizdatreverse.Portal.Rebind). No-op without a
// tunnel or portal.
func (c *VPNClient) RebindReversePortal() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return nil
	}
	return c.tunnel.rebindReversePortal()
}

// ReversePortalListening reports whether the running tunnel's portal holds a
// listener. It is false with no tunnel or no portal.
func (c *VPNClient) ReversePortalListening() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tunnel != nil && c.tunnel.reversePortalListening()
}

// ReverseSessionLive reports whether the running tunnel's portal holds a
// session for reverseTag that can carry traffic now: one the friend's bridge
// dialed in that is neither closed nor replaced. It is false with no tunnel
// or no portal, whatever SetReverseOutbounds was given.
func (c *VPNClient) ReverseSessionLive(reverseTag string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tunnel != nil && c.tunnel.reverseSessionLive(reverseTag)
}

// PhysicalInterfaceControl returns a socket control that binds a dial to the
// running tunnel's underlying default interface, so the dial bypasses the
// tunnel. It is nil with no tunnel running or no interface monitor to bind by.
func (c *VPNClient) PhysicalInterfaceControl() control.Func {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return nil
	}
	nm := service.FromContext[adapter.NetworkManager](c.tunnel.ctx)
	if nm == nil {
		return nil
	}
	return nm.AutoDetectInterfaceFunc()
}

// BoxContext returns the running tunnel's sing-box context, or nil with no
// tunnel running. Code that opens sockets in this process for itself reads the
// tunnel's network and DNS services from it.
func (c *VPNClient) BoxContext() context.Context {
	if ctx := c.boxCtx.Load(); ctx != nil {
		return *ctx
	}
	return nil
}

// sharePlatformMonitor reports whether the tunnel's platform is shared with the Unbounded direct
// exit's boxes: on Android, whose exit runs on it. Tests replace it.
var sharePlatformMonitor = common.IsAndroid

// BoxPlatform returns the platform interface the tunnel's sing-box runs on, its default
// interface monitor shared so another box in this process can run on it too. It is nil except
// on Android.
func (c *VPNClient) BoxPlatform() libbox.PlatformInterface {
	if c.shared == nil {
		return nil
	}
	return c.shared
}

// setTunnelLocked makes t the running tunnel. The caller must hold c.mu.
func (c *VPNClient) setTunnelLocked(t *tunnel) {
	c.tunnel = t
	c.currentTunnel.Store(t)
	if t == nil {
		c.boxCtx.Store(nil)
		return
	}
	ctx := t.ctx
	c.boxCtx.Store(&ctx)
}

// restoreReverseLocked gives the tunnel the kept reverse direct state. The
// caller must hold c.mu.
func (c *VPNClient) restoreReverseLocked() error {
	tags := c.ReverseOutbounds()
	if c.reversePortal == nil && len(tags) == 0 {
		return nil
	}
	var errs []error
	if c.reversePortal != nil {
		errs = append(errs, c.tunnel.setReversePortal(c.reversePortal, c.reverseMasquerade))
	}
	errs = append(errs, c.tunnel.setReverseOutbounds(tags))
	return errors.Join(errs...)
}

func (c *VPNClient) RemoveOutbounds(tags []string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return ErrTunnelNotConnected
	}
	return c.tunnel.removeOutbounds(tags)
}

// Connections returns a list of the active connections. A non-nil error
// is only returned if there was an error retrieving the connections, or if the tunnel is closed.
// If there are no connections and the tunnel is open, an empty slice is returned without an error.
func (c *VPNClient) Connections() ([]Connection, error) {
	_, span := otel.Tracer(tracerName).Start(context.Background(), "connections")
	defer span.End()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return nil, fmt.Errorf("failed to get connections: %w", ErrTunnelNotConnected)
	}
	return c.tunnel.connTracker.activeConnections(), nil
}

// ActiveConnectionCount returns the number of active connections, or 0 if the tunnel is not
// connected. It is cheap enough to back an observable metric gauge.
func (c *VPNClient) ActiveConnectionCount() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return 0
	}
	return c.tunnel.connTracker.activeConnectionCount()
}

// ClearTunnelCache removes the tunnel cache file at dataPath. If the tunnel is active it records
// a marker so the next tunnel start can retry the deletion. The returned flag reports whether
// the caller should restart the tunnel now to apply a deferred clear.
func (c *VPNClient) ClearTunnelCache(dataPath string) (shouldRestart bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tunnel != nil {
		return true, writeCacheClearMarker(dataPath)
	}

	if err := removeCacheFile(dataPath); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return false, writeCacheClearMarker(dataPath)
		}
		return false, err
	}

	return false, nil
}

// Bytes returns the cumulative up/down byte counters for the active tunnel. ok is false if the
// tunnel is not connected; counters reset when a tunnel restarts.
func (c *VPNClient) Bytes() (up, down int64, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return 0, 0, false
	}
	up, down = c.tunnel.connTracker.Total()
	return up, down, true
}

// Throughput returns the most recent global and per-outbound throughput sample.
// Returns ErrTunnelNotConnected if the tunnel is not connected.
func (c *VPNClient) Throughput() (ThroughputSnapshot, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return ThroughputSnapshot{}, ErrTunnelNotConnected
	}
	tt := c.tunnel.connTracker.tp
	active, perOut := c.tunnel.connTracker.activeStats()
	return ThroughputSnapshot{
		Global:            tt.Global(),
		PerOutbound:       tt.PerOutbound(),
		ActiveConnections: active,
		ActivePerOutbound: perOut,
	}, nil
}

// SetConnObserver sets the observer notified when connections close, or nil to detach. It is
// retained across tunnels and attached to the live tunnel's tracker if one is connected.
func (c *VPNClient) SetConnObserver(observer ConnObserver) {
	c.mu.Lock()
	c.connObserver = observer

	var tracker *connTracker
	if c.tunnel != nil {
		tracker = c.tunnel.connTracker
	}

	c.mu.Unlock()

	if tracker != nil {
		tracker.SetObserver(observer)
	}
}

// SelectionSavedEvent means the saved selection may have changed since it
// was last read. It follows each successful save of the selected server or
// auto-select, once a settings read sees the save.
type SelectionSavedEvent struct {
	events.Event
}

// PersonalProxyFallbackEvent is emitted when the selected friend's personal
// proxy lost its last member and the selection fell back.
type PersonalProxyFallbackEvent struct {
	events.Event
	// Tag is the friend's direct outbound tag.
	Tag string `json:"tag"`
	// Fallback is the selection now in effect: PersonalProxiesTag or
	// AutoSelectTag.
	Fallback string `json:"fallback"`
}

// AutoSelectedEvent is emitted when the auto-selected server changes.
type AutoSelectedEvent struct {
	events.Event
	Selected string `json:"selected"`
}

const URLTestSourceOffline = "offline"

// URLTestCompleteEvent signals usable latency results are available. Count is the
// number of outbounds that succeeded; Results maps each tag to its latency in ms.
type URLTestCompleteEvent struct {
	events.Event
	Source  string            `json:"source"`
	Count   int               `json:"count"`
	Results map[string]uint16 `json:"results"`
}

func (c *VPNClient) CurrentAutoSelectedServer() (string, error) {
	_, tag, err := c.currentAutoSelected()
	return tag, err
}

// currentAutoSelected also returns the tunnel the selection was read from, nil when the tunnel
// is not running.
func (c *VPNClient) currentAutoSelected() (*tunnel, string, error) {
	if !c.isOpen() {
		c.logger.Log(nil, log.LevelTrace, "Tunnel not running, cannot get auto selections")
		return nil, "", nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return nil, "", ErrTunnelNotConnected
	}
	outbound, loaded := c.tunnel.outboundMgr.Outbound(AutoSelectTag)
	if !loaded {
		return nil, "", fmt.Errorf("auto select group not found")
	}
	return c.tunnel, outbound.(adapter.OutboundGroup).Now(), nil
}

// AnnouncedAutoSelectedServer returns the auto selection [VPNClient.AutoSelectedChangeListener]
// last announced for the running tunnel, or "" when the tunnel is not running or nothing has
// been announced for it. It can lag [VPNClient.CurrentAutoSelectedServer] by one poll, but a
// change it does not show is always followed by an event.
func (c *VPNClient) AnnouncedAutoSelectedServer() string {
	if !c.isOpen() {
		return ""
	}
	t := c.currentTunnel.Load()
	if t == nil {
		return ""
	}
	if tag := t.announcedAuto.Load(); tag != nil {
		return *tag
	}
	return ""
}

// CurrentSelectedServer returns the tag of the currently selected outbound in
// whichever selector mode (auto or manual) the tunnel is in. Returns an empty
// string with a nil error when the tunnel is not running.
func (c *VPNClient) CurrentSelectedServer() (string, error) {
	if !c.isOpen() {
		return "", nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil {
		return "", ErrTunnelNotConnected
	}
	mode := c.tunnel.clashModeManager.selectedMode()
	outbound, loaded := c.tunnel.outboundMgr.Outbound(mode)
	if !loaded {
		return "", fmt.Errorf("%s group not found", mode)
	}
	return outbound.(adapter.OutboundGroup).Now(), nil
}

// ManualSelection returns the manual selector's choice and true while the
// tunnel is in manual mode, and "" and false in auto mode or with no tunnel.
func (c *VPNClient) ManualSelection() (string, bool) {
	if !c.isOpen() {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tunnel == nil || c.tunnel.clashModeManager.selectedMode() != ManualSelectTag {
		return "", false
	}
	outbound, loaded := c.tunnel.outboundMgr.Outbound(ManualSelectTag)
	if !loaded {
		return "", false
	}
	return outbound.(adapter.OutboundGroup).Now(), true
}

const (
	rapidPollInterval  = 500 * time.Millisecond
	rapidPollWindow    = 15 * time.Second
	steadyPollInterval = 10 * time.Second
)

// announceAutoSelected records tag on t, the tunnel it was read from, so a listener still
// running after a reconnect can't attach an earlier tunnel's selection to the new one.
func announceAutoSelected(t *tunnel, tag string) {
	if t != nil {
		t.announcedAuto.Store(&tag)
	}
	events.Emit(AutoSelectedEvent{Selected: tag})
}

// AutoSelectedChangeListener polls for auto-selection changes and emits an
// AutoSelectedEvent whenever the selection differs from the previous value.
// It performs an initial rapid poll to catch the first selection soon after
// tunnel connect, then settles into a slower steady-state interval. Each emitted
// selection is what [VPNClient.AnnouncedAutoSelectedServer] returns for the tunnel
// it was read from until the next one.
func (c *VPNClient) AutoSelectedChangeListener(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		var prev string

		// Rapid initial poll to emit the first selection promptly after connect.
		initialDeadline := time.NewTimer(rapidPollWindow)
		defer initialDeadline.Stop()
		tick := time.NewTimer(rapidPollInterval)
		defer func() {
			tick.Stop()
			close(done)
		}()
	initial:
		for {
			select {
			case <-ctx.Done():
				return
			case <-initialDeadline.C:
				break initial
			case <-tick.C:
				t, curr, err := c.currentAutoSelected()
				if err != nil {
					tick.Reset(rapidPollInterval)
					continue
				}
				if curr != prev {
					prev = curr
					announceAutoSelected(t, curr)
					if curr != "" {
						break initial
					}
				}
				tick.Reset(rapidPollInterval)
			}
		}

		// Drain tick before reusing for steady-state.
		if !tick.Stop() {
			select {
			case <-tick.C:
			default:
			}
		}
		tick.Reset(steadyPollInterval)

		// Steady-state polling for ongoing changes.
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				t, curr, err := c.currentAutoSelected()
				if err != nil {
					tick.Reset(steadyPollInterval)
					continue
				}
				if curr != prev {
					prev = curr
					announceAutoSelected(t, curr)
				}
				tick.Reset(steadyPollInterval)
			}
		}
	}()
	return done
}

// RunOfflineURLTests probes outbounds that pass the host-access check while disconnected.
// It returns [ErrTunnelAlreadyConnected] if the tunnel is connected.
//
// Tests are cancelled and results discarded if ctx is cancelled or
// [VPNClient.Connect] is called while they are running.
func (c *VPNClient) RunOfflineURLTests(ctx context.Context, basePath string, outbounds []option.Outbound, banditURLs map[string]string, autoSelect *lbO.MutableAutoSelectOutboundOptions) (results map[string]uint16, err error) {
	defer func() {
		if err != nil {
			results = nil
		}
	}()
	defer recoverToError(&err, "running offline URL tests")

	c.mu.Lock()
	if c.tunnel != nil {
		c.mu.Unlock()
		return nil, ErrTunnelAlreadyConnected
	}
	select {
	case <-c.offlineTestDone:
	default:
		c.mu.Unlock()
		return nil, errors.New("offline tests already running")
	}

	ctx, cancel := context.WithCancel(hostaccess.Context(ctx))
	defer cancel()
	c.offlineTestCancel = cancel
	done := make(chan struct{})
	c.offlineTestDone = done
	c.mu.Unlock()
	defer close(done)

	// Extract bandit trace context for distributed tracing
	traceCtx, hasTrace := traces.ExtractBanditTraceContext(banditURLs)

	outbounds = allowedOutbounds(outbounds)
	c.logger.Info("Performing offline URL tests", "outbound_count", len(outbounds), "timeout", offlineURLTestTimeout)
	tags := make([]string, 0, len(outbounds))
	for _, ob := range outbounds {
		tags = append(tags, ob.Tag)
	}
	outbounds = append(outbounds, urlTestOutbound("offline-test", tags, banditURLs, autoSelect))
	// CacheFile must stay disabled: enabling it holds an exclusive flock on
	// a file in the iOS App Group container, which the OS kills across
	// suspend with 0xdead10cc.
	options := option.Options{
		Log:       &option.LogOptions{Disabled: true},
		Outbounds: outbounds,
	}

	// Standard box: the offline pre-warm needs no platform interface.
	ctx = service.ContextWith[filemanager.Manager](ctx, nil)

	// MutableAutoSelect probes outbounds with bounded concurrency, so the
	// offline pre-warm needs enough total budget for multiple probe waves.
	ctx, cancel = context.WithTimeout(ctx, offlineURLTestTimeout)
	defer cancel()
	instance, err := sbox.New(sbox.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sing-box instance: %w", err)
	}
	defer instance.Close()
	// connect may have been called while we were setting up, so check if we should abort before
	// starting the instance.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("offline tests cancelled: %w", ctx.Err())
	default:
	}
	if err := instance.PreStart(); err != nil {
		return nil, fmt.Errorf("failed to start sing-box instance: %w", err)
	}
	outbound, found := instance.Outbound().Outbound("offline-test")
	if !found {
		return nil, errors.New("offline-test outbound not registered")
	}
	tester, ok := outbound.(adapter.URLTestGroup)
	if !ok {
		return nil, fmt.Errorf("offline-test outbound (type %q) does not implement URLTestGroup", outbound.Type())
	}
	results, err = tester.URLTest(ctx)
	if err != nil {
		c.logger.Error("offline URL test failed", "error", err)
		return nil, fmt.Errorf("offline URL test failed: %w", err)
	}

	// Record URL test results in a span linked to the bandit's trace.
	if hasTrace {
		_, span := otel.Tracer(tracerName).Start(traceCtx, "url_tests_complete",
			trace.WithAttributes(
				attribute.Int("bandit.test_count", len(results)),
			),
		)
		for tag, delay := range results {
			span.AddEvent("url_test_result", trace.WithAttributes(
				attribute.String("outbound", tag),
				attribute.Int("latency_ms", int(delay)),
			))
		}
		span.End()
	}

	var fmttedResults []string
	for tag, delay := range results {
		fmttedResults = append(fmttedResults, fmt.Sprintf("%s: [%dms]", tag, delay))
	}
	c.logger.Info("offline URL test complete")
	c.logger.Log(nil, log.LevelTrace, "offline URL test results", "results", strings.Join(fmttedResults, "; "))
	return results, nil
}

// AttemptFixNetState attempts to clear any error state left by a previous unclean shutdown, such
// as from a crash. No errors are returned and this fails silently.
func AttemptFixNetState() {
	options := baseOpts("")
	options = option.Options{
		Log:      &option.LogOptions{Disabled: true},
		DNS:      options.DNS,
		Inbounds: options.Inbounds,
		Route: &option.RouteOptions{
			AutoDetectInterface: true,
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Protocol: []string{"dns"},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeHijackDNS,
						},
					},
				},
			},
		},
	}
	ctx, cancel := context.WithCancel(box.BaseContext())
	defer cancel()
	b, err := sbox.New(sbox.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return
	}
	defer b.Close()
	b.Start()
}
