// Package backend provides the main interface for all the major components of Radiance.
package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"time"

	"github.com/Xuanwo/go-locale"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	C "github.com/getlantern/common"
	wire "github.com/getlantern/common/usermessage"
	"github.com/getlantern/publicip"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/deviceid"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/issue"
	"github.com/getlantern/radiance/kindling"
	"github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/telemetry"
	"github.com/getlantern/radiance/traces"
	"github.com/getlantern/radiance/unbounded"
	clientmessage "github.com/getlantern/radiance/usermessage"
	"github.com/getlantern/radiance/vpn"

	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

const tracerName = "github.com/getlantern/radiance/backend"

// LocalBackend ties all the core functionality of Radiance together. It manages the configuration,
// servers, VPN connection, account management, issue reporting, and telemetry for the application.
//
// A nil LocalBackend is valid for reporting issues.
type LocalBackend struct {
	// proxylessMu orders applyProxyless calls from config updates and
	// settings changes.
	proxylessMu sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc

	confHandler   *config.ConfigHandler
	issueReporter *issue.IssueReporter
	accountClient *account.Client
	userMessages  *clientmessage.Service

	srvManager *servers.Manager
	vpnClient  *vpn.VPNClient
	// live, if set, replaces vpnClient as the liveTunnel, for tests that have
	// no tunnel.
	live liveTunnel
	// beforeManagerRemove, if set, runs in RemoveServers just before the
	// manager removes the servers, for tests of a concurrent add.
	beforeManagerRemove func()
	// beforeRestartSelection, if set, runs in restartBoxOptions, with
	// r.selectionMu held, between capturing the outbounds and the saved
	// selection, for tests of a concurrent selection.
	beforeRestartSelection func()
	splitTunnelMgr         *vpn.SplitTunnel
	sessionHistory         *vpn.SessionHistory

	peerClient   peerController
	peerToggleMu sync.Mutex
	peerWG       sync.WaitGroup
	// peerWGMu orders peerWG.Add against closePeerClient's Wait: once
	// peerClosing is set, nothing adds to peerWG.
	peerWGMu    sync.Mutex
	peerClosing bool
	// peerReregCancel cancels the running re-register retry loop, so only the
	// latest request's loop runs. peerReregAttemptCtx is what attempts run
	// under; a newer request leaves it alone, and turning sharing off or on,
	// or Close, cancels it. Guarded by peerWGMu.
	peerReregCancel        context.CancelFunc
	peerReregAttemptCtx    context.Context
	peerReregAttemptCancel context.CancelFunc
	// peerForPairings is set while the peer client runs, with Share My
	// Connection off, only to serve this device's volunteer pairings. See
	// peer_pairings.go.
	peerForPairings atomic.Bool
	// pairingSyncQueued is set while a syncPairingRoute worker waits for
	// peerToggleMu, so queued reconciles coalesce.
	pairingSyncQueued atomic.Bool
	// pairingRetryTimer and pairingRetryWait drive the backoff between failed
	// pairings-only starts, and pairingLastAttempt rate-limits the retries a
	// network change forces. Guarded by pairingRetryMu.
	pairingRetryMu     sync.Mutex
	pairingRetryTimer  *time.Timer
	pairingRetryWait   time.Duration
	pairingLastAttempt time.Time
	pairingStartedAt   time.Time
	// pairingNotBefore is when the scheduled retry is due; a start reached
	// earlier, by a stale timer say, leaves the attempt to it.
	pairingNotBefore time.Time

	shutdownFuncs []func() error
	closeOnce     sync.Once

	// Rejects overlapping ConnectVPN calls (TryLock) so a burst can't each
	// drive a full tunnel bring-up.
	connectMu sync.Mutex
	// pendingConnect cancels the waits of the ConnectVPN in progress, for
	// DisconnectVPN: a connect still waiting for a config or tickets has no
	// tunnel for Disconnect to stop. Guarded by pendingConnectMu.
	pendingConnectMu sync.Mutex
	pendingConnect   context.CancelFunc

	// selectionMu serializes a selection and its persistence with the server
	// changes that can withdraw it (config updates and removals), so the
	// tunnel's choice and the persisted one cannot disagree.
	selectionMu sync.Mutex
	// selectionClosed is set by Close; a ticket-change reconcile then does
	// nothing. Guarded by selectionMu.
	selectionClosed bool
	// connectPending says a connect has built, or is building, a tunnel whose
	// selection it has not persisted yet. Until it has, the saved selection
	// is not restored over the requested one. Guarded by selectionMu.
	connectPending bool

	deviceID string

	telemetryCfgSub *events.Subscription[config.NewConfigEvent]

	// reused across reconnects; fully released only when telemetry shuts down.
	connObserver    vpn.ConnObserver
	stopConnMetrics context.CancelFunc
	connMetricsMu   sync.Mutex

	dataCapCh   chan *account.DataCapInfo // latest datacap update; nil when stream not running
	stopDataCap context.CancelFunc
	dataCapMu   sync.Mutex

	stopSelectionHistoryListener context.CancelFunc
	selectionHistoryMu           sync.Mutex
	// stopSelectionRestore ends the periodic restoreSavedSelection of the
	// connected tunnel and waits for a restore in progress. Guarded by
	// selectionRestoreMu.
	stopSelectionRestore func()
	selectionRestoreMu   sync.Mutex
	selectionReporter    *selectionReporter

	exhaustionGate exhaustionGate

	// helperTickets is this device's helper pairing tickets: the one source
	// for the process, shared by the widget's volunteer side and the tunnel's
	// inviter side so they draw on a single fetch budget. It stops fetching
	// when ctx ends.
	helperTickets *helper.Source
	// helperUsage is the rooms-mode bytes relayed per helper pairing, shared
	// by the widget and the ticket fetcher.
	helperUsage *helper.Usage
	// helperRelay sends the app's helper-invite requests to lantern-cloud.
	helperRelay *helper.Relayer
	// helperActivity is today's sharing time and bytes, kept on the device.
	helperActivity *helper.ActivityTracker
	// helperPairingKeys is the K_pair of each helper pairing, pushed by
	// lantern-core over IPC.
	helperPairingKeys *helper.PairingKeys
	// reverseClient serves this device's paired helpers as a reverse inviter
	// while reverseGate runs it. Nil where reverseUnsupported.
	reverseClient reverseController
	reverseGate   atomic.Pointer[reverseGate]
	// reverseFriends keeps the selections of friends reachable by reverse
	// outbound while those outbounds are down.
	reverseFriends *reverseFriends
	// bridgeClient serves this device's inviters over reverse routes while
	// the widget runs.
	bridgeClient *helper.BridgeClient
}

type Options struct {
	DataDir  string
	LogDir   string
	Locale   string
	LogLevel string
	// TimeZone is the device's IANA time zone name (e.g. "Asia/Tehran"). Empty keeps the
	// previously stored zone.
	TimeZone string
	// DeviceID overrides the saved ID on mobile; desktop ignores this option.
	DeviceID string
	// TelemetryConsent overrides the saved preference unless PreserveTelemetryConsent is true.
	TelemetryConsent bool
	// PreserveTelemetryConsent leaves the stored telemetry preference unchanged at startup.
	PreserveTelemetryConsent bool
	PlatformInterface        vpn.PlatformInterface
	UserMessageCapabilities  wire.ClientCapabilities
	// EnvOverrides are applied via os.Setenv before common.Init so sandboxed
	// system extensions (macOS/iOS), which don't inherit shell env, still see
	// RADIANCE_* vars from the host process. Entries are set verbatim — no
	// filtering.
	EnvOverrides map[string]string
}

// NewLocalBackend performs global initialization and returns a new LocalBackend instance.
// It should be called once at the start of the application.
// Initialization tolerates component failures to preserve issue reporting, except when
// common initialization fails.
func NewLocalBackend(ctx context.Context, opts Options) (*LocalBackend, error) {
	// Must run before common.Init: it reads RADIANCE_VERSION once and
	// freezes it, so a later Setenv is ignored by the header-fill path.
	var envOverrideErrs error
	for k, v := range opts.EnvOverrides {
		if err := os.Setenv(k, v); err != nil {
			envOverrideErrs = errors.Join(envOverrideErrs, fmt.Errorf("apply env override %q: %w", k, err))
		}
	}
	if err := common.Init(opts.DataDir, opts.LogDir, opts.LogLevel); err != nil {
		return nil, fmt.Errorf("failed to initialize common components: %w", err)
	}
	if envOverrideErrs != nil {
		slog.Warn("Failed to apply some env overrides", "error", envOverrideErrs)
	}
	dataDir := settings.GetString(settings.DataPathKey)
	if err := settings.Patch(startupSettings(opts)); err != nil {
		slog.Warn("Persisting startup settings", "error", err)
	}
	platformDeviceID := settings.GetString(settings.DeviceIDKey)

	accountClient := account.NewClient(kindling.HTTPClient(), dataDir, slog.Default().With("service", "account"))

	svrMgr, err := servers.NewManager(
		dataDir, slog.Default().With("service", "server_manager"),
	)
	if err != nil {
		slog.Error("Loading server manager", "error", err)
	}

	splitTunnelMgr, err := vpn.NewSplitTunnelHandler(
		dataDir, slog.Default().With("service", "split_tunnel"),
	)
	if err != nil {
		slog.Error("Loading split tunnel handler", "error", err)
	}
	// Empty filters do not persist the invert flag, so reload can reset the
	// loaded policy. Re-apply the persisted setting as the source of truth.
	if err := splitTunnelMgr.SetPolicy(vpn.SplitTunnelPolicy(settings.GetString(settings.SplitTunnelPolicyKey))); err != nil {
		slog.Warn("Reconciling split-tunnel policy", "error", err)
	}

	vpnClient := vpn.NewVPNClient(dataDir, slog.Default().With("service", "vpn"), opts.PlatformInterface)

	// Degraded, not fatal, per the invariant above: a nil peerClient only
	// disables Share My Connection, and must not cost the user their ability
	// to report an issue. applyPeerShare and PeerStatus handle nil.
	// The peer client outlives this function, and self-stops only after a
	// Start, which needs r; the closure reads r once it exists.
	var backend *LocalBackend
	peerClient, err := newPeerClient(platformDeviceID, func(reason error) {
		if backend != nil {
			backend.onPeerSelfStop(reason)
		}
	}, func() bool {
		return backend != nil && backend.peerForPairings.Load()
	}, vpnClient.PhysicalInterfaceControl)
	if err != nil {
		slog.Error("Loading peer client", "error", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	cOpts := config.Options{
		DataPath:      dataDir,
		Locale:        settings.GetString(settings.LocaleKey),
		AccountClient: accountClient,
		HTTPClient:    kindling.HTTPClient(),
		Logger:        slog.Default().With("service", "config_handler"),
	}
	r := &LocalBackend{
		ctx:               ctx,
		cancel:            cancel,
		issueReporter:     newIssueReporter(),
		selectionReporter: newSelectionReporter(kindling.HTTPClient()),
		accountClient:     accountClient,
		confHandler:       config.NewConfigHandler(ctx, cOpts),
		srvManager:        svrMgr,
		vpnClient:         vpnClient,
		splitTunnelMgr:    splitTunnelMgr,
		peerClient:        peerClient,
		shutdownFuncs: []func() error{
			telemetry.Close, kindling.Close,
		},
		closeOnce: sync.Once{},
		deviceID:  platformDeviceID,
		dataCapCh: make(chan *account.DataCapInfo, 1),
	}
	r.helperUsage = &helper.Usage{}
	r.helperPairingKeys = &helper.PairingKeys{}
	r.reverseFriends = loadReverseFriends(filepath.Join(dataDir, reverseFriendsFileName))
	if !reverseUnsupported() {
		r.useReverseClient(r.newReverseClient(platformDeviceID))
	}
	r.bridgeClient = r.newBridgeClient(platformDeviceID)
	r.helperPairingKeys.SetOnChange(r.pairingKeysChanged)
	r.helperTickets = helper.NewSource(ctx, helper.NewFetcher(kindling.HTTPClient(), common.GetBaseURL()).WithUsage(r.helperUsage).Fetch)
	r.helperTickets.SetOnInviterChange(r.reconcilePersonalProxy)
	vpnClient.SetInviterTickets(r.helperTickets)
	// The widget and the tunnel share r.helperTickets, so invalidating it
	// reaches both when the app's pairings change.
	r.helperRelay = helper.NewRelayer(kindling.HTTPClient(), common.GetBaseURL(), func() {
		if r.helperTickets != nil {
			r.helperTickets.Invalidate()
		}
	})
	backend = r
	r.helperActivity = helper.NewActivityTracker(filepath.Join(dataDir, "helper-activity.json"), r.sharingCounters)
	r.sessionHistory = vpn.NewSessionHistory(slog.Default().With("service", "session_history"), r.sessionInfo())
	r.shutdownFuncs = append(r.shutdownFuncs, func() error { r.sessionHistory.Close(); return nil })
	r.userMessages = loadUserMessageService(opts.UserMessageCapabilities, dataDir)
	r.clearSelectedIfMissing()
	return r, nil
}

func startupSettings(opts Options) settings.Settings {
	deviceID := settings.GetString(settings.DeviceIDKey)
	switch common.Platform {
	case "ios", "android":
		if opts.DeviceID != "" {
			deviceID = opts.DeviceID
		}
		if deviceID == "" {
			slog.Warn("No device ID was found")
		}
	default:
		if deviceID == "" {
			deviceID = deviceid.Get(settings.GetString(settings.DataPathKey))
		}
	}
	localeName := opts.Locale
	if localeName == "" {
		localeName = settings.GetString(settings.LocaleKey)
	}
	if localeName == "" {
		if tag, err := locale.Detect(); err == nil {
			localeName = tag.String()
		} else {
			localeName = "en-US"
		}
	}
	startup := settings.Settings{
		settings.LocaleKey:              localeName,
		settings.DeviceIDKey:            deviceID,
		settings.ConfigFetchDisabledKey: env.GetBool(env.DisableFetch),
	}
	if !opts.PreserveTelemetryConsent {
		startup[settings.TelemetryKey] = opts.TelemetryConsent
	}
	if opts.TimeZone != "" {
		startup[settings.TimeZoneKey] = opts.TimeZone
	}
	return startup
}

// loadUserMessageService returns nil when capabilities disable messaging or service initialization fails.
func loadUserMessageService(capabilities wire.ClientCapabilities, dataDir string) *clientmessage.Service {
	if capabilities.Version == "" {
		return nil
	}
	if err := capabilities.Validate(); err != nil {
		slog.Warn("User messages disabled", "reason", "invalid_capabilities")
		return nil
	}
	service, err := clientmessage.New(clientmessage.Options{
		DataDir: dataDir,
		Fetcher: clientmessage.NewHTTPFetcher(
			kindling.HTTPClient(),
			clientmessage.Endpoint(common.GetBaseURL()),
			capabilities,
		),
		ContextProvider: func() clientmessage.ClientContext {
			return clientmessage.ClientContext{
				UserID:     settings.GetString(settings.UserIDKey),
				ProToken:   settings.GetString(settings.TokenKey),
				Locale:     clientmessage.NormalizeLocale(settings.GetString(settings.LocaleKey)),
				Platform:   clientmessage.NormalizePlatform(common.Platform),
				AppVersion: common.GetVersion(),
			}
		},
	})
	if err != nil {
		slog.Error("Loading user-message state", "error", err)
		return nil
	}
	return service
}

func (r *LocalBackend) Start() {
	// eagerly start kindling so it's ready by the time we need to make network requests
	kindling.Init()
	r.startUserMessages()
	stored := loadStoredPublicIP()
	go func() {
		ip := detectPublicIP(r.ctx, func() bool {
			s := r.VPNStatus()
			return s == "" || s == vpn.Disconnected
		}, lookupPublicIP)
		if ip == nil || !storePublicIP(ip, stored) {
			return
		}
		// Fetches until now carried no IP or one from another network, so the API may have
		// geolocated a relay. Don't wait for the next poll to correct the assignment.
		if err := r.confHandler.Fetch(); err != nil && !errors.Is(err, config.ErrConfigFetchDisabled) {
			slog.Warn("Failed to refetch config after detecting public IP", "error", err)
		}
	}()

	if settings.GetBool(settings.TelemetryKey) {
		if err := r.startTelemetry(); err != nil {
			slog.Error("Failed to start telemetry", "error", err)
		}
	}
	r.startVPNStatusListeners()
	r.startReverse()
	r.startAutoSelectedListener()
	r.startSessionAutoSelectListener()

	r.resumePeerShareIfEnabled()
	r.syncPairingRoute()
	go r.helperActivity.Run(r.ctx, time.Minute)

	// Wire the broflake / Unbounded widget proxy lifecycle to config
	// updates. This single subscription handles all three start/stop
	// triggers (local toggle, server feature flag, server-supplied
	// config); InitSubscription is sync.Once-guarded so a future Start
	// retry after Close won't double-subscribe.
	//
	// Seed with the already-cached config (loaded from disk before
	// Start runs) so an opted-in user auto-starts the widget on
	// launch instead of waiting for the next config refresh.
	cachedCfg, _ := r.confHandler.GetConfig()
	// The widget joins its helper pairings' rooms on freddie with the
	// volunteer tickets lantern-cloud issues this device, fetched on first use
	// and renewed in the background. A nil *helper.Source would be a non-nil
	// interface, so partial backends in tests skip it.
	if r.helperTickets != nil {
		unbounded.SetTicketSource(r.helperTickets)
		unbounded.SetPairedUsage(r.helperUsage)
	}
	// The bridges run while the widget does; on iOS that is only in the
	// foreground.
	if r.bridgeClient != nil {
		unbounded.SetRunHook(func(running bool) { r.bridgeClient.SetRunning(r.ctx, running) })
	}
	// The widget reports the tunnel's state with its STUN preflights, so
	// freddie can tell whether STUN failures follow the VPN. The widget also
	// reads the tunnel's sing-box context to keep its WebRTC sockets off the
	// tunnel.
	if r.vpnClient != nil {
		unbounded.SetVPNStatus(func() string { return string(r.vpnClient.Status()) })
		unbounded.SetBoxContext(r.vpnClient.BoxContext)
		unbounded.SetPlatformInterface(directExitPlatform(r.vpnClient))
	}
	unbounded.SetDirectExitAllowed(r.directExitAllowed)
	slog.Info("Unbounded: arming the widget", "config_cached", cachedCfg != nil)
	unbounded.InitSubscription(cachedCfg)

	events.SubscribeContext(r.ctx, func(evt config.NewConfigEvent) {
		if setCountryCodeFromConfig(evt.New) {
			r.CountryCodeChanged()
		}
		r.applyConfig(evt.New, true)
		go r.prewarmOfflineURLTests("config update")
	})
	if r.applyCurrentConfig() {
		go r.prewarmOfflineURLTests("cached config")
	}
	r.confHandler.Start()
}

// applyCurrentConfig applies any config already loaded from disk before the
// fetch loop has a chance to refresh it.
func (r *LocalBackend) applyCurrentConfig() bool {
	cfg, err := r.confHandler.GetConfig()
	if err != nil {
		return false
	}
	if setCountryCodeFromConfig(cfg) {
		r.CountryCodeChanged()
	}
	r.applyConfig(cfg, false)
	return true
}

// prewarmOfflineURLTests records reachability history for the not-yet-connected
// tunnel path and treats connected-tunnel races as harmless.
func (r *LocalBackend) prewarmOfflineURLTests(source string) {
	if err := r.RunOfflineURLTests(); err != nil && !errors.Is(err, vpn.ErrTunnelAlreadyConnected) {
		// ErrTunnelAlreadyConnected is expected while the VPN is up:
		// updateServers already pushed the new outbounds into the live
		// tunnel via UpdateOutbounds, so the offline pre-warm, which
		// targets the not-yet-connected case, would duplicate work and
		// conflict with the live auto-select group.
		slog.Error("Failed to run offline URL tests", "source", source, "error", err)
	}
}

// ConfigAppliedEvent is emitted once a config's servers and outbounds are applied to the
// backend, so reads made on it see that config. [config.NewConfigEvent] can arrive before then.
type ConfigAppliedEvent struct {
	events.Event
}

// applyConfig updates the runtime server state from a config snapshot. The
// proxyless switch follows the handler's current config, not cfg.
func (r *LocalBackend) applyConfig(cfg *config.Config, evict bool) {
	if cfg == nil {
		return
	}
	list := serverListFromConfig(cfg)
	if len(cfg.BanditURLOverrides) > 0 {
		if ctx, ok := traces.ExtractBanditTraceContext(cfg.BanditURLOverrides); ok {
			// Link this marker span to the API's bandit trace so config receipt
			// and the per-outbound callback stay visible in one distributed trace.
			_, span := otel.Tracer(tracerName).Start(ctx, "radiance.config_received",
				trace.WithAttributes(
					attribute.Int("bandit.override_count", len(cfg.BanditURLOverrides)),
					attribute.Int("bandit.outbound_count", len(cfg.Options.Outbounds)),
				),
			)
			span.End()
		}
	}
	if err := r.updateServers(list, evict); err != nil {
		slog.Error("updating servers in manager", "error", err)
	}
	if err := r.vpnClient.UpdateNonSelectableOutbounds(nonSelectableOutboundsFromConfig(cfg)); err != nil &&
		!errors.Is(err, vpn.ErrTunnelNotConnected) {
		slog.Error("updating non-selectable outbounds", "error", err)
	}
	r.applyProxyless()
	events.Emit(ConfigAppliedEvent{})
}

// proxylessFeature is the server-side flag for proxyless access. It is the
// kill switch: off, no tunnel goes proxyless whatever the user's setting.
const proxylessFeature = "proxyless"

// proxylessOn reports whether the proxyless hedge should take new
// connections: smart routing is on, the server's flag is on, and the user
// hasn't turned the setting off. Only smart routing builds the hedge, but a
// tunnel that was connecting when smart routing went off isn't restarted, so
// it can have one; checking smart routing here keeps that hedge off.
func proxylessOn(cfg *config.Config) bool {
	return cfg != nil && cfg.Features[proxylessFeature] &&
		settings.GetBool(settings.SmartRoutingKey) && settings.ProxylessEnabled()
}

// proxylessOptions builds the tunnel's proxyless hedge options from the
// flag, the setting and the server's measurement settings for this client.
func proxylessOptions(cfg *config.Config) *vpn.ProxylessOptions {
	p := &vpn.ProxylessOptions{Enabled: proxylessOn(cfg)}
	if cfg != nil {
		if s := cfg.Proxyless.Sanitize(); s != nil {
			p.ExploreRate = s.ExploreRate
			p.TelemetrySites = s.TelemetrySites
		}
	}
	return p
}

// applyProxyless switches the running tunnel's proxyless hedge to match the
// current config's flag and the setting, without a restart. A tunnel without
// a hedge has nothing to switch.
func (r *LocalBackend) applyProxyless() {
	// A config update and a settings change can both get here. Each reads
	// the current config and setting under the lock, never a copy taken
	// before it, so whichever applies last applies the newest of both.
	r.proxylessMu.Lock()
	defer r.proxylessMu.Unlock()
	cfg, _ := r.confHandler.GetConfig()
	if err := r.vpnClient.SetProxylessEnabled(proxylessOn(cfg)); err != nil &&
		!errors.Is(err, vpn.ErrTunnelNotConnected) {
		slog.Error("switching proxyless", "error", err)
	}
}

// setCountryCodeFromConfig records the API-assigned country for issue reports
// and the tunnel's client info unless an explicit country override is active,
// reporting whether the live value changed. A failed save can still change it,
// so that is read back rather than inferred from the error. Callers apply it to
// every config, not once per session, because a later fetch can correct the
// country, e.g. once the public IP is detected and the API stops geolocating a
// relay.
func setCountryCodeFromConfig(cfg *config.Config) bool {
	if env.GetString(env.Country) != "" || cfg == nil || cfg.Country == "" ||
		cfg.Country == settings.GetString(settings.CountryCodeKey) {
		return false
	}
	if err := settings.Set(settings.CountryCodeKey, cfg.Country); err != nil {
		slog.Error("failed to set country code in settings", "error", err)
	} else {
		slog.Info("Set country code from config", "country_code", cfg.Country)
	}
	return settings.GetString(settings.CountryCodeKey) == cfg.Country
}

// recheckDirectExit re-checks the widget's direct exit against
// directExitAllowed. Tests replace it.
var recheckDirectExit = unbounded.RecheckDirectExit

// directExitNeedsVPN reports whether the widget's direct exit runs only while
// the VPN is connected: on Android its boxes run on the VPN service's platform
// interface, whose default interface monitor and socket protection work only
// then. Tests replace it.
var directExitNeedsVPN = common.IsAndroid

// boxPlatformer is the part of vpn.VPNClient directExitPlatform reads.
type boxPlatformer interface {
	BoxPlatform() libbox.PlatformInterface
}

// directExitPlatform is the platform interface the widget's direct exit boxes
// run on: the VPN's, shared, only where directExitNeedsVPN (Android). Elsewhere
// it is nil, and the exit boxes keep sing-box's own interface monitor, even on
// macOS, whose network extension has a platform interface too.
func directExitPlatform(vc boxPlatformer) libbox.PlatformInterface {
	if !directExitNeedsVPN() {
		return nil
	}
	return vc.BoxPlatform()
}

// directExitAllowed reports whether the widget may exit users' traffic itself:
// from a country that is known and not censored, as for the pairings-only
// route, and where directExitNeedsVPN, on a platform interface while the VPN
// is connected.
func (r *LocalBackend) directExitAllowed() bool {
	if !pairingRouteCountryAllowed() {
		return false
	}
	if !directExitNeedsVPN() {
		return true
	}
	return r.vpnClient != nil && directExitVPNReady(r.vpnClient.BoxPlatform() != nil, r.vpnClient.Status())
}

// directExitVPNReady is directExitAllowed's VPN check where directExitNeedsVPN.
func directExitVPNReady(hasPlatform bool, status vpn.VPNStatus) bool {
	return hasPlatform && status == vpn.Connected
}

// CountryCodeChanged reconciles what depends on this device's country after
// it changes: the pairings-only route and the widget's direct exit run only
// where it is allowed. The exit stops at once when the country becomes
// unknown or censored, rather than at the next config, so this can wait for
// the exit to tear down.
func (r *LocalBackend) CountryCodeChanged() {
	r.syncPairingRoute()
	recheckDirectExit()
}

// serverListFromConfig converts config outbounds and endpoints into managed
// Lantern servers while preserving location and bandit URL metadata.
func serverListFromConfig(cfg *config.Config) servers.ServerList {
	nonSelectable := nonSelectableSet(cfg)
	srvs := make([]*servers.Server, 0, len(cfg.Options.Outbounds)+len(cfg.Options.Endpoints))
	addSvr := func(tag, typ string, opts any, loc *C.ServerLocation) {
		// Non-selectable tags are merged into the box for dialing but must never
		// become managed servers, or they surface in the server list, get probed by
		// offline URL tests, and join the auto-select group on live update.
		if _, ok := nonSelectable[tag]; ok {
			return
		}
		s := &servers.Server{
			Tag: tag, Type: typ, IsLantern: true, Options: opts,
		}
		if loc != nil {
			s.Location = *loc
		}
		srvs = append(srvs, s)
	}
	for _, out := range cfg.Options.Outbounds {
		addSvr(out.Tag, out.Type, out, cfg.OutboundLocations[out.Tag])
	}
	for _, ep := range cfg.Options.Endpoints {
		addSvr(ep.Tag, ep.Type, ep, cfg.OutboundLocations[ep.Tag])
	}
	return servers.ServerList{
		Servers:           srvs,
		URLOverrides:      cfg.BanditURLOverrides,
		AutoSelectOptions: vpn.DecodeAutoSelectOptions(cfg.AutoSelectOptions),
	}
}

func nonSelectableSet(cfg *config.Config) map[string]struct{} {
	set := make(map[string]struct{}, len(cfg.NonSelectableOutbounds))
	for _, tag := range cfg.NonSelectableOutbounds {
		set[tag] = struct{}{}
	}
	return set
}

// nonSelectableOutboundsFromConfig returns the config's non-selectable outbounds for
// the tunnel to instantiate off the managed-server path. Endpoints are excluded: a
// non-selectable endpoint stays build-time only.
func nonSelectableOutboundsFromConfig(cfg *config.Config) servers.ServerList {
	nonSelectable := nonSelectableSet(cfg)
	srvs := make([]*servers.Server, 0, len(nonSelectable))
	for _, out := range cfg.Options.Outbounds {
		if _, ok := nonSelectable[out.Tag]; !ok {
			continue
		}
		// The proxyless outbound keeps the UDP default the tunnel was built
		// with, or replacing it would turn off proxyless QUIC.
		out = vpn.WithProxylessUDP(out)
		srvs = append(srvs, &servers.Server{Tag: out.Tag, Type: out.Type, IsLantern: true, Options: out})
	}
	return servers.ServerList{Servers: srvs}
}

func (r *LocalBackend) Close() {
	r.closeOnce.Do(func() {
		slog.Debug("Closing Radiance")
		// Waits out a ticket-change reconcile in flight, and turns away later
		// ones, so none saves a selection a replacement backend may own.
		r.selectionMu.Lock()
		r.selectionClosed = true
		r.selectionMu.Unlock()
		// Stop the activity ticker and wait for it, then count the last
		// partial interval while sharing still runs, so nothing saves
		// after Close returns.
		if r.helperActivity != nil {
			r.helperActivity.Stop()
			r.helperActivity.Flush()
		}
		r.closePeerClient()
		r.stopReverse()
		// unbounded.start spawns its worker on a context.Background-
		// derived ctx (it has to outlive any single NewConfigEvent),
		// so Close has to explicitly tell it to shut down — otherwise
		// the broflake widget goroutine survives backend close and
		// leaks until process exit. Use a fresh ctx so a cancelled
		// shutdown path doesn't skip the Stop.
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := unbounded.Stop(stopCtx); err != nil {
			slog.Warn("unbounded stop on backend close returned error", "error", err)
		}
		if r.bridgeClient != nil {
			r.bridgeClient.Stop(stopCtx)
		}
		cancel()
		// vpnClient is always set in production via NewLocalBackend, but
		// peer-focused unit tests construct partial LocalBackends without
		// one. Guard the call so Close stays robust under those paths
		// rather than panicking in DisconnectVPN.
		if r.vpnClient != nil {
			if err := r.DisconnectVPN(); err != nil {
				slog.Error("Failed to disconnect VPN on shutdown", "error", err)
			}
		}
		r.cancel() // cancels context, unsubscribes all event listeners and stops child goroutines
		for _, shutdown := range r.shutdownFuncs {
			if err := shutdown(); err != nil {
				slog.Error("Failed to shutdown", "error", err)
			}
		}
	})
}

func (r *LocalBackend) startVPNStatusListeners() {
	r.startHelperReconcileListener()
	events.SubscribeContext(r.ctx, func(evt vpn.StatusUpdateEvent) {
		r.updateConnMetrics(evt.Status)
	})
	events.SubscribeContext(r.ctx, func(evt vpn.StatusUpdateEvent) {
		r.updateDataCapStream(evt.Status)
	})
	events.SubscribeContext(r.ctx, func(evt vpn.StatusUpdateEvent) {
		r.updateSelectionHistoryListener(evt.Status)
	})
	events.SubscribeContext(r.ctx, func(vpn.ExhaustionEvent) {
		r.refetchOnExhaustion()
	})
	events.SubscribeContext(r.ctx, func(evt vpn.NetworkEvent) {
		switch evt.EventType {
		case vpn.NetworkEventPaused:
			kindling.SetNetworkPaused(r.ctx, true)
		case vpn.NetworkEventWake:
			kindling.SetNetworkPaused(r.ctx, false)
		}
	})
	r.startSelectionFallbackListener()
	r.startDirectExitVPNListener()
}

// startDirectExitVPNListener re-checks the widget's direct exit on each VPN
// status change where it follows the VPN (directExitNeedsVPN).
func (r *LocalBackend) startDirectExitVPNListener() {
	if !directExitNeedsVPN() {
		return
	}
	events.SubscribeContext(r.ctx, func(vpn.StatusUpdateEvent) {
		recheckDirectExit()
	})
}

func (r *LocalBackend) startSelectionFallbackListener() {
	events.SubscribeContext(r.ctx, func(evt vpn.StatusUpdateEvent) {
		switch evt.Status {
		case vpn.Disconnected, vpn.ErrorStatus, vpn.Restarting:
			r.clearSelectedIfMissing()
		}
	})
}

func (r *LocalBackend) sessionInfo() vpn.SessionInfo {
	return vpn.SessionInfo{
		Status: r.vpnClient.Status,
		SelectedServer: func() (tag, city, country string) {
			server, _, err := r.SelectedServer()
			if err != nil || server == nil {
				return "", "", ""
			}
			return server.Tag, server.Location.City, server.Location.Country
		},
		Bytes: r.vpnClient.Bytes,
	}
}

func (r *LocalBackend) Sessions(limit int) []vpn.Session {
	return r.sessionHistory.Sessions(limit)
}

//////////////////
// Issue Report //
//////////////////

type issueReportMetadata struct {
	country            string
	deviceID           string
	reporter           *issue.IssueReporter
	splitTunnelEnabled bool
}

// buildIssueReportMetadata gathers the backend state needed to file an issue
// report. It is safe to call with a nil or partially initialized backend.
func (r *LocalBackend) buildIssueReportMetadata() issueReportMetadata {
	meta := issueReportMetadata{
		country:            settings.GetString(settings.CountryCodeKey),
		deviceID:           settings.GetString(settings.DeviceIDKey),
		splitTunnelEnabled: settings.GetBool(settings.SplitTunnelKey),
	}

	if r == nil {
		meta.reporter = newIssueReporter()
		return meta
	}
	if r.issueReporter != nil {
		meta.reporter = r.issueReporter
	} else {
		meta.reporter = newIssueReporter()
	}
	if r.deviceID != "" {
		meta.deviceID = r.deviceID
	}

	if r.confHandler != nil {
		if cfg, err := r.confHandler.GetConfig(); err != nil {
			slog.Warn("failed to get config", "error", err)
		} else {
			if cfg.Country != "" {
				meta.country = cfg.Country
			}
		}
	}

	if r.splitTunnelMgr != nil {
		meta.splitTunnelEnabled = r.splitTunnelMgr.IsEnabled()
	}

	return meta
}

// ReportIssue sends an issue report with current metadata and diagnostic attachments.
//
// ReportIssue is safe to call with a nil receiver; in that case it uses settings-backed metadata.
func (r *LocalBackend) ReportIssue(
	ctx context.Context,
	issueType issue.IssueType,
	description, email string,
	additionalAttachments []string,
	attachments []*issue.Attachment,
) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "report_issue")
	defer span.End()

	meta := r.buildIssueReportMetadata()

	attachmentPaths := baseIssueAttachments()
	if meta.splitTunnelEnabled {
		attachmentPaths = append(attachmentPaths, filepath.Join(settings.GetString(settings.DataPathKey), internal.SplitTunnelFileName))
	}
	attachmentPaths = append(attachmentPaths, additionalAttachments...)

	report := issue.IssueReport{
		Type:                  issueType,
		Description:           description,
		Email:                 email,
		CountryCode:           meta.country,
		DeviceID:              meta.deviceID,
		UserID:                settings.GetString(settings.UserIDKey),
		SubscriptionLevel:     settings.GetString(settings.UserLevelKey),
		Locale:                settings.GetString(settings.LocaleKey),
		Attachments:           attachments,
		AdditionalAttachments: attachmentPaths,
	}
	if err := meta.reporter.Report(ctx, report); err != nil {
		slog.Error("Failed to report issue", "error", err)
		return traces.RecordError(ctx, fmt.Errorf("failed to report issue: %w", err))
	}
	slog.Info("Issue reported successfully")
	return nil
}

func newIssueReporter() *issue.IssueReporter {
	tunnel := &http.Client{
		// Leaves time for the kindling fallback when the tunnel is up but stalls.
		Timeout: 2 * time.Minute,
		Transport: traces.NewRoundTripper(&http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "socks5", Host: common.TunnelProxyAddr}),
			IdleConnTimeout: 30 * time.Second,
		}),
	}
	return issue.NewIssueReporter(tunnel, kindling.HTTPClient(), slog.Default().With("service", "issue_reporter"))
}

// baseIssueAttachments returns a list of file paths to include as attachments in every issue report
// in order of importance.
func baseIssueAttachments() []string {
	logPath := settings.GetString(settings.LogPathKey)
	dataPath := settings.GetString(settings.DataPathKey)
	files := []string{
		filepath.Join(dataPath, internal.ConfigFileName),
		filepath.Join(dataPath, internal.ServersFileName),
		filepath.Join(dataPath, internal.DebugBoxOptionsFileName),
	}
	memdump := filepath.Join(logPath, internal.MemoryDumpFileName)
	if _, err := os.Stat(memdump); err == nil {
		// put memory dump first in the list so it's prioritized.
		files = append([]string{memdump}, files...)
	}
	return files
}

/////////////////
//  Settings   //
/////////////////

// UpdateConfig forces an immediate fetch of the latest configuration. It returns
// [config.ErrConfigFetchDisabled] if config fetching is disabled in settings.
func (r *LocalBackend) UpdateConfig() error {
	return r.confHandler.Fetch()
}

// Features returns the features available in the current configuration, returned from the server in the
// config response.
func (r *LocalBackend) Features() map[string]bool {
	_, span := otel.Tracer(tracerName).Start(context.Background(), "features")
	defer span.End()
	cfg, err := r.confHandler.GetConfig()
	if err != nil {
		slog.Info("Failed to get config for features", "error", err)
		return map[string]bool{}
	}
	if cfg == nil {
		slog.Info("No config available for features, returning empty map")
		return map[string]bool{}
	}
	slog.Debug("Returning features from config", "features", cfg.Features)
	if cfg.Features == nil {
		slog.Info("No features available in config, returning empty map")
		return map[string]bool{}
	}
	return cfg.Features
}

func (r *LocalBackend) PatchSettings(updates settings.Settings) error {
	curr := settings.GetAllFor(slices.Collect(maps.Keys(updates))...)
	diff := updates.Diff(curr)
	slog.Log(nil, log.LevelTrace, "Patching settings", "updates", updates, "current", curr, "diff", diff)
	// Reject an invalid split-tunnel policy before applying or persisting anything, so settings.json
	// can't hold a value the runtime would silently fall back to exclude for.
	if v, ok := diff[settings.SplitTunnelPolicyKey]; ok {
		if p, _ := v.(string); !vpn.SplitTunnelPolicy(p).Valid() {
			return fmt.Errorf("invalid %s: want %q or %q (got %T)",
				settings.SplitTunnelPolicyKey, vpn.SplitTunnelPolicyExclude, vpn.SplitTunnelPolicyInclude, v)
		}
	}
	if v, ok := diff[settings.SendLogsToSigNozKey]; ok {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("invalid %s: want a bool, got %T", settings.SendLogsToSigNozKey, v)
		}
	}
	// An explicit peer toggle is applied whether or not it changes the stored
	// value, and before any other handler: the stored value can lag the
	// runtime (a peer that stopped itself, or an "on" still starting), and
	// applyPeerShare, which persists it, is what orders toggles.
	var errs error
	peerValue, peerRequested := updates[settings.PeerShareEnabledKey]
	var peerOn, peerRegistered bool
	if peerRequested {
		on, ok := peerValue.(bool)
		if !ok {
			return fmt.Errorf("invalid %s: want a bool, got %T", settings.PeerShareEnabledKey, peerValue)
		}
		peerOn = on
		diff = maps.Clone(diff)
		delete(diff, settings.PeerShareEnabledKey)
	}
	// The rest of the patch is persisted before the toggle applies, so a
	// peer it starts registers with this patch's peer settings, such as
	// peer_serve_pool, rather than the previous ones.
	var patchErr error
	if len(diff) > 0 {
		patchErr = settings.Patch(diff)
	}
	// A failed save still applies the live value, so the country route, the
	// proxyless hedge and log upload follow it before the error returns: a
	// retry would be an empty diff.
	if _, ok := diff[settings.CountryCodeKey]; ok {
		r.CountryCodeChanged()
	}
	_, logUploadChanged := diff[settings.SendLogsToSigNozKey]
	if _, consentChanged := diff[settings.TelemetryKey]; logUploadChanged || consentChanged {
		if err := telemetry.UpdateLogUpload(); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	// The proxyless and smart routing settings switch the running hedge,
	// without a restart.
	_, proxylessChanged := diff[settings.ProxylessKey]
	if _, smartChanged := diff[settings.SmartRoutingKey]; proxylessChanged || smartChanged {
		r.applyProxyless()
	}
	if peerRequested {
		registered, err := r.applyPeerShareRegistered(peerOn)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		peerRegistered = registered
	}
	if len(diff) == 0 {
		return errs
	}
	if patchErr != nil {
		return errors.Join(errs, fmt.Errorf("failed to update settings: %w", patchErr))
	}
	_, autoChanged := diff[settings.AutoConnectKey]
	if _, selectedChanged := diff[settings.SelectedServerKey]; autoChanged || selectedChanged {
		emitSelectionSaved()
	}
	if _, ok := diff[settings.LocaleKey]; ok {
		r.RefreshUserMessages()
	}
	// telemetry settings
	if _, ok := diff[settings.TelemetryKey]; ok {
		if settings.GetBool(settings.TelemetryKey) {
			if err := r.startTelemetry(); err != nil {
				slog.Error("Failed to start telemetry", "error", err)
			}
		} else {
			r.stopTelemetry()
		}
	}

	// vpn settings
	//
	// settings.Patch above already persisted the whole diff, so an early return
	// on a handler error would leave a persisted key that no runtime state
	// matches — the divergence applyPeerShare's rollback exists to prevent. Run
	// every handler and join their errors so the caller sees write failures.
	if _, ok := diff[settings.SplitTunnelKey]; ok {
		if err := r.splitTunnelMgr.SetEnabled(settings.GetBool(settings.SplitTunnelKey)); err != nil {
			errs = errors.Join(errs, fmt.Errorf("set split-tunnel enabled: %w", err))
		}
	}
	if _, ok := diff[settings.SplitTunnelPolicyKey]; ok {
		if err := r.splitTunnelMgr.SetPolicy(vpn.SplitTunnelPolicy(settings.GetString(settings.SplitTunnelPolicyKey))); err != nil {
			errs = errors.Join(errs, fmt.Errorf("set split-tunnel policy: %w", err))
		}
	}
	if err := r.maybeRestartVPN(diff); err != nil {
		errs = errors.Join(errs, err)
	}
	// Drive the Unbounded widget proxy off the toggle change immediately
	// rather than waiting for the next NewConfigEvent to re-evaluate.
	// settings.Patch above has already persisted the new value, so go
	// straight to Apply() — SetEnabled would short-circuit on the
	// already-matching persisted value and never re-evaluate the
	// manager. Apply re-checks the three-condition predicate against
	// the cached server-side state and starts or stops accordingly.
	if _, ok := diff[settings.UnboundedKey]; ok {
		if err := unbounded.Apply(); err != nil {
			slog.Warn("unbounded apply failed", "error", err)
		}
	}
	// "Help others too" is sent when the peer registers, so a running peer
	// re-registers now. Not when this patch's toggle already brought the
	// registration in line (a Start, or a hand-off from pairings-only), or
	// turned sharing off. A patch that turned sharing on for a sharing run
	// already going changed nothing, so it re-registers.
	turnedOff := peerRequested && !peerOn
	// A pairings-only run registers serve_pool=false whatever the setting
	// says, so a change to it has nothing to re-register.
	if _, ok := diff[settings.PeerServePoolKey]; ok && !peerRegistered && !turnedOff && !r.peerForPairings.Load() {
		r.reregisterPeer()
	}
	return errs
}

// maybeRestartVPN restarts the VPN connection if either the ad block or smart routing settings
// were changed and the VPN is currently connected. Returns an error if the VPN restart fails;
// otherwise returns nil.
func (r *LocalBackend) maybeRestartVPN(updates settings.Settings) error {
	_, adBlockChanged := updates[settings.AdBlockKey]
	_, smartRoutingChanged := updates[settings.SmartRoutingKey]
	if (adBlockChanged || smartRoutingChanged) && r.vpnClient.Status() == vpn.Connected {
		slog.Info("Restarting VPN to apply new settings", "ad_block_changed", adBlockChanged, "smart_routing_changed", smartRoutingChanged)
		if err := r.RestartVPN(); err != nil {
			return fmt.Errorf(
				"failed to restart VPN (ad_block_changed=%v, smart_routing_changed=%v): %w",
				adBlockChanged, smartRoutingChanged, err,
			)
		}
	}
	return nil
}

/////////////////
//  telemetry  //
/////////////////

func (r *LocalBackend) startTelemetry() error {
	cfg, err := r.confHandler.GetConfig()
	if err == nil {
		if err := telemetry.Initialize(r.deviceID, *cfg, settings.IsPro()); err != nil {
			return fmt.Errorf("failed to initialize telemetry: %w", err)
		}
	}
	if r.telemetryCfgSub != nil {
		return nil
	}
	// subscribe to config changes to update telemetry config
	r.telemetryCfgSub = events.SubscribeContext(r.ctx, func(evt config.NewConfigEvent) {
		if !settings.GetBool(settings.TelemetryKey) {
			return
		}
		if evt.Old != nil && reflect.DeepEqual(evt.Old.OTEL, evt.New.OTEL) {
			// no changes to telemetry config, no need to update
			return
		}
		if err := telemetry.Initialize(r.deviceID, *evt.New, settings.IsPro()); err != nil {
			slog.Error("Failed to update telemetry config", "error", err)
		}
	})
	return nil
}

func (r *LocalBackend) stopTelemetry() {
	if r.telemetryCfgSub != nil {
		r.telemetryCfgSub.Unsubscribe()
		r.telemetryCfgSub = nil
	}
	r.teardownConnMetrics()
	telemetry.Close()
}

func (r *LocalBackend) updateConnMetrics(status vpn.VPNStatus) {
	if !settings.GetBool(settings.TelemetryKey) {
		return
	}
	r.connMetricsMu.Lock()
	defer r.connMetricsMu.Unlock()

	if status != vpn.Connected {
		r.vpnClient.SetConnObserver(nil)
		return
	}
	if !r.ensureConnMetricsObserverLocked() {
		return
	}
	r.vpnClient.SetConnObserver(r.connObserver)
}

func (r *LocalBackend) ensureConnMetricsObserverLocked() bool {
	if r.connObserver != nil {
		return true
	}

	ctx, cancel := context.WithCancel(r.ctx)
	observer, err := telemetry.StartConnectionMetrics(ctx, r.vpnClient.ActiveConnectionCount)
	if err != nil {
		cancel()
		slog.Warn("Failed to start connection metrics collection", "error", err)
		return false
	}

	r.connObserver = observer
	r.stopConnMetrics = cancel
	return true
}

// teardownConnMetrics fully detaches and releases the connection metrics observer.
func (r *LocalBackend) teardownConnMetrics() {
	r.connMetricsMu.Lock()
	defer r.connMetricsMu.Unlock()
	if r.vpnClient != nil {
		r.vpnClient.SetConnObserver(nil)
	}
	if r.stopConnMetrics != nil {
		r.stopConnMetrics()
		r.stopConnMetrics = nil
	}
	r.connObserver = nil
}

///////////////////////
// Server management //
///////////////////////

func (r *LocalBackend) AllServers() []*servers.Server {
	return r.srvManager.AllServers()
}

// GetServerByTag returns the server with the given tag, an exact match first.
// Otherwise a live reverse outbound, which the manager never holds, resolves
// to its friend's helper server, or to the friend's personal proxy when the
// manager has none; one that is not live resolves to nothing.
func (r *LocalBackend) GetServerByTag(tag string) (*servers.Server, bool) {
	if srv, found := r.serverByTag(tag); found {
		return srv, true
	}
	if friend, ok := lbA.HelperTagOfReverse(tag); ok {
		if !slices.Contains(r.reverseOutbounds(), tag) {
			return nil, false
		}
		if srv, found := r.srvManager.GetServerByTag(friend); found {
			return srv, true
		}
		return r.personalProxyServer(friend)
	}
	return r.serverByTag(tag)
}

// serverByTag is the manager's lookup plus the personal proxy groups, which
// are selectable by tag but never managed servers, so never listed.
func (r *LocalBackend) serverByTag(tag string) (*servers.Server, bool) {
	if tag == vpn.PersonalProxiesTag {
		return r.personalProxiesServer()
	}
	if friend, ok := vpn.ParsePersonalProxySelection(tag); ok {
		return r.personalProxyServer(friend)
	}
	return r.srvManager.GetServerByTag(tag)
}

// personalProxiesServer stands in for the tunnel's group over helper
// outbounds. It exists while the group does, and while a reverse friend's
// pairing lasts, so a selection of the group stands while the friend's
// reverse outbound is down.
func (r *LocalBackend) personalProxiesServer() (*servers.Server, bool) {
	if !r.personalProxiesLive() && len(r.reverseFriends.friends()) == 0 {
		return nil, false
	}
	return &servers.Server{Tag: vpn.PersonalProxiesTag, Type: lbC.TypeMutableURLTest}, true
}

// personalProxiesLive reports whether the tunnel's group exists: whether a
// helper or reverse outbound does.
func (r *LocalBackend) personalProxiesLive() bool {
	for _, srv := range r.srvManager.AllServers() {
		if lbA.IsHelperTag(srv.Tag) {
			return true
		}
	}
	return len(r.reverseOutbounds()) > 0
}

// startSelection is the selection a tunnel built now starts on for tag. A
// personal proxies group with no member yet starts on auto-select, which is
// not saved, until restoreSavedSelectionLocked selects the group.
func (r *LocalBackend) startSelection(tag string) string {
	if tag == vpn.PersonalProxiesTag && !r.personalProxiesLive() {
		return vpn.AutoSelectTag
	}
	return tag
}

func (r *LocalBackend) RemoveServers(tags []string) error {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	if r.beforeManagerRemove != nil {
		r.beforeManagerRemove()
	}
	// The manager reports what it removed even when the save fails, since the
	// servers left it in memory first: those are gone either way, so the
	// selection falls back first, then the tunnel follows.
	removed, err := r.srvManager.RemoveServers(tags)
	if err != nil {
		err = fmt.Errorf("failed to remove servers from ServerManager: %w", err)
	}
	gone := make([]string, 0, len(removed))
	for _, srv := range removed {
		gone = append(gone, srv.Tag)
	}
	if len(gone) == 0 {
		return err
	}
	r.clearSelectedIfMissingLocked()
	if rmErr := r.liveTunnel().RemoveOutbounds(gone); rmErr != nil && !errors.Is(rmErr, vpn.ErrTunnelNotConnected) {
		err = errors.Join(err, fmt.Errorf("failed to remove outbounds: %w", rmErr))
	}
	err = errors.Join(err, r.reconcileLiveHelpersLocked())
	r.restoreSavedSelectionLocked()
	return err
}

// AddServers adds user-supplied servers, clearing IsLantern on each.
func (r *LocalBackend) AddServers(list servers.ServerList) error {
	for _, srv := range list.Servers {
		srv.IsLantern = false
	}
	if err := r.srvManager.AddServers(list, false); err != nil {
		return fmt.Errorf("failed to add servers to ServerManager: %w", err)
	}
	if err := r.vpnClient.AddOutbounds(list); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
		return fmt.Errorf("failed to add outbounds to VPN client: %w", err)
	}
	return nil
}

func (r *LocalBackend) AddServersByJSON(config string) ([]string, error) {
	list, err := r.srvManager.AddServersByJSON(r.ctx, []byte(config))
	if err != nil {
		return nil, fmt.Errorf("failed to add servers by JSON: %w", err)
	}
	if err := r.vpnClient.AddOutbounds(*list); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
		return nil, fmt.Errorf("failed to add outbounds to VPN client: %w", err)
	}
	return list.Tags(), nil
}

func (r *LocalBackend) AddServersByURL(urls []string, skipCertVerification bool) ([]string, error) {
	list, err := r.srvManager.AddServersByURL(r.ctx, urls, skipCertVerification)
	if err != nil {
		return nil, fmt.Errorf("failed to add servers by URL: %w", err)
	}
	if err := r.vpnClient.AddOutbounds(*list); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
		return nil, fmt.Errorf("failed to add outbounds to VPN client: %w", err)
	}
	return list.Tags(), nil
}

// AddPrivateServer registers a private server and adds it to a running tunnel.
func (r *LocalBackend) AddPrivateServer(tag, ip string, port int, accessToken string, loc C.ServerLocation, joined bool) error {
	if err := r.srvManager.AddPrivateServer(tag, ip, port, accessToken, loc, joined); err != nil {
		return err
	}
	// Held from the lookup through the tunnel update, so a concurrent
	// RemoveServers can't drop the server in between and have it added back.
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	server, found := r.srvManager.GetServerByTag(tag)
	if !found {
		return fmt.Errorf("private server %q disappeared after registration", tag)
	}
	list := servers.ServerList{Servers: []*servers.Server{server}}
	if cfg, _ := r.confHandler.GetConfig(); cfg != nil {
		list.URLOverrides = cfg.BanditURLOverrides
	}
	if err := r.vpnClient.AddOutbounds(list); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
		return fmt.Errorf("failed to add private server to VPN client: %w", err)
	}
	return nil
}

func (r *LocalBackend) InviteToPrivateServer(ip string, port int, accessToken string, inviteName string) (string, error) {
	return r.srvManager.InviteToPrivateServer(ip, port, accessToken, inviteName)
}

func (r *LocalBackend) RevokePrivateServerInvite(ip string, port int, accessToken string, inviteName string) error {
	return r.srvManager.RevokePrivateServerInvite(ip, port, accessToken, inviteName)
}

// liveTunnel is the part of vpn.VPNClient the backend drives the running
// tunnel through.
type liveTunnel interface {
	Connect(ctx context.Context, boxOptions vpn.BoxOptions) error
	CurrentAutoSelectedServer() (string, error)
	AnnouncedAutoSelectedServer() string
	CurrentSelectedServer() (string, error)
	ManualSelection() (string, bool)
	SelectedPersonalProxy() string
	UpdateOutbounds(list servers.ServerList) error
	SelectServer(tag string) error
	RemoveOutbounds(tags []string) error
	ReconcileHelpers(helpers servers.ServerList) error
	Restart(boxOptions vpn.BoxOptions) error
	Status() vpn.VPNStatus
}

func (r *LocalBackend) liveTunnel() liveTunnel {
	if r.live != nil {
		return r.live
	}
	return r.vpnClient
}

// maxRetainedLanternServers caps the number of working Lantern servers retained
// across config updates.
const maxRetainedLanternServers = 60

// updateServers adds the servers in list that are not already present and
// pass [servers.Server.CheckHostAccess], and refreshes the helper servers in
// list whose options changed. When evict is set it first evicts retained
// Lantern servers (see lanternServersToEvict). Only a newly received config
// may evict: a config that was already applied, such as the cached one at
// startup, would judge its own offers a second time.
func (r *LocalBackend) updateServers(list servers.ServerList, evict bool) (err error) {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	// Whatever else fails, fall back from a selection the manager no longer
	// holds and bring the tunnel's helpers in line with the manager, in that
	// order, so traffic is on auto-select before a selected helper goes.
	defer func() {
		r.clearSelectedIfMissingLocked()
		err = errors.Join(err, r.reconcileLiveHelpersLocked())
		r.restoreSavedSelectionLocked()
	}()
	// MSN 3.4.11 SR-REJECT: with the Iran pool selected, a draw that carries
	// no '-ir-free-' server is a geo-detection miss (the server draws the
	// pool from the config fetch's exit IP; on the 3.4.10 field network no
	// fetch served the IR pool at all). Reject the non-ir-free offers so the
	// manager, the picker and the box options keep the ir-free servers the
	// device already holds instead of rotating into a dead worldwide pool —
	// the pre-3.4.11 filter kept the previous list in the TUNNEL but still
	// let this same draw refill the manager and the picker. Helpers and
	// user-added servers never carry the -ir-free- marker and are kept; the
	// ir-free offers of a mixed draw are kept too.
	if vpn.IrPoolSelected() {
		hasIr := false
		for _, srv := range list.Servers {
			if strings.Contains(srv.Tag, "-ir-free-") {
				hasIr = true
				break
			}
		}
		if !hasIr {
			kept := slices.DeleteFunc(list.Servers, func(srv *servers.Server) bool {
				return srv.IsLantern && !lbA.IsHelperTag(srv.Tag) &&
					!strings.Contains(srv.Tag, "-ir-free-")
			})
			if len(kept) < len(list.Servers) {
				slog.Warn("RADIANCE_POOL=iran: draw had no ir-free servers; keeping the held pool",
					"offered", len(list.Servers), "kept", len(kept))
			}
			list.Servers = kept
		} else {
			list.Servers = slices.DeleteFunc(list.Servers, func(srv *servers.Server) bool {
				return srv.IsLantern && !lbA.IsHelperTag(srv.Tag) &&
					!strings.Contains(srv.Tag, "-ir-free-")
			})
		}
	}
	existing := r.srvManager.AllServers()
	existingTags := serverTagSet(existing)
	incomingHelpers := make(map[string]struct{})
	for _, srv := range list.Servers {
		if lbA.IsHelperTag(srv.Tag) {
			incomingHelpers[srv.Tag] = struct{}{}
		}
	}
	// A helper's tag is stable per pairing and route while the credentials in
	// its options rotate, so a known helper tag with new options replaces the
	// stored server. Other known tags keep the server first offered.
	var refreshed []*servers.Server
	offeredTags := make(map[string]struct{}, len(list.Servers))
	list.Servers = slices.DeleteFunc(list.Servers, func(srv *servers.Server) bool {
		if _, exists := existingTags[srv.Tag]; exists {
			offeredTags[srv.Tag] = struct{}{}
			if stored, found := r.srvManager.GetServerByTag(srv.Tag); found &&
				stored.IsLantern && lbA.IsHelperTag(srv.Tag) && !r.srvManager.HasOptions(srv) {
				if err := srv.CheckHostAccess(); err != nil {
					slog.Warn("Not refreshing helper server whose options grant host access", "tag", srv.Tag, "error", err)
					return true
				}
				refresh := srv.Clone()
				refresh.SelectionHistory = stored.SelectionHistory
				refreshed = append(refreshed, refresh)
			}
			return true
		}
		if err := srv.CheckHostAccess(); err != nil {
			slog.Warn("Dropping config server whose options grant host access", "tag", srv.Tag, "error", err)
			return true
		}
		offeredTags[srv.Tag] = struct{}{}
		return false
	})

	// A helper the config no longer carries ended its pairing. This holds for
	// the cached config applied at startup too: the process can stop after a
	// new config is saved but before it is applied, and later fetches of the
	// same config bring no update.
	toRemove := endedHelpers(existing, incomingHelpers)
	if evict {
		var selectedTag string
		var selected servers.Server
		if err := settings.GetStruct(settings.SelectedServerKey, &selected); err == nil {
			selectedTag = selected.Tag
		}

		tagsToEvict := lanternServersToEvict(existing, offeredTags, maxRetainedLanternServers, selectedTag)
		if len(tagsToEvict) > 0 {
			slog.Debug(
				"Evicting retained Lantern servers to make room for new config batch",
				"count", len(tagsToEvict),
				"tags", tagsToEvict,
			)
		}
		toRemove = append(toRemove, tagsToEvict...)
	}
	if len(toRemove) > 0 {
		if _, err := r.srvManager.RemoveServers(toRemove); err != nil {
			return fmt.Errorf("remove retained Lantern servers: %w", err)
		}
	}

	slog.Debug(
		"Adding new Lantern servers from config update",
		"count", len(list.Servers),
		"tags", slices.Collect(maps.Keys(serverTagSet(list.Servers))),
	)
	if err := r.srvManager.AddServers(list, false); err != nil {
		return fmt.Errorf("add Lantern servers: %w", err)
	}
	if len(refreshed) > 0 {
		slog.Debug("Refreshing helper servers whose options changed", "count", len(refreshed))
		if err := r.srvManager.AddServers(servers.ServerList{Servers: refreshed}, true); err != nil {
			return fmt.Errorf("refresh helper servers: %w", err)
		}
	}
	// updateOutbounds evicts any outbound absent from the list; include all
	// servers so user-added outbounds aren't removed on a Lantern config update.
	allList := servers.ServerList{
		Servers:           r.srvManager.AllServers(),
		URLOverrides:      list.URLOverrides,
		AutoSelectOptions: list.AutoSelectOptions,
	}
	// An evicted selection falls back to auto-select before the update removes
	// it from the tunnel: the manual selector would otherwise pick an
	// arbitrary member meanwhile.
	r.clearSelectedIfMissingLocked()
	outboundErr := r.liveTunnel().UpdateOutbounds(allList)
	if outboundErr != nil && !errors.Is(outboundErr, vpn.ErrTunnelNotConnected) {
		return fmt.Errorf("failed to update VPN outbounds: %w", outboundErr)
	}
	return nil
}

// startHelperReconcileListener reconciles each tunnel that comes up with the
// helpers the server manager holds, and restores the saved selection on it.
// A connect or restart builds its tunnel from options captured before it took
// the VPN lock, so a config update in between, which found no tunnel or the
// previous one, may have ended, added or rotated a helper the new tunnel does
// not reflect. While connected, the restore also runs every
// selectionRestoreInterval.
func (r *LocalBackend) startHelperReconcileListener() {
	events.SubscribeContext(r.ctx, func(evt vpn.StatusUpdateEvent) {
		switch evt.Status {
		case vpn.Connected:
			r.tunnelConnected()
		case vpn.Disconnected, vpn.ErrorStatus:
			r.setSelectionRestoreTicker(false)
		}
	})
}

func (r *LocalBackend) tunnelConnected() {
	r.selectionMu.Lock()
	if err := r.reconcileLiveHelpersLocked(); err != nil {
		slog.Warn("Failed to reconcile the new tunnel's helpers", "error", err)
	}
	r.restoreSavedSelectionLocked()
	r.selectionMu.Unlock()
	r.setSelectionRestoreTicker(true)
}

// selectionRestoreInterval is how often a connected tunnel's saved selection
// is restored, catching a member that arrived by a path that did not restore
// it. A var so tests can shorten it.
var selectionRestoreInterval = 30 * time.Second

// setSelectionRestoreTicker starts, or restarts, or stops the periodic
// restoreSavedSelection. It ends with r.ctx either way.
func (r *LocalBackend) setSelectionRestoreTicker(on bool) {
	r.selectionRestoreMu.Lock()
	defer r.selectionRestoreMu.Unlock()
	if r.stopSelectionRestore != nil {
		r.stopSelectionRestore()
		r.stopSelectionRestore = nil
	}
	if !on {
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan struct{})
	// Waiting means no restore selects after the ticker is stopped. Callers
	// do not hold selectionMu, which a restore takes.
	r.stopSelectionRestore = func() { cancel(); <-done }
	go func() {
		defer close(done)
		ticker := time.NewTicker(selectionRestoreInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.restoreSavedSelection()
			}
		}
	}()
}

// reconcileLiveHelpersLocked makes the tunnel's helpers the ones the server
// manager holds, which is the record of the pairings that remain: helpers
// that ended are removed (the last also withdraws the personal proxies
// group), new ones added and rotated credentials swapped in. updateOutbounds
// alone can keep an ended helper dialable: it skips an empty list and keeps
// old outbounds when every new one fails to load. With no tunnel up there is
// nothing to do; the next one is reconciled when it connects. The caller must
// hold r.selectionMu.
func (r *LocalBackend) reconcileLiveHelpersLocked() error {
	var helpers servers.ServerList
	for _, srv := range r.srvManager.AllServers() {
		if lbA.IsHelperTag(srv.Tag) {
			helpers.Servers = append(helpers.Servers, srv)
		}
	}
	if err := r.liveTunnel().ReconcileHelpers(helpers); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
		return fmt.Errorf("reconcile helpers: %w", err)
	}
	return nil
}

func serverTagSet(list []*servers.Server) map[string]struct{} {
	tags := make(map[string]struct{}, len(list))
	for _, srv := range list {
		tags[srv.Tag] = struct{}{}
	}
	return tags
}

// endedHelpers returns the Lantern helper servers in existing that the config
// no longer carries (incomingHelpers): their pairings ended. When the last one
// goes, so does the personal proxies group, and a selection of it falls back
// to auto-select.
func endedHelpers(existing []*servers.Server, incomingHelpers map[string]struct{}) []string {
	var ended []string
	for _, srv := range existing {
		if !srv.IsLantern || !lbA.IsHelperTag(srv.Tag) {
			continue
		}
		if _, carried := incomingHelpers[srv.Tag]; !carried {
			ended = append(ended, srv.Tag)
		}
	}
	return ended
}

// lanternServersToEvict returns the Lantern server tags to evict for a config
// offering the tags in offered. Hard-demoted servers are always evicted, even
// when offered or selected. Otherwise, servers that are neither offered nor
// selectedTag are evicted, least recently updated SelectionHistory first
// (missing sorts oldest), until the retained and newly offered servers fit in
// limit. Offered and selected servers are never evicted to make room, so the
// total can exceed limit.
// Helper servers are the user's pairings, not offers to rotate: they are
// never evicted and take no retention slot (see endedHelpers for those whose
// pairing ended).
func lanternServersToEvict(
	existing []*servers.Server,
	offered map[string]struct{},
	limit int,
	selectedTag string,
) []string {
	existingTags := serverTagSet(existing)
	retained := 0
	for tag := range offered {
		if _, ok := existingTags[tag]; !ok && !lbA.IsHelperTag(tag) {
			retained++
		}
	}

	tagsToEvict := make([]string, 0)
	candidates := make([]*servers.Server, 0, len(existing))
	for _, srv := range existing {
		if !srv.IsLantern {
			continue
		}
		if lbA.IsHelperTag(srv.Tag) {
			continue
		}
		if isHardDemoted(srv) {
			tagsToEvict = append(tagsToEvict, srv.Tag)
			continue
		}
		retained++
		if _, isOffered := offered[srv.Tag]; isOffered || srv.Tag == selectedTag {
			continue
		}
		candidates = append(candidates, srv)
	}

	overflow := min(max(retained-limit, 0), len(candidates))
	if overflow == 0 {
		return tagsToEvict
	}
	slices.SortFunc(candidates, compareSelectionAge)
	for _, srv := range candidates[:overflow] {
		tagsToEvict = append(tagsToEvict, srv.Tag)
	}
	return tagsToEvict
}

func isHardDemoted(srv *servers.Server) bool {
	return srv.SelectionHistory != nil && srv.SelectionHistory.HardDemoted
}

func compareSelectionAge(a, b *servers.Server) int {
	return selectionUpdatedAt(a).Compare(selectionUpdatedAt(b))
}

func selectionUpdatedAt(srv *servers.Server) time.Time {
	if srv.SelectionHistory == nil {
		return time.Time{}
	}
	return srv.SelectionHistory.UpdatedAt
}

// clearSelectedIfMissing reverts the persisted selection to its fallback (see
// fallbackFor) when the selected server is no longer present in the manager.
func (r *LocalBackend) clearSelectedIfMissing() {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	r.clearSelectedIfMissingLocked()
}

// clearSelectedIfMissingLocked is clearSelectedIfMissing for a caller holding
// r.selectionMu.
func (r *LocalBackend) clearSelectedIfMissingLocked() {
	// Auto-select has no server to go missing, and saving it again would
	// announce a selection that did not change.
	if settings.GetBool(settings.AutoConnectKey) {
		return
	}
	var selected servers.Server
	if err := settings.GetStruct(settings.SelectedServerKey, &selected); err != nil {
		return
	}
	if _, found := r.serverByTag(selected.Tag); found {
		return
	}
	r.fallBackLocked(selected.Tag)
}

const selectionHistoryFlushInterval = 5 * time.Second

func (r *LocalBackend) updateSelectionHistoryListener(status vpn.VPNStatus) {
	r.selectionHistoryMu.Lock()
	defer r.selectionHistoryMu.Unlock()
	switch status {
	case vpn.Connected:
		if r.stopSelectionHistoryListener != nil {
			r.stopSelectionHistoryListener()
			r.stopSelectionHistoryListener = nil
		}
		storage := r.vpnClient.HistoryStorage()
		if storage == nil {
			return
		}
		ctx, cancel := context.WithCancel(r.ctx)
		r.stopSelectionHistoryListener = cancel
		hook := make(chan struct{}, 1)
		storage.SetHook(func(string) {
			// Per-tag granularity isn't useful — flushSelectionHistory
			// iterates every server. Non-blocking send so storage
			// writes never block on a slow flush.
			select {
			case hook <- struct{}{}:
			default:
			}
		})
		go r.runSelectionHistoryListener(ctx, storage, hook)
		if r.selectionReportInterval() > 0 {
			r.selectionReporter.reset()
			go r.runSelectionReporter(ctx, storage)
		}
		slog.Debug("Started selection history listener")
	case vpn.Disconnected, vpn.ErrorStatus:
		if r.stopSelectionHistoryListener != nil {
			r.stopSelectionHistoryListener()
			r.stopSelectionHistoryListener = nil
			slog.Debug("Stopped selection history listener")
		}
	}
}

// runSelectionHistoryListener coalesces per-result hook notifications into a periodic flush so the
// servers file isn't rewritten for each parallel probe completion. A final flush runs on shutdown so
// any results that arrived since the last tick are persisted.
func (r *LocalBackend) runSelectionHistoryListener(ctx context.Context, storage vpn.AutoSelectHistoryStorage, hook <-chan struct{}) {
	ticker := time.NewTicker(selectionHistoryFlushInterval)
	defer ticker.Stop()
	dirty := true // start dirty so a seed/result present before the listener started still gets persisted
	for {
		select {
		case <-ctx.Done():
			if dirty {
				r.flushSelectionHistory(storage)
			}
			return
		case <-hook:
			dirty = true
		case <-ticker.C:
			if dirty {
				r.flushSelectionHistory(storage)
				dirty = false
			}
		}
	}
}

func (r *LocalBackend) flushSelectionHistory(storage vpn.AutoSelectHistoryStorage) {
	history := r.collectSelectionHistory(storage)
	if len(history) == 0 {
		return
	}

	if err := r.srvManager.UpdateSelectionHistory(history); err != nil {
		slog.Warn("Failed to persist selection history", "error", err)
	}
}

func (r *LocalBackend) collectSelectionHistory(storage vpn.AutoSelectHistoryStorage) map[string]servers.SelectionHistory {
	history := make(map[string]servers.SelectionHistory)
	for _, srv := range r.srvManager.AllServers() {
		if h := storage.Load(srv.Tag); h != nil {
			history[srv.Tag] = *h
		}
	}
	return history
}

// selectionReportInterval is the server-configured report cadence. Zero is
// returned if reporting is disabled or the config is unavailable.
func (r *LocalBackend) selectionReportInterval() time.Duration {
	cfg, _ := r.confHandler.GetConfig()
	if cfg == nil || cfg.RouteSelectionReportIntervalSeconds <= 0 {
		return 0
	}

	return time.Duration(cfg.RouteSelectionReportIntervalSeconds) * time.Second
}

func (r *LocalBackend) runSelectionReporter(ctx context.Context, storage vpn.AutoSelectHistoryStorage) {
	runReportLoop(ctx, r.selectionReportInterval, func() {
		r.reportSelectionHistory(ctx, storage)
	})
}

// runReportLoop calls report once per interval() until the context is canceled
// or interval() returns a non-positive duration. The interval is re-derived each
// cycle so a changed cadence takes effect the next tick and a dropped interval
// stops the loop within one cycle.
func runReportLoop(ctx context.Context, interval func() time.Duration, report func()) {
	for {
		wait := interval()
		if wait <= 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			report()
		}
	}
}

func (r *LocalBackend) reportSelectionHistory(ctx context.Context, storage vpn.AutoSelectHistoryStorage) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "report_selection_history")
	defer span.End()

	cfg, _ := r.confHandler.GetConfig()
	if cfg == nil || len(cfg.BanditReportTokens) == 0 {
		return
	}
	snapshot := r.collectSelectionHistory(storage)
	if len(snapshot) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, selectionReportTimeout)
	defer cancel()
	if err := r.selectionReporter.report(ctx, snapshot, cfg.BanditReportTokens); err != nil {
		slog.Warn("Failed to report selection history", "error", err)
		span.RecordError(err)
	}
}

/////////////////
//     VPN     //
/////////////////

func (r *LocalBackend) VPNStatus() vpn.VPNStatus {
	return r.vpnClient.Status()
}

// ErrConnectInProgress signals that a connect attempt is already running. It is
// benign, not a failure: bursts of connect requests (e.g. rapid taps while every
// attempt is blocked in a censored network) must not each drive a full tunnel
// bring-up.
var ErrConnectInProgress = errors.New("connect already in progress")

func (r *LocalBackend) ConnectVPN(ctx context.Context, tag string) error {
	// Shed overlapping connects before getBoxOptions: it assembles the full
	// outbound set, and without this each queued request also stacks a full
	// sing-box bring-up behind vpnClient's mutex.
	if !r.connectMu.TryLock() {
		return ErrConnectInProgress
	}
	defer r.connectMu.Unlock()

	// waitCtx bounds only the waits below; the tunnel gets ctx, so a later
	// cancel can never reach a tunnel this started.
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.pendingConnectMu.Lock()
	r.pendingConnect = cancel
	r.pendingConnectMu.Unlock()
	defer func() {
		r.pendingConnectMu.Lock()
		r.pendingConnect = nil
		r.pendingConnectMu.Unlock()
	}()

	if tag == "" || tag == vpn.AutoSelectTag {
		tag = vpn.AutoSelectTag
		// A platform restart reconnects through here on auto; keep the saved selection.
		if r.liveTunnel().Status() == vpn.Restarting {
			tag = r.savedSelectionTag()
		}
	}
	if err := r.awaitConnectable(waitCtx, tag); err != nil {
		return err
	}
	if tag != vpn.AutoSelectTag {
		if _, found := r.serverByTag(tag); !found {
			return fmt.Errorf("no server found with tag %s", tag)
		}
	}
	if err := r.checkConnectSelection(waitCtx, tag); err != nil {
		return err
	}
	// A disconnect during the waits leaves nothing to start.
	if err := waitCtx.Err(); err != nil {
		return fmt.Errorf("connect cancelled: %w", err)
	}
	bOptions := r.getBoxOptions()
	bOptions.InitialServer = r.startSelection(tag)
	r.setConnectPending(true)
	if err := r.liveTunnel().Connect(ctx, bOptions); err != nil {
		r.setConnectPending(false)
		return fmt.Errorf("failed to connect VPN: %w", err)
	}
	r.persistConnectedSelection(tag)
	return nil
}

func (r *LocalBackend) setConnectPending(pending bool) {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	r.connectPending = pending
}

// persistConnectedSelection persists the tag a connect selected. A config
// update during the connect may have withdrawn it from the manager after the
// tunnel was built with it; that update's own fallback then saw the old
// setting, so the selection falls back here instead.
func (r *LocalBackend) persistConnectedSelection(tag string) {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	r.connectPending = false
	if tag != vpn.AutoSelectTag {
		if _, found := r.serverByTag(tag); !found {
			slog.Info("Connected server was withdrawn during the connect, falling back", "tag", tag)
			r.fallBackLocked(tag)
			return
		}
	}
	if !r.settleFriendLocked(tag) {
		return
	}
	r.persistSelection(tag)
	// Reapplied even when the tunnel seems on it: auto mode reports the
	// server it chose, which can be the one just pinned.
	if _, friend := vpn.ParsePersonalProxySelection(tag); !friend {
		if err := r.liveTunnel().SelectServer(r.startSelection(tag)); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
			slog.Warn("Failed to apply the connected selection", "tag", tag, "error", err)
		}
	}
	// Members may have arrived since the tunnel was built without them.
	r.restoreSavedSelectionLocked()
}

// settleFriendLocked moves a running tunnel that is not on tag's friend, as
// one built while the friend had no member is not, onto it. It returns false
// only if the tunnel refused and tag's fallback was committed instead. A
// reverse friend whose outbound is not up yet is not committed away from:
// the tunnel runs on the fallback until restoreSavedSelectionLocked.
// The caller must hold r.selectionMu.
func (r *LocalBackend) settleFriendLocked(tag string) bool {
	friend, ok := vpn.ParsePersonalProxySelection(tag)
	if !ok || r.liveTunnel().SelectedPersonalProxy() == friend {
		return true
	}
	// The tunnel may have been built from options captured before the friend
	// was added, and the Connected listener's reconcile may not have run yet.
	if err := r.reconcileLiveHelpersLocked(); err != nil {
		slog.Warn("Failed to reconcile helpers before taking up the selected personal proxy", "error", err)
	}
	err := r.liveTunnel().SelectServer(tag)
	if err == nil || errors.Is(err, vpn.ErrTunnelNotConnected) {
		return true
	}
	if r.reverseFriends.has(friend) && !slices.Contains(r.reverseOutbounds(), lbA.ReverseHelperTag(friend)) {
		fallback := r.fallbackFor(tag)
		if err := r.liveTunnel().SelectServer(fallback); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
			slog.Warn("Failed to switch to the fallback until the reverse outbound is up", "fallback", fallback, "error", err)
		}
		return true
	}
	slog.Info("Tunnel could not take up the selected personal proxy, falling back",
		"unavailable", errors.Is(err, vpn.ErrPersonalProxyUnavailable))
	r.fallBackLocked(tag)
	return false
}

// awaitConnectable blocks until the connect has something to dial, or ctx is
// done. Connecting with neither a config nor a server of the user's own
// produces "no outbounds or endpoints found", and on mobile the process that
// reports that failure is the one hosting the config fetch it needed, so
// failing fast deadlocks the first run.
func (r *LocalBackend) awaitConnectable(ctx context.Context, tag string) error {
	if r.connectable(tag) {
		return nil
	}
	slog.Info("Waiting for a config before connecting", "tag", tag)
	ready := make(chan struct{})
	// Subscribe, not SubscribeOnce: this unsubscribes on return anyway, and
	// SubscribeUntil's self-referential `sub` capture is read from the callback
	// goroutine without synchronization.
	//
	// Emit runs each callback on its own goroutine, so configs landing together
	// can both reach this. Closing twice would panic.
	var closeOnce sync.Once
	sub := events.Subscribe(func(config.NewConfigEvent) {
		closeOnce.Do(func() { close(ready) })
	})
	defer sub.Unsubscribe()
	// A config can land between the check above and the subscription.
	if r.connectable(tag) {
		return nil
	}
	select {
	case <-ready:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("no config to connect with: %w", ctx.Err())
	}
}

// connectable reports whether a connect can proceed right now: either a config
// has been loaded, or the user has a server of their own to dial without one.
func (r *LocalBackend) connectable(tag string) bool {
	if _, err := r.confHandler.GetConfig(); err == nil {
		return true
	}
	if tag != vpn.AutoSelectTag {
		_, found := r.serverByTag(tag)
		return found
	}
	return len(r.srvManager.AllServers()) > 0
}

func (r *LocalBackend) getBoxOptions() vpn.BoxOptions {
	// ignore error, we can still connect with default options if config is not available for some reason
	cfg, _ := r.confHandler.GetConfig()
	bOptions := vpn.BoxOptions{
		BasePath: settings.GetString(settings.DataPathKey),
	}
	if cfg != nil {
		bOptions.Options = cfg.Options
		bOptions.NonSelectableOutbounds = cfg.NonSelectableOutbounds
		bOptions.BanditURLOverrides = cfg.BanditURLOverrides
		bOptions.AutoSelectOptions = vpn.DecodeAutoSelectOptions(cfg.AutoSelectOptions)
		if settings.GetBool(settings.SmartRoutingKey) {
			bOptions.SmartRouting = cfg.SmartRouting
			// Full tunnel sends everything through the proxy, so only smart
			// routing builds the proxyless hedge; the flag and the setting
			// switch it.
			bOptions.Proxyless = proxylessOptions(cfg)
		}
		if settings.GetBool(settings.AdBlockKey) {
			bOptions.AdBlock = cfg.AdBlock
		}
	}
	managedServers := r.srvManager.AllServers()
	appendManagedServerOptions(&bOptions.Options, managedServers)
	bOptions.LanternServerTags = lanternServerTags(cfg, managedServers)

	seed := make(map[string]lbA.TagHistory)
	for _, srv := range managedServers {
		if srv.SelectionHistory != nil {
			seed[srv.Tag] = *srv.SelectionHistory
		}
	}
	if len(seed) > 0 {
		bOptions.SelectionHistorySeed = seed
	}
	return bOptions
}

// lanternServerTags collects the tags of the Lantern servers in cfg and
// managed, to seed the tunnel's client-info Injector, which covers outbounds
// only. Every cfg outbound and endpoint is a Lantern server; managed servers
// carry the flag explicitly.
func lanternServerTags(cfg *config.Config, managed []*servers.Server) []string {
	seen := make(map[string]struct{})
	var tags []string
	add := func(tag string) {
		if tag == "" {
			return
		}
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	if cfg != nil {
		for _, out := range cfg.Options.Outbounds {
			add(out.Tag)
		}
		for _, ep := range cfg.Options.Endpoints {
			add(ep.Tag)
		}
	}
	for _, srv := range managed {
		if srv.IsLantern {
			add(srv.Tag)
		}
	}
	if IrPoolSelected() {
		// MSN 3.4.11 SR-REJECT: the pin in buildOptions drops the
		// non-ir-free members; the injector's tag list must match what
		// survives, or a dropped worldwide tag lingers here and the
		// injector keeps attributing data usage to an outbound that no
		// longer exists.
		tags = slices.DeleteFunc(tags, func(tag string) bool {
			return !strings.Contains(tag, "-ir-free-") && !lbA.IsHelperTag(tag) &&
				!lbA.IsReverseHelperTag(tag)
		})
	}
	return tags
}

// appendManagedServerOptions adds server-manager options that are missing from
// the current config options. Config options remain authoritative for duplicate
// tags, but retained Lantern servers and user servers stay connectable on cold
// tunnel start.
func appendManagedServerOptions(options *option.Options, managed []*servers.Server) {
	existingTags := optionTagSet(*options)
	for _, srv := range managed {
		switch opts := srv.Options.(type) {
		case option.Outbound:
			tag := opts.Tag
			if tag == "" {
				continue
			}
			if _, exists := existingTags[tag]; exists {
				continue
			}
			options.Outbounds = append(options.Outbounds, opts)
			existingTags[tag] = struct{}{}
		case option.Endpoint:
			tag := opts.Tag
			if tag == "" {
				continue
			}
			if _, exists := existingTags[tag]; exists {
				continue
			}
			options.Endpoints = append(options.Endpoints, opts)
			existingTags[tag] = struct{}{}
		}
	}
}

// optionTagSet returns the outbound and endpoint tags already present in the
// box options.
func optionTagSet(options option.Options) map[string]struct{} {
	tags := make(map[string]struct{}, len(options.Outbounds)+len(options.Endpoints))
	for _, out := range options.Outbounds {
		tags[out.Tag] = struct{}{}
	}
	for _, ep := range options.Endpoints {
		tags[ep.Tag] = struct{}{}
	}
	return tags
}

func (r *LocalBackend) DisconnectVPN() error {
	// A connect still waiting has no tunnel to stop; stop it from starting one.
	r.pendingConnectMu.Lock()
	if r.pendingConnect != nil {
		r.pendingConnect()
	}
	r.pendingConnectMu.Unlock()
	return r.vpnClient.Disconnect()
}

// RestartVPN rebuilds the tunnel on the saved selection, including one saved
// during the restart.
func (r *LocalBackend) RestartVPN() error {
	bOptions := r.restartBoxOptions()
	// selectionMu is not held across the restart: a platform restart may
	// reconnect through this backend, which takes it.
	if err := r.liveTunnel().Restart(bOptions); err != nil {
		return err
	}
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	tag := r.savedSelectionTag()
	if _, ok := vpn.ParsePersonalProxySelection(tag); ok {
		r.settleFriendLocked(tag)
		return nil
	}
	if start := r.startSelection(tag); start != bOptions.InitialServer {
		if err := r.liveTunnel().SelectServer(start); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
			return fmt.Errorf("apply the selection saved during the restart: %w", err)
		}
	}
	return nil
}

// restartBoxOptions captures the outbounds and the saved selection under
// r.selectionMu, so a config update cannot pair a selection with outbounds
// that lack it.
func (r *LocalBackend) restartBoxOptions() vpn.BoxOptions {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	bOptions := r.getBoxOptions()
	if r.beforeRestartSelection != nil {
		r.beforeRestartSelection()
	}
	bOptions.InitialServer = r.startSelection(r.savedSelectionTag())
	return bOptions
}

// savedSelectionTag returns the saved selection's tag, or AutoSelectTag when
// none is saved or serverByTag no longer finds it.
func (r *LocalBackend) savedSelectionTag() string {
	var saved servers.Server
	if !settings.GetBool(settings.AutoConnectKey) &&
		settings.GetStruct(settings.SelectedServerKey, &saved) == nil && saved.Tag != "" {
		if _, found := r.serverByTag(saved.Tag); found {
			return saved.Tag
		}
	}
	return vpn.AutoSelectTag
}

// ResetNetwork drops the VPN's connections and re-seeds its interface state,
// and has the reverse client re-register from the new network.
func (r *LocalBackend) ResetNetwork() {
	r.vpnClient.ResetNetwork()
	r.reverseNetworkChanged()
	r.pairingRouteNetworkChanged()
}

// ResetNetworkForMonitor resets connections only if listener belongs to the current tunnel.
// The reverse client re-registers from the new network either way.
func (r *LocalBackend) ResetNetworkForMonitor(listener libbox.InterfaceUpdateListener) {
	r.vpnClient.ResetNetworkForMonitor(listener)
	r.reverseNetworkChanged()
	r.pairingRouteNetworkChanged()
}

// Pause pauses the VPN for a device sleep.
func (r *LocalBackend) Pause() { r.vpnClient.Pause() }

// Wake wakes the VPN after a device sleep.
func (r *LocalBackend) Wake() { r.vpnClient.Wake() }

// SelectServer selects the server identified by tag. The empty string is treated as [vpn.AutoSelectTag].
func (r *LocalBackend) SelectServer(tag string) error {
	if tag == "" {
		tag = vpn.AutoSelectTag
	}
	r.selectionMu.Lock()
	// Resolved before the tunnel changes: a server a config update just
	// withdrew could still be live there, but its selection could not be
	// persisted.
	if friend, ok := vpn.ParsePersonalProxySelection(tag); ok && !r.friendReach(friend).selectable() {
		r.selectionMu.Unlock()
		return fmt.Errorf("failed to select server: %w", vpn.ErrPersonalProxyUnavailable)
	}
	// Saved as resolved here: a friend's ticket can lapse while the tunnel
	// switches, and the switch still has to be saved.
	var server *servers.Server
	if tag != vpn.AutoSelectTag {
		srv, found := r.serverByTag(tag)
		if !found {
			r.selectionMu.Unlock()
			if tag == vpn.PersonalProxiesTag {
				return fmt.Errorf("failed to select server: %w", vpn.ErrPersonalProxiesUnavailable)
			}
			return fmt.Errorf("failed to select server: no server found with tag %s", tag)
		}
		server = srv
	}
	if err := r.liveTunnel().SelectServer(tag); err != nil {
		r.selectionMu.Unlock()
		return fmt.Errorf("failed to select server: %w", err)
	}
	if server == nil {
		r.persistSelection(vpn.AutoSelectTag)
	} else {
		r.persistServer(server)
	}
	r.selectionMu.Unlock()
	if r.vpnClient.Status() == vpn.Connected {
		if sel, _, err := r.SelectedServer(); err == nil && sel != nil {
			r.sessionHistory.HandleServerChange(sel.Tag, sel.Location.City, sel.Location.Country)
		}
	}
	return nil
}

// persistSelection records the user's server choice in settings. tag must be
// AutoSelectTag or the tag of a server known to the manager.
func (r *LocalBackend) persistSelection(tag string) {
	if tag == vpn.AutoSelectTag {
		if err := settings.Patch(settings.Settings{
			settings.AutoConnectKey:    true,
			settings.SelectedServerKey: nil,
		}); err != nil {
			slog.Warn("failed to update settings", "error", err)
			return
		}
		emitSelectionSaved()
		return
	}
	server, found := r.serverByTag(tag)
	if !found {
		slog.Warn("no server found for tag, skipping settings persistence", "tag", tag)
		return
	}
	r.persistServer(server)
}

// persistServer saves server as the user's server choice without looking it up
// again. It clears server.Options.
func (r *LocalBackend) persistServer(server *servers.Server) {
	server.Options = nil
	if err := settings.Patch(settings.Settings{
		settings.AutoConnectKey:    false,
		settings.SelectedServerKey: server,
	}); err != nil {
		slog.Warn("Failed to save selected server in settings", "error", err)
		return
	}
	emitSelectionSaved()
	slog.Info("Selected server", "tag", server.Tag, "type", server.Type)
}

// emitSelectionSaved announces a save of the selection that just completed.
func emitSelectionSaved() {
	events.Emit(vpn.SelectionSavedEvent{})
}

// VPNConnections returns a list of the active connections. If there are no connections and the
// tunnel is open, an empty slice is returned without an error.
func (r *LocalBackend) VPNConnections() ([]vpn.Connection, error) {
	return r.vpnClient.Connections()
}

func (r *LocalBackend) VPNThroughput() (vpn.ThroughputSnapshot, error) {
	return r.vpnClient.Throughput()
}

// SelectedServer returns the currently selected server and whether the server is still available.
// The server may no longer be available if it was removed from the manager since it was selected.
func (r *LocalBackend) SelectedServer() (*servers.Server, bool, error) {
	if settings.GetBool(settings.AutoConnectKey) {
		tag, err := r.liveTunnel().CurrentAutoSelectedServer()
		if err != nil {
			return nil, false, fmt.Errorf("failed to get current auto-selected server: %w", err)
		}
		server, found := r.GetServerByTag(tag)
		return server, found, nil
	}
	if !settings.Exists(settings.SelectedServerKey) {
		tag, err := r.liveTunnel().CurrentSelectedServer()
		if err != nil {
			return nil, false, fmt.Errorf("failed to get current selected server: %w", err)
		}
		if tag == "" {
			return nil, false, fmt.Errorf("no selected server")
		}
		server, found := r.GetServerByTag(tag)
		return server, found, nil
	}
	var selected servers.Server
	if err := settings.GetStruct(settings.SelectedServerKey, &selected); err != nil {
		return nil, false, fmt.Errorf("failed to get selected server from settings: %w", err)
	}
	server, found := r.serverByTag(selected.Tag)
	stillExists := found &&
		server.IsLantern == selected.IsLantern &&
		server.Type == selected.Type &&
		server.Location == selected.Location
	return &selected, stillExists, nil
}

// CurrentAutoSelectedServer returns the tag of the server that is currently auto-selected by the
// VPN client.
func (r *LocalBackend) CurrentAutoSelectedServer() (string, error) {
	return r.liveTunnel().CurrentAutoSelectedServer()
}

// AnnouncedAutoSelectedServer returns the auto selection the running tunnel's change listener
// last announced, or "" when there is none.
func (r *LocalBackend) AnnouncedAutoSelectedServer() string {
	return r.liveTunnel().AnnouncedAutoSelectedServer()
}

func (r *LocalBackend) startSessionAutoSelectListener() {
	events.SubscribeContext(r.ctx, func(evt vpn.AutoSelectedEvent) {
		if evt.Selected == "" || r.vpnClient.Status() != vpn.Connected {
			return
		}
		var city, country string
		if server, found := r.srvManager.GetServerByTag(evt.Selected); found {
			city = server.Location.City
			country = server.Location.Country
		}
		r.sessionHistory.HandleServerChange(evt.Selected, city, country)
	})
}

func (r *LocalBackend) startAutoSelectedListener() {
	var (
		mu     sync.Mutex
		cancel context.CancelFunc
		done   <-chan struct{}
	)
	events.SubscribeContext(r.ctx, func(evt vpn.StatusUpdateEvent) {
		mu.Lock()
		defer mu.Unlock()
		if cancel != nil {
			cancel()
			<-done
			cancel = nil
		}
		if evt.Status == vpn.Connected {
			var ctx context.Context
			ctx, cancel = context.WithCancel(r.ctx)
			done = r.vpnClient.AutoSelectedChangeListener(ctx)
		}
	})
}

// ClearTunnelCache removes the tunnel cache from the configured data directory.
// If removal was deferred because the tunnel was active, it restarts the tunnel
// to apply the clear immediately.
func (r *LocalBackend) ClearTunnelCache() error {
	shouldRestart, err := r.vpnClient.ClearTunnelCache(settings.GetString(settings.DataPathKey))
	if err != nil || !shouldRestart {
		return err
	}

	err = r.RestartVPN()
	if err == nil || errors.Is(err, vpn.ErrTunnelNotConnected) {
		return nil
	}
	return err
}

func (r *LocalBackend) RunOfflineURLTests() error {
	cfg, err := r.confHandler.GetConfig()
	if err != nil {
		return fmt.Errorf("no config available: %w", err)
	}
	svrs := r.srvManager.AllServers()
	slog.Debug("Running offline URL tests", "server_count", len(svrs), "url_override_count", len(cfg.BanditURLOverrides))
	results, err := r.vpnClient.RunOfflineURLTests(
		// Backend shutdown must stop probes before they use a tunnel started by another process.
		r.ctx,
		settings.GetString(settings.DataPathKey),
		servers.ServerList{Servers: svrs}.Outbounds(),
		cfg.BanditURLOverrides,
		vpn.DecodeAutoSelectOptions(cfg.AutoSelectOptions),
	)
	if err != nil {
		return err
	}
	now := time.Now()
	histories := make(map[string]servers.SelectionHistory, len(results))
	for tag, delay := range results {
		// Offline pre-warm produces only a single success delay per tag;
		// shape it as a probe-success snapshot so the production tunnel's
		// AutoSelectHistoryStorage can seed cold-start ranking from it
		// without further translation.
		histories[tag] = lbA.TagHistory{
			LastSuccessDelayMs: uint32(delay),
			LastOutcomeAt:      now,
			UpdatedAt:          now,
		}
	}
	if len(histories) > 0 {
		if err := r.srvManager.UpdateSelectionHistory(histories); err != nil {
			slog.Warn("Failed to persist offline selection history", "error", err)
		}
		events.Emit(vpn.URLTestCompleteEvent{Source: vpn.URLTestSourceOffline, Count: len(histories), Results: results})
		selected, err := r.vpnClient.CurrentAutoSelectedServer()
		if err != nil {
			slog.Warn("Failed to get current auto-selected server after URL tests", "error", err)
		} else {
			events.Emit(vpn.AutoSelectedEvent{Selected: selected})
		}
	}
	return nil
}

// defaultExhaustionRefetchGap rate-limits exhaustion-driven refetches
// so a misbehaving config handler can't hammer /config-new.
var defaultExhaustionRefetchGap = time.Minute

// exhaustionGate rate-limits exhaustion-driven refetches. lastAt is
// recorded before the fetch runs so a failing fetcher doesn't
// tight-loop.
type exhaustionGate struct {
	mu     sync.Mutex
	lastAt time.Time
}

func (g *exhaustionGate) allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if !g.lastAt.IsZero() && now.Sub(g.lastAt) < defaultExhaustionRefetchGap {
		return false
	}
	g.lastAt = now
	return true
}

func (r *LocalBackend) refetchOnExhaustion() {
	if !r.exhaustionGate.allow() {
		return
	}
	if err := r.confHandler.Fetch(); err != nil {
		slog.Warn("MutableAutoSelect exhaustion refetch failed", "error", err)
	}
}

////////////////////
// Helper invites //
////////////////////

var errHelperRelayUnavailable = errors.New("helper relay unavailable")

// HelperRelay sends one helper-invite request for the app (see
// helper.Relayer). The op is checked first, so an unknown op is refused even
// on a backend whose relayer failed to build.
func (r *LocalBackend) HelperRelay(ctx context.Context, op string, body []byte) (helper.RelayResult, error) {
	if op != helper.OpRefreshTickets && !helper.IsRelayOp(op) {
		return helper.RelayResult{}, helper.ErrUnknownOp
	}
	if r.helperRelay == nil {
		return helper.RelayResult{}, errHelperRelayUnavailable
	}
	return r.helperRelay.Relay(ctx, op, body)
}

// sharingCounters reads both sharing modes' snapshots for the activity
// tracker.
func (r *LocalBackend) sharingCounters() (bool, string, uint64) {
	// Bytes and epoch unfiltered, so paired traffic counts and a hand-off
	// isn't a counter reset; running filtered, so an idle pairings-only route
	// isn't time spent sharing.
	ps := peer.Snapshot{}
	if r.peerClient != nil {
		ps = r.peerClient.RelaySnapshot()
		ps.Running = ps.Running && !r.peerClient.CurrentStatus().PairingsOnly
	}
	us := unbounded.CurrentSnapshot()
	return ps.Running || us.Running, ps.Epoch + "/" + us.Epoch, ps.BytesDown + ps.BytesUp + us.BytesDown + us.BytesUp
}

// HelperActivity is today's sharing totals for the app's "You're helping"
// section.
func (r *LocalBackend) HelperActivity() helper.Activity {
	if r.helperActivity == nil {
		return helper.Activity{Day: time.Now().In(helper.LocalZone()).Format("2006-01-02")}
	}
	return r.helperActivity.Today()
}

// HelperLive is whether each helper pairing's friend is connected to this
// volunteer now.
func (r *LocalBackend) HelperLive() helper.LiveSnapshot {
	return helper.DefaultLive.Snapshot()
}

// SetHelperPairingKeys replaces this device's helper pairing keys (see
// helper.PairingKeys.Set).
func (r *LocalBackend) SetHelperPairingKeys(keys map[string]helper.PairingKey) {
	r.helperPairingKeys.Set(keys)
}

// HelperPairingKeys returns the store SetHelperPairingKeys writes to; it is
// nil on a backend not built by NewLocalBackend.
func (r *LocalBackend) HelperPairingKeys() *helper.PairingKeys {
	return r.helperPairingKeys
}

// UseHelperPairingKeysForTest sets the store SetHelperPairingKeys writes to,
// for tests of the IPC route, which cannot build a full backend.
func (r *LocalBackend) UseHelperPairingKeysForTest(p *helper.PairingKeys) {
	r.helperPairingKeys = p
}

// SetHelperRelayForTest sets the relayer HelperRelay uses, for tests of the
// IPC route, which cannot build a full backend.
func (r *LocalBackend) SetHelperRelayForTest(rl *helper.Relayer) {
	r.helperRelay = rl
}

// SetLiveTunnelForTest replaces the tunnel every backend tunnel call goes to,
// for tests of the IPC route, which cannot build a full backend.
func (r *LocalBackend) SetLiveTunnelForTest(t liveTunnel) {
	r.live = t
}

//////////////////
// Split Tunnel //
/////////////////

func (r *LocalBackend) SplitTunnelFilters() vpn.SplitTunnelFilter {
	return r.splitTunnelMgr.Filters()
}

func (r *LocalBackend) AddSplitTunnelItems(items vpn.SplitTunnelFilter) error {
	return r.splitTunnelMgr.AddItems(items)
}

func (r *LocalBackend) RemoveSplitTunnelItems(items vpn.SplitTunnelFilter) error {
	return r.splitTunnelMgr.RemoveItems(items)
}

/////////////
// Account //
/////////////

func (r *LocalBackend) NewUser(ctx context.Context) (*account.UserData, error) {
	return r.accountClient.NewUser(ctx)
}

func (r *LocalBackend) Login(ctx context.Context, email, password string) (*account.UserData, error) {
	return r.accountClient.Login(ctx, email, password)
}

func (r *LocalBackend) Logout(ctx context.Context, email string) (*account.UserData, error) {
	return r.accountClient.Logout(ctx, email)
}

func (r *LocalBackend) FetchUserData(ctx context.Context) (*account.UserData, error) {
	return r.accountClient.FetchUserData(ctx)
}

func (r *LocalBackend) VerifyPassword(ctx context.Context, email, password string) error {
	_, err := r.accountClient.VerifyPassword(ctx, email, password)
	return err
}

func (r *LocalBackend) StartChangeEmail(ctx context.Context, newEmail, password string) error {
	return r.accountClient.StartChangeEmail(ctx, newEmail, password)
}

func (r *LocalBackend) CompleteChangeEmail(ctx context.Context, newEmail, password, code string) error {
	return r.accountClient.CompleteChangeEmail(ctx, newEmail, password, code)
}

func (r *LocalBackend) StartRecoveryByEmail(ctx context.Context, email string) error {
	return r.accountClient.StartRecoveryByEmail(ctx, email)
}

func (r *LocalBackend) CompleteRecoveryByEmail(ctx context.Context, email, newPassword, code string) error {
	return r.accountClient.CompleteRecoveryByEmail(ctx, email, newPassword, code)
}

func (r *LocalBackend) DeleteAccount(ctx context.Context, email, password string) (*account.UserData, error) {
	return r.accountClient.DeleteAccount(ctx, email, password)
}

func (r *LocalBackend) SignUp(ctx context.Context, email, password string) ([]byte, *account.SignupResponse, error) {
	return r.accountClient.SignUp(ctx, email, password)
}

func (r *LocalBackend) SignupEmailConfirmation(ctx context.Context, email, code string) error {
	return r.accountClient.SignupEmailConfirmation(ctx, email, code)
}

func (r *LocalBackend) SignupEmailResendCode(ctx context.Context, email string) error {
	return r.accountClient.SignupEmailResendCode(ctx, email)
}

func (r *LocalBackend) ValidateEmailRecoveryCode(ctx context.Context, email, code string) error {
	return r.accountClient.ValidateEmailRecoveryCode(ctx, email, code)
}

func (r *LocalBackend) DataCapInfo(ctx context.Context) (*account.DataCapInfo, error) {
	return r.accountClient.DataCapInfo(ctx)
}

// DataCapUpdates returns the channel that receives datacap updates from the
// upstream SSE stream. The stream runs while the VPN is connected; the channel
// is never closed so callers should select on it alongside a context or other
// signal.
func (r *LocalBackend) DataCapUpdates() <-chan *account.DataCapInfo {
	return r.dataCapCh
}

func (r *LocalBackend) updateDataCapStream(status vpn.VPNStatus) {
	r.dataCapMu.Lock()
	defer r.dataCapMu.Unlock()
	if status == vpn.Connected {
		if r.stopDataCap != nil {
			return // already running
		}
		ctx, cancel := context.WithCancel(r.ctx)
		r.stopDataCap = cancel
		go func() {
			_ = r.accountClient.DataCapStream(ctx, func(info *account.DataCapInfo) {
				// Non-blocking send; drops stale updates if the reader is slow.
				select {
				case r.dataCapCh <- info:
				default:
					select {
					case <-r.dataCapCh:
					default:
					}
					r.dataCapCh <- info
				}
			})
		}()
		slog.Debug("Started datacap SSE stream")
	} else if r.stopDataCap != nil {
		r.stopDataCap()
		r.stopDataCap = nil
		slog.Debug("Stopped datacap SSE stream")
	}
}

func (r *LocalBackend) RemoveDevice(ctx context.Context, deviceID string) (*account.LinkResponse, error) {
	return r.accountClient.RemoveDevice(ctx, deviceID)
}

func (r *LocalBackend) OAuthLoginCallback(ctx context.Context, oAuthToken string) (*account.UserData, error) {
	return r.accountClient.OAuthLoginCallback(ctx, oAuthToken)
}

// OAuthDeviceLimitCallback stores the account identity from a device-limit
// OAuth token without logging the user in.
func (r *LocalBackend) OAuthDeviceLimitCallback(ctx context.Context, oAuthToken string) error {
	return r.accountClient.OAuthDeviceLimitCallback(ctx, oAuthToken)
}

func (r *LocalBackend) OAuthLoginURL(ctx context.Context, provider string) (string, error) {
	return r.accountClient.OAuthLoginURL(ctx, provider)
}

func (r *LocalBackend) UserDevices() ([]settings.Device, error) {
	return settings.Devices()
}

func (r *LocalBackend) UserData() (*account.UserData, error) {
	var userData account.UserData
	if err := settings.GetStruct(settings.UserDataKey, &userData); err != nil {
		return nil, fmt.Errorf("failed to get user data from settings: %w", err)
	}
	return &userData, nil
}

// CurrentUserMessage returns the current account's pending message.
func (r *LocalBackend) CurrentUserMessage() (*clientmessage.Message, error) {
	if r.userMessages == nil {
		return nil, nil
	}
	return r.userMessages.Current()
}

func (r *LocalBackend) startUserMessages() {
	if r.userMessages == nil {
		return
	}
	events.SubscribeContext(r.ctx, func(account.UserChangeEvent) {
		r.userMessages.Refresh()
	})
	r.userMessages.Start(r.ctx)
}

// RefreshUserMessages schedules an immediate eligibility refresh when messaging is enabled.
func (r *LocalBackend) RefreshUserMessages() {
	if r.userMessages != nil {
		r.userMessages.Refresh()
	}
}

// AcknowledgeUserMessage records that the UI displayed displayID.
func (r *LocalBackend) AcknowledgeUserMessage(displayID, accountID string) error {
	if r.userMessages == nil {
		return clientmessage.ErrMessageNotPending
	}
	return r.userMessages.Acknowledge(displayID, accountID)
}

// SetUserMessageActivity adjusts polling for the app lifecycle.
func (r *LocalBackend) SetUserMessageActivity(active bool) {
	if r.userMessages != nil {
		r.userMessages.SetActivity(active)
	}
}

///////////////////
// Subscriptions //
///////////////////

func (r *LocalBackend) ActivationCode(ctx context.Context, email, resellerCode string) (*account.PurchaseResponse, error) {
	return r.accountClient.ActivationCode(ctx, email, resellerCode)
}

func (r *LocalBackend) NewStripeSubscription(ctx context.Context, email, planID, couponCode string) (string, error) {
	return r.accountClient.NewStripeSubscription(ctx, email, planID, couponCode)
}

func (r *LocalBackend) PaymentRedirect(ctx context.Context, data account.PaymentRedirectData) (string, error) {
	return r.accountClient.PaymentRedirect(ctx, data)
}

func (r *LocalBackend) ReferralAttach(ctx context.Context, code, channel string) (*account.ReferralAttachResponse, error) {
	return r.accountClient.ReferralAttach(ctx, code, channel)
}

func (r *LocalBackend) StripeBillingPortalURL(ctx context.Context) (string, error) {
	return r.accountClient.StripeBillingPortalURL(ctx,
		common.GetProServerURL(), settings.GetString(settings.UserIDKey), settings.GetString(settings.TokenKey),
	)
}

func (r *LocalBackend) SubscriptionPaymentRedirectURL(ctx context.Context, data account.PaymentRedirectData) (string, error) {
	return r.accountClient.SubscriptionPaymentRedirectURL(ctx, data)
}

func (r *LocalBackend) SubscriptionPlans(ctx context.Context, channel string) (string, error) {
	return r.accountClient.SubscriptionPlans(ctx, channel)
}

func (r *LocalBackend) VerifySubscription(ctx context.Context, service account.SubscriptionService, data map[string]string) (string, error) {
	return r.accountClient.VerifySubscription(ctx, service, data)
}

func (r *LocalBackend) RestoreSubscription(ctx context.Context, service account.SubscriptionService, data map[string]string) (*account.RestoreSubscriptionResponse, error) {
	return r.accountClient.RestoreSubscription(ctx, service, data)
}

const (
	publicIPAttempts       = 8
	publicIPAttemptTimeout = 5 * time.Second
)

var (
	// publicIPDirectPoll is how often detectPublicIP checks whether traffic leaves directly again.
	publicIPDirectPoll = 30 * time.Second
	publicIPBackoff    = func() *common.Backoff { return common.NewBackoff(2*time.Second, 2*time.Minute) }
)

// detectPublicIP records the device's public IP for API requests and returns it, or nil if it
// gave up. It retries with backoff because the lookup services are often slow or blocked where
// Lantern is used most. Without the IP, the API geolocates whichever relay delivered the request.
// The lookups don't bypass the VPN, so it only looks up while direct reports true and discards a
// result if the tunnel came up during the lookup. It gives up after publicIPAttempts lookups or
// when ctx is done.
func detectPublicIP(ctx context.Context, direct func() bool, lookup func(context.Context) (*publicip.DetectResult, error)) net.IP {
	backoff := publicIPBackoff()
	for attempt := 1; attempt <= publicIPAttempts; attempt++ {
		if !waitForDirect(ctx, direct) {
			return nil
		}
		network := common.PublicIPNetwork()
		attemptCtx, cancel := context.WithTimeout(ctx, publicIPAttemptTimeout)
		result, err := lookup(attemptCtx)
		cancel()
		switch {
		case err != nil:
			slog.Warn("Failed to get public IP", "error", err, "attempt", attempt)
		case !direct():
			slog.Debug("Discarded public IP looked up while the VPN came up", "attempt", attempt)
			continue
		default:
			common.SetPublicIPFrom(result.IP.String(), network)
			// IP intentionally omitted — Lantern users in censored regions
			// can't safely have their public IP in routinely-collected
			// client logs. Confidence + sources are enough for operator
			// triage; the actual IP is correlated server-side via traces.
			slog.Info("Detected public IP", "confidence", result.Confidence, "sources", result.Sources, "attempt", attempt)
			return result.IP
		}
		if attempt < publicIPAttempts {
			backoff.Wait(ctx)
		}
	}
	return nil
}

// loadStoredPublicIP makes the IP stored by a previous session available to API requests, so
// requests sent before detection completes (or while the VPN is up and detection can't run) still
// carry it. It returns the stored IP, or "" if there is none.
func loadStoredPublicIP() string {
	stored := settings.GetString(settings.PublicIPKey)
	if net.ParseIP(stored) == nil {
		return ""
	}
	common.SetPublicIP(stored)
	return stored
}

// storePublicIP persists ip for future sessions and reports whether it is
// significantly different from stored, the value requests have carried so far.
func storePublicIP(ip net.IP, stored string) bool {
	if err := settings.Set(settings.PublicIPKey, ip.String()); err != nil {
		slog.Warn("Failed to store public IP", "error", err)
	}
	return publicIPDiffers(net.ParseIP(stored), ip)
}

// publicIPDiffers reports whether ip falls outside prev's /16 (IPv4) or /32 (IPv6), roughly the
// span of one ISP allocation, so an address rotating within a carrier's pool doesn't count. A
// change of address family doesn't count either: dual-stack devices can detect either family, and
// the two can't be compared.
func publicIPDiffers(prev, ip net.IP) bool {
	if prev == nil {
		return true
	}
	prev4, ip4 := prev.To4(), ip.To4()
	switch {
	case (prev4 == nil) != (ip4 == nil):
		return false
	case ip4 != nil:
		mask := net.CIDRMask(16, 32)
		return !prev4.Mask(mask).Equal(ip4.Mask(mask))
	default:
		mask := net.CIDRMask(32, 128)
		return !prev.Mask(mask).Equal(ip.Mask(mask))
	}
}

// waitForDirect blocks until direct reports true, and reports false if ctx ends first.
func waitForDirect(ctx context.Context, direct func() bool) bool {
	for !direct() {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(publicIPDirectPoll):
		}
	}
	return ctx.Err() == nil
}

func lookupPublicIP(ctx context.Context) (*publicip.DetectResult, error) {
	return publicip.Detect(ctx, &publicip.Config{
		Timeout:      publicIPAttemptTimeout,
		MinConsensus: 1,
		Methods:      publicip.DefaultMethods(),
	})
}
