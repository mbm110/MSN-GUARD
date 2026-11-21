package lanternbridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/vpn"
)

type byteTotals struct {
	up   int64
	down int64
}

func persistentDeviceID(dataDir string) (string, error) {
	path := filepath.Join(dataDir, ".lanternsecrets", ".deviceid")
	if existing, err := os.ReadFile(path); err == nil && len(existing) > 0 {
		return string(existing), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("create Lantern device identity directory: %w", err)
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate Lantern device ID: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	id := fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(raw[0:4]), hex.EncodeToString(raw[4:6]), hex.EncodeToString(raw[6:8]), hex.EncodeToString(raw[8:10]), hex.EncodeToString(raw[10:16]))
	if err := os.WriteFile(path, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("persist Lantern device ID: %w", err)
	}
	return id, nil
}

var state struct {
	mu            sync.RWMutex
	backend       *backend.LocalBackend
	backendCancel context.CancelFunc
	connectCancel context.CancelFunc
	connectID     uint64
	lastErr       string
	initialized   bool
	initErr       error
	trafficMu     sync.Mutex
	trafficSeen   map[string]byteTotals
	completedUp   int64
	completedDn   int64

	// retentionPollCancel stops the internal retention poller (see
	// startRetentionPolling). Guarded by trafficMu together with the maps.
	retentionPollCancel context.CancelFunc
}

// Init initializes Radiance once for this app process. The novpn build tag
// replaces Radiance's TUN inbound with a loopback-only mixed HTTP/SOCKS
// listener; MSN-GUARD remains the sole owner of Android's VpnService and TUN.
//
// The locale MUST be the device's real locale, not a hardcoded one: Radiance
// picks its direct-path DNS server from it (fa-IR → AliDNS, ru → Yandex,
// anything else → Quad9). The reference app passes the device locale the same
// way, and a hardcoded "en" made every direct-outbound lookup ride DoH to
// Quad9, which Iranian DPI resets — the field logs showed exactly that EOF
// cascade killing Lantern sessions after minutes of connected time.
// Init starts the Radiance backend. socksAddress is retained for the CLI's
// flag compatibility but is inert since 3.4.0 (the TUN build has no SOCKS
// inbound; the engine's own loopback tunnel proxy on 127.0.0.1:14986 serves
// app-side probes instead).
func Init(dataDir, logDir, socksAddress, locale string) error {
	state.mu.Lock()

	if state.backend != nil || state.initialized {
		state.mu.Unlock()
		return state.initErr
	}
	if dataDir == "" || logDir == "" {
		state.mu.Unlock()
		return errors.New("Radiance data and log directories are required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	device, err := persistentDeviceID(dataDir)
	if err != nil {
		state.initErr = err
		state.initialized = true
		state.mu.Unlock()
		return err
	}
	b, err := backend.NewLocalBackend(ctx, backend.Options{
		DataDir:                  dataDir,
		LogDir:                   logDir,
		Locale:                  locale,
		DeviceID:                 device,
		LogLevel:                 "info",
		TelemetryConsent:         false,
		PreserveTelemetryConsent: false,
		// The Android sidecar has no gomobile bindings, so it supplies a pure-Go
		// platform interface; without one sing-box builds a netlink network
		// monitor that Android bans for unprivileged apps.
		PlatformInterface: newPlatformInterface(),
		// 3.4.0: no RADIANCE_USE_SOCKS_PROXY / RADIANCE_SOCKS_ADDRESS overrides
		// anymore — those belonged to the novpn proxy build. The real TUN
		// inbound (boxoptions_default.go) is compiled in now and takes the fd
		// our OpenTun serves from the app's handoff.
	})
	if err != nil {
		cancel()
		state.lastErr = err.Error()
		state.initErr = fmt.Errorf("initialize Radiance: %w", err)
		state.initialized = true
		state.mu.Unlock()
		return state.initErr
	}

	state.backend = b
	state.backendCancel = cancel
	state.lastErr = ""
	state.initialized = true
	state.initErr = nil
	state.mu.Unlock()
	// Start asynchronously. The control socket is already live, so the Android
	// service can report precise config/account errors instead of timing out
	// while Radiance performs its first network prewarm.
	go b.Start()
	return nil
}

// Connect waits for Radiance's current public configuration and connects using
// its automatic server selector. No private server credentials are required.
// Ready reports whether Radiance finished initialization and can serve control requests.
func Ready() bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.backend != nil && state.initErr == nil
}

func Connect(timeoutSeconds int64) error {
	b := currentBackend()
	if b == nil {
		return errors.New("Radiance is not initialized")
	}
	if b.VPNStatus() == vpn.Connected {
		return nil
	}
	if timeoutSeconds < 30 {
		timeoutSeconds = 30
	}
	if timeoutSeconds > 300 {
		timeoutSeconds = 300
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	state.mu.Lock()
	state.connectID++
	connectID := state.connectID
	state.connectCancel = cancel
	state.mu.Unlock()
	defer func() {
		cancel()
		state.mu.Lock()
		if state.connectID == connectID {
			state.connectCancel = nil
		}
		state.mu.Unlock()
	}()

	resetTraffic()
	err := b.ConnectVPN(ctx, vpn.AutoSelectTag)
	setLastError(err)
	if err != nil {
		return fmt.Errorf("connect to public Lantern servers: %w", err)
	}
	startRetentionPolling()
	return nil
}

// startRetentionPolling folds the active-connection counters into the
// retained totals every 150 ms.
//
// The retention design (TrafficJSON below) only folds a closed connection's
// bytes if SOME poll observed it while it was still active. The app polls
// /traffic at 1 Hz, and the CI probe made the gap precise: two real HTTP
// fetches through the SOCKS inbound closed between the app's one-second
// ticks and their bytes were folded into NOTHING — the exact shape of the
// field report (Lantern carries traffic while Down/Up/Speed sit at 0; only
// long-lived connections like Telegram ever surface). A busy tunnel can also
// make the 1.5 s /traffic request itself time out, skipping the tick
// entirely.
//
// This internal poller closes the gap without touching Radiance: 150 ms is
// well under the lifetime of any connection that carries payload, and
// TrafficJSON is safe to call concurrently (trafficMu + the tracker's own
// atomics). It is stopped in Disconnect and restarted per Connect, exactly
// like the counters themselves.
func startRetentionPolling() {
	state.trafficMu.Lock()
	if state.retentionPollCancel != nil {
		state.retentionPollCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	state.retentionPollCancel = cancel
	state.trafficMu.Unlock()
	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = TrafficJSON()
			}
		}
	}()
}

// CancelConnect interrupts a connection attempt without waiting for the
// backend's tunnel lock. It is safe to call from Android's service main thread.
func CancelConnect() {
	state.mu.RLock()
	cancel := state.connectCancel
	state.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

// Disconnect stops the Radiance tunnel but keeps its backend initialized so a
// later reconnect does not repeat global process initialization.
func Disconnect() error {
	b := currentBackend()
	if b == nil {
		return nil
	}
	CancelConnect()
	if b.VPNStatus() == vpn.Disconnected {
		return nil
	}
	_ = TrafficJSON() // capture the last active-connection counters before close
	state.trafficMu.Lock()
	for _, previous := range state.trafficSeen {
		state.completedUp += previous.up
		state.completedDn += previous.down
	}
	state.trafficSeen = make(map[string]byteTotals)
	if state.retentionPollCancel != nil {
		state.retentionPollCancel()
		state.retentionPollCancel = nil
	}
	state.trafficMu.Unlock()
	err := b.DisconnectVPN()
	setLastError(err)
	if err != nil {
		return fmt.Errorf("disconnect Radiance: %w", err)
	}
	return nil
}

// Status returns Radiance's current VPN status as a stable string.
func Status() string {
	b := currentBackend()
	if b == nil {
		return string(vpn.Disconnected)
	}
	return string(b.VPNStatus())
}

// TrafficJSON returns cumulative byte totals as {"tx":...,"rx":...}.
// Radiance exposes active connection byte counters; this wrapper retains the
// last observed totals when a connection closes between polling intervals.
func TrafficJSON() string {
	b := currentBackend()
	if b == nil {
		return "{\"tx\":0,\"rx\":0}"
	}
	connections, err := b.VPNConnections()
	if err != nil {
		return currentTrafficJSON()
	}

	current := make(map[string]byteTotals, len(connections))
	var liveUp, liveDown int64
	for _, connection := range connections {
		v := byteTotals{up: connection.Uplink, down: connection.Downlink}
		current[connection.ID] = v
		liveUp += v.up
		liveDown += v.down
	}

	state.trafficMu.Lock()
	for id, previous := range state.trafficSeen {
		if _, stillActive := current[id]; !stillActive {
			state.completedUp += previous.up
			state.completedDn += previous.down
		}
	}
	state.trafficSeen = current
	up := state.completedUp + liveUp
	down := state.completedDn + liveDown
	state.trafficMu.Unlock()

	encoded, err := json.Marshal(map[string]int64{"tx": up, "rx": down})
	if err != nil {
		return "{\"tx\":0,\"rx\":0}"
	}
	return string(encoded)
}

func currentTrafficJSON() string {
	state.trafficMu.Lock()
	defer state.trafficMu.Unlock()
	up, down := state.completedUp, state.completedDn
	for _, active := range state.trafficSeen {
		up += active.up
		down += active.down
	}
	encoded, _ := json.Marshal(map[string]int64{"tx": up, "rx": down})
	return string(encoded)
}

func resetTraffic() {
	state.trafficMu.Lock()
	state.trafficSeen = make(map[string]byteTotals)
	state.completedUp = 0
	state.completedDn = 0
	state.trafficMu.Unlock()
}

// LastError returns the last initialization/connect/disconnect error, if any.
func LastError() string {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.lastErr
}

func currentBackend() *backend.LocalBackend {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.backend
}

func setLastError(err error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if err == nil {
		state.lastErr = ""
	} else {
		state.lastErr = err.Error()
	}
}

// Shutdown releases the backend when the Android application process exits.
func Shutdown() {
	CancelConnect()
	state.mu.Lock()
	b := state.backend
	cancel := state.backendCancel
	state.backend = nil
	state.backendCancel = nil
	state.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if b != nil {
		b.Close()
	}
}

// ---- Server selection & probe surface for the app's Lantern settings ----

// lanternServer is one selectable Lantern server as the app's settings screen
// sees it. The server list itself comes from Radiance's config handler and is
// refreshed by Lantern's own background config updates — nothing here pins it.
type lanternServer struct {
	Tag     string `json:"tag"`
	Type    string `json:"type"`
	City    string `json:"city"`
	Country string `json:"country"`
	// CountryCode is the ISO 3166-1 alpha-2 code Lantern itself provides
	// ("US", "DE", ...): the same source the official app renders its flags
	// from. Names alone are unreliable for that ("USA" vs "United States").
	CountryCode string `json:"country_code"`
	// PingMs is the last successful probe latency in milliseconds; Probed
	// distinguishes "measured, fast" from "never answered".
	PingMs uint32 `json:"ping_ms"`
	Probed bool   `json:"probed"`
}

type serversSnapshot struct {
	Status   string          `json:"status"`
	Servers  []lanternServer `json:"servers"`
	Auto     bool            `json:"auto"`
	Selected string          `json:"selected"`
	Current  string          `json:"current"`
}

// ServersJSON lists the current servers with their last probe latency, plus
// the selection state (auto vs pinned) and the currently active server.
func ServersJSON() string {
	b := currentBackend()
	if b == nil {
		return mustJSON(serversSnapshot{Status: string(vpn.Disconnected)})
	}
	snapshot := serversSnapshot{
		Status:  string(b.VPNStatus()),
		Servers: []lanternServer{},
		// AutoConnect is Radiance's own switch between its continuous
		// probe-and-rank auto selection and a user-pinned server.
		Auto: settings.GetBool(settings.AutoConnectKey),
	}
	for _, srv := range b.AllServers() {
		if srv == nil {
			continue
		}
		entry := lanternServer{
			Tag:         srv.Tag,
			Type:        srv.Type,
			City:        srv.Location.City,
			Country:     srv.Location.Country,
			CountryCode: srv.Location.CountryCode,
		}
		if h := srv.SelectionHistory; h != nil && h.LastSuccessDelayMs > 0 {
			entry.PingMs = h.LastSuccessDelayMs
			entry.Probed = true
		}
		snapshot.Servers = append(snapshot.Servers, entry)
	}
	if !snapshot.Auto {
		if sel, exists, err := b.SelectedServer(); err == nil && sel != nil && exists {
			snapshot.Selected = sel.Tag
		}
	}
	if tag, err := b.CurrentAutoSelectedServer(); err == nil {
		snapshot.Current = tag
	}
	return mustJSON(snapshot)
}

// SelectServer switches the live tunnel to the given server tag. The empty
// string restores automatic (fastest) selection. The backend persists the
// choice, so it also survives restarts.
func SelectServer(tag string) error {
	b := currentBackend()
	if b == nil {
		return errors.New("Radiance is not initialized")
	}
	if err := b.SelectServer(tag); err != nil {
		return fmt.Errorf("select Lantern server: %w", err)
	}
	return nil
}

// PingServers refreshes every server's latency by running Radiance's offline
// URL tests. The fresh results also re-seed the auto-selection ranking.
func PingServers() error {
	b := currentBackend()
	if b == nil {
		return errors.New("Radiance is not initialized")
	}
	if err := b.RunOfflineURLTests(); err != nil {
		return fmt.Errorf("probe Lantern servers: %w", err)
	}
	return nil
}

func mustJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

