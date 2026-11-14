package lanternbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/vpn"
)

type byteTotals struct {
	up   int64
	down int64
}

var state struct {
	mu          sync.RWMutex
	backend     *backend.LocalBackend
	lastErr     string
	trafficMu   sync.Mutex
	trafficSeen map[string]byteTotals
	completedUp int64
	completedDn int64
}

// Init initializes Radiance once for this app process. The novpn build tag
// replaces Radiance's TUN inbound with a loopback-only mixed HTTP/SOCKS
// listener; MSN-GUARD remains the sole owner of Android's VpnService and TUN.
func Init(dataDir, logDir, socksAddress string) error {
	state.mu.Lock()

	if state.backend != nil {
		state.mu.Unlock()
		return nil
	}
	if dataDir == "" || logDir == "" {
		state.mu.Unlock()
		return errors.New("Radiance data and log directories are required")
	}
	if socksAddress == "" {
		socksAddress = "127.0.0.1:1831"
	}

	ctx, cancel := context.WithCancel(context.Background())
	b, err := backend.NewLocalBackend(ctx, backend.Options{
		DataDir:                  dataDir,
		LogDir:                   logDir,
		Locale:                   "en",
		LogLevel:                 "info",
		TelemetryConsent:         false,
		PreserveTelemetryConsent: false,
		EnvOverrides: map[string]string{
			"RADIANCE_SOCKS_ADDRESS": socksAddress,
		},
	})
	if err != nil {
		cancel()
		state.lastErr = err.Error()
		state.mu.Unlock()
		return fmt.Errorf("initialize Radiance: %w", err)
	}

	state.backend = b
	state.lastErr = ""
	state.mu.Unlock()
	b.Start()
	return nil
}

// Connect waits for Radiance's current public configuration and connects using
// its automatic server selector. No private server credentials are required.
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
	defer cancel()

	resetTraffic()
	err := b.ConnectVPN(ctx, vpn.AutoSelectTag)
	setLastError(err)
	if err != nil {
		return fmt.Errorf("connect to public Lantern servers: %w", err)
	}
	return nil
}

// Disconnect stops the Radiance tunnel but keeps its backend initialized so a
// later reconnect does not repeat global process initialization.
func Disconnect() error {
	b := currentBackend()
	if b == nil {
		return nil
	}
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
	state.mu.Lock()
	b := state.backend
	state.backend = nil
	state.mu.Unlock()
	if b != nil {
		b.Close()
	}
}
