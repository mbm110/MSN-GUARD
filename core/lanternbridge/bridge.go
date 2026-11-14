package lanternbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/vpn"
)

var state struct {
	mu      sync.RWMutex
	backend *backend.LocalBackend
	cancel  context.CancelFunc
	lastErr string
}

// Init initializes Radiance once for this app process. The novpn build tag
// replaces Radiance's TUN inbound with a loopback-only mixed HTTP/SOCKS
// listener; MSN-GUARD remains the sole owner of Android's VpnService and TUN.
func Init(dataDir, logDir, socksAddress string) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.backend != nil {
		return nil
	}
	if dataDir == "" || logDir == "" {
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
		return fmt.Errorf("initialize Radiance: %w", err)
	}

	state.backend = b
	state.cancel = cancel
	state.lastErr = ""
	b.Start()
	return nil
}

// Connect waits for Radiance's current public configuration and connects using
// its automatic server selector. No private server credentials are required.
func Connect(timeoutSeconds int) error {
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

// ThroughputJSON returns Radiance's most recent global throughput sample.
// Values in global.up and global.down are bits per second.
func ThroughputJSON() string {
	b := currentBackend()
	if b == nil {
		return "{}"
	}
	snapshot, err := b.VPNThroughput()
	if err != nil {
		return "{}"
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return "{}"
	}
	return string(encoded)
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

// Keep os linked in the mobile build so environment overrides remain available
// to downstream Radiance components that read process environment directly.
var _ = os.Getenv
