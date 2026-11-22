package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing/service"

	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/log"
)

const rejectMode = "reject"

// selectableModes are the modes [clashModeManager.SetMode] accepts.
var selectableModes = []string{AutoSelectTag, ManualSelectTag}

// clashModeManager switches the clash mode that the mode and reject rules
// match on, keeping the user's mode while reject mode is enabled.
type clashModeManager struct {
	// clashMode holds the mode the rules match on: rejectMode while reject mode
	// is enabled, otherwise mode. Only this manager sets it.
	clashMode *clashmode.Manager

	mu   sync.Mutex
	mode string
}

// newClashModeManager registers sing-box's clash mode manager with the box
// whose context ctx is. It must be called after sbox.New and before the box
// starts, when the mode rules look up the manager. sing-box's manager is never
// started, so it never restores a saved mode.
func newClashModeManager(ctx context.Context, logger log.Logger, initialMode string) (*clashModeManager, error) {
	if !slices.Contains(selectableModes, initialMode) {
		return nil, fmt.Errorf("initial mode %q is not in mode list", initialMode)
	}
	clashMode := clashmode.NewManager(ctx, logger, initialMode, append(slices.Clone(selectableModes), rejectMode))
	service.MustRegisterPtr(ctx, clashMode)
	return &clashModeManager{clashMode: clashMode, mode: initialMode}, nil
}

// SetMode selects the user's mode and returns the previous one. While reject
// mode is enabled, the new mode takes effect when reject mode is disabled.
func (m *clashModeManager) SetMode(mode string) (prev string, err error) {
	i := slices.IndexFunc(selectableModes, func(s string) bool {
		return strings.EqualFold(s, mode)
	})
	if i == -1 {
		return "", fmt.Errorf("mode %q is not in mode list", mode)
	}
	mode = selectableModes[i]
	m.mu.Lock()
	defer m.mu.Unlock()
	prev = m.mode
	if prev != mode {
		slog.Info("Switching mode", "from", prev, "to", mode)
		m.mode = mode
		if !m.rejecting() {
			m.clashMode.SetMode(mode)
		}
	}
	return prev, nil
}

// selectedMode returns the user's mode, ignoring reject mode.
func (m *clashModeManager) selectedMode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// setRejectMode enables or disables reject mode. Existing connections continue;
// only new ones are refused.
func (m *clashModeManager) setRejectMode(enable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rejecting() == enable {
		return
	}
	if enable {
		slog.Warn("Enabling reject mode: all connections will be rejected until disabled")
		m.clashMode.SetMode(rejectMode)
		return
	}
	slog.Info("Disabling reject mode: routing will resume as normal")
	m.clashMode.SetMode(m.mode)
}

func (m *clashModeManager) rejecting() bool {
	return m.clashMode.Mode() == rejectMode
}
