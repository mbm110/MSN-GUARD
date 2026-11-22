package vpn

import (
	"context"
	"io"
	"log/slog"
	runtimeDebug "runtime/debug"
	"slices"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/vpn/memmon"
)

const (
	// iOS uses dynamic headroom when available and falls back to this budget otherwise.
	defaultIOSMemLimitBytes    = 48 * 1024 * 1024  // 48 MB
	defaultNonIOSMemLimitBytes = 512 * 1024 * 1024 // 512 MB

	// minMemLimitMB is the minimum override. It is floored at GOMEMLIMIT so GC
	// can react before the fixed-budget monitor starts shedding work.
	minMemLimitMB = mobileMemoryLimit / (1024 * 1024)
	maxMemLimitMB = 512
)

// memoryReclaimer adapts connTracker to memmon.Reclaimer.
type memoryReclaimer struct {
	tracker *connTracker
}

func (r *memoryReclaimer) OldestConnections(limit int) (oldest []memmon.ConnectionRef, total int) {
	oldest = make([]memmon.ConnectionRef, 0, max(limit, 0))
	for id, rec := range r.tracker.conns.Iter() {
		total++
		createdAt := rec.createdAt
		// A candidate that can't join the oldest-limit window is skipped, but the loop
		// continues so total still counts every connection.
		if limit <= 0 || (len(oldest) == limit && !createdAt.Before(oldest[limit-1].CreatedAt)) {
			continue
		}
		i, _ := slices.BinarySearchFunc(oldest, createdAt, func(ref memmon.ConnectionRef, t time.Time) int {
			return ref.CreatedAt.Compare(t)
		})
		if len(oldest) < limit {
			oldest = append(oldest, memmon.ConnectionRef{})
		}
		// At limit, this evicts the newest kept entry to make room.
		copy(oldest[i+1:], oldest[i:])
		oldest[i] = memmon.ConnectionRef{ID: id, CreatedAt: createdAt}
	}
	return oldest, total
}

func (r *memoryReclaimer) FreeOSMemory() {
	runtimeDebug.FreeOSMemory()
}

func (r *memoryReclaimer) OpenConnectionCount() int {
	return int(r.tracker.activeConnectionCount())
}

func (r *memoryReclaimer) TotalDialedConnections() int {
	return int(r.tracker.activeConnectionCount())
}

func (r *memoryReclaimer) CloseConn(id uuid.UUID) {
	r.tracker.closeConn(id)
}

func (r *memoryReclaimer) CloseAllConnections() {
	closeAllRouted(r.tracker)
}

func closeAllRouted(tracker *connTracker) {
	tracker.closeAllTracked()
}

// startMemoryMonitor creates and starts a visibility-only memory monitor,
// returning the monitor so an executor can be installed later and a Closer that
// stops the run loop and waits for it to exit.
func startMemoryMonitor(ctx context.Context) (*memmon.Monitor, io.Closer) {
	limit := getLimit()
	monitor := memmon.New(
		memoryMonitorConfig(limit),
		memmon.NewSensor(limit),
		nil,
	)

	return monitor, runUntilClosed(ctx, monitor.Run)
}

// initExecutor attaches reclaim and admission control after the connection
// tracker becomes available. The monitor starts earlier in visibility-only mode.
func initExecutor(monitor *memmon.Monitor, tracker *connTracker, modes *clashModeManager) {
	// Use a dedicated sensor here. Sharing the monitor sensor would race its
	// reused runtime/metrics buffers.
	limit := getLimit()
	gate := memmon.NewAdmissionGate(
		memmon.AdmissionConfig{},
		memmon.NewSensor(limit),
		admissionRejectionHandler(modes),
	)
	tracker.SetAdmissionGate(gate)

	reclaimer := &memoryReclaimer{tracker: tracker}
	executor := memmon.NewExecutor(
		reclaimer,
		settings.GetString(settings.LogPathKey),
		common.Platform,
		common.Version,
		gate,
	)
	monitor.SetExecutor(executor)
}

func getLimit() memmon.LimitProvider {
	if common.IsIOS() {
		return memmon.FixedLimit(monitorLimitBytes())
	}
	return memmon.FixedLimit(defaultNonIOSMemLimitBytes)
}

func monitorLimitBytes() uint64 {
	mb := env.GetInt(env.MemoryLimitMB)
	switch {
	case mb <= 0:
		return defaultIOSMemLimitBytes
	case mb < minMemLimitMB:
		slog.Warn("Ignoring low memory monitor limit override", "mb", mb, "min_mb", minMemLimitMB)
	case mb > maxMemLimitMB:
		slog.Warn("Ignoring high memory monitor limit override", "mb", mb, "max_mb", maxMemLimitMB)
	default:
		return uint64(mb) * 1024 * 1024
	}
	return defaultIOSMemLimitBytes
}

func memoryMonitorConfig(limit memmon.LimitProvider) memmon.Config {
	cfg := memmon.Config{LimitProvider: limit}
	if !common.IsIOS() {
		// On Android/dev the governing signal includes the Go heap, so pin soft-enter to the
		// GOMEMLIMIT footprint and let GC act before eviction. iOS steers on dynamic headroom, which
		// already reflects whatever GC freed, so no clamp is wanted there.
		cfg.GoMemLimit = mobileMemoryLimit
	}
	return cfg
}

func admissionRejectionHandler(modes *clashModeManager) func(bool) {
	if !settings.GetBool(settings.AdmissionRejectionDisabledKey) {
		return modes.setRejectMode
	}

	slog.Warn("[DEV] Admission rejection disabled; connections will not be rejected under high memory pressure")
	return func(reject bool) {
		slog.Warn("[DEV] Rejection toggle fired (notice-only)", "reject", reject)
	}
}
