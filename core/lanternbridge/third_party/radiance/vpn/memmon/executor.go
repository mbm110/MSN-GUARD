package memmon

import (
	"log/slog"
	"time"
)

// executor is the reaction actuator. It is a pure actuator: it obeys the
// Decision's flags and never decides when to act — all timing (the hard edge,
// cooldown, dwell, and settle) lives in the DecisionEngine. All of its state is owned by
// the single monitor-loop goroutine, so it needs no locking; now is threaded in
// from the loop so the FreeOSMemory rate limit is deterministic.
type executor struct {
	reclaimer Reclaimer
	dump      *dumpWriter
	gate      *AdmissionGate
	cfg       reactionConfig

	lastLevel  PressureLevel
	dumped     bool
	lastFreeOS time.Time
}

// NewExecutor builds the reaction executor. An empty dumpDir disables crash
// dumps, and a nil gate disables admission control. platform and version are
// stamped into the dump.
func NewExecutor(reclaimer Reclaimer, dumpDir, platform, version string, gate *AdmissionGate) Executor {
	return newExecutor(reclaimer, dumpDir, platform, version, gate, reactionConfig{})
}

func newExecutor(reclaimer Reclaimer, dumpDir, platform, version string, gate *AdmissionGate, config reactionConfig) Executor {
	var dump *dumpWriter
	if dumpDir != "" {
		dump = newDumpWriter(dumpDir, platform, version)
	}
	return &executor{reclaimer: reclaimer, dump: dump, gate: gate, cfg: config.applyDefaults(), lastLevel: LevelNormal}
}

func (e *executor) Apply(decision Decision, now time.Time) {
	if decision.WriteDump {
		// Written before reclaiming: the dump captures the live process at the
		// cliff, and a SIGKILL during reclaim must not lose the reason we were
		// about to act on.
		e.maybeDump(decision, now)
	}
	switch {
	case decision.CloseAllConnections:
		open := e.reclaimer.OpenConnectionCount()
		e.reclaimer.CloseAllConnections()
		// Hard reclaim always scavenges immediately.
		e.freeOSMemoryNow(now)
		slog.Warn("hard reclaim: closing all connections", "open_conns", open)
	case decision.Level == LevelSoft && decision.EvictOldestBatch:
		evicted, total := e.softEvict()
		e.freeOSMemoryRateLimited(now)
		slog.Debug("soft reclaim: evicted oldest batch", "evicted", evicted, "remaining", total-evicted)
	}
	if decision.Level != e.lastLevel {
		if decision.Level <= LevelSoft {
			e.dumped = false // re-arm the per-episode dump once pressure recedes out of Hard
		}
		e.lastLevel = decision.Level
	}
	if e.gate != nil {
		e.gate.Observe(decision.Level, decision.PressureRatio, now)
	}
}

func (e *executor) softEvict() (evicted, total int) {
	// Request only the largest possible batch; batchFor may choose fewer after seeing total.
	oldest, total := e.reclaimer.OldestConnections(e.cfg.SoftBatchMax)
	n := min(e.batchFor(total), len(oldest))
	for _, c := range oldest[:n] {
		e.reclaimer.CloseConn(c.ID)
	}
	return n, total
}

func (e *executor) batchFor(available int) int {
	if available == 0 {
		return 0
	}
	n := available / e.cfg.SoftDivisor
	n = max(n, 1)
	return min(n, available, e.cfg.SoftBatchMax)
}

// freeOSMemoryRateLimited runs FreeOSMemory at most once per
// FreeOSMinInterval. Hard reclaim bypasses this limiter.
func (e *executor) freeOSMemoryRateLimited(now time.Time) {
	if now.Sub(e.lastFreeOS) < e.cfg.FreeOSMinInterval {
		return
	}
	e.freeOSMemoryNow(now)
}

// freeOSMemoryNow runs FreeOSMemory immediately and records the run time.
func (e *executor) freeOSMemoryNow(now time.Time) {
	e.lastFreeOS = now
	e.reclaimer.FreeOSMemory()
}

// maybeDump writes one crash dump per pressure episode (e.dumped is reset when
// the level recedes to at most Soft). The Go numbers come from the Decision's
// Snapshot (runtime/metrics, no ReadMemStats), so the whole path is
// stop-the-world-free.
func (e *executor) maybeDump(decision Decision, now time.Time) {
	if e.dumped || e.dump == nil || decision.Snapshot == nil {
		return
	}
	err := e.dump.write(decision, e.reclaimer.OpenConnectionCount(), e.reclaimer.TotalDialedConnections(), now)
	if err != nil {
		slog.Warn("failed to write memory crash dump", "error", err)
		return
	}
	slog.Info("wrote memory crash dump",
		"footprint_mb", logMB(decision.Footprint),
		"pressure", logRound2(decision.PressureRatio),
	)
	e.dumped = true
}
