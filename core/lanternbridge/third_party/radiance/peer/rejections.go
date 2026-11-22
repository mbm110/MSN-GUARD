package peer

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
)

// maxRejectedHosts bounds the tally file, since sharded CDN hostnames are
// unbounded in number.
const maxRejectedHosts = 2000

// maxPortsPerHost bounds each host's port breakdown, which a port scan could
// otherwise grow to every port. Further ports are counted under otherPorts.
const maxPortsPerHost = 16

const otherPorts = "other"

// rejectionsFileMode is owner-only on every platform: the file lists hosts
// people in censored countries asked for.
const rejectionsFileMode = fileperm.Private

// rejectionTally counts destinations this peer refused by a reject rule — the
// server-issued allowlist or an abuse block — so that hosts the allowlist
// wrongly excludes can be found in the tally file, since the peer's logs redact
// hosts.
//
// It keeps only the refused host and port. It never records who asked or
// when, since the people using this peer are in censored countries and the
// file sits on a volunteer's disk.
type rejectionTally struct {
	path string

	mu    sync.Mutex
	state rejectionState
	dirty bool
}

type rejectionState struct {
	Hosts map[string]*rejectedHost `json:"hosts"`
	// Overflow counts refusals of new hosts after maxRejectedHosts was reached.
	Overflow int64 `json:"overflow"`
}

type rejectedHost struct {
	Count int64            `json:"count"`
	Ports map[string]int64 `json:"ports"`
}

// newRejectionTally loads the tally at path. An empty path keeps it in memory
// only. A missing or unreadable file starts a fresh tally rather than failing,
// because the tally is a diagnostic and must never stop the peer from serving.
func newRejectionTally(path string) *rejectionTally {
	t := &rejectionTally{path: path, state: rejectionState{Hosts: map[string]*rejectedHost{}}}
	if path == "" {
		return t
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return t
	}
	var loaded rejectionState
	if err == nil {
		err = json.Unmarshal(raw, &loaded)
	}
	if err != nil {
		slog.Warn("peer: starting a fresh rejection tally", "path", path, "err", err)
		return t
	}
	if !validRejectionState(loaded) {
		slog.Warn("peer: starting a fresh rejection tally", "path", path, "err", "invalid saved state")
		return t
	}
	if loaded.Hosts != nil {
		t.state = loaded
	}
	return t
}

// validRejectionState reports whether saved state is safe to resume from.
// Valid JSON can still hold entries that record and counts would dereference as
// nil, or more hosts than the cap allows.
func validRejectionState(s rejectionState) bool {
	if len(s.Hosts) > maxRejectedHosts || s.Overflow < 0 {
		return false
	}
	for _, h := range s.Hosts {
		if h == nil || h.Ports == nil || h.Count < 0 {
			return false
		}
		// record only exceeds maxPortsPerHost named ports by adding otherPorts.
		if _, other := h.Ports[otherPorts]; len(h.Ports) > maxPortsPerHost+1 ||
			len(h.Ports) == maxPortsPerHost+1 && !other {
			return false
		}
		for _, n := range h.Ports {
			if n < 0 {
				return false
			}
		}
	}
	return true
}

// record counts one refusal of destination, a "host:port" string. It runs on
// the inbound's connection path, so it only updates memory; flush writes it.
func (t *rejectionTally) record(destination string) {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host, port = destination, ""
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dirty = true
	h, ok := t.state.Hosts[host]
	if !ok {
		if len(t.state.Hosts) >= maxRejectedHosts {
			t.state.Overflow++
			return
		}
		h = &rejectedHost{Ports: map[string]int64{}}
		t.state.Hosts[host] = h
	}
	h.Count++
	if port == "" {
		return
	}
	if _, known := h.Ports[port]; !known && len(h.Ports) >= maxPortsPerHost {
		port = otherPorts
	}
	h.Ports[port]++
}

// counts returns the number of refusals, including those past the host cap, and
// of distinct registrable domains among the tracked hosts.
func (t *rejectionTally) counts() (total int64, domains int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := make(map[string]struct{}, len(t.state.Hosts))
	for host, h := range t.state.Hosts {
		seen[registrableDomain(host)] = struct{}{}
		total += h.Count
	}
	return total + t.state.Overflow, len(seen)
}

// flush writes the tally if it changed and logs the refusal counts. The
// write is atomic so a crash mid-write cannot leave a truncated tally that the
// next start would discard.
func (t *rejectionTally) flush() {
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return
	}
	t.dirty = false
	raw, err := json.MarshalIndent(t.state, "", "  ")
	t.mu.Unlock()
	if err != nil {
		slog.Warn("peer: encoding rejection tally", "err", err)
		return
	}

	total, domains := t.counts()
	slog.Info("peer: destinations refused by reject rules", "total", total,
		"domains", domains, "path", t.path)

	if t.path == "" {
		return
	}
	if err := atomicfile.WriteFile(t.path, raw, rejectionsFileMode); err != nil {
		slog.Warn("peer: writing rejection tally", "path", t.path, "err", err)
		t.mu.Lock()
		t.dirty = true
		t.mu.Unlock()
	}
}

// registrableDomain collapses sharded hostnames such as
// rr1---sn-abc.googlevideo.com to googlevideo.com. IP literals and names the
// public suffix list cannot place are returned unchanged.
func registrableDomain(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}
