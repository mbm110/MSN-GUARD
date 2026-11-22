package peer

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/getlantern/lantern-box/tracker/peerconn"

	"github.com/getlantern/radiance/helper"
)

// relayRetention keeps a departed client's byte totals in the snapshot long
// enough for the app's 1s poller to observe its final count.
const relayRetention = 60 * time.Second

// Snapshot is the data direct sharing has relayed, in the shape of
// unbounded.Snapshot so the app can fold both with the same code. Like
// Unbounded's, Epoch is fixed for the process and byte counts are cumulative
// across sessions, so a Stop and Start between two polls loses nothing.
type Snapshot struct {
	Epoch     string      `json:"epoch"`
	Running   bool        `json:"running"`
	Peers     []string    `json:"peers"`
	BytesDown uint64      `json:"bytesDown"`
	BytesUp   uint64      `json:"bytesUp"`
	PeerBytes []PeerBytes `json:"peerBytes"`
}

// PeerBytes is the cumulative traffic relayed for one client IP. An entry
// pruned after relayRetention restarts at zero if the IP returns, which
// consumers treat as a reset.
type PeerBytes struct {
	IP   string `json:"ip"`
	Down uint64 `json:"down"`
	Up   uint64 `json:"up"`
	// Pairing is the helper pairing of this client's latest connection, ""
	// for the pool or not yet attributed. It identifies a friend
	// relationship and must never be logged.
	Pairing string `json:"pairing,omitempty"`
}

// relayTally is one client IP's bytes: closed holds its finished
// connections' totals; its open connections are read live from relay.conns.
type relayTally struct {
	closedDown, closedUp uint64
	open                 int
	endedAt              time.Time
	// pairing is the pairing of the client's latest connection, and
	// latest that connection's counter, so a connection attributed late
	// relabels the client only if it is still the latest.
	pairing string
	latest  *peerconn.Counter
}

// relayConn is an open connection's state and, once a later session has
// begun, when its own session was retired. A retired connection may still be
// draining in a box that has not finished closing, so its counter is read
// live for relayRetention before being folded into the totals.
type relayConn struct {
	source    string
	retiredAt time.Time
	// pairing is the helper pairing the connection came through, "" for the
	// pool or not yet attributed.
	pairing string
	// reported is how many of the counter's bytes have already been added
	// to the pending usage.
	reported uint64
}

// relayStats accumulates relayed bytes from the counters lantern-box
// attaches to each connection. It has its own lock because
// Snapshot is polled every second and must not wait on Start or Stop.
type relayStats struct {
	mu    sync.Mutex
	epoch string
	// conns holds each open connection's counter. The counter, not the
	// source, is the key: samizdat multiplexes streams over one TCP conn, so
	// several open streams can share a source, and the same counter comes
	// back on each stream's close.
	conns                map[*peerconn.Counter]relayConn
	ips                  map[string]*relayTally
	closedDown, closedUp uint64
	// endedAt is when the session stopped, or zero while it runs. Stop drops
	// the close events of connections still open, so those are retired by
	// time instead: relayRetention after endedAt, or at the next begin.
	endedAt time.Time
	// gen identifies the running session and changes at every begin and end.
	// A listener callback that resumes after Stop, or after Stop and Start,
	// carries an old generation, so its event is ignored rather than counted
	// after the session it belongs to has ended.
	gen uint64
	// pendingTotal and pendingPaired are the bytes accrued but not yet taken.
	// Only takeUsage clears them: they carry across sessions, unlike the
	// snapshot's retention. takeUsage calls pendingPaired.Take with r.mu
	// held, so SetFlush must never be called on pendingPaired.
	pendingTotal  uint64
	pendingPaired helper.Usage
	now           func() time.Time
}

func (r *relayStats) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// RelayUsage is the bytes relayed over one usage interval: RelayedBytes in
// total, and PairedBytes the part of it that came through each helper pairing.
type RelayUsage struct {
	RelayedBytes uint64
	PairedBytes  []helper.PairedBytes
}

// accrueLocked adds c's bytes since its last accrual to the pending usage and
// returns rc marked with them. Caller must hold r.mu.
func (r *relayStats) accrueLocked(c *peerconn.Counter, rc relayConn) relayConn {
	cur := c.Down() + c.Up()
	if cur <= rc.reported {
		return rc
	}
	n := cur - rc.reported
	rc.reported = cur
	r.pendingTotal += n
	r.pendingPaired.Add(rc.pairing, n)
	return rc
}

// takeUsage returns the bytes relayed since the last take and forgets them.
func (r *relayStats) takeUsage() RelayUsage {
	r.mu.Lock()
	defer r.mu.Unlock()
	for c, rc := range r.conns {
		r.conns[c] = r.accrueLocked(c, rc)
	}
	u := RelayUsage{RelayedBytes: r.pendingTotal, PairedBytes: r.pendingPaired.Take()}
	r.pendingTotal = 0
	return u
}

// restoreUsage puts back a takeUsage result whose heartbeat failed.
func (r *relayStats) restoreUsage(u RelayUsage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pendingTotal += u.RelayedBytes
	r.pendingPaired.Restore(u.PairedBytes)
}

// begin starts a session and returns its generation. Totals carry on from
// earlier sessions under the same epoch. Connections the previous session left
// open are retired: no longer listed as peers, but still read live until
// relayRetention has passed, since the old box may still be draining them.
func (r *relayStats) begin() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch == "" {
		r.epoch = strconv.FormatInt(r.clock().UnixNano(), 10)
	}
	now := r.clock()
	for c, rc := range r.conns {
		if !rc.retiredAt.IsZero() {
			continue
		}
		rc.retiredAt = now
		r.conns[c] = rc
		if t := r.ips[ipOf(rc.source)]; t != nil {
			t.release(now)
		}
	}
	r.endedAt = time.Time{}
	r.gen++
	return r.gen
}

// end marks the session stopped and ends its generation, so the listener's
// late events are ignored. Its open connections' counters stay readable for
// relayRetention, long enough for the app's poller to see the bytes relayed
// while the box closed, and are then folded into the totals and dropped.
func (r *relayStats) end() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endedAt = r.clock()
	r.gen++
}

// foldLocked moves a finished connection's count into the totals, its
// client's tally and the pending usage. Caller must hold r.mu and remove c
// from r.conns.
func (r *relayStats) foldLocked(c *peerconn.Counter, rc relayConn) {
	r.accrueLocked(c, rc)
	down, up := c.Down(), c.Up()
	r.closedDown += down
	r.closedUp += up
	if t := r.ips[ipOf(rc.source)]; t != nil {
		t.closedDown += down
		t.closedUp += up
	}
}

// release ends one of a client's open connections.
func (t *relayTally) release(now time.Time) {
	t.open--
	if t.open <= 0 {
		t.open = 0
		t.endedAt = now
	}
}

func ipOf(source string) string {
	ip, _, err := net.SplitHostPort(source)
	if err != nil {
		return source
	}
	return ip
}

// pruneLocked folds connections retired more than relayRetention ago into the
// totals, does the same for every connection once a stopped session is past
// it, and drops clients that left more than relayRetention ago. Caller must
// hold r.mu.
func (r *relayStats) pruneLocked(now time.Time) {
	ended := !r.endedAt.IsZero() && now.Sub(r.endedAt) > relayRetention
	for c, rc := range r.conns {
		if ended || (!rc.retiredAt.IsZero() && now.Sub(rc.retiredAt) > relayRetention) {
			r.foldLocked(c, rc)
			delete(r.conns, c)
		}
	}
	if ended {
		r.ips = nil
		return
	}
	for ip, t := range r.ips {
		if t.open == 0 && now.Sub(t.endedAt) > relayRetention {
			delete(r.ips, ip)
		}
	}
}

// record follows one connection's accept or close. A close folds the
// connection's final count, so totals keep it after the connection is gone.
func (r *relayStats) record(state int, source string, bytes *peerconn.Counter) {
	r.mu.Lock()
	gen := r.gen
	r.mu.Unlock()
	r.recordFor(gen, state, source, bytes)
}

// recordFor is record for the session with generation gen; an event from any
// other session is ignored.
func (r *relayStats) recordFor(gen uint64, state int, source string, bytes *peerconn.Counter) {
	r.recordPairingFor(gen, state, source, "", bytes)
}

// recordPairingFor is recordFor for a connection that came through pairing,
// "" for the pool.
func (r *relayStats) recordPairingFor(gen uint64, state int, source, pairing string, bytes *peerconn.Counter) {
	if bytes == nil {
		return
	}
	ip, _, err := net.SplitHostPort(source)
	if err != nil {
		ip = source
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if gen != r.gen {
		return
	}
	if state > 0 {
		// Pruned here too, so a session no one polls does not keep every
		// client it has ever seen. Before acquiring, so a returning IP's
		// fresh tally does not inherit its pruned totals.
		r.pruneLocked(r.clock())
	}
	if r.ips == nil {
		r.ips = make(map[string]*relayTally)
	}
	if r.conns == nil {
		r.conns = make(map[*peerconn.Counter]relayConn)
	}
	switch {
	case state > 0:
		// A counter seen again keeps what it has already reported.
		r.conns[bytes] = relayConn{source: source, pairing: pairing, reported: r.conns[bytes].reported}
		t := r.ips[ip]
		if t == nil {
			t = &relayTally{}
			r.ips[ip] = t
		}
		t.open++
		t.pairing = pairing
		t.latest = bytes
	case state < 0:
		rc, ok := r.conns[bytes]
		if !ok || !rc.retiredAt.IsZero() {
			return
		}
		delete(r.conns, bytes)
		r.foldLocked(bytes, rc)
		if t := r.ips[ip]; t != nil {
			t.release(r.clock())
		}
	}
}

// setPairing attributes an open connection to pairing, for a connection
// attributed after it was accepted.
func (r *relayStats) setPairing(bytes *peerconn.Counter, pairing string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rc, ok := r.conns[bytes]
	if !ok || !rc.retiredAt.IsZero() {
		return
	}
	rc.pairing = pairing
	r.conns[bytes] = rc
	if t := r.ips[ipOf(rc.source)]; t != nil && t.latest == bytes {
		t.pairing = pairing
	}
}

func (r *relayStats) snapshot(running bool) Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(r.clock())
	s := Snapshot{
		Epoch:     r.epoch,
		Running:   running,
		Peers:     []string{},
		BytesDown: r.closedDown,
		BytesUp:   r.closedUp,
		PeerBytes: []PeerBytes{},
	}
	live := make(map[string]PeerBytes, len(r.ips))
	for c, rc := range r.conns {
		down, up := c.Down(), c.Up()
		s.BytesDown += down
		s.BytesUp += up
		if running && rc.retiredAt.IsZero() {
			s.Peers = append(s.Peers, rc.source)
		}
		ip := ipOf(rc.source)
		pb := live[ip]
		pb.Down += down
		pb.Up += up
		live[ip] = pb
	}
	for ip, t := range r.ips {
		pb := live[ip]
		s.PeerBytes = append(s.PeerBytes, PeerBytes{IP: ip, Down: t.closedDown + pb.Down, Up: t.closedUp + pb.Up, Pairing: t.pairing})
	}
	sort.Strings(s.Peers)
	sort.Slice(s.PeerBytes, func(i, j int) bool { return s.PeerBytes[i].IP < s.PeerBytes[j].IP })
	return s
}

// RelaySnapshot reports what the current or most recent direct-sharing
// session has relayed.
func (c *Client) RelaySnapshot() Snapshot {
	return c.relay.snapshot(c.CurrentStatus().Phase == PhaseServing)
}
