package unbounded

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/broflake/clientcore"

	"github.com/getlantern/radiance/helper"
)

var snapshotEpoch = strconv.FormatInt(time.Now().UnixNano(), 10)

// peerRetention keeps a departed consumer's byte totals in the snapshot long
// enough for the app's 1s poller to observe its final count.
const peerRetention = 60 * time.Second

// Snapshot describes the current widget state, including peers missed by event subscribers.
// Byte counts are cumulative since Epoch, like Arrivals.
type Snapshot struct {
	Epoch    string `json:"epoch"`
	Arrivals uint64 `json:"arrivals"`
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	// Blocked is why the widget isn't running (one of the Blocked*
	// constants), or "" when it is running or starting.
	Blocked   string      `json:"blocked,omitempty"`
	Peers     []string    `json:"peers"`
	BytesDown uint64      `json:"bytesDown"`
	BytesUp   uint64      `json:"bytesUp"`
	PeerBytes []PeerBytes `json:"peerBytes"`
}

// PeerBytes is the cumulative traffic relayed for one consumer IP. Counts only
// grow while the entry exists; an entry pruned after peerRetention restarts at
// zero if the IP returns, which consumers treat as a reset.
type PeerBytes struct {
	IP   string `json:"ip"`
	Down uint64 `json:"down"`
	Up   uint64 `json:"up"`
	// Pairing is the helper pairing this consumer most recently came
	// through, "" for the pool or one broflake could not attribute. It
	// identifies a friend relationship and must never be logged.
	Pairing string `json:"pairing,omitempty"`
}

// slotBytes holds bytes relayed through one broflake worker slot since they
// were last folded into the manager's totals. Chunk callbacks only touch these
// atomics, so the per-chunk data path never contends on m.mu.
type slotBytes struct {
	down, up atomic.Uint64
	// total is every byte the slot has relayed, never reset, which the
	// LiveTracker samples for a slot serving a helper pairing.
	total atomic.Uint64
}

// slotTable is created per worker run so chunks a stopped worker delivers late
// land in an orphaned table instead of the next run's attribution.
type slotTable struct {
	slots sync.Map
	// mu is read-held by each chunk callback around its add, so close can
	// wait out callbacks already past the closed check before the final fold.
	mu     sync.RWMutex
	closed bool
}

func (t *slotTable) add(idx int, size uint64, down bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return
	}
	s := t.slot(idx)
	s.total.Add(size)
	if down {
		s.down.Add(size)
	} else {
		s.up.Add(size)
	}
}

// close stops the table accepting bytes and returns once every in-flight add
// has landed, so a fold after close sees all accepted bytes.
func (t *slotTable) close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}

func (t *slotTable) slot(idx int) *slotBytes {
	if s, ok := t.slots.Load(idx); ok {
		return s.(*slotBytes)
	}
	s, _ := t.slots.LoadOrStore(idx, &slotBytes{})
	return s.(*slotBytes)
}

type peerTally struct {
	down, up uint64
	// active counts slots currently held by this IP; endedAt is set when it drops to zero.
	active  int
	endedAt time.Time
	// pairing is the helper pairing of the IP's latest slot, "" for the pool.
	pairing string
}

// chunkCounter returns a broflake ChunkFunc that adds relayed bytes to the
// slot's downstream or upstream counter. It keeps counting after the worker's
// context is cancelled: broflake tears down asynchronously after ui.Stop
// returns and can still deliver bytes, which the retired run absorbs.
func chunkCounter(slots *slotTable, down bool) clientcore.ChunkFunc {
	return func(size int, workerIdx int) {
		if size <= 0 {
			return
		}
		slots.add(workerIdx, uint64(size), down)
	}
}

// CurrentSnapshot returns an independent copy of the live widget state.
func CurrentSnapshot() Snapshot {
	// The app polls this, so a backend that never armed the widget, and so
	// never evaluates the gate itself, still logs why it isn't running.
	manager.noteBlockedAsync()
	return manager.snapshot()
}

func (m *unboundedManager) snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prunePeerBytes()
	enabled := Enabled()
	s := Snapshot{
		Epoch:     snapshotEpoch,
		Arrivals:  m.arrivals,
		Enabled:   enabled,
		Running:   m.running,
		Blocked:   m.blockedLocked(enabled),
		Peers:     []string{},
		BytesDown: m.bytesDown,
		BytesUp:   m.bytesUp,
		PeerBytes: []PeerBytes{},
	}
	if m.running {
		for _, source := range m.peers {
			if source != "" {
				s.Peers = append(s.Peers, source)
			}
		}
	}
	sort.Strings(s.Peers)
	for ip, t := range m.peerBytes {
		s.PeerBytes = append(s.PeerBytes, PeerBytes{IP: ip, Down: t.down, Up: t.up, Pairing: t.pairing})
	}
	sort.Slice(s.PeerBytes, func(i, j int) bool { return s.PeerBytes[i].IP < s.PeerBytes[j].IP })
	return s
}

func (m *unboundedManager) recordConnection(ctx context.Context, state, slot int, source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	// Prune before acquiring, so a returning IP's fresh tally can't pick up
	// bytes still pending from its pruned lifetime.
	m.prunePeerBytes()
	if state > 0 {
		if m.peers == nil {
			m.peers = make(map[int]string)
		}
		if source != "" {
			known := false
			for _, existing := range m.peers {
				if existing == source {
					known = true
					break
				}
			}
			if !known {
				m.arrivals++
			}
		}
		// Bytes counted before this accept belong to the slot's previous occupant.
		m.foldSlot(slot)
		if prev, ok := m.peers[slot]; ok {
			m.releasePeer(prev)
		}
		delete(m.lastOwner, slot)
		delete(m.slotPairing, slot)
		m.peers[slot] = source
		m.acquirePeer(source)
	} else if state < 0 {
		m.foldSlot(slot)
		if prev, ok := m.peers[slot]; ok {
			m.releasePeer(prev)
			// broflake batches upstream bytes for up to 250ms and reports the
			// close without flushing them, so the closed peer keeps the slot's
			// bytes until the next accept.
			if m.lastOwner == nil {
				m.lastOwner = make(map[int]*peerTally)
			}
			m.lastOwner[slot] = m.peerBytes[prev]
		}
		delete(m.peers, slot)
	}
}

// liveOwner groups this package's slots in the LiveTracker.
const liveOwner = "unbounded"

// liveSlot identifies one slot of one run in the LiveTracker.
type liveSlot struct {
	slots *slotTable
	idx   int
}

// recordPairing follows broflake's pairing for a slot's connection change,
// which arrives just after recordConnection's.
func (m *unboundedManager) recordPairing(ctx context.Context, slots *slotTable, state, slot int, pairing string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil || slots == nil {
		return
	}
	key := liveSlot{slots: slots, idx: slot}
	if state < 0 {
		m.liveTracker().Close(key)
		return
	}
	if state == 0 {
		return
	}
	if pairing == "" {
		delete(m.slotPairing, slot)
	} else {
		if m.slotPairing == nil {
			m.slotPairing = make(map[int]string)
		}
		m.slotPairing[slot] = pairing
	}
	if source := m.peers[slot]; source != "" {
		if t := m.peerBytes[source]; t != nil {
			t.pairing = pairing
		}
	}
	if pairing == "" {
		m.liveTracker().Close(key)
		return
	}
	m.liveTracker().Open(liveOwner, key, pairing, slots.slot(slot).total.Load)
}

func (m *unboundedManager) liveTracker() *helper.LiveTracker {
	if m.live != nil {
		return m.live
	}
	return helper.DefaultLive
}

// retiredRun keeps a stopped run's slot table and its final slot owners and
// pairings, so bytes broflake delivers during its asynchronous teardown are
// still counted and credited to the consumers and pairings that relayed them.
type retiredRun struct {
	slots     *slotTable
	owners    map[int]*peerTally
	pairings  map[int]string
	retiredAt time.Time
}

// releaseAllPeers folds outstanding slot bytes, ends every live peer so their
// final totals stay visible for peerRetention, and retires the run's slot
// table for the same period. Caller must hold m.mu.
func (m *unboundedManager) releaseAllPeers() {
	m.prunePeerBytes()
	m.liveTracker().CloseOwner(liveOwner)
	for _, source := range m.peers {
		m.releasePeer(source)
	}
	if m.slots != nil {
		owners := make(map[int]*peerTally, len(m.lastOwner)+len(m.peers))
		for idx, t := range m.lastOwner {
			owners[idx] = t
		}
		for idx, source := range m.peers {
			owners[idx] = m.peerBytes[source]
		}
		m.retired = append(m.retired, retiredRun{slots: m.slots, owners: owners, pairings: m.slotPairing, retiredAt: m.clock()})
	}
	m.slots = nil
	m.lastOwner = nil
	m.slotPairing = nil
}

// foldRetiredRuns folds bytes stopped runs received since the last fold, and
// drops runs retired longer than peerRetention after a final fold. Caller
// must hold m.mu.
func (m *unboundedManager) foldRetiredRuns() {
	now := m.clock()
	kept := m.retired[:0]
	for _, r := range m.retired {
		expired := now.Sub(r.retiredAt) > peerRetention
		if expired {
			r.slots.close()
		}
		r.slots.slots.Range(func(k, v any) bool {
			m.addSlotBytes(r.owners[k.(int)], r.pairings[k.(int)], v.(*slotBytes))
			return true
		})
		if !expired {
			kept = append(kept, r)
		}
	}
	clear(m.retired[len(kept):])
	m.retired = kept
}

// foldSlot moves a slot's pending bytes into the totals and, when the slot's
// IP is known, that IP's tally, and credits them to m.usage when the slot
// serves a helper pairing. Caller must hold m.mu.
func (m *unboundedManager) foldSlot(idx int) {
	if m.slots == nil {
		return
	}
	if s, ok := m.slots.slots.Load(idx); ok {
		m.addSlotBytes(m.slotOwner(idx), m.slotPairing[idx], s.(*slotBytes))
	}
}

func (m *unboundedManager) foldAllSlots() {
	if m.slots == nil {
		return
	}
	m.slots.slots.Range(func(k, v any) bool {
		m.addSlotBytes(m.slotOwner(k.(int)), m.slotPairing[k.(int)], v.(*slotBytes))
		return true
	})
}

// foldPending folds the pending bytes of every slot, live and retired, and
// credits paired bytes to m.usage. It takes m.mu, so callers must not hold it.
func (m *unboundedManager) foldPending() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.foldAllSlots()
	m.foldRetiredRuns()
}

// slotOwner is the tally credited with a live slot's bytes: its current
// consumer's, or the last one's while the slot is vacant. Owners are held as
// tallies rather than IPs, so bytes from a pruned lifetime never reach a
// returning IP's fresh tally.
func (m *unboundedManager) slotOwner(idx int) *peerTally {
	if owner, live := m.peers[idx]; live {
		return m.peerBytes[owner]
	}
	return m.lastOwner[idx]
}

// addSlotBytes drains s into the totals, and into m.usage for a non-empty
// pairing, even when t is nil. Caller must hold m.mu.
func (m *unboundedManager) addSlotBytes(t *peerTally, pairing string, s *slotBytes) {
	down, up := s.down.Swap(0), s.up.Swap(0)
	if down == 0 && up == 0 {
		return
	}
	m.bytesDown += down
	m.bytesUp += up
	if t != nil {
		t.down += down
		t.up += up
	}
	if pairing != "" {
		m.usage.Add(pairing, down+up)
	}
}

func (m *unboundedManager) acquirePeer(source string) {
	if source == "" {
		return
	}
	if m.peerBytes == nil {
		m.peerBytes = make(map[string]*peerTally)
	}
	t := m.peerBytes[source]
	if t == nil {
		t = &peerTally{}
		m.peerBytes[source] = t
	}
	t.active++
}

func (m *unboundedManager) releasePeer(source string) {
	t := m.peerBytes[source]
	if t == nil || t.active == 0 {
		return
	}
	t.active--
	if t.active == 0 {
		t.endedAt = m.clock()
	}
}

// prunePeerBytes drops tallies of IPs ended more than peerRetention ago, and
// expired retired runs. It first folds every pending byte, so bytes are
// always credited to the tally lifetime they were relayed in. Caller must
// hold m.mu.
func (m *unboundedManager) prunePeerBytes() {
	m.foldAllSlots()
	m.foldRetiredRuns()
	now := m.clock()
	for ip, t := range m.peerBytes {
		if t.active == 0 && now.Sub(t.endedAt) > peerRetention {
			delete(m.peerBytes, ip)
		}
	}
}

func (m *unboundedManager) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}
