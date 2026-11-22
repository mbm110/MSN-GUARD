package vpn

import (
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	A "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	R "github.com/sagernet/sing-box/route/rule"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	lsync "github.com/getlantern/common/sync"
	"github.com/getlantern/lantern-box/adapter/groups"
)

var (
	_ groups.ConnectionManager = (*connTracker)(nil)
	_ A.ConnectionTracker      = (*connTracker)(nil)
)

// record holds the lean per-connection state radiance actually reads. It is built once when a
// connection is routed and never retains the full adapter.InboundContext; the scalars below are
// copied out at creation. upload/download are mutated on the data path via atomics; every other
// field is immutable after creation.
type record struct {
	id        uuid.UUID
	createdAt time.Time
	upload    atomic.Int64
	download  atomic.Int64

	// closed is the exactly-once gate for leave: Close may fire more than once (half-close,
	// error/abort, ctx-cancel then explicit close), but the accounting must fold only once.
	closed atomic.Bool

	// closer closes the underlying wrapped connection; set once at creation so the memory monitor
	// can evict a specific connection by id. Closing it folds the record out via leave.
	closer io.Closer

	outbound     string // raw leaf outbound tag: per-outbound bucket key and group-manager shim
	outboundType string
	chain        []string

	// Labels are prejoined because IPC polling rebuilds Connection values for every live record.
	// Keep outboundLabel aligned with outbound/outboundType so rendered labels and structured
	// routing metadata describe the same path.
	outboundLabel string
	inboundLabel  string

	ipVersion    uint8
	network      string
	source       string
	destination  string
	domain       string
	protocol     string
	fromOutbound string
	ruleStr      string
}

// attrs returns the telemetry attribute set for the connection.
func (r *record) attrs() ConnAttrs {
	return ConnAttrs{
		FromOutbound: r.fromOutbound,
		Outbound:     r.outboundLabel,
		Inbound:      r.inboundLabel,
		Network:      r.network,
		Protocol:     r.protocol,
		IPVersion:    int(r.ipVersion),
		Rule:         r.ruleStr,
		ChainList:    r.chain,
	}
}

// trackerMetadata synthesizes the upstream metadata view required by the lantern-box group manager.
// ClosedAt is left zero because only active records are ever exposed.
// Upload/Download point at the live atomics so the value is safe to marshal.
func (r *record) trackerMetadata() trafficcontrol.TrackerMetadata {
	return trafficcontrol.TrackerMetadata{
		ID:           r.id,
		CreatedAt:    r.createdAt,
		Upload:       &r.upload,
		Download:     &r.download,
		Chain:        r.chain,
		Outbound:     r.outbound,
		OutboundType: r.outboundType,
	}
}

// ConnAttrs is the attribute set describing a connection, carried on each ConnClose push.
type ConnAttrs struct {
	FromOutbound string
	Outbound     string
	Inbound      string
	Network      string
	Protocol     string
	IPVersion    int
	Rule         string
	ChainList    []string
}

// ConnClose is pushed when a connection closes, carrying its final accounting.
type ConnClose struct {
	ConnAttrs
	DurationSeconds float64
	Uplink          int64
	Downlink        int64
}

// ConnObserver receives a push notification when a connection closes. Implementations must not
// block: OnClose runs on the connection's close goroutine.
type ConnObserver interface {
	OnClose(ConnClose)
}

// connTracker is radiance's connection tracker. It holds only the active set and global byte totals;
// closed connections are pushed to the throughput sampler and the telemetry observer at close rather
// than retained.
type connTracker struct {
	upTotal   atomic.Int64
	downTotal atomic.Int64

	conns       lsync.TypedMap[uuid.UUID, *record]
	activeCount atomic.Int64

	tp *throughputTracker // wired after construction

	obsMu    sync.RWMutex
	observer ConnObserver

	// outbound resolves the chain of each routed connection.
	outbound      A.OutboundManager
	admissionGate atomic.Value // dialAdmissionGate; set once before the box routes, read lock-free on the dial path

	sampler io.Closer
}

func newConnTracker() *connTracker { return &connTracker{} }

// startConnTracker returns a tracker for connections the box routes through
// outbound, sampling throughput until Close.
func startConnTracker(ctx context.Context, outbound A.OutboundManager) *connTracker {
	m := newConnTracker()
	m.outbound = outbound
	m.tp = newThroughputTracker(m, 0)
	m.sampler = runUntilClosed(ctx, m.tp.Run)
	return m
}

// Close stops sampling throughput. Tracked connections stay open.
func (m *connTracker) Close() error {
	if m.sampler == nil {
		return nil
	}
	return m.sampler.Close()
}

// dialAdmissionGate is notified via RecordDial on each dial, with the dial time.
type dialAdmissionGate interface {
	RecordDial(time.Time)
}

// SetAdmissionGate installs the admission gate consulted on each dial. Nil
// is ignored, so the gate can be updated but not cleared.
func (m *connTracker) SetAdmissionGate(gate dialAdmissionGate) {
	if gate != nil {
		m.admissionGate.Store(gate)
	}
}

// SetObserver sets the telemetry observer, or nil to detach. It is re-set on each tunnel connect
// because the tracker is recreated per tunnel while the observer outlives it.
func (m *connTracker) SetObserver(o ConnObserver) {
	m.obsMu.Lock()
	m.observer = o
	m.obsMu.Unlock()
}

func (m *connTracker) currentObserver() ConnObserver {
	m.obsMu.RLock()
	defer m.obsMu.RUnlock()
	return m.observer
}

func (m *connTracker) pushUploaded(n int64)   { m.upTotal.Add(n) }
func (m *connTracker) pushDownloaded(n int64) { m.downTotal.Add(n) }

// Total returns the cumulative up/down byte counters across all connections, including those already
// closed (counting happens on the data path, independent of the active set).
func (m *connTracker) Total() (up, down int64) {
	return m.upTotal.Load(), m.downTotal.Load()
}

func (m *connTracker) join(r *record) {
	// A published record can be reclaimed before join returns.
	m.activeCount.Add(1)
	m.conns.Store(r.id, r)
}

// leave folds the connection's final accounting exactly once, gated by record.closed.
func (m *connTracker) leave(r *record) {
	if !r.closed.CompareAndSwap(false, true) {
		return
	}

	up, down := r.upload.Load(), r.download.Load()
	// Hand the close to the sampler before removing the connection from the active set: a sample
	// tick that misses the connection in its active walk must then find it in the pending drain,
	// never in neither. Were it absent from both, the tick would evict the connection's byte
	// baseline and the next tick would recount its lifetime bytes against a zero baseline.
	if m.tp != nil {
		m.tp.recordClosed(r.id, r.outbound, up, down)
	}
	m.conns.Delete(r.id)
	m.activeCount.Add(-1)

	if o := m.currentObserver(); o != nil {
		o.OnClose(ConnClose{
			ConnAttrs:       r.attrs(),
			DurationSeconds: time.Since(r.createdAt).Seconds(),
			Uplink:          up,
			Downlink:        down,
		})
	}
}

// Connections satisfies groups.ConnectionManager (github.com/getlantern/lantern-box/adapter/groups),
// returning the active connections as synthesized trafficcontrol.TrackerMetadata.
func (m *connTracker) Connections() []trafficcontrol.TrackerMetadata {
	out := make([]trafficcontrol.TrackerMetadata, 0, m.activeCount.Load())
	for _, r := range m.conns.Iter() {
		out = append(out, r.trackerMetadata())
	}
	return out
}

// activeConnections returns the current active connections as IPC Connection values. An empty
// slice is returned if there are no active connections.
func (m *connTracker) activeConnections() []Connection {
	out := make([]Connection, 0, m.activeCount.Load())
	for _, r := range m.conns.Iter() {
		out = append(out, newConnection(r))
	}
	return out
}

// activeStats returns the active connection count and the per-(raw)-outbound-tag active counts.
func (m *connTracker) activeStats() (count int, perOutbound map[string]int) {
	perOutbound = make(map[string]int)
	for _, r := range m.conns.Iter() {
		count++
		perOutbound[r.outbound]++
	}
	return count, perOutbound
}

func (m *connTracker) activeConnectionCount() int64 {
	return m.activeCount.Load()
}

func (m *connTracker) closeRecord(r *record) {
	if r == nil || r.closer == nil {
		return
	}
	_ = r.closer.Close()
}

// closeConn closes the connection with id by closing its wrapper, which folds it out via leave.
func (m *connTracker) closeConn(id uuid.UUID) {
	r, ok := m.conns.Load(id)
	if !ok {
		return
	}
	m.closeRecord(r)
}

func (m *connTracker) closeAllTracked() {
	for _, r := range m.conns.Iter() {
		m.closeRecord(r)
	}
}

// closeMatchedTo closes the connections whose route rule matched tag, not those that only pass
// through it.
func (m *connTracker) closeMatchedTo(tag string) {
	for _, r := range m.conns.Iter() {
		chain := r.chain
		if len(chain) == 0 || chain[len(chain)-1] != tag {
			continue
		}
		m.closeRecord(r)
	}
}

// newRecord builds a lean record for a routed connection, copying the scalars radiance reads out of
// metadata and resolving the outbound chain.
func (m *connTracker) newRecord(metadata A.InboundContext, matchedRule A.Rule, matchOutbound A.Outbound) *record {
	id, _ := uuid.NewV4()
	outbound, outboundType, chain := m.resolveChain(matchOutbound)
	return &record{
		id:            id,
		createdAt:     time.Now(),
		outbound:      outbound,
		outboundType:  outboundType,
		chain:         chain,
		outboundLabel: outboundType + "/" + outbound,
		inboundLabel:  metadata.InboundType + "/" + metadata.Inbound,

		ipVersion:    metadata.IPVersion,
		network:      metadata.Network,
		source:       metadata.Source.String(),
		destination:  metadata.Destination.String(),
		domain:       metadata.Domain,
		protocol:     metadata.Protocol,
		fromOutbound: metadata.Outbound,
		ruleStr:      formatRule(matchedRule),
	}
}

func (m *connTracker) resolveChain(matchOutbound A.Outbound) (outbound, outboundType string, chain []string) {
	var next string
	if matchOutbound != nil {
		next = matchOutbound.Tag()
	} else {
		next = m.outbound.Default().Tag()
	}

	for next != "" {
		detour, loaded := m.outbound.Outbound(next)
		if !loaded {
			if outbound == "" {
				outbound = next
			}
			break
		}

		chain = append(chain, next)
		outbound = detour.Tag()
		outboundType = detour.Type()

		group, isGroup := detour.(A.OutboundGroup)
		if !isGroup {
			// The proxyless hedge isn't a group, and which way it sends a
			// connection is decided only when it dials. Follow its fallback,
			// the auto group, so auto-mode traffic stays attributed to the
			// selected server as before. A connection the hedge serves
			// proxyless is attributed to that server too, and nothing here
			// tells the two apart; per-path accounting needs the hedge to
			// report the path it took.
			if detour.Tag() == ProxylessHedgeTag {
				next = AutoSelectTag
				continue
			}
			break
		}
		next = group.Now()
	}

	return outbound, outboundType, common.Reverse(chain)
}

func formatRule(rule A.Rule) string {
	if rule == nil {
		return ""
	}
	return rule.String() + " => " + rule.Action().String()
}

func (m *connTracker) countUpload(r *record, n int64) {
	r.upload.Add(n)
	m.pushUploaded(n)
}

func (m *connTracker) countDownload(r *record, n int64) {
	r.download.Add(n)
	m.pushDownloaded(n)
}

func (m *connTracker) uploadCounter(r *record) N.CountFunc {
	return func(n int64) { m.countUpload(r, n) }
}

func (m *connTracker) downloadCounter(r *record) N.CountFunc {
	return func(n int64) { m.countDownload(r, n) }
}

func (m *connTracker) admitConnection(now time.Time) {
	if gate, _ := m.admissionGate.Load().(dialAdmissionGate); gate != nil {
		gate.RecordDial(now)
	}
}

func (m *connTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata A.InboundContext, matchedRule A.Rule, matchOutbound A.Outbound) net.Conn {
	m.admitConnection(time.Now())

	r := m.newRecord(metadata, matchedRule, matchOutbound)
	c := &tcpConn{
		ExtendedConn: bufio.NewCounterConn(
			conn,
			[]N.CountFunc{m.uploadCounter(r)},
			[]N.CountFunc{m.downloadCounter(r)},
		),
		rec: r,
		ct:  m,
	}
	r.closer = c
	m.join(r)
	return c
}

func (m *connTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata A.InboundContext, matchedRule A.Rule, matchOutbound A.Outbound) N.PacketConn {
	m.admitConnection(time.Now())

	r := m.newRecord(metadata, matchedRule, matchOutbound)
	c := &udpConn{
		PacketConn: bufio.NewCounterPacketConn(
			conn,
			[]N.CountFunc{m.uploadCounter(r)},
			[]N.CountFunc{m.downloadCounter(r)},
		),
		rec: r,
		ct:  m,
	}
	r.closer = c
	m.join(r)
	return c
}

// RoutedFlow tracks a flow that sing-tun forwards to the outbound as packets
// instead of as a connection, such as traffic to a WireGuard endpoint.
func (m *connTracker) RoutedFlow(ctx context.Context, metadata A.InboundContext, matchedRule A.Rule, matchOutbound A.Outbound) tun.FlowTracker {
	m.admitConnection(time.Now())
	r := m.newRecord(metadata, matchedRule, matchOutbound)
	r.chain = m.flowChain(matchedRule, matchOutbound)
	f := &flowConn{rec: r, ct: m}
	r.closer = f
	return f
}

// flowChain returns a flow's chain, leaf first, like resolveChain's. sing-box
// resolves groups before it calls RoutedFlow, so leaf is a group's selection at
// routing time rather than the group the rule names; the chain keeps leaf and
// takes the groups from the rule's outbound, whose selection may have changed.
func (m *connTracker) flowChain(matchedRule A.Rule, leaf A.Outbound) []string {
	var tag string
	if matchedRule != nil {
		switch action := matchedRule.Action().(type) {
		case *R.RuleActionRoute:
			tag = action.Outbound
		case *R.RuleActionBypass:
			tag = action.Outbound
		}
	}
	target, loaded := m.outbound.Outbound(tag)
	if !loaded {
		target = m.outbound.Default()
	}
	if target == nil || target.Tag() == leaf.Tag() {
		return []string{leaf.Tag()}
	}
	_, _, chain := m.resolveChain(target)
	if len(chain) == 0 {
		return []string{leaf.Tag()}
	}
	chain[0] = leaf.Tag()
	return chain
}

func (m *connTracker) closeThrough(group string) {
	for _, r := range m.conns.Iter() {
		if slices.Contains(r.chain, group) {
			m.closeRecord(r)
		}
	}
}

// tcpConn and udpConn wrap a counted connection. Upstream/ReaderReplaceable/WriterReplaceable let
// bufio unwrap to the underlying conn for its vectorised and read-waiter fast paths. Close first
// closes the wrapped conn, then folds the connection out of the tracker so the final accounting
// snapshot includes any bytes counted by in-flight I/O that completes as close races it.
type tcpConn struct {
	N.ExtendedConn
	rec *record
	ct  *connTracker
}

func (c *tcpConn) Close() error {
	err := c.ExtendedConn.Close()
	c.ct.leave(c.rec)
	return err
}

func (c *tcpConn) Upstream() any           { return c.ExtendedConn }
func (c *tcpConn) ReaderReplaceable() bool { return true }
func (c *tcpConn) WriterReplaceable() bool { return true }

type udpConn struct {
	N.PacketConn
	rec *record
	ct  *connTracker
}

func (c *udpConn) Close() error {
	err := c.PacketConn.Close()
	c.ct.leave(c.rec)
	return err
}

func (c *udpConn) Upstream() any           { return c.PacketConn }
func (c *udpConn) ReaderReplaceable() bool { return true }
func (c *udpConn) WriterReplaceable() bool { return true }

// flowConn tracks a flow that sing-tun forwards as packets. It joins the tracker
// once sing-tun attaches it, leaves when sing-tun closes it, and Close ends it
// through sing-tun's handle. sing-tun can close a flow before attaching it, so a
// flow closed first never joins.
type flowConn struct {
	rec *record
	ct  *connTracker

	access sync.Mutex
	handle tun.FlowHandle
	closed bool
}

func (f *flowConn) AttachFlow(handle tun.FlowHandle) {
	f.access.Lock()
	defer f.access.Unlock()
	if f.closed {
		return
	}
	f.handle = handle
	f.ct.join(f.rec)
}

// CountForward and CountReverse drop bytes counted after CloseFlow, which
// sing-tun can call concurrently: leave has already reported the flow's total.
func (f *flowConn) CountForward(n int) {
	f.access.Lock()
	defer f.access.Unlock()
	if !f.closed {
		f.ct.countUpload(f.rec, int64(n))
	}
}

func (f *flowConn) CountReverse(n int) {
	f.access.Lock()
	defer f.access.Unlock()
	if !f.closed {
		f.ct.countDownload(f.rec, int64(n))
	}
}

func (f *flowConn) FlowEstablished() {}

func (f *flowConn) CloseFlow(tun.FlowCloseReason) {
	f.access.Lock()
	joined := f.handle != nil && !f.closed
	f.closed = true
	f.access.Unlock()
	// leave runs the close observer, so it runs unlocked.
	if joined {
		f.ct.leave(f.rec)
	}
}

func (f *flowConn) Close() error {
	f.access.Lock()
	handle := f.handle
	f.access.Unlock()
	if handle != nil {
		handle.CloseFlow()
	}
	return nil
}

// Compile-time guard that the wrappers implement the interfaces sing-box's router expects.
var (
	_ net.Conn        = (*tcpConn)(nil)
	_ N.PacketConn    = (*udpConn)(nil)
	_ tun.FlowTracker = (*flowConn)(nil)
)
