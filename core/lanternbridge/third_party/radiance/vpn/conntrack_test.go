package vpn

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	A "github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingObserver struct {
	mu     sync.Mutex
	closes []ConnClose
}

func (o *recordingObserver) OnClose(c ConnClose) {
	o.mu.Lock()
	o.closes = append(o.closes, c)
	o.mu.Unlock()
}

// closeWaitsForWriteConn forces tcpConn.Close's fold to observe an in-flight Write's byte count:
// Close blocks on writeAccounted, which the test signals only after tcpConn.Write returns (after
// CounterConn counts). Without that gate the close-before-fold contract could only be checked on a
// timing race.
type closeWaitsForWriteConn struct {
	writeStarted   chan struct{}
	releaseWrite   chan struct{}
	writeAccounted chan struct{}
	closeOnce      sync.Once
}

func newCloseWaitsForWriteConn() *closeWaitsForWriteConn {
	return &closeWaitsForWriteConn{
		writeStarted:   make(chan struct{}),
		releaseWrite:   make(chan struct{}),
		writeAccounted: make(chan struct{}),
	}
}

func (c *closeWaitsForWriteConn) Read(_ []byte) (int, error) { return 0, io.EOF }

func (c *closeWaitsForWriteConn) Write(p []byte) (int, error) {
	close(c.writeStarted)
	<-c.releaseWrite
	return len(p), nil
}

func (c *closeWaitsForWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.releaseWrite) })
	<-c.writeAccounted
	return nil
}

func (c *closeWaitsForWriteConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *closeWaitsForWriteConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *closeWaitsForWriteConn) SetDeadline(_ time.Time) error      { return nil }
func (c *closeWaitsForWriteConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *closeWaitsForWriteConn) SetWriteDeadline(_ time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

// wrapTCP mirrors connTracker.RoutedConnection's counter wiring so byte counting can be exercised
// without a full tunnel.
func wrapTCP(ct *connTracker, r *record, conn net.Conn) *tcpConn {
	c := &tcpConn{
		ExtendedConn: bufio.NewCounterConn(conn, []N.CountFunc{func(n int64) {
			r.upload.Add(n)
			ct.pushUploaded(n)
		}}, []N.CountFunc{func(n int64) {
			r.download.Add(n)
			ct.pushDownloaded(n)
		}}),
		rec: r,
		ct:  ct,
	}
	ct.join(r)
	return c
}

func TestConnTracker_LeaveFoldsOnce(t *testing.T) {
	ct := newConnTracker()
	tr := newThroughputTracker(ct, time.Second)
	ct.tp = tr

	r := newRec("out")
	ct.join(r)
	addBytes(ct, r, 100, 50)

	ct.leave(r)
	ct.leave(r) // repeat close must be a no-op

	_, ok := ct.conns.Load(r.id)
	assert.False(t, ok, "record should be removed from the active set")
	require.Len(t, tr.pending, 1, "final bytes folded exactly once")
	assert.Equal(t, closedDelta{id: r.id, outbound: "out", up: 100, down: 50}, tr.pending[0])
}

func TestConnTracker_ObserverOnClose(t *testing.T) {
	ct := newConnTracker()
	obs := &recordingObserver{}
	ct.SetObserver(obs)

	r := newRec("vpn-a")
	r.createdAt = time.Now().Add(-2 * time.Second)
	r.outboundType = "vmess"
	r.outboundLabel = "vmess/vpn-a"
	r.inboundLabel = "tun/tun-in"

	ct.join(r)
	addBytes(ct, r, 300, 120)
	ct.leave(r)

	require.Len(t, obs.closes, 1)
	c := obs.closes[0]
	assert.Equal(t, "vmess/vpn-a", c.Outbound)
	assert.Equal(t, "tun/tun-in", c.Inbound)
	assert.Equal(t, int64(300), c.Uplink)
	assert.Equal(t, int64(120), c.Downlink)
	assert.InDelta(t, 2.0, c.DurationSeconds, 0.5)
}

func TestConnTracker_CloseMatchedTo(t *testing.T) {
	ct := newConnTracker()
	now := time.Now()
	matched := joinClosable(ct, "srv-a", now, "srv-a", AutoSelectTag)
	passingThrough := joinClosable(ct, "srv-a", now, "srv-a", AutoSelectTag, "sr-group")
	otherMode := joinClosable(ct, "srv-b", now, "srv-b", ManualSelectTag)
	direct := joinClosable(ct, "direct", now, "direct")
	unresolved := joinClosable(ct, "", now)

	ct.closeMatchedTo(AutoSelectTag)

	assert.True(t, matched.closed.Load(), "a flow matched to the tag must be closed")
	assert.False(t, passingThrough.closed.Load(), "a flow only passing through the tag must stay open")
	assert.False(t, otherMode.closed.Load())
	assert.False(t, direct.closed.Load())
	assert.False(t, unresolved.closed.Load())
}

func TestConnTracker_TotalAndShim(t *testing.T) {
	ct := newConnTracker()
	a, b := newRec("vpn-a"), newRec("vpn-b")
	a.outboundType = "vmess"
	ct.join(a)
	ct.join(b)
	addBytes(ct, a, 10, 20)
	addBytes(ct, b, 5, 7)

	up, down := ct.Total()
	assert.Equal(t, int64(15), up)
	assert.Equal(t, int64(27), down)

	conns := ct.Connections()
	require.Len(t, conns, 2)
	for _, m := range conns {
		assert.True(t, m.ClosedAt.IsZero(), "active records report a zero ClosedAt")
		assert.NotNil(t, m.Upload)
		assert.NotNil(t, m.Download)
		assert.Contains(t, []string{"vpn-a", "vpn-b"}, m.Outbound)
	}

	count, perOut := ct.activeStats()
	assert.Equal(t, 2, count)
	assert.Equal(t, map[string]int{"vpn-a": 1, "vpn-b": 1}, perOut)

	active := ct.activeConnections()
	require.Len(t, active, 2)
}

func TestConnTracker_CountsBytesAndFoldsOnClose(t *testing.T) {
	ct := newConnTracker()
	tr := newThroughputTracker(ct, time.Second)
	ct.tp = tr

	srv, cli := net.Pipe()
	defer srv.Close()
	r := newRec("out")
	tc := wrapTCP(ct, r, cli)

	msg := []byte("hello, world!")
	done := make(chan struct{})
	go func() {
		buf := make([]byte, len(msg))
		io.ReadFull(srv, buf)
		close(done)
	}()
	n, err := tc.Write(msg)
	require.NoError(t, err)
	require.Equal(t, len(msg), n)
	<-done

	_, down := ct.Total()
	assert.Equal(t, int64(len(msg)), down)
	assert.Equal(t, int64(len(msg)), r.download.Load())

	require.NoError(t, tc.Close())
	_ = tc.Close() // second close: leave is a no-op, inner close may error

	_, ok := ct.conns.Load(r.id)
	assert.False(t, ok)
	require.Len(t, tr.pending, 1)
	assert.Equal(t, int64(len(msg)), tr.pending[0].down)
}

func TestConnTracker_ConcurrentJoinLeave(t *testing.T) {
	ct := newConnTracker()
	tr := newThroughputTracker(ct, time.Second)
	ct.tp = tr

	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := newRec("out")
			ct.join(r)
			addBytes(ct, r, 1, 1)
			ct.leave(r)
		}()
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ct.Connections()
			_, _ = ct.activeStats()
			ct.Total()
		}()
	}
	wg.Wait()

	count, _ := ct.activeStats()
	assert.Equal(t, 0, count, "all connections left")
	up, down := ct.Total()
	assert.Equal(t, int64(n), up)
	assert.Equal(t, int64(n), down)
}

func TestConnTracker_JoinReclaim(t *testing.T) {
	ct := newConnTracker()
	stop := make(chan struct{})
	reclaimed := make(chan struct{})
	var wg sync.WaitGroup
	var minimum int64

	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				ct.closeAllTracked()
				minimum = min(minimum, ct.activeConnectionCount())
				runtime.Gosched()
			}
		}
	})
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				ct.Connections()
				ct.activeConnections()
				runtime.Gosched()
			}
		}
	})

	for range 5000 {
		r := newRec("out")
		r.closer = closerFunc(func() error {
			ct.leave(r)
			minimum = min(minimum, ct.activeConnectionCount())
			reclaimed <- struct{}{}
			return nil
		})
		ct.join(r)
		<-reclaimed
	}
	close(stop)
	wg.Wait()

	assert.Zero(t, minimum, "active count went negative during reclamation")
	assert.Zero(t, ct.activeConnectionCount())
	assert.Empty(t, ct.Connections())
	assert.Empty(t, ct.activeConnections())
}

func TestConnTracker_CloseWaitsForInFlightWriteAccounting(t *testing.T) {
	ct := newConnTracker()
	tr := newThroughputTracker(ct, time.Second)
	ct.tp = tr
	obs := &recordingObserver{}
	ct.SetObserver(obs)

	r := newRec("out")
	inner := newCloseWaitsForWriteConn()
	tc := wrapTCP(ct, r, inner)
	msg := []byte("late bytes")

	writeErr := make(chan error, 1)
	go func() {
		_, err := tc.Write(msg)
		close(inner.writeAccounted) // unblocks inner.Close only after CounterConn has counted msg
		writeErr <- err
	}()
	<-inner.writeStarted

	require.NoError(t, tc.Close())
	require.NoError(t, <-writeErr)

	_, ok := ct.conns.Load(r.id)
	assert.False(t, ok)
	require.Len(t, tr.pending, 1)
	assert.Equal(t, int64(len(msg)), tr.pending[0].down)
	require.Len(t, obs.closes, 1)
	assert.Equal(t, int64(len(msg)), obs.closes[0].Downlink)
}

type fakeFlowHandle struct {
	flow   *flowConn
	closes int
}

func (h *fakeFlowHandle) CloseFlow() {
	h.closes++
	h.flow.CloseFlow(tun.FlowCloseReset)
}

func TestFlowConnTracksFlow(t *testing.T) {
	ct := newConnTracker()
	r := newRec("wg")
	f := &flowConn{rec: r, ct: ct}
	r.closer = f
	assert.Zero(t, ct.activeConnectionCount(), "a flow joins only once attached")

	handle := &fakeFlowHandle{flow: f}
	f.AttachFlow(handle)
	require.EqualValues(t, 1, ct.activeConnectionCount())
	f.CountForward(3)
	f.CountReverse(5)
	up, down := ct.Total()
	assert.EqualValues(t, 3, up)
	assert.EqualValues(t, 5, down)

	ct.closeRecord(r)
	assert.Equal(t, 1, handle.closes, "closing the record ends the flow through its handle")
	assert.Zero(t, ct.activeConnectionCount())
	f.CloseFlow(tun.FlowCloseFinished)
	assert.Zero(t, ct.activeConnectionCount(), "a flow leaves once")
}

func TestFlowConnClosedBeforeAttachNeverJoins(t *testing.T) {
	ct := newConnTracker()
	obs := &recordingObserver{}
	ct.SetObserver(obs)
	r := newRec("wg")
	f := &flowConn{rec: r, ct: ct}
	r.closer = f

	f.CloseFlow(tun.FlowCloseReset)
	f.AttachFlow(&fakeFlowHandle{flow: f})
	assert.Zero(t, ct.activeConnectionCount())
	_, ok := ct.conns.Load(r.id)
	assert.False(t, ok)
	assert.Empty(t, obs.closes, "a flow that never joined reports no close")
}

func TestFlowConnConcurrentAttachAndClose(t *testing.T) {
	ct := newConnTracker()
	for range 200 {
		r := newRec("wg")
		f := &flowConn{rec: r, ct: ct}
		r.closer = f
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			f.AttachFlow(&fakeFlowHandle{flow: f})
		}()
		go func() {
			defer wg.Done()
			f.CloseFlow(tun.FlowCloseReset)
		}()
		wg.Wait()
	}
	assert.Zero(t, ct.activeConnectionCount())
	for range ct.conns.Iter() {
		t.Fatal("a flow outlived its close")
	}
}

type taggedOutbound struct {
	A.Outbound
	tag string
}

func (o taggedOutbound) Tag() string  { return o.tag }
func (o taggedOutbound) Type() string { return "stub" }

type taggedGroup struct {
	taggedOutbound
	now string
}

func (g taggedGroup) Now() string   { return g.now }
func (g taggedGroup) All() []string { return []string{g.now} }

type routeRule struct {
	A.Rule
	action A.RuleAction
}

func (r routeRule) Action() A.RuleAction { return r.action }
func (r routeRule) String() string       { return "stub" }

func TestRoutedFlowChainStartsAtRuleOutbound(t *testing.T) {
	endpoint := taggedOutbound{tag: "wg"}
	ct := newConnTracker()
	ct.outbound = stubOutboundManager{outbounds: map[string]A.Outbound{
		AutoSelectTag: taggedGroup{taggedOutbound: taggedOutbound{tag: AutoSelectTag}, now: "wg"},
		"wg":          endpoint,
	}}
	rule := routeRule{action: &R.RuleActionRoute{Outbound: AutoSelectTag}}

	// sing-box passes the endpoint the group resolved to, not the group.
	f, ok := ct.RoutedFlow(context.Background(), A.InboundContext{}, rule, endpoint).(*flowConn)
	require.True(t, ok)
	assert.Equal(t, []string{"wg", AutoSelectTag}, f.rec.chain)

	handle := &fakeFlowHandle{flow: f}
	f.AttachFlow(handle)
	ct.closeMatchedTo(AutoSelectTag)
	assert.Equal(t, 1, handle.closes, "a mode switch closes flows routed through the group")
	assert.Zero(t, ct.activeConnectionCount())
}

func TestRoutedFlowKeepsResolvedEndpointAfterGroupSwitch(t *testing.T) {
	endpoint := taggedOutbound{tag: "wg-a"}
	ct := newConnTracker()
	ct.outbound = stubOutboundManager{outbounds: map[string]A.Outbound{
		AutoSelectTag: taggedGroup{taggedOutbound: taggedOutbound{tag: AutoSelectTag}, now: "wg-b"},
		"wg-a":        endpoint,
		"wg-b":        taggedOutbound{tag: "wg-b"},
	}}
	rule := routeRule{action: &R.RuleActionRoute{Outbound: AutoSelectTag}}

	// auto switched to wg-b after sing-box routed the flow to wg-a.
	f, ok := ct.RoutedFlow(context.Background(), A.InboundContext{}, rule, endpoint).(*flowConn)
	require.True(t, ok)
	assert.Equal(t, "wg-a", f.rec.outbound)
	assert.Equal(t, []string{"wg-a", AutoSelectTag}, f.rec.chain)
}

func TestFlowConnDropsBytesCountedAfterClose(t *testing.T) {
	ct := newConnTracker()
	obs := &recordingObserver{}
	ct.SetObserver(obs)
	r := newRec("wg")
	f := &flowConn{rec: r, ct: ct}
	r.closer = f
	f.AttachFlow(&fakeFlowHandle{flow: f})
	f.CountForward(3)

	f.CloseFlow(tun.FlowCloseReset)
	f.CountForward(7)
	f.CountReverse(5)
	require.Len(t, obs.closes, 1)
	assert.EqualValues(t, 3, obs.closes[0].Uplink)
	assert.Zero(t, obs.closes[0].Downlink)
	up, down := ct.Total()
	assert.EqualValues(t, 3, up)
	assert.Zero(t, down)
}

func TestFlowConnCountsConcurrentlyWithClose(t *testing.T) {
	ct := newConnTracker()
	obs := &recordingObserver{}
	ct.SetObserver(obs)
	for range 100 {
		r := newRec("wg")
		f := &flowConn{rec: r, ct: ct}
		r.closer = f
		f.AttachFlow(&fakeFlowHandle{flow: f})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				f.CountForward(1)
				f.CountReverse(1)
			}
		}()
		go func() {
			defer wg.Done()
			f.CloseFlow(tun.FlowCloseReset)
		}()
		wg.Wait()
	}
	// Every counted byte lands in a flow's close report.
	var up, down int64
	for _, c := range obs.closes {
		up += c.Uplink
		down += c.Downlink
	}
	totalUp, totalDown := ct.Total()
	assert.Equal(t, totalUp, up)
	assert.Equal(t, totalDown, down)
}
