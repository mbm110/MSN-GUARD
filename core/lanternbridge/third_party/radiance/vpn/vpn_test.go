package vpn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/getlantern/lantern-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/servers"
)

// stubPlatform implements PlatformInterface for testing without real VPN operations.
type stubPlatform struct {
	libbox.PlatformInterface

	restartErr      error
	restartCalled   bool
	postCloseCalled bool
	restartFn       func() error // optional hook invoked inside RestartService
	mu              sync.Mutex
}

func (s *stubPlatform) RestartService() error {
	s.mu.Lock()
	s.restartCalled = true
	fn := s.restartFn
	errRet := s.restartErr
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return errRet
}

func (s *stubPlatform) PostServiceClose() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postCloseCalled = true
}

func TestNewVPNClient(t *testing.T) {
	t.Run("nil logger defaults to slog.Default", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), nil, nil)
		require.NotNil(t, c)
		assert.Equal(t, slog.Default(), c.logger)
		assert.Equal(t, Disconnected, c.Status())
	})

	t.Run("custom logger is retained", func(t *testing.T) {
		logger := rlog.NoOpLogger()
		c := NewVPNClient(t.TempDir(), logger, nil)
		require.NotNil(t, c)
		assert.Equal(t, logger, c.logger)
	})
}

func TestStatus(t *testing.T) {
	t.Run("disconnected when no tunnel", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
		assert.Equal(t, Disconnected, c.Status())
		assert.False(t, c.isOpen())
	})

	t.Run("concurrent reads", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = c.Status()
			}()
		}
		wg.Wait()
	})
}

func TestConnect(t *testing.T) {
	t.Run("already connected", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
		c.status.Store(Connected)
		c.tunnel = &tunnel{}

		err := c.Connect(context.Background(), BoxOptions{})
		assert.ErrorIs(t, err, ErrTunnelAlreadyConnected)
	})

	t.Run("transient state refused", func(t *testing.T) {
		for _, status := range []VPNStatus{Restarting, Connecting, Disconnecting} {
			t.Run(string(status), func(t *testing.T) {
				c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
				c.status.Store(status)
				c.tunnel = &tunnel{}

				err := c.Connect(context.Background(), BoxOptions{})
				require.Error(t, err)
				assert.Contains(t, err.Error(), string(status))
			})
		}
	})

	t.Run("cleans up stale tunnel", func(t *testing.T) {
		for _, status := range []VPNStatus{Disconnected, ErrorStatus} {
			t.Run(string(status), func(t *testing.T) {
				c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
				c.status.Store(status)
				c.tunnel = &tunnel{}

				// Connect fails because BoxOptions has no outbounds, but the stale
				// tunnel should be cleared first so the error comes from buildOptions.
				err := c.Connect(context.Background(), BoxOptions{BasePath: t.TempDir()})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "no outbounds")
			})
		}
	})
}

func TestConnect_CanceledDuringOfflineTestWait(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	// An open (never-closed) channel keeps the offline-test wait blocked, so the
	// only way out of Connect is ctx cancellation.
	c.offlineTestDone = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.Connect(ctx, BoxOptions{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestDisconnect_NoTunnel(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	assert.NoError(t, c.Disconnect())
}

func TestRestart(t *testing.T) {
	t.Run("no tunnel", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
		err := c.Restart(BoxOptions{})
		assert.ErrorIs(t, err, ErrTunnelNotConnected)
	})

	t.Run("tunnel not connected", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
		c.status.Store(Disconnected)
		c.tunnel = &tunnel{}

		err := c.Restart(BoxOptions{})
		assert.ErrorIs(t, err, ErrTunnelNotConnected)
	})

	t.Run("platform interface success", func(t *testing.T) {
		// While RestartService is in flight, VPNClient.Status() must report
		// Restarting — bridging the window where the old tunnel is torn down and
		// the new one has not yet reached Connected. Once RestartService returns
		// successfully, status reflects the new tunnel's Connected state — which a
		// real platform drives by calling VPNClient.Disconnect + Connect
		// internally. The stub simulates that via a direct setStatus(Connected).
		entered := make(chan struct{})
		release := make(chan struct{})
		p := &stubPlatform{}
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), p)
		c.status.Store(Connected)
		c.tunnel = &tunnel{}

		p.restartFn = func() error {
			close(entered)
			<-release
			c.setStatus(Connected, nil)
			return nil
		}

		done := make(chan error, 1)
		go func() { done <- c.Restart(BoxOptions{}) }()

		<-entered
		assert.Equal(t, Restarting, c.Status(), "status should report Restarting while RestartService runs")
		close(release)

		require.NoError(t, <-done)

		p.mu.Lock()
		assert.True(t, p.restartCalled)
		p.mu.Unlock()
		assert.Equal(t, Connected, c.Status(), "status should reflect the new tunnel after restart completes")
	})

	t.Run("platform interface error", func(t *testing.T) {
		restartErr := errors.New("restart failed")
		p := &stubPlatform{restartErr: restartErr}
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), p)
		c.status.Store(Connected)
		c.tunnel = &tunnel{}

		err := c.Restart(BoxOptions{})
		require.Error(t, err)
		assert.ErrorIs(t, err, restartErr)
		assert.Equal(t, ErrorStatus, c.Status())
	})
}

func TestSelectServer(t *testing.T) {
	t.Run("no tunnel", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
		err := c.SelectServer("some-tag")
		assert.ErrorIs(t, err, ErrTunnelNotConnected)
	})

	t.Run("tunnel disconnected", func(t *testing.T) {
		c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
		c.status.Store(Disconnected)
		c.tunnel = &tunnel{}

		err := c.SelectServer("some-tag")
		assert.ErrorIs(t, err, ErrTunnelNotConnected)
	})
}

func TestNoTunnelOperations(t *testing.T) {
	ops := map[string]func(*VPNClient) error{
		"UpdateOutbounds": func(c *VPNClient) error { return c.UpdateOutbounds(servers.ServerList{}) },
		"AddOutbounds":    func(c *VPNClient) error { return c.AddOutbounds(servers.ServerList{}) },
		"RemoveOutbounds": func(c *VPNClient) error { return c.RemoveOutbounds([]string{"tag1"}) },
		"Connections": func(c *VPNClient) error {
			_, err := c.Connections()
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
			assert.ErrorIs(t, op(c), ErrTunnelNotConnected)
		})
	}
}

func TestCurrentAutoSelectedServer_NotOpen(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	selected, err := c.CurrentAutoSelectedServer()
	assert.NoError(t, err)
	assert.Empty(t, selected)
}

func TestRunOfflineURLTests_AlreadyConnected(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	c.status.Store(Connected)
	c.tunnel = &tunnel{}

	_, err := c.RunOfflineURLTests(t.Context(), "", nil, nil, nil)
	assert.ErrorIs(t, err, ErrTunnelAlreadyConnected)
}

type offlinePanicOutbound struct {
	adapter.Outbound
	phase  string
	closed *atomic.Bool
}

func (o *offlinePanicOutbound) Start(stage adapter.StartStage) error {
	if o.phase == "close" && stage == adapter.StartStateInitialize {
		return assert.AnError
	}
	if o.phase == "initialize" && stage == adapter.StartStateInitialize ||
		o.phase == "start" && stage == adapter.StartStateStart {
		panic(o.phase)
	}
	return nil
}

func (o *offlinePanicOutbound) Close() error {
	o.closed.Store(true)
	if o.phase == "close" {
		panic(o.phase)
	}
	if closer, ok := o.Outbound.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func registerWrappedDirect(ctx context.Context, typ string, wrap func(context.Context, adapter.Outbound) adapter.Outbound) {
	registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
	outbound.Register[O.DirectOutboundOptions](registry, typ,
		func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts O.DirectOutboundOptions) (adapter.Outbound, error) {
			ob, err := direct.NewOutbound(ctx, router, logger, tag, opts)
			if err != nil {
				return nil, err
			}
			return wrap(ctx, ob), nil
		})
}

func TestRunOfflineURLTests_Panic(t *testing.T) {
	for _, phase := range []string{"construct", "initialize", "start", "close"} {
		t.Run(phase, func(t *testing.T) {
			crashLog := useTempCrashLog(t)
			ctx, cancel := context.WithCancel(box.Context(t.Context()))
			defer cancel()
			var factoryCtx context.Context
			var closed atomic.Bool
			registerWrappedDirect(ctx, "panic-test", func(ctx context.Context, ob adapter.Outbound) adapter.Outbound {
				factoryCtx = ctx
				if phase == "construct" {
					panic(phase)
				}
				return &offlinePanicOutbound{Outbound: ob, phase: phase, closed: &closed}
			})

			client := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
			results, err := client.RunOfflineURLTests(ctx, "", []O.Outbound{{Type: "panic-test", Tag: "panic"}}, nil, nil)
			require.ErrorContains(t, err, "panic running offline URL tests:")
			assert.Contains(t, err.Error(), phase)
			assert.NotContains(t, err.Error(), "\n")
			crash := readCrashLog(t, crashLog)
			assert.Contains(t, crash, "recovered panic running offline URL tests")
			assert.Contains(t, crash, "vpn/vpn.go:")
			switch phase {
			case "construct":
				assert.Contains(t, crash, "adapter/outbound/registry.go:")
			case "initialize", "start":
				assert.Contains(t, crash, "(*offlinePanicOutbound).Start")
			case "close":
				assert.Contains(t, crash, "(*offlinePanicOutbound).Close")
			}
			assert.Nil(t, results)
			require.NotNil(t, factoryCtx)
			assert.ErrorIs(t, factoryCtx.Err(), context.Canceled)
			assert.Equal(t, phase != "construct", closed.Load())
			select {
			case <-client.offlineTestDone:
			default:
				t.Fatal("offline test completion was not signalled")
			}

			results, err = client.RunOfflineURLTests(t.Context(), "", []O.Outbound{{Type: "missing-outbound", Tag: "invalid"}}, nil, nil)
			require.ErrorContains(t, err, "failed to create sing-box instance")
			assert.NotContains(t, err.Error(), "offline tests already running")
			assert.Nil(t, results)
		})
	}
}

func TestClearTunnelCache(t *testing.T) {
	newClient := func(t *testing.T, s VPNStatus, tun *tunnel, dir string) (*VPNClient, string) {
		t.Helper()
		path := cacheFilePath(dir)
		require.NoError(t, os.WriteFile(path, []byte("cache"), 0o600))
		c := NewVPNClient(dir, rlog.NoOpLogger(), nil)
		c.status.Store(s)
		c.tunnel = tun
		return c, path
	}

	t.Run("disconnected deletes in place", func(t *testing.T) {
		dir := t.TempDir()
		c, path := newClient(t, Disconnected, nil, dir)

		restart, err := c.ClearTunnelCache(dir)
		assert.NoError(t, err)
		assert.False(t, restart)
		assert.NoFileExists(t, path)
		assert.NoFileExists(t, cacheClearMarkerPath(dir))
	})

	t.Run("connected defers via marker and requests restart", func(t *testing.T) {
		dir := t.TempDir()
		c, path := newClient(t, Connected, &tunnel{}, dir)

		restart, err := c.ClearTunnelCache(dir)
		assert.NoError(t, err)
		assert.True(t, restart)
		assert.FileExists(t, path)
		assert.FileExists(t, cacheClearMarkerPath(dir))
		assert.NotNil(t, c.tunnel)
	})
}

func TestConsumeCacheClearMarker(t *testing.T) {
	t.Run("marker present deletes cache and marker", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(cacheFilePath(dir), []byte("cache"), 0o600))
		require.NoError(t, writeCacheClearMarker(dir))

		assert.NoError(t, consumeCacheClearMarker(dir))
		assert.NoFileExists(t, cacheFilePath(dir))
		assert.NoFileExists(t, cacheClearMarkerPath(dir))
	})

	t.Run("no marker leaves cache untouched", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(cacheFilePath(dir), []byte("cache"), 0o600))

		assert.NoError(t, consumeCacheClearMarker(dir))
		assert.FileExists(t, cacheFilePath(dir))
	})
}

type stubOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m stubOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outbounds[tag]
	return o, ok
}

type stubGroup struct {
	adapter.OutboundGroup
	now string
}

func (g stubGroup) Now() string { return g.now }

func TestCurrentSelectedServer_WhileRejecting(t *testing.T) {
	tun := newModeTestTunnel(t)
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{
		AutoSelectTag: stubGroup{now: "srv-a"},
	}}
	tun.clashModeManager.setRejectMode(true)
	c := &VPNClient{tunnel: tun}
	c.status.Store(Connected)

	tag, err := c.CurrentSelectedServer()
	require.NoError(t, err)
	assert.Equal(t, "srv-a", tag)
}

func TestSelectedPersonalProxy(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	assert.Empty(t, c.SelectedPersonalProxy(), "no tunnel")

	friend := "helper-aaaaaaaaaaaa"
	c.tunnel = &tunnel{}
	c.tunnel.personalProxy.Store(&friend)
	assert.Empty(t, c.SelectedPersonalProxy(), "a tunnel that is not connected")

	c.status.Store(Connected)
	assert.Equal(t, friend, c.SelectedPersonalProxy())
	c.tunnel.personalProxy.Store(nil)
	assert.Empty(t, c.SelectedPersonalProxy())
}

func TestManualSelectionIsModeAware(t *testing.T) {
	_, ok := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil).ManualSelection()
	assert.False(t, ok, "no tunnel")

	tun := newModeTestTunnel(t)
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{
		AutoSelectTag:   stubGroup{now: "srv-a"},
		ManualSelectTag: stubGroup{now: "srv-a"},
	}}
	c := &VPNClient{tunnel: tun}
	c.status.Store(Connected)
	_, ok = c.ManualSelection()
	assert.False(t, ok, "auto mode on srv-a is not a pin of srv-a")

	_, err := tun.clashModeManager.SetMode(ManualSelectTag)
	require.NoError(t, err)
	tag, ok := c.ManualSelection()
	assert.True(t, ok)
	assert.Equal(t, "srv-a", tag)
}

func TestBoxContextWithoutATunnel(t *testing.T) {
	c := &VPNClient{}
	assert.Nil(t, c.BoxContext())
}

func TestBoxContextFollowsTheTunnel(t *testing.T) {
	c := &VPNClient{}
	ctx := context.WithValue(context.Background(), boxCtxKey{}, 1)
	c.setTunnelLocked(&tunnel{ctx: ctx})
	assert.Equal(t, ctx, c.BoxContext())
	c.setTunnelLocked(nil)
	assert.Nil(t, c.BoxContext())
}

type boxCtxKey struct{}

func TestBoxContextDoesNotWaitOnABringUp(t *testing.T) {
	c := &VPNClient{}
	ctx := context.WithValue(context.Background(), boxCtxKey{}, 1)
	c.setTunnelLocked(&tunnel{ctx: ctx})
	c.mu.Lock()
	defer c.mu.Unlock()
	got := make(chan context.Context, 1)
	go func() { got <- c.BoxContext() }()
	select {
	case g := <-got:
		assert.Equal(t, ctx, g)
	case <-time.After(5 * time.Second):
		t.Fatal("BoxContext waited on c.mu")
	}
}
