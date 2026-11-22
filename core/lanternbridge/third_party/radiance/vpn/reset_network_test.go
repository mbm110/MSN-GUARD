package vpn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/getlantern/lantern-box"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

type resetMonitor struct {
	tun.DefaultInterfaceMonitor
	closed func()
	iface  *control.Interface
}

func (m *resetMonitor) DefaultInterface() *control.Interface                               { return m.iface }
func (*resetMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {}
func (*resetMonitor) MyInterfaces() []string                                               { return nil }

func (*resetMonitor) Start() error { return nil }
func (m *resetMonitor) Close() error {
	if m.closed != nil {
		m.closed()
	}
	return nil
}
func (*resetMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (*resetMonitor) UpdateDefaultInterface(string, int32, bool, bool) {}
func (*resetMonitor) UpdateNetworkPath(string)                         {}

type resetPlatform struct {
	adapter.PlatformInterface
	monitor *resetMonitor
}

func (*resetPlatform) Initialize(adapter.NetworkManager) error { return nil }
func (p *resetPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return p.monitor
}
func (*resetPlatform) UsePlatformNetworkInterfaces() bool       { return true }
func (*resetPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (*resetPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return nil, nil
}

type resetRouter struct {
	adapter.Router
	resets  atomic.Int32
	onReset func()
	monitor *resetMonitor
}

func (r *resetRouter) ResetNetwork() {
	r.resets.Add(1)
	if r.onReset != nil {
		r.onReset()
	}
}

func resetTestTunnel(t *testing.T) (*tunnel, *resetRouter) {
	t.Helper()
	p := &resetPlatform{monitor: &resetMonitor{}}
	ctx := service.ContextWith[adapter.PlatformInterface](box.Context(context.Background()), p)
	instance, err := sbox.New(sbox.Options{Context: ctx, Options: option.Options{
		Log: &option.LogOptions{Disabled: true},
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, instance.Close()) })
	router := &resetRouter{monitor: p.monitor}
	service.MustRegister[adapter.Router](ctx, router)
	require.NoError(t, instance.Network().Start(adapter.StartStateInitialize))
	return &tunnel{boxInstance: instance}, router
}

func TestResetNetworkForMonitor(t *testing.T) {
	tn, router := resetTestTunnel(t)
	client := &VPNClient{tunnel: tn}
	client.ResetNetworkForMonitor(nil)
	client.ResetNetworkForMonitor(&resetMonitor{})
	require.Zero(t, router.resets.Load())

	client.ResetNetworkForMonitor(router.monitor)
	require.EqualValues(t, 1, router.resets.Load())
	client.ResetNetwork()
	require.EqualValues(t, 2, router.resets.Load())

	client.tunnel = nil
	client.ResetNetworkForMonitor(router.monitor)
	client.tunnel = &tunnel{}
	client.ResetNetworkForMonitor(router.monitor)
	require.EqualValues(t, 2, router.resets.Load())
}

func TestResetNetworkForMonitorRejectsReplacementAfterWaitingForLock(t *testing.T) {
	oldTunnel, oldRouter := resetTestTunnel(t)
	newTunnel, newRouter := resetTestTunnel(t)
	client := &VPNClient{tunnel: oldTunnel}

	client.mu.Lock()
	unlock := sync.OnceFunc(client.mu.Unlock)
	t.Cleanup(unlock)
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		client.ResetNetworkForMonitor(oldRouter.monitor)
		close(done)
	}()
	<-started
	select {
	case <-done:
		t.Fatal("reset did not wait for the tunnel lock")
	case <-time.After(20 * time.Millisecond):
	}
	client.tunnel = newTunnel
	unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reset did not finish after tunnel replacement")
	}
	require.Zero(t, oldRouter.resets.Load())
	require.Zero(t, newRouter.resets.Load())
}

func TestResetNetworkForMonitorHoldsTunnelUntilResetCompletes(t *testing.T) {
	oldTunnel, oldRouter := resetTestTunnel(t)
	newTunnel, _ := resetTestTunnel(t)
	client := &VPNClient{tunnel: oldTunnel}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	oldRouter.onReset = func() {
		close(entered)
		<-release
	}
	go func() {
		client.ResetNetworkForMonitor(oldRouter.monitor)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reset did not reach the current tunnel")
	}
	locked := client.mu.TryLock()
	if locked {
		client.mu.Unlock()
	}
	require.False(t, locked, "replacement must wait for reset to finish")
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reset did not finish")
	}
	client.mu.Lock()
	client.tunnel = newTunnel
	client.mu.Unlock()
}

func TestResetNetworkForMonitorAllowsMonitorCallbacks(t *testing.T) {
	tn, router := resetTestTunnel(t)
	client := &VPNClient{tunnel: tn}
	callbackRan := make(chan struct{})
	var callbackOnce sync.Once
	router.monitor.closed = func() { callbackOnce.Do(func() { close(callbackRan) }) }
	router.onReset = func() { _ = router.monitor.Close() }
	done := make(chan struct{})
	go func() {
		client.ResetNetworkForMonitor(router.monitor)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reset blocked a monitor callback")
	}
	select {
	case <-callbackRan:
	default:
		t.Fatal("reset did not invoke the monitor callback")
	}
	require.EqualValues(t, 1, router.resets.Load())
}

// monitorCapturePlatform is a native platform that keeps the listener its monitor was started
// with, as macOS's network extension does to pass back to ResetNetworkForMonitor.
type monitorCapturePlatform struct {
	libbox.PlatformInterface
	listener atomic.Pointer[libbox.InterfaceUpdateListener]
}

func (*monitorCapturePlatform) UseProcFS() bool                             { return false }
func (*monitorCapturePlatform) UnderNetworkExtension() bool                 { return false }
func (*monitorCapturePlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (*monitorCapturePlatform) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return nil, errors.New("no interfaces")
}
func (p *monitorCapturePlatform) StartDefaultInterfaceMonitor(l libbox.InterfaceUpdateListener) error {
	p.listener.Store(&l)
	return nil
}
func (*monitorCapturePlatform) CloseDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error {
	return nil
}
func (*monitorCapturePlatform) RestartService() error { return nil }
func (*monitorCapturePlatform) PostServiceClose()     {}

// platformTunnel builds a tunnel box on c's box platform, as tunnel.init does, and returns its
// router and the listener the native platform got.
func platformTunnel(t *testing.T, c *VPNClient, native *monitorCapturePlatform) (*resetRouter, libbox.InterfaceUpdateListener) {
	t.Helper()
	ctx := service.ContextWith[adapter.PlatformInterface](box.Context(context.Background()), libbox.NewPlatformInterfaceWrapper(c.boxPlatform))
	instance, err := sbox.New(sbox.Options{Context: ctx, Options: option.Options{
		Log: &option.LogOptions{Disabled: true},
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, instance.Close()) })
	router := &resetRouter{}
	service.MustRegister[adapter.Router](ctx, router)
	require.NoError(t, instance.Network().Start(adapter.StartStateInitialize))
	c.tunnel = &tunnel{boxInstance: instance}
	got := native.listener.Load()
	require.NotNil(t, got, "the box must start the platform's monitor")
	return router, *got
}

// TestResetNetworkForMonitorTakesThePlatformsListener checks that the listener the native
// platform holds resets the tunnel, whether the platform is the tunnel's own (macOS) or shared
// with the direct exit (Android), and that a foreign or retired one doesn't.
func TestResetNetworkForMonitorTakesThePlatformsListener(t *testing.T) {
	prev := sharePlatformMonitor
	t.Cleanup(func() { sharePlatformMonitor = prev })
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared=%v", shared), func(t *testing.T) {
			sharePlatformMonitor = func() bool { return shared }
			native := &monitorCapturePlatform{}
			c := NewVPNClient(t.TempDir(), nil, native)
			router, listener := platformTunnel(t, c, native)

			c.ResetNetworkForMonitor(&resetMonitor{})
			require.Zero(t, router.resets.Load(), "a foreign listener resets nothing")
			c.ResetNetworkForMonitor(listener)
			require.EqualValues(t, 1, router.resets.Load())
			if !shared {
				return
			}
			// The tunnel's monitor closes and a new one starts: the old forwarder is retired.
			monitor := c.tunnel.boxInstance.Network().InterfaceMonitor().(libbox.InterfaceUpdateListener)
			require.NoError(t, c.shared.CloseDefaultInterfaceMonitor(monitor))
			require.NoError(t, c.shared.StartDefaultInterfaceMonitor(monitor))
			c.ResetNetworkForMonitor(listener)
			require.EqualValues(t, 1, router.resets.Load(), "a retired forwarder resets nothing")
			c.ResetNetworkForMonitor(*native.listener.Load())
			require.EqualValues(t, 2, router.resets.Load())
		})
	}
}
