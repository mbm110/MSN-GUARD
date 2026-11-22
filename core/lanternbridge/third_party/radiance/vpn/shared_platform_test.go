package vpn

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// monitorPlatform is a platform whose default interface monitor takes one listener, as
// Android's does.
type monitorPlatform struct {
	libbox.PlatformInterface

	mu       sync.Mutex
	listener libbox.InterfaceUpdateListener
	starts   int
	closes   int
	startErr error
}

func (p *monitorPlatform) StartDefaultInterfaceMonitor(l libbox.InterfaceUpdateListener) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.starts++
	if p.startErr != nil {
		return p.startErr
	}
	p.listener = l
	return nil
}

func (p *monitorPlatform) CloseDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	p.listener = nil
	return nil
}

func (p *monitorPlatform) update(name string, index int32) {
	p.mu.Lock()
	l := p.listener
	p.mu.Unlock()
	if l != nil {
		l.UpdateDefaultInterface(name, index, false, false)
	}
}

func (p *monitorPlatform) counts() (starts, closes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.starts, p.closes
}

type recordingListener struct {
	mu      sync.Mutex
	updates []string
	paths   []string
	// onUpdate, if set, runs on each update, outside mu.
	onUpdate func()
}

func (l *recordingListener) UpdateDefaultInterface(name string, _ int32, _, _ bool) {
	l.mu.Lock()
	l.updates = append(l.updates, name)
	l.mu.Unlock()
	if l.onUpdate != nil {
		l.onUpdate()
	}
}

func (l *recordingListener) UpdateNetworkPath(path string) {
	l.mu.Lock()
	l.paths = append(l.paths, path)
	l.mu.Unlock()
}

func (l *recordingListener) got() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.updates...)
}

func TestSharedPlatformNil(t *testing.T) {
	assert.Nil(t, newSharedPlatform(nil))
	var p PlatformInterface
	assert.Nil(t, NewVPNClient(t.TempDir(), nil, p).BoxPlatform())
}

func TestSharedPlatformFansOut(t *testing.T) {
	under := &monitorPlatform{}
	s := newSharedPlatform(under)
	a, b := &recordingListener{}, &recordingListener{}

	require.NoError(t, s.StartDefaultInterfaceMonitor(a))
	under.update("wlan0", 1)
	require.NoError(t, s.StartDefaultInterfaceMonitor(b))
	starts, _ := under.counts()
	assert.Equal(t, 1, starts, "the platform's monitor starts once")
	assert.Equal(t, []string{"wlan0"}, b.got(), "a late listener gets the latest update")

	under.update("rmnet0", 2)
	assert.Equal(t, []string{"wlan0", "rmnet0"}, a.got())
	assert.Equal(t, []string{"wlan0", "rmnet0"}, b.got())

	under.listener.UpdateNetworkPath("satisfied")
	assert.Equal(t, []string{"satisfied"}, a.paths)
	assert.Equal(t, []string{"satisfied"}, b.paths)

	require.NoError(t, s.CloseDefaultInterfaceMonitor(a))
	_, closes := under.counts()
	assert.Equal(t, 0, closes, "the platform's monitor stays up while a listener remains")
	under.update("wlan0", 1)
	assert.Equal(t, []string{"wlan0", "rmnet0"}, a.got(), "a closed listener gets no updates")
	assert.Equal(t, []string{"wlan0", "rmnet0", "wlan0"}, b.got())

	require.NoError(t, s.CloseDefaultInterfaceMonitor(b))
	require.NoError(t, s.CloseDefaultInterfaceMonitor(b), "closing twice is a no-op")
	starts, closes = under.counts()
	assert.Equal(t, 1, starts)
	assert.Equal(t, 1, closes, "the last listener closes the platform's monitor once")

	// A fresh start doesn't replay an update from before the monitor closed.
	c := &recordingListener{}
	require.NoError(t, s.StartDefaultInterfaceMonitor(c))
	assert.Empty(t, c.got())
	starts, _ = under.counts()
	assert.Equal(t, 2, starts)
}

func TestSharedPlatformDropsUpdatesAfterTheLastClose(t *testing.T) {
	under := &monitorPlatform{}
	s := newSharedPlatform(under)
	a := &recordingListener{}
	require.NoError(t, s.StartDefaultInterfaceMonitor(a))
	fanOut := under.listener
	require.NoError(t, s.CloseDefaultInterfaceMonitor(a))
	// An update the platform sent as the monitor closed.
	fanOut.UpdateDefaultInterface("stale0", 9, false, false)

	b, c := &recordingListener{}, &recordingListener{}
	require.NoError(t, s.StartDefaultInterfaceMonitor(b))
	require.NoError(t, s.StartDefaultInterfaceMonitor(c))
	assert.Empty(t, b.got())
	assert.Empty(t, c.got(), "no listener gets an interface from before the monitor restarted")
	under.update("wlan0", 1)
	assert.Equal(t, []string{"wlan0"}, c.got())
}

func TestSharedPlatformStartError(t *testing.T) {
	under := &monitorPlatform{startErr: errors.New("netlink banned")}
	s := newSharedPlatform(under)
	a := &recordingListener{}
	require.Error(t, s.StartDefaultInterfaceMonitor(a))
	under.startErr = nil
	require.NoError(t, s.StartDefaultInterfaceMonitor(a))
	starts, _ := under.counts()
	assert.Equal(t, 2, starts, "a failed start is retried by the next listener")
	under.update("wlan0", 1)
	assert.Equal(t, []string{"wlan0"}, a.got())
}

func TestSharedPlatformListenerReentry(t *testing.T) {
	under := &monitorPlatform{}
	s := newSharedPlatform(under)
	a, b := &recordingListener{}, &recordingListener{}
	a.onUpdate = func() {
		// A box starting its monitor, and another closing one, from an update.
		_ = s.StartDefaultInterfaceMonitor(b)
		_ = s.CloseDefaultInterfaceMonitor(a)
	}
	require.NoError(t, s.StartDefaultInterfaceMonitor(a))
	done := make(chan struct{})
	go func() {
		under.update("wlan0", 1)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an update that re-enters the shared platform deadlocked")
	}
	assert.Equal(t, []string{"wlan0"}, a.got())
	assert.Equal(t, []string{"wlan0"}, b.got(), "the new listener gets the latest update")
	starts, closes := under.counts()
	assert.Equal(t, 1, starts)
	assert.Equal(t, 0, closes)
}

func TestVPNClientSharesBoxPlatform(t *testing.T) {
	prev := sharePlatformMonitor
	t.Cleanup(func() { sharePlatformMonitor = prev })

	sharePlatformMonitor = func() bool { return false }
	platform := &fakeVPNPlatform{}
	c := NewVPNClient(t.TempDir(), nil, platform)
	assert.Same(t, platform, c.boxPlatform, "off Android the tunnel runs on the platform itself")
	assert.Nil(t, c.BoxPlatform(), "and shares nothing")

	sharePlatformMonitor = func() bool { return true }
	c = NewVPNClient(t.TempDir(), nil, platform)
	p := c.BoxPlatform()
	require.NotNil(t, p)
	assert.Same(t, p, c.BoxPlatform(), "one shared platform per client")
	assert.Same(t, c.shared, c.boxPlatform, "the tunnel runs on the shared platform")
}

func TestSharedPlatformIgnoresARetiredForwarder(t *testing.T) {
	under := &monitorPlatform{}
	s := newSharedPlatform(under)
	a := &recordingListener{}
	require.NoError(t, s.StartDefaultInterfaceMonitor(a))
	old := under.listener
	require.NoError(t, s.CloseDefaultInterfaceMonitor(a))

	b, c := &recordingListener{}, &recordingListener{}
	require.NoError(t, s.StartDefaultInterfaceMonitor(b))
	assert.NotSame(t, old, under.listener, "each platform start gets its own forwarder")
	// An update the platform queued for the closed monitor.
	old.UpdateDefaultInterface("stale0", 9, false, false)
	old.UpdateNetworkPath("stale")
	require.NoError(t, s.StartDefaultInterfaceMonitor(c))
	assert.Empty(t, b.got())
	assert.Empty(t, b.paths)
	assert.Empty(t, c.got(), "nor is the stale update cached for a later listener")

	under.update("wlan0", 1)
	assert.Equal(t, []string{"wlan0"}, b.got())
	assert.Equal(t, []string{"wlan0"}, c.got())
}

type fakeVPNPlatform struct{ libbox.PlatformInterface }

func (fakeVPNPlatform) RestartService() error { return nil }
func (fakeVPNPlatform) PostServiceClose()     {}
