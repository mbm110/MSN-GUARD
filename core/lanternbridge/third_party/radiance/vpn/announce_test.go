package vpn

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/events"
)

// A reader woken by an AutoSelectedEvent must find that selection already announced. The
// debug hook runs inside Emit, so it sees the state at the moment of the emit.
func TestAnnounceAutoSelectedStoresBeforeEmit(t *testing.T) {
	tun := &tunnel{}
	var atEmit *string
	events.SetEmitDebugLogger(func(eventType reflect.Type, _ int) {
		if eventType == reflect.TypeFor[AutoSelectedEvent]() {
			atEmit = tun.announcedAuto.Load()
		}
	})
	t.Cleanup(func() { events.SetEmitDebugLogger(nil) })

	announceAutoSelected(tun, "fastest")

	require.NotNil(t, atEmit, "nothing announced at emit")
	assert.Equal(t, "fastest", *atEmit)
}

func TestAnnouncedAutoSelectedServerIsPerTunnel(t *testing.T) {
	old := &tunnel{}
	c := &VPNClient{}
	c.setTunnelLocked(old)
	c.status.Store(Connected)
	announceAutoSelected(old, "old-pick")
	require.Equal(t, "old-pick", c.AnnouncedAutoSelectedServer())

	// A reconnect replaces the tunnel; a listener that has not stopped yet can only
	// announce into the tunnel it read from.
	next := &tunnel{}
	c.setTunnelLocked(next)
	announceAutoSelected(old, "late-old-pick")
	assert.Empty(t, c.AnnouncedAutoSelectedServer())

	announceAutoSelected(next, "new-pick")
	assert.Equal(t, "new-pick", c.AnnouncedAutoSelectedServer())

	c.status.Store(Disconnected)
	assert.Empty(t, c.AnnouncedAutoSelectedServer())
}

// Connect and restart hold c.mu through box start, so a read that waited on it would stall
// the SSE frame behind lifecycle work.
func TestAnnouncedAutoSelectedServerDoesNotWaitOnLifecycleLock(t *testing.T) {
	tun := &tunnel{}
	c := &VPNClient{}
	c.setTunnelLocked(tun)
	c.status.Store(Connected)
	announceAutoSelected(tun, "pick")

	c.mu.Lock()
	defer c.mu.Unlock()
	got := make(chan string, 1)
	go func() { got <- c.AnnouncedAutoSelectedServer() }()
	select {
	case tag := <-got:
		assert.Equal(t, "pick", tag)
	case <-time.After(2 * time.Second):
		t.Fatal("AnnouncedAutoSelectedServer waited on c.mu")
	}
}
