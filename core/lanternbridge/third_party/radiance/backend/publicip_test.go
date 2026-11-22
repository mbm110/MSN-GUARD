package backend

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/publicip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
)

func recordedPublicIP(t *testing.T) string {
	t.Helper()
	req, err := common.NewRequestWithHeaders(context.Background(), http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	return req.Header.Get(common.ClientIPHeader)
}

func fixedLookup(ip string, calls *atomic.Int32) func(context.Context) (*publicip.DetectResult, error) {
	return func(context.Context) (*publicip.DetectResult, error) {
		calls.Add(1)
		return &publicip.DetectResult{IP: net.ParseIP(ip)}, nil
	}
}

// runDetect runs detectPublicIP until it returns or until stopAfter elapses, when it cancels ctx.
func runDetect(t *testing.T, stopAfter time.Duration, direct func() bool, lookup func(context.Context) (*publicip.DetectResult, error)) {
	t.Helper()
	prevPoll, prevBackoff := publicIPDirectPoll, publicIPBackoff
	publicIPDirectPoll = 10 * time.Millisecond
	publicIPBackoff = func() *common.Backoff { return common.NewBackoff(time.Millisecond, time.Millisecond) }
	t.Cleanup(func() { publicIPDirectPoll, publicIPBackoff = prevPoll, prevBackoff })

	ctx, cancel := context.WithTimeout(context.Background(), stopAfter)
	defer cancel()
	done := make(chan struct{})
	go func() {
		detectPublicIP(ctx, direct, lookup)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopAfter + 5*time.Second):
		t.Fatal("detectPublicIP did not return after its context ended")
	}
}

func TestDetectPublicIPRecordsDirectLookup(t *testing.T) {
	common.SetPublicIP("")
	var calls atomic.Int32
	runDetect(t, 5*time.Second, func() bool { return true }, fixedLookup("203.0.113.7", &calls))
	assert.Equal(t, "203.0.113.7", recordedPublicIP(t))
	assert.EqualValues(t, 1, calls.Load())
}

func TestDetectPublicIPWaitsWhileTunnelUp(t *testing.T) {
	common.SetPublicIP("")
	var calls atomic.Int32
	runDetect(t, 100*time.Millisecond, func() bool { return false }, fixedLookup("203.0.113.7", &calls))
	assert.Empty(t, recordedPublicIP(t))
	assert.Zero(t, calls.Load(), "no lookup while the tunnel may route it")
}

func TestDetectPublicIPResumesAfterTunnelGoesDown(t *testing.T) {
	common.SetPublicIP("")
	var tunnelUp atomic.Bool
	tunnelUp.Store(true)
	time.AfterFunc(50*time.Millisecond, func() { tunnelUp.Store(false) })
	var calls atomic.Int32
	runDetect(t, 5*time.Second, func() bool { return !tunnelUp.Load() }, fixedLookup("203.0.113.7", &calls))
	assert.Equal(t, "203.0.113.7", recordedPublicIP(t))
}

func TestDetectPublicIPDiscardsResultIfTunnelCameUp(t *testing.T) {
	common.SetPublicIP("")
	var tunnelUp atomic.Bool
	lookup := func(context.Context) (*publicip.DetectResult, error) {
		tunnelUp.Store(true) // the VPN connects while the lookup is in flight
		return &publicip.DetectResult{IP: net.ParseIP("198.51.100.9")}, nil
	}
	runDetect(t, 100*time.Millisecond, func() bool { return !tunnelUp.Load() }, lookup)
	assert.Empty(t, recordedPublicIP(t), "a result that may be the VPN exit must not be recorded")
}

// A lookup that began before a network change leaves the IP stale, so
// requests leave it out.
func TestDetectPublicIPFromAnOldNetworkStaysStale(t *testing.T) {
	common.SetPublicIP("")
	t.Cleanup(func() { common.SetPublicIP("") })
	lookup := func(context.Context) (*publicip.DetectResult, error) {
		common.MarkPublicIPStale()
		return &publicip.DetectResult{IP: net.ParseIP("198.51.100.9")}, nil
	}
	runDetect(t, 5*time.Second, func() bool { return true }, lookup)
	assert.True(t, common.PublicIPStale())

	var calls atomic.Int32
	runDetect(t, 5*time.Second, func() bool { return true }, fixedLookup("203.0.113.7", &calls))
	assert.False(t, common.PublicIPStale())
}

func TestDetectPublicIPRetriesAfterFailure(t *testing.T) {
	common.SetPublicIP("")
	var calls atomic.Int32
	lookup := func(context.Context) (*publicip.DetectResult, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("lookup blocked")
		}
		return &publicip.DetectResult{IP: net.ParseIP("203.0.113.7")}, nil
	}
	runDetect(t, 5*time.Second, func() bool { return true }, lookup)
	assert.Equal(t, "203.0.113.7", recordedPublicIP(t))
	assert.EqualValues(t, 2, calls.Load())
}

func TestDetectPublicIPStopsAfterAttemptLimit(t *testing.T) {
	common.SetPublicIP("")
	var calls atomic.Int32
	lookup := func(context.Context) (*publicip.DetectResult, error) {
		calls.Add(1)
		return nil, errors.New("lookup blocked")
	}
	runDetect(t, 5*time.Second, func() bool { return true }, lookup)
	assert.Empty(t, recordedPublicIP(t))
	assert.EqualValues(t, publicIPAttempts, calls.Load())
}

func TestPublicIPDiffers(t *testing.T) {
	tests := []struct {
		name     string
		prev, ip string
		want     bool
	}{
		{"nothing stored", "", "203.0.113.7", true},
		{"same /16", "203.0.113.0", "203.0.42.9", false},
		{"other /16", "203.0.113.0", "198.51.100.9", true},
		{"same IPv6 /32", "2001:db8:1::", "2001:db8:ffff::1", false},
		{"other IPv6 /32", "2001:db8:1::", "2001:db9::1", true},
		{"family change", "203.0.113.0", "2001:db8::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, publicIPDiffers(net.ParseIP(tt.prev), net.ParseIP(tt.ip)))
		})
	}
}

func TestStoredPublicIPRoundTrip(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	common.SetPublicIP("")
	t.Cleanup(func() { common.SetPublicIP("") })

	assert.Empty(t, loadStoredPublicIP())
	assert.Empty(t, recordedPublicIP(t))

	assert.True(t, storePublicIP(net.ParseIP("203.0.113.7"), ""), "first detection must refetch")
	assert.Equal(t, "203.0.113.7", settings.GetString(settings.PublicIPKey), "the full IP is stored")

	stored := loadStoredPublicIP()
	assert.Equal(t, "203.0.113.7", stored)
	assert.Equal(t, "203.0.113.7", recordedPublicIP(t), "the stored IP is sent before detection completes")

	assert.False(t, storePublicIP(net.ParseIP("203.0.200.1"), stored))
	assert.True(t, storePublicIP(net.ParseIP("198.51.100.9"), stored))
	assert.Equal(t, "198.51.100.9", settings.GetString(settings.PublicIPKey))
}

func TestDetectPublicIPReturnsIP(t *testing.T) {
	common.SetPublicIP("")
	var calls atomic.Int32
	got := detectPublicIP(context.Background(), func() bool { return true }, fixedLookup("203.0.113.7", &calls))
	assert.Equal(t, "203.0.113.7", got.String())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Nil(t, detectPublicIP(ctx, func() bool { return true }, fixedLookup("203.0.113.7", &calls)))
}
