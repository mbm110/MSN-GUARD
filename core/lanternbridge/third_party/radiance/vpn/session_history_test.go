package vpn

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeInfo struct {
	mu       sync.Mutex
	status   VPNStatus
	tag      string
	city     string
	country  string
	up, down int64
	bytesOK  bool
}

func (f *fakeInfo) info() SessionInfo {
	return SessionInfo{
		Status: func() VPNStatus {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.status
		},
		SelectedServer: func() (string, string, string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.tag, f.city, f.country
		},
		Bytes: func() (int64, int64, bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.up, f.down, f.bytesOK
		},
	}
}

func (f *fakeInfo) set(status VPNStatus, tag, city, country string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
	f.tag, f.city, f.country = tag, city, country
}

func (f *fakeInfo) setBytes(up, down int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up, f.down, f.bytesOK = up, down, true
}

// newTestHistory skips the global event subscription and pruner goroutine
// so tests can drive state directly.
func newTestHistory(t *testing.T, status VPNStatus, tag string, up, down int64) (*SessionHistory, *fakeInfo) {
	t.Helper()
	info := &fakeInfo{}
	info.set(status, tag, "", "")
	info.setBytes(up, down)
	return &SessionHistory{info: info.info()}, info
}

func TestSessionHistory_StatusEvents(t *testing.T) {
	tests := []struct {
		name        string
		run         func(h *SessionHistory, info *fakeInfo)
		wantCurrent bool
		wantStored  int
		extra       func(t *testing.T, h *SessionHistory)
	}{
		{
			name: "connect then disconnect records session",
			run: func(h *SessionHistory, info *fakeInfo) {
				h.handleStatus(StatusUpdateEvent{Status: Connected})
				info.set(Disconnected, "", "", "")
				info.setBytes(500, 1000)
				h.handleStatus(StatusUpdateEvent{Status: Disconnected})
			},
			wantStored: 1,
			extra: func(t *testing.T, h *SessionHistory) {
				assert.Equal(t, int64(500), h.stored[0].BytesUp)
				assert.Equal(t, int64(1000), h.stored[0].BytesDown)
				assert.False(t, h.stored[0].DisconnectedAt.IsZero())
			},
		},
		{
			name: "repeat Connected leaves current session intact",
			run: func(h *SessionHistory, info *fakeInfo) {
				h.handleStatus(StatusUpdateEvent{Status: Connected})
				h.handleStatus(StatusUpdateEvent{Status: Connected})
			},
			wantCurrent: true,
		},
		{
			name: "Disconnected ignored while live=Connected",
			run: func(h *SessionHistory, info *fakeInfo) {
				h.handleStatus(StatusUpdateEvent{Status: Connected})
				info.set(Connected, "vpn-a", "", "")
				h.handleStatus(StatusUpdateEvent{Status: Disconnected})
			},
			wantCurrent: true,
		},
		{
			name: "Disconnected ignored while live=Restarting",
			run: func(h *SessionHistory, info *fakeInfo) {
				h.handleStatus(StatusUpdateEvent{Status: Connected})
				info.set(Restarting, "vpn-a", "", "")
				h.handleStatus(StatusUpdateEvent{Status: Disconnected})
			},
			wantCurrent: true,
		},
		{
			name: "stale Connected (live != Connected) ignored",
			run: func(h *SessionHistory, info *fakeInfo) {
				h.handleStatus(StatusUpdateEvent{Status: Connected})
				info.set(Connecting, "vpn-a", "", "")
				h.handleStatus(StatusUpdateEvent{Status: Connected})
			},
			wantCurrent: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, info := newTestHistory(t, Connected, "vpn-a", 0, 0)
			tt.run(h, info)
			if tt.wantCurrent {
				assert.NotNil(t, h.current)
			} else {
				assert.Nil(t, h.current)
			}
			require.Len(t, h.stored, tt.wantStored)
			if tt.extra != nil {
				tt.extra(t, h)
			}
		})
	}
}

func TestSessionHistory_ServerSwitch(t *testing.T) {
	tests := []struct {
		name         string
		startStatus  VPNStatus
		startBytes   [2]int64
		setup        func(h *SessionHistory, info *fakeInfo)
		switchTag    string
		wantCurrent  string
		wantStored   []string
		wantBytesUp  int64
		wantBytesDow int64
	}{
		{
			name:        "same tag is a no-op",
			startStatus: Connected,
			setup: func(h *SessionHistory, info *fakeInfo) {
				h.handleStatus(StatusUpdateEvent{Status: Connected})
			},
			switchTag:   "vpn-a",
			wantCurrent: "vpn-a",
		},
		{
			name:        "new tag finalizes prior session with carried bytes",
			startStatus: Connected,
			startBytes:  [2]int64{100, 200},
			setup: func(h *SessionHistory, info *fakeInfo) {
				h.handleStatus(StatusUpdateEvent{Status: Connected})
				info.setBytes(300, 600)
			},
			switchTag:    "vpn-b",
			wantCurrent:  "vpn-b",
			wantStored:   []string{"vpn-a"},
			wantBytesUp:  200,
			wantBytesDow: 400,
		},
		{
			name:        "no current session is a no-op",
			startStatus: Disconnected,
			setup:       func(h *SessionHistory, info *fakeInfo) {},
			switchTag:   "vpn-a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, info := newTestHistory(t, tt.startStatus, "vpn-a", tt.startBytes[0], tt.startBytes[1])
			tt.setup(h, info)
			h.HandleServerChange(tt.switchTag, "", "")

			if tt.wantCurrent == "" {
				assert.Nil(t, h.current)
			} else {
				require.NotNil(t, h.current)
				assert.Equal(t, tt.wantCurrent, h.current.Server.Tag)
			}
			require.Len(t, h.stored, len(tt.wantStored))
			for i, tag := range tt.wantStored {
				assert.Equal(t, tag, h.stored[i].Server.Tag)
			}
			if len(tt.wantStored) > 0 {
				assert.Equal(t, tt.wantBytesUp, h.stored[0].BytesUp)
				assert.Equal(t, tt.wantBytesDow, h.stored[0].BytesDown)
			}
		})
	}
}

func TestSessionHistory_ByteAccounting(t *testing.T) {
	h, _ := newTestHistory(t, Connected, "vpn-a", 100, 200)
	h.handleStatus(StatusUpdateEvent{Status: Connected})

	tests := []struct {
		name             string
		observeUp, obDn  int64
		wantUp, wantDown int64
	}{
		{"initial", 100, 200, 0, 0},
		{"steady accumulation", 150, 260, 50, 60},
		{"counter reset preserves prior tally", 10, 20, 60, 80},
		{"continued growth after reset", 40, 70, 90, 130},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.observeBytes(tt.observeUp, tt.obDn)
			up, down := h.sessionBytes()
			assert.Equal(t, tt.wantUp, up)
			assert.Equal(t, tt.wantDown, down)
		})
	}
}

func TestSessionHistory_Storage(t *testing.T) {
	t.Run("prune drops entries older than retention", func(t *testing.T) {
		h, _ := newTestHistory(t, Disconnected, "", 0, 0)
		now := time.Now()
		h.stored = []Session{
			{DisconnectedAt: now.Add(-30 * time.Second)},
			{DisconnectedAt: now.Add(-9 * time.Minute)},
			{DisconnectedAt: now.Add(-20 * time.Minute)},
			{DisconnectedAt: now.Add(-50 * time.Minute)},
		}
		h.pruneLocked(now)
		require.Len(t, h.stored, 2)
		for _, s := range h.stored {
			assert.WithinDuration(t, now, s.DisconnectedAt, sessionRetention)
		}
	})

	t.Run("Sessions returns current first then stored, honoring limit", func(t *testing.T) {
		h, _ := newTestHistory(t, Connected, "vpn-current", 0, 0)
		now := time.Now()
		h.stored = []Session{
			{DisconnectedAt: now.Add(-30 * time.Second), Server: SessionServer{Tag: "older"}},
			{DisconnectedAt: now.Add(-90 * time.Second), Server: SessionServer{Tag: "oldest"}},
		}
		h.handleStatus(StatusUpdateEvent{Status: Connected})

		tags := func(ss []Session) []string {
			out := make([]string, len(ss))
			for i, s := range ss {
				out[i] = s.Server.Tag
			}
			return out
		}
		assert.Equal(t, []string{"vpn-current", "older", "oldest"}, tags(h.Sessions(0)))
		assert.Equal(t, []string{"vpn-current", "older"}, tags(h.Sessions(2)))
	})

	t.Run("stored slice caps at maxSessions", func(t *testing.T) {
		h, info := newTestHistory(t, Connected, "tag", 0, 0)
		for i := 0; i < maxSessions+3; i++ {
			info.set(Connected, "tag", "", "")
			h.handleStatus(StatusUpdateEvent{Status: Connected})
			info.set(Disconnected, "", "", "")
			h.handleStatus(StatusUpdateEvent{Status: Disconnected})
		}
		assert.LessOrEqual(t, len(h.stored), maxSessions)
	})
}
