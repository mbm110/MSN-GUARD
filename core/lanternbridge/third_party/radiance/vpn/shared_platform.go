package vpn

import (
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// sharedPlatform is a platform interface whose default interface monitor several sing-box
// boxes can run at once: the VPN tunnel's and the Unbounded direct exit's. The platform keeps
// one monitor listener (Android's is a single global one), so sharedPlatform registers its own
// and fans each update out to every box's. Everything else passes through.
//
// Each platform monitor start gets its own forwarder, and only the current one's updates count:
// the platform can still deliver an update queued for a closed monitor, and Android drops those
// only for a listener other than the current one.
//
// Listeners may start or close monitors from an update, except from one the platform delivers
// inside its own start or close call.
type sharedPlatform struct {
	libbox.PlatformInterface

	// opMu orders the platform's monitor start and close. started is guarded by it.
	opMu    sync.Mutex
	started bool

	mu sync.Mutex
	// current is the forwarder of the platform's running monitor, nil with none.
	current   *platformFanOut
	listeners []*monitorListener
	seq       uint64
	// last is the latest default interface update, nil before one or once the monitor closes.
	last *interfaceUpdate
}

// newSharedPlatform wraps p, or returns nil for a nil p.
func newSharedPlatform(p libbox.PlatformInterface) *sharedPlatform {
	if p == nil {
		return nil
	}
	return &sharedPlatform{PlatformInterface: p}
}

type interfaceUpdate struct {
	name                       string
	index                      int32
	isExpensive, isConstrained bool
}

// monitorListener is one box's listener. seq is the latest update delivered to it, so a replay
// never lands after a newer update.
type monitorListener struct {
	l      libbox.InterfaceUpdateListener
	closed atomic.Bool

	mu  sync.Mutex
	seq uint64
}

func (m *monitorListener) deliver(seq uint64, u interfaceUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq <= m.seq || m.closed.Load() {
		return
	}
	m.seq = seq
	m.l.UpdateDefaultInterface(u.name, u.index, u.isExpensive, u.isConstrained)
}

// StartDefaultInterfaceMonitor adds listener, starting the platform's monitor for the first.
// A later listener gets the latest update at once, as the platform gives a new listener.
func (s *sharedPlatform) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	entry := &monitorListener{l: listener}
	s.opMu.Lock()
	s.mu.Lock()
	var fwd *platformFanOut
	if !s.started {
		// A fresh monitor waits for the platform's first update.
		fwd = &platformFanOut{s: s}
		s.current, s.last = fwd, nil
	}
	s.listeners = append(s.listeners, entry)
	seq, last := s.seq, s.last
	s.mu.Unlock()
	if fwd != nil {
		if err := s.PlatformInterface.StartDefaultInterfaceMonitor(fwd); err != nil {
			s.mu.Lock()
			s.current = nil
			s.mu.Unlock()
			s.removeListener(listener)
			s.opMu.Unlock()
			return err
		}
		s.started = true
		last = nil
	}
	s.opMu.Unlock()
	if last != nil {
		entry.deliver(seq, *last)
	}
	return nil
}

// CloseDefaultInterfaceMonitor removes listener, closing the platform's monitor with the last.
func (s *sharedPlatform) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.removeListener(listener) {
		return nil
	}
	s.mu.Lock()
	empty := len(s.listeners) == 0
	fwd := s.current
	if empty {
		s.current, s.last = nil, nil
	}
	s.mu.Unlock()
	if !empty || !s.started {
		return nil
	}
	s.started = false
	return s.PlatformInterface.CloseDefaultInterfaceMonitor(fwd)
}

// forwardsTo reports whether listener is the running monitor's forwarder and monitor is one of
// the listeners it forwards to, so a platform handing back the listener it holds names monitor.
func (s *sharedPlatform) forwardsTo(listener, monitor libbox.InterfaceUpdateListener) bool {
	fwd, ok := listener.(*platformFanOut)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return fwd == s.current && slices.ContainsFunc(s.listeners, func(m *monitorListener) bool { return m.l == monitor })
}

func (s *sharedPlatform) removeListener(listener libbox.InterfaceUpdateListener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.listeners, func(m *monitorListener) bool { return m.l == listener })
	if i < 0 {
		return false
	}
	s.listeners[i].closed.Store(true)
	s.listeners = slices.Delete(s.listeners, i, i+1)
	return true
}

// platformFanOut is sharedPlatform's listener on one start of the platform's monitor. Once that
// monitor closes, it forwards nothing.
type platformFanOut struct{ s *sharedPlatform }

func (f *platformFanOut) UpdateDefaultInterface(name string, index int32, isExpensive, isConstrained bool) {
	u := interfaceUpdate{name: name, index: index, isExpensive: isExpensive, isConstrained: isConstrained}
	f.s.mu.Lock()
	if f.s.current != f {
		f.s.mu.Unlock()
		return
	}
	f.s.seq++
	seq := f.s.seq
	f.s.last = &u
	listeners := slices.Clone(f.s.listeners)
	f.s.mu.Unlock()
	for _, m := range listeners {
		m.deliver(seq, u)
	}
}

func (f *platformFanOut) UpdateNetworkPath(networkPath string) {
	f.s.mu.Lock()
	if f.s.current != f {
		f.s.mu.Unlock()
		return
	}
	listeners := slices.Clone(f.s.listeners)
	f.s.mu.Unlock()
	for _, m := range listeners {
		if !m.closed.Load() {
			m.l.UpdateNetworkPath(networkPath)
		}
	}
}
