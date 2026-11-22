//go:build novpn

package vpn

import "log/slog"

// SplitTunnel is an inert stand-in for the split-tunnel manager. The novpn build
// has no tunnel to split, but the backend and CLI still reference this type, so it
// preserves the exported surface while doing nothing.
type SplitTunnel struct{}

func NewSplitTunnelHandler(_ string, _ *slog.Logger) (*SplitTunnel, error) {
	return &SplitTunnel{}, nil
}

func (s *SplitTunnel) IsEnabled() bool { return false }

func (s *SplitTunnel) SetEnabled(_ bool) error { return nil }

func (s *SplitTunnel) Policy() SplitTunnelPolicy { return SplitTunnelPolicyExclude }

func (s *SplitTunnel) SetPolicy(_ SplitTunnelPolicy) error { return nil }

func (s *SplitTunnel) Filters() SplitTunnelFilter { return SplitTunnelFilter{} }

func (s *SplitTunnel) AddItems(_ SplitTunnelFilter) error { return nil }

func (s *SplitTunnel) RemoveItems(_ SplitTunnelFilter) error { return nil }
