package vpn

import (
	"github.com/sagernet/sing-box/adapter"

	lbA "github.com/getlantern/lantern-box/adapter"

	"github.com/getlantern/radiance/events"
)

// AutoSelectHistoryStorage aliases the lantern-box per-tag history-storage interface.
type AutoSelectHistoryStorage = lbA.AutoSelectHistoryStorage

// StatusUpdateEvent is emitted when the VPN status changes.
type StatusUpdateEvent struct {
	events.Event
	Status VPNStatus `json:"status"`
	Error  string    `json:"error,omitempty"`
}

// ExhaustionEvent is emitted when the MutableAutoSelect group's reconnection loop has exhausted
// all outbounds with no working candidate.
type ExhaustionEvent struct {
	events.Event
}

// NetworkEventType is the availability state carried by a NetworkEvent.
type NetworkEventType string

const (
	// NetworkEventPaused means the pause manager reports a missing default route.
	NetworkEventPaused NetworkEventType = "network_paused"
	// NetworkEventWake means the network pause ended or the tunnel is closing.
	NetworkEventWake NetworkEventType = "network_wake"
)

// NetworkEvent reports network pause transitions and tunnel teardown.
type NetworkEvent struct {
	events.Event
	EventType NetworkEventType `json:"event_type"`
}

// Selector is helper interface to check if an outbound is a selector or wrapper of selector.
type Selector interface {
	adapter.OutboundGroup
	SelectOutbound(tag string) bool
}

type OutboundGroup struct {
	Tag       string      `json:"tag"`
	Type      string      `json:"type"`
	Selected  string      `json:"selected"`
	Outbounds []Outbounds `json:"outbounds"`
}

type Outbounds struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
}

// ThroughputSnapshot is the most recent throughput sample for the tunnel.
type ThroughputSnapshot struct {
	Global            Throughput            `json:"global"`
	PerOutbound       map[string]Throughput `json:"per_outbound"`
	ActiveConnections int                   `json:"active_connections"`
	ActivePerOutbound map[string]int        `json:"active_per_outbound"`
}

type Connection struct {
	ID           string   `json:"id"`
	Inbound      string   `json:"inbound"`
	IPVersion    int      `json:"ip_version"`
	Network      string   `json:"network"`
	Source       string   `json:"source"`
	Destination  string   `json:"destination"`
	Domain       string   `json:"domain,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	FromOutbound string   `json:"from_outbound,omitempty"`
	CreatedAt    int64    `json:"created_at"`
	ClosedAt     int64    `json:"closed_at,omitempty"`
	Uplink       int64    `json:"uplink"`
	Downlink     int64    `json:"downlink"`
	Rule         string   `json:"rule,omitempty"`
	Outbound     string   `json:"outbound"`
	ChainList    []string `json:"chain,omitempty"`
}

// newConnection creates a Connection from a tracker record. Only active records are exposed, so
// ClosedAt is always zero.
func newConnection(r *record) Connection {
	return Connection{
		ID:           r.id.String(),
		Inbound:      r.inboundLabel,
		IPVersion:    int(r.ipVersion),
		Network:      r.network,
		Source:       r.source,
		Destination:  r.destination,
		Domain:       r.domain,
		Protocol:     r.protocol,
		FromOutbound: r.fromOutbound,
		CreatedAt:    r.createdAt.UnixMilli(),
		Uplink:       r.upload.Load(),
		Downlink:     r.download.Load(),
		Rule:         r.ruleStr,
		Outbound:     r.outboundLabel,
		ChainList:    r.chain,
	}
}
