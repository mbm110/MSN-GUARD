//go:build (!android && !ios && !darwin) || (darwin && standalone)

package ipc

import (
	"context"
	"encoding/json"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/unbounded"
	"github.com/getlantern/radiance/vpn"
)

// AutoSelectedEvents streams auto-selection changes. Blocks until ctx is cancelled.
func (c *Client) AutoSelectedEvents(ctx context.Context, handler func(vpn.AutoSelectedEvent)) error {
	return c.sseRetryLoop(ctx, serverAutoSelectedEventsEndpoint, func(data []byte) {
		var evt vpn.AutoSelectedEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// PersonalProxyFallbackEvents streams the fallbacks of a selected friend's
// personal proxy that lost its last member. Blocks until ctx is cancelled.
func (c *Client) PersonalProxyFallbackEvents(ctx context.Context, handler func(vpn.PersonalProxyFallbackEvent)) error {
	return c.sseRetryLoop(ctx, helperPersonalProxyFallbackEndpoint, func(data []byte) {
		var evt vpn.PersonalProxyFallbackEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// SelectionSavedEvents calls handler each time the stream connects or
// reconnects and after each save of the selection. Blocks until ctx is
// cancelled.
func (c *Client) SelectionSavedEvents(ctx context.Context, handler func(vpn.SelectionSavedEvent)) error {
	return c.sseRetryLoop(ctx, serverSelectionEventsEndpoint, func(data []byte) {
		var evt vpn.SelectionSavedEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// URLTestEvents streams URL-test completion notifications. An event is sent
// only when a test run produced usable latency results, for either the offline
// pre-warm run or the live auto-select probe. Blocks until ctx is cancelled.
func (c *Client) URLTestEvents(ctx context.Context, handler func(vpn.URLTestCompleteEvent)) error {
	return c.sseRetryLoop(ctx, serverURLTestEventsEndpoint, func(data []byte) {
		var evt vpn.URLTestCompleteEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// ConfigEvents calls handler each time the stream connects or reconnects and
// after a config change is applied; events carry no payload. Blocks until ctx is
// cancelled.
func (c *Client) ConfigEvents(ctx context.Context, handler func()) error {
	return c.sseRetryLoop(ctx, configEventsEndpoint, func([]byte) { handler() })
}

// UserMessageEvents streams pending-message notifications until ctx is canceled.
func (c *Client) UserMessageEvents(ctx context.Context, handler func()) error {
	return c.sseRetryLoop(ctx, userMessageEventsEndpoint, func([]byte) { handler() })
}

// VPNStatusEvents streams VPN status changes. Blocks until ctx is cancelled.
func (c *Client) VPNStatusEvents(ctx context.Context, handler func(vpn.StatusUpdateEvent)) error {
	return c.sseRetryLoop(ctx, vpnStatusEventsEndpoint, func(data []byte) {
		var evt vpn.StatusUpdateEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// DataCapStream streams data-cap updates while the VPN is connected. Blocks until ctx is cancelled.
func (c *Client) DataCapStream(ctx context.Context, handler func(account.DataCapInfo)) error {
	return c.dataCapStream(ctx, handler)
}

// PeerStatusEvents streams peer-share lifecycle status changes. Frames arrive
// in order, so the last one seen is the current phase. Blocks until ctx is
// cancelled.
func (c *Client) PeerStatusEvents(ctx context.Context, handler func(peer.StatusEvent)) error {
	return c.sseRetryLoop(ctx, peerStatusEventsEndpoint, func(data []byte) {
		var evt peer.StatusEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// PeerConnectionEvents streams accept/close events for the local
// samizdat-in inbound. Blocks until ctx is cancelled.
//
// Why this exists alongside events.Subscribe[peer.ConnectionEvent]:
// the events package's globals are process-scoped, so a subscriber in
// Liblantern can't see emits in lanternd. The SSE path bridges them.
func (c *Client) PeerConnectionEvents(ctx context.Context, handler func(peer.ConnectionEvent)) error {
	return c.sseRetryLoop(ctx, peerConnectionEventsEndpoint, func(data []byte) {
		var evt peer.ConnectionEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// UnboundedConnectionEvents streams accept/close events for the local broflake
// widget proxy ("Unbounded" / Basic mode). Blocks until ctx is cancelled.
func (c *Client) UnboundedConnectionEvents(ctx context.Context, handler func(unbounded.ConnectionEvent)) error {
	return c.sseRetryLoop(ctx, unboundedConnectionEventsEndpoint, func(data []byte) {
		var evt unbounded.ConnectionEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}
