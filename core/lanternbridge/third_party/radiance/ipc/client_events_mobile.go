//go:build android || ios || (darwin && !standalone)

package ipc

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/unbounded"
	"github.com/getlantern/radiance/usermessage"
	"github.com/getlantern/radiance/vpn"
)

// AutoSelectedEvents streams auto-selection changes. Blocks until ctx is cancelled.
func (c *Client) AutoSelectedEvents(ctx context.Context, handler func(vpn.AutoSelectedEvent)) error {
	// The bus subscription is not redundant with SSE: when the tunnel process is down,
	// the client's fallback LocalBackend emits these events on the in-process bus.
	events.SubscribeContext(ctx, handler)
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
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
	// The bus subscription is not redundant with SSE: when the tunnel process is down,
	// the client's fallback LocalBackend emits these events on the in-process bus.
	events.SubscribeContext(ctx, handler)
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.sseRetryLoop(ctx, helperPersonalProxyFallbackEndpoint, func(data []byte) {
		var evt vpn.PersonalProxyFallbackEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// SelectionSavedEvents calls handler on subscribing, each time the stream
// connects or reconnects, and after each save of the selection. Blocks until
// ctx is cancelled.
func (c *Client) SelectionSavedEvents(ctx context.Context, handler func(vpn.SelectionSavedEvent)) error {
	// The bus subscription is not redundant with SSE: when the tunnel process is down,
	// the client's fallback LocalBackend emits these events on the in-process bus.
	events.SubscribeContext(ctx, handler)
	// A save before the subscription went unheard.
	handler(vpn.SelectionSavedEvent{})
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
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
	// The bus subscription is not redundant with SSE: when the tunnel process is down,
	// the client's fallback LocalBackend emits these events on the in-process bus.
	events.SubscribeContext(ctx, handler)
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.sseRetryLoop(ctx, serverURLTestEventsEndpoint, func(data []byte) {
		var evt vpn.URLTestCompleteEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// ConfigEvents calls handler on subscribing, each time the stream connects or
// reconnects, and after a config change is applied; events carry no payload. Blocks
// until ctx is cancelled.
func (c *Client) ConfigEvents(ctx context.Context, handler func()) error {
	// The bus worker, this goroutine and the SSE stream all call handler; serialized, each call
	// reads state no older than the last one's.
	var mu sync.Mutex
	notify := func() {
		mu.Lock()
		defer mu.Unlock()
		handler()
	}
	// The bus subscription is not redundant with SSE: when the tunnel process is down,
	// the client's fallback LocalBackend emits ConfigAppliedEvents on the in-process bus.
	events.SubscribeContext(ctx, func(backend.ConfigAppliedEvent) { notify() })
	// A config applied before the subscription, such as the fallback's cached one, went unheard.
	notify()
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.sseRetryLoop(ctx, configEventsEndpoint, func([]byte) { notify() })
}

// UserMessageEvents streams pending-message notifications until ctx is canceled.
func (c *Client) UserMessageEvents(ctx context.Context, handler func()) error {
	events.SubscribeContext(ctx, func(usermessage.AvailableEvent) { handler() })
	handler()
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.sseRetryLoop(ctx, userMessageEventsEndpoint, func([]byte) { handler() })
}

// VPNStatusEvents streams VPN status changes. Blocks until ctx is cancelled.
func (c *Client) VPNStatusEvents(ctx context.Context, handler func(vpn.StatusUpdateEvent)) error {
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.sseRetryLoop(ctx, vpnStatusEventsEndpoint, func(data []byte) {
		var evt vpn.StatusUpdateEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// DataCapStream streams data-cap updates while the VPN is connected. Blocks until ctx is cancelled.
func (c *Client) DataCapStream(ctx context.Context, handler func(account.DataCapInfo)) error {
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.dataCapStream(ctx, handler)
}

// PeerStatusEvents streams peer-share lifecycle status changes. Frames may
// arrive out of order — a delayed frame can follow a newer one — so do not
// assume monotonic ordering. Blocks until ctx is cancelled.
func (c *Client) PeerStatusEvents(ctx context.Context, handler func(peer.StatusEvent)) error {
	events.SubscribeContext(ctx, handler)
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.sseRetryLoop(ctx, peerStatusEventsEndpoint, func(data []byte) {
		var evt peer.StatusEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}

// PeerConnectionEvents streams accept/close events for the local samizdat-in
// inbound. Blocks until ctx is cancelled.
func (c *Client) PeerConnectionEvents(ctx context.Context, handler func(peer.ConnectionEvent)) error {
	events.SubscribeContext(ctx, handler)
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
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
	events.SubscribeContext(ctx, handler)
	if c.localOnly {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.sseRetryLoop(ctx, unboundedConnectionEventsEndpoint, func(data []byte) {
		var evt unbounded.ConnectionEvent
		if err := json.Unmarshal(data, &evt); err == nil {
			handler(evt)
		}
	})
}
