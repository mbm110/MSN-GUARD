package lanternbridge

import (
	"fmt"
	"time"
)

// The TUN fd handoff (3.4.0) — the official-app data path for MSN's Lantern.
//
// 3.4.4 restructure, mirroring the reference app exactly: the ENGINE drives
// the TUN. In the official Lantern app (getlantern/lantern,
// LanternVpnService.openTun) sing-tun calls the platform's openTun(tunOptions)
// DURING the tunnel start, and the app builds the VpnService Builder from the
// engine's own options at that moment and returns establish().fd — no TUN
// exists before the engine asks for one. The 3.4.0–3.4.3 pre-staged push
// (establish first, hand the fd over before /connect) raced the sidecar boot
// and hung in the field; the reference semantics remove the race by
// construction: nothing flows until OpenTun runs, inside ConnectVPN.
//
// The split-process twin: OpenTun serializes the engine's TunOptions into one
// OPEN json line, pushes it onto the request channel and blocks for the app's
// reply. The sidecar's handoff socket server (cmd/lanternsidecar's
// serveTunHandoff) relays that line to the app's long-lived connection, which
// mirrors the reference's createVPNBuilder(tunOptions) — close the previous
// interface first (openTun's stale-descriptor comment), establish() with the
// engine's own address plan, then return the fd via SCM_RIGHTS. Tunnel
// restarts simply issue another OPEN on the same connection.

// TunHandoffRequest is one engine→app OPEN request in flight. The relay
// (cmd/lanternsidecar) pulls it, sends the payload to the app and delivers
// the app's answer through Reply.
type TunHandoffRequest struct {
	// Payload is the OPEN line (json, no newline) to relay to the app.
	Payload []byte
	// result carries the app's reply: the established fd, or the error.
	result chan tunHandoffReply
}

type tunHandoffReply struct {
	fd  int
	err error
}

// tunHandoffRequests is the rendezvous between OpenTun (sing-tun's tunnel
// goroutine, inside ConnectVPN) and the handoff relay (the app's single
// long-lived connection). OpenTun pushes; the relay pulls.
var tunHandoffRequests = make(chan TunHandoffRequest, 4)

// PullTunRequest blocks until the engine issues an OPEN request (or the
// timeout passes). The relay serves one request at a time; the small
// timeout keeps the relay responsive to connection shutdown.
func PullTunRequest(timeout time.Duration) (TunHandoffRequest, bool) {
	select {
	case req := <-tunHandoffRequests:
		return req, true
	case <-time.After(timeout):
		return TunHandoffRequest{}, false
	}
}

// Reply delivers the app's answer (or the relay error) to the waiting OpenTun
// call. Buffered, so a stale reply after a timeout never blocks the relay.
func (r TunHandoffRequest) Reply(fd int, err error) {
	r.result <- tunHandoffReply{fd: fd, err: err}
}

// requestTun relays one OPEN request to the app and waits for the fd. The
// timeout covers both "the app has not connected yet" and "the app stalled":
// the app connects right around dispatching /connect, so the wait is normally
// milliseconds, but a bounded patience keeps a dead app from wedging the
// tunnel goroutine forever.
func requestTun(payload []byte, timeout time.Duration) (int, error) {
	req := TunHandoffRequest{Payload: payload, result: make(chan tunHandoffReply, 1)}
	select {
	case tunHandoffRequests <- req:
	case <-time.After(timeout):
		return -1, fmt.Errorf("no handoff connection is serving the app side (the app never connected)")
	}
	select {
	case reply := <-req.result:
		if reply.err != nil {
			return -1, reply.err
		}
		return reply.fd, nil
	case <-time.After(timeout):
		return -1, fmt.Errorf("the app did not answer the TUN request in time")
	}
}
