package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"github.com/getlantern/lantern-box/portforward"
)

// Start's failures reach the user as raw Go error text: the desktop share card
// renders the returned error verbatim. A peer that failed because the machine
// was offline showed this:
//
//	register with lantern-cloud: send: all transports failed: transport
//	smart: timed out, transport errors: transport proxyless: dial tcp:
//	lookup api.iantem.io: no such host
//
// Four nested wraps naming four internals, and the one fact the user could act
// on — the network was down — is the last clause of the innermost error. This
// turns the tree into one line, and keeps the tree in the log.
//
// Only failures we can actually name are rewritten. Everything else keeps its
// original error, because a vague-but-honest wrap beats a confident guess.

// Reason is a stable, machine-readable classification of a Start failure. It
// exists so the UI can localize these later without another radiance release:
// the message strings below are English, and a UI that only has the string can
// only display it.
type Reason string

const (
	// ReasonNoInternet means every attempt failed the way a disconnected
	// machine fails: name resolution or the route itself.
	ReasonNoInternet Reason = "no_internet"
	// ReasonNoPortForwarding means the router declined to map a port.
	ReasonNoPortForwarding Reason = "no_port_forwarding"
	// ReasonPortUnreachable means lantern-cloud's dial-back to the peer port
	// never arrived, whether the port was mapped by UPnP or configured by hand.
	ReasonPortUnreachable Reason = "port_unreachable"
	// ReasonCanceled means the caller gave up — usually the user toggling
	// sharing back off mid-start.
	ReasonCanceled Reason = "canceled"
)

// StartError is a named Start failure. Error() is the one line the UI shows;
// the original tree stays reachable through Unwrap for callers that want it,
// and is logged in full at the point of classification either way.
type StartError struct {
	Reason Reason
	msg    string
	cause  error
}

func (e *StartError) Error() string { return e.msg }
func (e *StartError) Unwrap() error { return e.cause }

// classifyStartFailure names err if it can, and returns nil when it cannot —
// in which case the caller keeps the raw error. Every rule below is justified
// by the error's own identity, and the one that consults phase is narrow
// enough to stay sound.
//
// manualPort is the router port the user forwarded by hand, or 0 when UPnP
// mapped it.
//
// It deliberately has no catch-all "something network-ish went wrong at this
// phase" rule. A phase spans more than one operation — validating the
// server's launch config and patching it for the local VPN both happen after
// registration has already succeeded, while the phase still reads
// "registering" — so a phase-keyed guess reported a launch config that failed
// our own safety check as "couldn't reach Lantern's servers", pointing the
// user at their network for a server-side problem. Guessing from position is
// how you get a confident wrong answer; an unnamed error at least stays
// honest.
func classifyStartFailure(phase Phase, err error, manualPort uint16) *StartError {
	if err == nil {
		return nil
	}
	named := func(r Reason, msg string) *StartError {
		return &StartError{Reason: r, msg: msg, cause: err}
	}

	// Cancellation gets its own branch so a user who toggles sharing back
	// off mid-start reads a sentence about that rather than the raw wrap.
	//
	// It cannot collide with the offline check below, which is why the order
	// here is defensive rather than load-bearing: offline() demands that
	// every branch of the tree be an offline signal, and context.Canceled is
	// not one, so a tree carrying it is never called offline whichever runs
	// first.
	if errors.Is(err, context.Canceled) {
		return named(ReasonCanceled, "Sharing was stopped before it finished starting.")
	}
	if errors.Is(err, portforward.ErrNoPortForwarding) {
		return named(ReasonNoPortForwarding,
			"Your router won't open a port automatically. Check that UPnP is enabled in its settings.")
	}
	if offline(err) {
		return named(ReasonNoInternet, "No internet connection.")
	}

	// A 422 from verify means lantern-cloud's dial-back never arrived: the
	// router either accepted a UPnP mapping and didn't honor it, or the user's
	// manual forward isn't working.
	// Distinguished from a plain unreachable server because the fix is
	// entirely different — this one is the user's router, not our outage.
	//
	// Narrow to that one status on purpose. Any other failure at verify,
	// 5xx especially, says nothing about the router and blaming it would
	// send the user to reconfigure hardware that is working.
	//
	// Reading the operation off phase is safe here, unlike as a fallback:
	// Verify is the only API call Start makes while the phase is
	// PhaseVerifying (Register is a phase earlier, Heartbeat a phase later),
	// so a 422 seen here came from the dial-back and nothing else.
	var apiErr *APIError
	if phase == PhaseVerifying && errors.As(err, &apiErr) &&
		apiErr.Status == http.StatusUnprocessableEntity {
		if manualPort != 0 {
			return named(ReasonPortUnreachable, fmt.Sprintf(
				"Port %d isn't reachable from the internet. Check that your router forwards it to this computer.",
				manualPort))
		}
		return named(ReasonPortUnreachable,
			"Your router accepted the port mapping but isn't forwarding traffic to this computer.")
	}
	return nil
}

// offline reports whether every distinct failure in err's tree is one a
// machine with no working network produces.
//
// Every, not any: kindling races several transports and joins their errors, so
// a tree where one transport got an HTTP status back is proof the network
// works, whatever the others say.
//
// Written as an explicit walk rather than errors.Is/As at the top, because
// those traverse joined errors with "any" semantics — errors.As(tree,
// &dnsErr) is true when a single transport hit DNS trouble, which is the
// opposite of the question being asked here.
//
// A DNS failure counts, which is not universally safe: a poisoned resolver
// looks the same and is a censorship signal rather than a local one. It is
// safe here specifically. This path only runs for Share My Connection, whose
// users are running an exit node in an uncensored network by definition; a
// user whose DNS is being tampered with is not the person seeing this string.
func offline(err error) bool {
	for err != nil {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			branches := joined.Unwrap()
			if len(branches) == 0 {
				return false
			}
			for _, branch := range branches {
				if !offline(branch) {
					return false
				}
			}
			return true
		}
		if offlineNode(err) {
			return true
		}
		unwrappable, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrappable.Unwrap()
	}
	return false
}

// offlineNode tests one node with a type switch rather than errors.Is, so it
// cannot accidentally traverse into a joined error and answer about a sibling.
func offlineNode(err error) bool {
	switch e := err.(type) {
	case *net.DNSError:
		return true
	case syscall.Errno:
		// ECONNREFUSED is deliberately absent: something answered, so the
		// network works and the problem is at the other end.
		return e == syscall.ENETUNREACH || e == syscall.EHOSTUNREACH ||
			e == syscall.ENETDOWN || e == syscall.EHOSTDOWN || e == syscall.ENETRESET
	}
	return false
}
