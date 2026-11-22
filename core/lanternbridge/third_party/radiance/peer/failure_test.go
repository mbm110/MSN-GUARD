package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/lantern-box/portforward"
	"github.com/getlantern/radiance/events"
)

// dnsFailure is what a dial looks like when nothing can be resolved.
func dnsFailure(host string) error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true},
	}
}

// routeFailure is the other shape of offline: the name resolved (or was an IP)
// and the kernel had nowhere to send the packet.
func routeFailure() error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: os.NewSyscallError("connect", syscall.ENETUNREACH),
	}
}

// kindlingTree reproduces the shape radiance actually receives from a failed
// kindling round-trip: a per-tier errors.Join nested inside an outer
// errors.Join, wrapped twice. Built by hand rather than by driving kindling so
// the test states the shape it depends on — if kindling changes it, this
// failing is the point.
func kindlingTree(leaves ...error) error {
	tier := make([]error, 0, len(leaves))
	names := []string{"proxyless", "fronted", "dnstt"}
	for i, leaf := range leaves {
		tier = append(tier, fmt.Errorf("transport %s: %w", names[i%len(names)], leaf))
	}
	inner := fmt.Errorf("timed out, transport errors: %w", errors.Join(tier...))
	return fmt.Errorf("send: %w", fmt.Errorf("all transports failed: %w",
		errors.Join(fmt.Errorf("transport smart: %w", inner))))
}

// The failure from the field: every transport failed to resolve, and the user
// saw four nested wraps ending in "lookup api.iantem.io: no such host".
func TestClassifyStartFailure_OfflineKindlingTreeBecomesOneLine(t *testing.T) {
	err := fmt.Errorf("register with lantern-cloud: %w",
		kindlingTree(dnsFailure("api.iantem.io"), dnsFailure("api.iantem.io"), routeFailure()))

	got := classifyStartFailure(PhaseRegistering, err, 0)
	require.NotNil(t, got)
	assert.Equal(t, ReasonNoInternet, got.Reason)
	assert.Equal(t, "No internet connection.", got.Error())
	// One sentence, not a tree: the internals that leaked into the share card
	// must not be in the message any more.
	assert.NotContains(t, got.Error(), "transport")
	assert.NotContains(t, got.Error(), "lookup")
	// The tree is still reachable for anything that wants it.
	assert.ErrorContains(t, errors.Unwrap(got), "all transports failed")
}

// The load-bearing property of offline(): every branch, not any. kindling
// races transports, so one transport that got an HTTP response back is proof
// the network works — no matter how many siblings failed to resolve.
func TestClassifyStartFailure_OneReachableTransportIsNotOffline(t *testing.T) {
	err := fmt.Errorf("register with lantern-cloud: %w", kindlingTree(
		dnsFailure("api.iantem.io"),
		dnsFailure("api.iantem.io"),
		// No wrapped cause, exactly as kindling formats a status: proof a
		// server answered.
		errors.New("http status 503"),
	))

	assert.Nil(t, classifyStartFailure(PhaseRegistering, err, 0),
		"a tree containing a reachable transport must not be called offline")
}

// A user who toggles sharing off mid-start cancels the ctx, and the dials that
// were in flight fail alongside it. What matters is that the result is never
// "No internet connection." — blaming their network for their own click.
//
// This holds structurally rather than by check order: offline() requires every
// branch to be an offline signal and context.Canceled is not one, so the tree
// cannot be called offline regardless of which condition is tested first.
func TestClassifyStartFailure_CancellationIsNeverReportedAsNoInternet(t *testing.T) {
	err := fmt.Errorf("register with lantern-cloud: %w",
		errors.Join(kindlingTree(dnsFailure("api.iantem.io")), context.Canceled))

	got := classifyStartFailure(PhaseRegistering, err, 0)
	require.NotNil(t, got)
	assert.Equal(t, ReasonCanceled, got.Reason)
	assert.NotEqual(t, ReasonNoInternet, got.Reason)
	assert.False(t, offline(err), "cancellation must not read as an offline tree")
}

func TestClassifyStartFailure_NoPortForwarding(t *testing.T) {
	err := fmt.Errorf("map port 38190: %w",
		fmt.Errorf("add port mapping: %w", portforward.ErrNoPortForwarding))

	got := classifyStartFailure(PhaseMappingPort, err, 0)
	require.NotNil(t, got)
	assert.Equal(t, ReasonNoPortForwarding, got.Reason)
	assert.Contains(t, got.Error(), "UPnP")
}

// In UPnP mode a 422 at verify means the router accepted the mapping but
// lantern-cloud's dial-back never arrived.
func TestClassifyStartFailure_VerifyUnprocessableMeansTheRouterLied(t *testing.T) {
	err := fmt.Errorf("verify with lantern-cloud: %w",
		fmt.Errorf("verify: %w", &APIError{
			Status: http.StatusUnprocessableEntity,
			Body:   "could not connect to peer port",
		}))

	got := classifyStartFailure(PhaseVerifying, err, 0)
	require.NotNil(t, got)
	assert.Equal(t, ReasonPortUnreachable, got.Reason)
	assert.Contains(t, got.Error(), "forwarding traffic")
}

// A 5xx at verify says nothing about the router. Blaming it would send the
// user to reconfigure hardware that is working, so this stays unnamed and the
// raw error survives.
func TestClassifyStartFailure_ServerErrorAtVerifyIsNotTheRoutersFault(t *testing.T) {
	err := fmt.Errorf("verify with lantern-cloud: %w",
		fmt.Errorf("verify: %w", &APIError{Status: http.StatusInternalServerError}))

	assert.Nil(t, classifyStartFailure(PhaseVerifying, err, 0))
}

// Regression for a bug this classifier shipped with in review: a phase-keyed
// fallback ("anything that fails while registering is a network problem")
// reported a launch_cfg that failed our own abuse-rule check as "couldn't
// reach Lantern's servers". peerrules.ValidateAbuseRules runs after Register has already
// succeeded, so the phase still reads registering — position is not evidence.
func TestClassifyStartFailure_PhaseAloneNeverNamesAFailure(t *testing.T) {
	for _, phase := range []Phase{PhaseMappingPort, PhaseDetectingIP, PhaseRegistering, PhaseVerifying, PhaseStartingBox} {
		err := fmt.Errorf("launch_cfg failed abuse-rule sanity check: %w",
			errors.New("inbound 0 is missing rule set"))
		assert.Nil(t, classifyStartFailure(phase, err, 0),
			"phase %s must not be enough to name an unrelated failure", phase)
	}
}

// An unnamed failure must keep its original text — a vague-but-honest wrap
// beats a confident guess, and the raw error is all the user has left.
func TestClient_Start_UnclassifiedFailureKeepsItsRawError(t *testing.T) {
	fwd := &fakeForwarder{extIPErr: errors.New("gateway returned empty")}
	c := newTestClient(t, fwd, &fakeBoxService{}, newStubServer(t))

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "gateway returned empty")
	assert.Empty(t, c.status.Reason, "an unnamed failure must not claim a reason")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// End to end: an offline Register makes Start return the one line the share
// card renders, and the StatusEvent carries the machine-readable reason
// alongside it.
func TestClient_Start_OfflineRegisterSurfacesOneLineAndAReason(t *testing.T) {
	srv := newStubServer(t)
	offline := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, kindlingTree(dnsFailure("api.iantem.io"), routeFailure())
	})}
	c := newTestClient(t, &fakeForwarder{externalIP: "203.0.113.42"}, &fakeBoxService{}, srv,
		func(cfg *Config) { cfg.API = NewAPI(offline, srv.server.URL+"/v1", "test-device") })

	got := make(chan StatusEvent, 16)
	sub := events.Subscribe(func(evt StatusEvent) { got <- evt })
	defer sub.Unsubscribe()

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.Equal(t, "No internet connection.", err.Error())

	deadline := time.After(time.Second)
	for {
		select {
		case evt := <-got:
			if evt.Status.Phase != PhaseError {
				assert.Empty(t, evt.Status.Reason, "progress events must carry no reason")
				continue
			}
			assert.Equal(t, ReasonNoInternet, evt.Status.Reason)
			assert.Equal(t, "No internet connection.", evt.Status.Error)
			return
		case <-deadline:
			t.Fatal("no PhaseError status event within 1s")
		}
	}
}

// In manual mode no mapping was requested, so the message must not claim one
// was accepted.
func TestClassifyStartFailure_VerifyUnprocessableWithManualPortNamesThePort(t *testing.T) {
	err := fmt.Errorf("verify with lantern-cloud: %w",
		fmt.Errorf("verify: %w", &APIError{
			Status: http.StatusUnprocessableEntity,
			Body:   "could not connect to peer port",
		}))

	got := classifyStartFailure(PhaseVerifying, err, 5698)
	require.NotNil(t, got)
	assert.Equal(t, ReasonPortUnreachable, got.Reason)
	assert.Contains(t, got.Error(), "5698")
	assert.NotContains(t, got.Error(), "accepted the port mapping")
}
