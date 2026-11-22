// Package ipc implements the IPC server between the client and the VPN service (lanternd), exposing HTTP endpoints over a Unix socket (named pipe on Windows).
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/internal/hostaccess"
	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/unbounded"
	clientmessage "github.com/getlantern/radiance/usermessage"
	"github.com/getlantern/radiance/vpn"

	sjson "github.com/sagernet/sing/common/json"
)

const (
	tracerName = "github.com/getlantern/radiance/ipc"

	// VPN endpoints
	vpnStatusEndpoint           = "/vpn/status"
	vpnConnectEndpoint          = "/vpn/connect"
	vpnDisconnectEndpoint       = "/vpn/disconnect"
	vpnRestartEndpoint          = "/vpn/restart"
	vpnConnectionsEndpoint      = "/vpn/connections"
	vpnThroughputEndpoint       = "/vpn/throughput"
	vpnOfflineTestsEndpoint     = "/vpn/offline-tests"
	vpnStatusEventsEndpoint     = "/vpn/status/events"
	vpnSessionsEndpoint         = "/vpn/sessions"
	vpnClearTunnelCacheEndpoint = "/vpn/cache/clear"
	vpnResetNetworkEndpoint     = "/vpn/network/reset"
	vpnPauseEndpoint            = "/vpn/pause"
	vpnWakeEndpoint             = "/vpn/wake"

	// Server selection endpoints
	serverSelectedEndpoint           = "/server/selected"
	serverAutoSelectedEndpoint       = "/server/auto-selected"
	serverAutoSelectedEventsEndpoint = "/server/auto-selected/events"
	serverURLTestEventsEndpoint      = "/server/url-test/events"
	serverSelectionEventsEndpoint    = "/server/selection/events"

	// Config endpoints
	configEventsEndpoint = "/config/events"
	configUpdateEndpoint = "/config/update"

	userMessageEndpoint            = "/user-messages"
	userMessageEventsEndpoint      = "/user-messages/events"
	userMessageRefreshEndpoint     = "/user-messages/refresh"
	userMessageAcknowledgeEndpoint = "/user-messages/acknowledge"
	userMessageActivityEndpoint    = "/user-messages/activity"

	// Server management endpoints
	serversEndpoint              = "/servers"
	serversAddEndpoint           = "/servers/add"
	serversRemoveEndpoint        = "/servers/remove"
	serversFromJSONEndpoint      = "/servers/json"
	serversFromURLsEndpoint      = "/servers/urls"
	serversPrivateEndpoint       = "/servers/private"
	serversPrivateInviteEndpoint = "/servers/private/invite"

	// Settings endpoints
	featuresEndpoint = "/settings/features"
	settingsEndpoint = "/settings"

	// Peer-share ("Share My Connection") endpoints
	peerStatusEndpoint           = "/peer/status"
	peerStatusEventsEndpoint     = "/peer/status/events"
	peerConnectionEventsEndpoint = "/peer/connection/events"
	peerSnapshotEndpoint         = "/peer/snapshot"

	// Unbounded ("Basic mode") endpoints. Connection events have the same
	// JSON shape as /peer/connection/events but are emitted from a
	// different in-process event type, so they need their own SSE bridge.
	unboundedConnectionEventsEndpoint = "/unbounded/connection/events"
	unboundedSnapshotEndpoint         = "/unbounded/snapshot"

	// Helper invites
	helperRelayEndpoint                 = "/helper/relay"
	helperActivityEndpoint              = "/helper/activity"
	helperLiveEndpoint                  = "/helper/live"
	helperPersonalProxiesEndpoint       = "/helper/personal-proxies"
	helperPersonalProxyFallbackEndpoint = "/helper/personal-proxies/fallback/events"
	helperPairingKeysEndpoint           = "/helper/pairing-keys"

	// Split tunnel endpoint
	splitTunnelEndpoint = "/split-tunnel"

	// Account endpoints
	accountNewUserEndpoint          = "/account/new-user"
	accountLoginEndpoint            = "/account/login"
	accountLogoutEndpoint           = "/account/logout"
	accountUserDataEndpoint         = "/account/user"
	accountDevicesEndpoint          = "/account/devices/"
	accountSignupEndpoint           = "/account/signup/"
	accountVerifyPasswordEndpoint   = "/account/verify-password"
	accountEmailEndpoint            = "/account/email"
	accountRecoveryEndpoint         = "/account/recovery"
	accountDeleteEndpoint           = "/account/delete"
	accountOAuthEndpoint            = "/account/oauth"
	accountOAuthDeviceLimitEndpoint = "/account/oauth/device-limit"
	accountDataCapEndpoint          = "/account/datacap"
	accountDataCapStreamEndpoint    = "/account/datacap/stream"

	// Subscription endpoints
	subscriptionActivationEndpoint         = "/subscription/activation"
	subscriptionStripeEndpoint             = "/subscription/stripe"
	subscriptionPaymentRedirectEndpoint    = "/subscription/payment-redirect"
	subscriptionReferralEndpoint           = "/subscription/referral"
	subscriptionBillingPortalEndpoint      = "/subscription/billing-portal"
	subscriptionPaymentRedirectURLEndpoint = "/subscription/payment-redirect-url"
	subscriptionPlansEndpoint              = "/subscription/plans"
	subscriptionVerifyEndpoint             = "/subscription/verify"
	subscriptionRestoreEndpoint            = "/subscription/restore"

	// Issue endpoint
	issueEndpoint = "/issue"

	// Logs endpoint
	logsStreamEndpoint = "/logs/stream"

	// Env endpoint (dev/testing)
	envEndpoint = "/env"
)

var (
	protocols = func() http.Protocols {
		var p http.Protocols
		p.SetUnencryptedHTTP2(true)
		return p
	}()

	ErrServiceIsNotReady = errors.New("service is not ready")
	ErrIPCNotRunning     = errors.New("IPC not running")
)

// Server represents the IPC server that communicates over a Unix domain socket for Unix-like
// systems, and a named pipe for Windows.
type Server struct {
	svr    *http.Server
	api    *localapi
	closed atomic.Bool
}

// NewServer returns an IPC server backed by b. When withAuth is true, the
// server authenticates each connection; when false, it accepts all connections.
func NewServer(b *backend.LocalBackend, withAuth bool) *Server {
	api := newLocalAPI(b, withAuth)
	svr := &http.Server{
		Handler:     api,
		ReadTimeout: 5 * time.Second,
		Protocols:   &protocols,
	}
	if withAuth {
		svr.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			// Windows pipe credentials are only available after reading the first request.
			peer := sync.OnceValues(func() (usr, error) { return getConnPeer(c) })
			return context.WithValue(ctx, peerLookupKey{}, peer)
		}
	}
	return &Server{svr: svr, api: api}
}

// SetBackend exposes b to subsequent requests without taking ownership of it.
// A nil backend permits only issue reporting and log streaming.
func (s *Server) SetBackend(b *backend.LocalBackend) { s.api.setBackend(b) }

// SetOwnerSID authorizes sid alongside administrators; sid must come from validated protected storage.
func (s *Server) SetOwnerSID(sid string) { s.api.ownerSID.Store(&sid) }

// Start begins listening for incoming IPC requests.
func (s *Server) Start() error {
	if s.closed.Load() {
		return errors.New("IPC server is closed")
	}
	l, err := listen()
	if err != nil {
		return fmt.Errorf("IPC server: listen: %w", err)
	}
	go func() {
		slog.Info("IPC server started", "address", l.Addr().String())
		if err := s.svr.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("IPC server error", "error", err)
		}
		s.closed.Store(true)
	}()
	return nil
}

// Close shuts down the IPC server.
func (s *Server) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	slog.Info("Closing IPC server")
	return s.svr.Close()
}

type backendKey struct{}

type localapi struct {
	be       atomic.Pointer[backend.LocalBackend]
	ownerSID atomic.Pointer[string]
	handler  http.Handler
}

// backend returns the LocalBackend snapshotted at the start of the request.
func (s *localapi) backend(ctx context.Context) *backend.LocalBackend {
	return ctx.Value(backendKey{}).(*backend.LocalBackend)
}

func newLocalAPI(b *backend.LocalBackend, withAuth bool) *localapi {
	s := &localapi{}
	s.be.Store(b)

	mux := http.NewServeMux()

	// traced wraps a handler with the tracer middleware.
	traced := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tracer(http.HandlerFunc(h)).ServeHTTP(w, r)
		}
	}

	// VPN
	mux.HandleFunc("GET "+vpnStatusEndpoint, traced(s.vpnStatusHandler))
	mux.HandleFunc("POST "+vpnConnectEndpoint, traced(s.vpnConnectHandler))
	mux.HandleFunc("POST "+vpnDisconnectEndpoint, traced(s.vpnDisconnectHandler))
	mux.HandleFunc("POST "+vpnRestartEndpoint, traced(s.vpnRestartHandler))
	mux.HandleFunc("GET "+vpnConnectionsEndpoint, traced(s.vpnConnectionsHandler))
	mux.HandleFunc("GET "+vpnThroughputEndpoint, traced(s.vpnThroughputHandler))
	mux.HandleFunc("POST "+vpnOfflineTestsEndpoint, traced(s.vpnOfflineTestsHandler))
	mux.HandleFunc("GET "+vpnSessionsEndpoint, traced(s.vpnSessionsHandler))
	mux.HandleFunc("POST "+vpnClearTunnelCacheEndpoint, traced(s.vpnClearTunnelCacheHandler))
	mux.HandleFunc("POST "+vpnResetNetworkEndpoint, traced(s.vpnResetNetworkHandler))
	mux.HandleFunc("POST "+vpnPauseEndpoint, traced(s.vpnPauseHandler))
	mux.HandleFunc("POST "+vpnWakeEndpoint, traced(s.vpnWakeHandler))

	// SSE routes skip the tracer middleware since it buffers the entire response body.
	mux.HandleFunc("GET "+vpnStatusEventsEndpoint, s.vpnStatusEventsHandler)

	// Server selection
	mux.HandleFunc(serverSelectedEndpoint, traced(s.serverSelectedHandler))
	mux.HandleFunc("GET "+serverAutoSelectedEndpoint, traced(s.serverAutoSelectedHandler))
	mux.HandleFunc("GET "+serverAutoSelectedEventsEndpoint, s.serverAutoSelectedEventsHandler)
	mux.HandleFunc("GET "+serverURLTestEventsEndpoint, s.serverURLTestEventsHandler)
	mux.HandleFunc("GET "+serverSelectionEventsEndpoint, s.serverSelectionEventsHandler)
	mux.HandleFunc("GET "+configEventsEndpoint, s.configEventsHandler)
	mux.HandleFunc("POST "+configUpdateEndpoint, traced(s.configUpdateHandler))

	mux.HandleFunc("GET "+userMessageEndpoint, traced(s.userMessageHandler))
	mux.HandleFunc("GET "+userMessageEventsEndpoint, s.userMessageEventsHandler)
	mux.HandleFunc("POST "+userMessageRefreshEndpoint, traced(s.userMessageRefreshHandler))
	mux.HandleFunc("POST "+userMessageAcknowledgeEndpoint, traced(s.userMessageAcknowledgeHandler))
	mux.HandleFunc("PATCH "+userMessageActivityEndpoint, traced(s.userMessageActivityHandler))

	// Server management
	mux.HandleFunc("GET "+serversEndpoint, traced(s.serversHandler))
	mux.HandleFunc("POST "+serversAddEndpoint, traced(s.serversAddHandler))
	mux.HandleFunc("POST "+serversRemoveEndpoint, traced(s.serversRemoveHandler))
	mux.HandleFunc("POST "+serversFromJSONEndpoint, traced(s.serversFromJSONHandler))
	mux.HandleFunc("POST "+serversFromURLsEndpoint, traced(s.serversFromURLsHandler))
	mux.HandleFunc("POST "+serversPrivateEndpoint, traced(s.serversPrivateAddHandler))
	mux.HandleFunc(serversPrivateInviteEndpoint, traced(s.serversPrivateInviteHandler))

	// Settings
	mux.HandleFunc("GET "+featuresEndpoint, traced(s.featuresHandler))
	mux.HandleFunc(settingsEndpoint, traced(s.settingsHandler))

	// Peer share
	mux.HandleFunc("GET "+peerStatusEndpoint, traced(s.peerStatusHandler))
	// SSE skips the tracer middleware since it buffers the entire response body.
	mux.HandleFunc("GET "+peerStatusEventsEndpoint, s.peerStatusEventsHandler)
	mux.HandleFunc("GET "+peerConnectionEventsEndpoint, s.peerConnectionEventsHandler)
	mux.HandleFunc("GET "+peerSnapshotEndpoint, traced(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.backend(r.Context()).PeerRelaySnapshot())
	}))
	mux.HandleFunc("GET "+unboundedConnectionEventsEndpoint, s.unboundedConnectionEventsHandler)

	mux.HandleFunc("GET "+unboundedSnapshotEndpoint, traced(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, unbounded.CurrentSnapshot())
	}))

	// Helper invites. Not traced: a span per relay call would show in
	// exported telemetry that the device uses helper invites, and how many
	// operations it ran.
	mux.HandleFunc("POST "+helperRelayEndpoint, s.helperRelayHandler)
	// Not traced either: a span would mark the device as having helper
	// pairings, and how often they change.
	mux.HandleFunc("POST "+helperPairingKeysEndpoint, s.helperPairingKeysHandler)
	// Not traced either: a traced poll would mark the device as a helper
	// volunteer in exported telemetry.
	mux.HandleFunc("GET "+helperActivityEndpoint, s.helperActivityHandler)
	// Not traced either, for the same reason.
	mux.HandleFunc("GET "+helperLiveEndpoint, s.helperLiveHandler)
	// Not traced either: a traced poll or stream would mark the device as an
	// inviter in exported telemetry.
	mux.HandleFunc("GET "+helperPersonalProxiesEndpoint, s.helperPersonalProxiesHandler)
	mux.HandleFunc("GET "+helperPersonalProxyFallbackEndpoint, s.helperPersonalProxyFallbackHandler)

	// Split tunnel
	mux.HandleFunc(splitTunnelEndpoint, traced(s.splitTunnelHandler))

	// Account
	mux.HandleFunc("POST "+accountNewUserEndpoint, traced(s.accountNewUserHandler))
	mux.HandleFunc("POST "+accountLoginEndpoint, traced(s.accountLoginHandler))
	mux.HandleFunc("POST "+accountLogoutEndpoint, traced(s.accountLogoutHandler))
	mux.HandleFunc("GET "+accountUserDataEndpoint, traced(s.accountUserDataHandler))
	mux.HandleFunc(accountDevicesEndpoint+"{deviceID...}", traced(s.accountDevicesHandler))
	mux.HandleFunc("POST "+accountSignupEndpoint+"{action...}", traced(s.accountSignupHandler))
	mux.HandleFunc("POST "+accountVerifyPasswordEndpoint, traced(s.accountVerifyPasswordHandler))
	mux.HandleFunc("POST "+accountEmailEndpoint+"/{action}", traced(s.accountEmailHandler))
	mux.HandleFunc("POST "+accountRecoveryEndpoint+"/{action}", traced(s.accountRecoveryHandler))
	mux.HandleFunc("DELETE "+accountDeleteEndpoint, traced(s.accountDeleteHandler))
	mux.HandleFunc(accountOAuthEndpoint, traced(s.accountOAuthHandler))
	mux.HandleFunc("POST "+accountOAuthDeviceLimitEndpoint, traced(s.accountOAuthDeviceLimitHandler))
	mux.HandleFunc("GET "+accountDataCapEndpoint, traced(s.accountDataCapHandler))

	// SSE routes skip the tracer middleware since it buffers the entire response body.
	mux.HandleFunc("GET "+accountDataCapStreamEndpoint, s.accountDataCapStreamHandler)

	// Subscriptions
	mux.HandleFunc("POST "+subscriptionActivationEndpoint, traced(s.subscriptionActivationHandler))
	mux.HandleFunc("POST "+subscriptionStripeEndpoint, traced(s.subscriptionStripeHandler))
	mux.HandleFunc("POST "+subscriptionPaymentRedirectEndpoint, traced(s.subscriptionPaymentRedirectHandler))
	mux.HandleFunc("POST "+subscriptionReferralEndpoint, traced(s.subscriptionReferralHandler))
	mux.HandleFunc("GET "+subscriptionBillingPortalEndpoint, traced(s.subscriptionBillingPortalHandler))
	mux.HandleFunc("POST "+subscriptionPaymentRedirectURLEndpoint, traced(s.subscriptionPaymentRedirectURLHandler))
	mux.HandleFunc("GET "+subscriptionPlansEndpoint, traced(s.subscriptionPlansHandler))
	mux.HandleFunc("POST "+subscriptionVerifyEndpoint, traced(s.subscriptionVerifyHandler))
	mux.HandleFunc("POST "+subscriptionRestoreEndpoint, traced(s.subscriptionRestoreHandler))

	// Issue
	mux.HandleFunc("POST "+issueEndpoint, traced(s.issueReportHandler))

	// Logs (SSE, skip tracer)
	mux.HandleFunc("GET "+logsStreamEndpoint, s.logsStreamHandler)

	// Env (dev/testing)
	mux.HandleFunc(envEndpoint, traced(s.envHandler))

	// Build the middleware chain: log -> (optional auth) -> mux
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.backend(r.Context()) == nil && r.URL.Path != issueEndpoint && r.URL.Path != logsStreamEndpoint {
			http.Error(w, "service is not ready", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
	if withAuth {
		handler = authPeer(handler)
	}
	handler = logger(handler)
	s.handler = handler

	return s
}

func (s *localapi) setBackend(b *backend.LocalBackend) *backend.LocalBackend {
	return s.be.Swap(b)
}

func (s *localapi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b := s.be.Load()
	ctx := context.WithValue(r.Context(), backendKey{}, b)
	if sid := s.ownerSID.Load(); sid != nil {
		ctx = context.WithValue(ctx, ownerSIDKey{}, *sid)
	}
	s.handler.ServeHTTP(w, r.WithContext(ctx))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("IPC: failed to write JSON response", "error", err)
	}
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func writeSingJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := sjson.NewEncoderContext(boxCtx, w).Encode(v); err != nil {
		slog.Error("IPC: failed to write JSON response", "error", err)
	}
}

func decodeSingJSON(r *http.Request, v any) error {
	return sjson.NewDecoderContext(boxCtx, r.Body).Decode(v)
}

// sseWriter sets headers for a Server-Sent Events response and returns the flusher.
// Returns nil if the ResponseWriter does not support flushing.
func sseWriter(w http.ResponseWriter) http.Flusher {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return nil
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return flusher
}

// sseStateStream serves an SSE stream of current state. An E event only wakes the stream, and
// wake-ups before the next frame coalesce into one. frame runs once after subscribing and again
// on each wake-up; it returns false to send nothing. It returns when the request ends or a write
// fails.
func sseStateStream[E events.Event, F any](w http.ResponseWriter, r *http.Request, frame func() (F, bool)) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	wake := make(chan struct{}, 1)
	sub := events.Subscribe(func(E) {
		select {
		case wake <- struct{}{}:
		default:
		}
	})
	defer sub.Unsubscribe()

	send := func() error {
		v, ok := frame()
		if !ok {
			return nil
		}
		data, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	if send() != nil {
		return
	}
	for {
		select {
		case <-wake:
			if send() != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

/////////////
//   VPN   //
/////////////

func (s *localapi) vpnStatusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.backend(r.Context()).VPNStatus())
}

func (s *localapi) vpnConnectHandler(w http.ResponseWriter, r *http.Request) {
	var req TagRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.backend(r.Context()).ConnectVPN(r.Context(), req.Tag); err != nil {
		if errors.Is(err, backend.ErrConnectInProgress) {
			w.WriteHeader(http.StatusOK) // a connect is already running; no-op
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.backend(r.Context()).DisconnectVPN(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnRestartHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.backend(r.Context()).RestartVPN(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnResetNetworkHandler(w http.ResponseWriter, r *http.Request) {
	s.backend(r.Context()).ResetNetwork()
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnPauseHandler(w http.ResponseWriter, r *http.Request) {
	s.backend(r.Context()).Pause()
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnWakeHandler(w http.ResponseWriter, r *http.Request) {
	s.backend(r.Context()).Wake()
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	conns, err := s.backend(r.Context()).VPNConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, conns)
}

func (s *localapi) vpnThroughputHandler(w http.ResponseWriter, r *http.Request) {
	tp, err := s.backend(r.Context()).VPNThroughput()
	if err != nil {
		// Disconnected has no traffic; a zero snapshot is the correct value, not an error.
		if errors.Is(err, vpn.ErrTunnelNotConnected) {
			writeJSON(w, http.StatusOK, vpn.ThroughputSnapshot{})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, tp)
}

func (s *localapi) vpnSessionsHandler(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, s.backend(r.Context()).Sessions(limit))
}

func (s *localapi) vpnClearTunnelCacheHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.backend(r.Context()).ClearTunnelCache(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnOfflineTestsHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.backend(r.Context()).RunOfflineURLTests(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) vpnStatusEventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	ch := make(chan []byte, 16)
	sub := events.Subscribe(func(evt vpn.StatusUpdateEvent) {
		data, err := json.Marshal(evt)
		if err != nil {
			return
		}
		select {
		case ch <- data:
		default:
		}
	})
	defer sub.Unsubscribe()

	// events.Subscribe is forward-only; write the current status directly
	// so a subscriber that attaches between setStatus calls still sees it.
	if cur := s.backend(r.Context()).VPNStatus(); cur != "" {
		if data, err := json.Marshal(vpn.StatusUpdateEvent{Status: cur}); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			slog.Info("[vpn-state-trace]", "hop", "ssehandler_flushed_replay", "data", string(data), "ts_ms", time.Now().UnixMilli())
		}
	}

	for {
		select {
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			// [vpn-state-trace] hop=ssehandler_flushed — bytes handed to the
			// HTTP response after Flush. Pairs with daemon_setstatus upstream
			// and sse_parsed downstream to bracket transit through the
			// (winio) named pipe on Windows.
			slog.Info("[vpn-state-trace]", "hop", "ssehandler_flushed", "data", string(data), "ts_ms", time.Now().UnixMilli())
		case <-r.Context().Done():
			return
		}
	}
}

/////////////////
//  Peer share //
/////////////////

func (s *localapi) peerStatusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.backend(r.Context()).PeerStatus())
}

func (s *localapi) peerStatusEventsHandler(w http.ResponseWriter, r *http.Request) {
	sseStateStream[peer.StatusEvent](w, r, func() (peer.StatusEvent, bool) {
		return peer.StatusEvent{Status: s.backend(r.Context()).PeerStatus()}, true
	})
}

// peerConnectionEventsHandler streams peer.ConnectionEvent over SSE for
// each accept/close on the local samizdat-in. Unlike peerStatusEventsHandler
// (which always sends the live snapshot), each event's captured value is
// load-bearing, not a resendable snapshot, so none may be collapsed into a
// single wakeup.
//
// The events package lives in this process (lanternd); cross-process
// consumers in Liblantern can only receive these via this SSE stream,
// since events.Subscribe in the Liblantern process sees a different
// (empty) subscriptions map.
func (s *localapi) peerConnectionEventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	// Buffered channel so a slow SSE consumer doesn't stall this
	// subscription's delivery goroutine, which would eventually fill the
	// bus's own queue and start dropping. 64 holds ~one second of
	// accept/close pairs under heavy load; beyond that we drop here to
	// avoid unbounded memory growth.
	queue := make(chan peer.ConnectionEvent, 64)
	sub := events.Subscribe(func(evt peer.ConnectionEvent) {
		select {
		case queue <- evt:
		default:
			// queue full — drop. SSE consumer is too slow; better to
			// lose this event here than to stall this subscription's
			// delivery goroutine and have the bus drop from further back.
		}
	})
	defer sub.Unsubscribe()

	for {
		select {
		case evt := <-queue:
			data, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// unboundedConnectionEventsHandler streams unbounded.ConnectionEvent over SSE
// for each consumer accept/disconnect on the broflake widget proxy. Mirrors
// peerConnectionEventsHandler — the JSON shape is identical, but events.Emit
// dispatches by concrete Go type so the two streams need separate
// subscriptions. Cross-process consumers (Flutter via Liblantern) merge the
// two SSE endpoints client-side into one peer-connection feed for the globe.
func (s *localapi) unboundedConnectionEventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	queue := make(chan unbounded.ConnectionEvent, 64)
	sub := events.Subscribe(func(evt unbounded.ConnectionEvent) {
		select {
		case queue <- evt:
		default:
			// queue full — drop. Same rationale as the peer handler:
			// better to lose this event than back up events.Emit.
		}
	})
	defer sub.Unsubscribe()

	for {
		select {
		case evt := <-queue:
			data, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

///////////////////////
// Server selection  //
///////////////////////

// serverSelectedHandler handles GET /server/selected (read) and POST /server/selected (set).
func (s *localapi) serverSelectedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req TagRequest
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.backend(r.Context()).SelectServer(req.Tag); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	server, exists, err := s.backend(r.Context()).SelectedServer()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeSingJSON(w, http.StatusOK, SelectedServerResponse{Server: server, Exists: exists})
}

func (s *localapi) serverAutoSelectedHandler(w http.ResponseWriter, r *http.Request) {
	tag, err := s.backend(r.Context()).CurrentAutoSelectedServer()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	server, found := s.backend(r.Context()).GetServerByTag(tag)
	if !found {
		http.Error(w, "auto-selected server not found", http.StatusNotFound)
		return
	}
	writeSingJSON(w, http.StatusOK, server)
}

func (s *localapi) serverAutoSelectedEventsHandler(w http.ResponseWriter, r *http.Request) {
	sseStateStream[vpn.AutoSelectedEvent](w, r, func() (vpn.AutoSelectedEvent, bool) {
		tag := s.backend(r.Context()).AnnouncedAutoSelectedServer()
		return vpn.AutoSelectedEvent{Selected: tag}, tag != ""
	})
}

func (s *localapi) serverSelectionEventsHandler(w http.ResponseWriter, r *http.Request) {
	sseStateStream[vpn.SelectionSavedEvent](w, r, func() (vpn.SelectionSavedEvent, bool) {
		return vpn.SelectionSavedEvent{}, true
	})
}

func (s *localapi) serverURLTestEventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	ch := make(chan []byte, 16)
	sub := events.Subscribe(func(evt vpn.URLTestCompleteEvent) {
		data, err := json.Marshal(evt)
		if err != nil {
			return
		}
		select {
		case ch <- data:
		default:
		}
	})
	defer sub.Unsubscribe()
	for {
		select {
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *localapi) configUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.backend(r.Context()).UpdateConfig(); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, config.ErrConfigFetchDisabled) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// configEventsHandler streams "{}" on subscribe and after a config change is applied. Subscribers
// fetch fresh state through the GET endpoints, so the potentially large Config is not serialized.
func (s *localapi) configEventsHandler(w http.ResponseWriter, r *http.Request) {
	sseStateStream[backend.ConfigAppliedEvent](w, r, func() (struct{}, bool) {
		return struct{}{}, true
	})
}

///////////////////////
// Server management //
///////////////////////

// serversHandler handles GET /servers
func (s *localapi) serversHandler(w http.ResponseWriter, r *http.Request) {
	if tag := r.URL.Query().Get("tag"); tag != "" {
		server, found := s.backend(r.Context()).GetServerByTag(tag)
		if !found {
			http.Error(w, "server not found", http.StatusNotFound)
			return
		}
		writeSingJSON(w, http.StatusOK, server)
		return
	}
	writeSingJSON(w, http.StatusOK, s.backend(r.Context()).AllServers())
}

func (s *localapi) serversAddHandler(w http.ResponseWriter, r *http.Request) {
	var req AddServersRequest
	if err := decodeSingJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.backend(r.Context()).AddServers(req.Servers); err != nil {
		http.Error(w, err.Error(), addServersStatus(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) serversRemoveHandler(w http.ResponseWriter, r *http.Request) {
	var req RemoveServersRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.backend(r.Context()).RemoveServers(req.Tags); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) serversFromJSONHandler(w http.ResponseWriter, r *http.Request) {
	var req JSONConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tags, err := s.backend(r.Context()).AddServersByJSON(req.Config)
	if err != nil {
		http.Error(w, err.Error(), addServersStatus(err))
		return
	}
	writeJSON(w, http.StatusOK, tags)
}

func (s *localapi) serversFromURLsHandler(w http.ResponseWriter, r *http.Request) {
	var req URLsRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tags, err := s.backend(r.Context()).AddServersByURL(req.URLs, req.SkipCertVerification)
	if err != nil {
		http.Error(w, err.Error(), addServersStatus(err))
		return
	}
	writeJSON(w, http.StatusOK, tags)
}

func (s *localapi) serversPrivateAddHandler(w http.ResponseWriter, r *http.Request) {
	var req PrivateServerRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.backend(r.Context()).AddPrivateServer(req.Tag, req.IP, req.Port, req.AccessToken, req.Location, req.Joined)
	if err != nil {
		http.Error(w, err.Error(), addServersStatus(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func addServersStatus(err error) int {
	if errors.Is(err, hostaccess.ErrDenied) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// serversPrivateInviteHandler handles POST (create) and DELETE (revoke) on /servers/private/invite.
func (s *localapi) serversPrivateInviteHandler(w http.ResponseWriter, r *http.Request) {
	var req PrivateServerInviteRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodDelete {
		if err := s.backend(r.Context()).RevokePrivateServerInvite(req.IP, req.Port, req.AccessToken, req.InviteName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	code, err := s.backend(r.Context()).InviteToPrivateServer(req.IP, req.Port, req.AccessToken, req.InviteName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, CodeResponse{Code: code})
}

//////////////
// Settings //
//////////////

func (s *localapi) featuresHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.backend(r.Context()).Features())
}

func (s *localapi) settingsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPatch:
		var updates settings.Settings
		if err := decodeJSON(r, &updates); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if peer, ok := r.Context().Value(peerKey{}).(usr); ok && !peer.isAdmin {
			for key := range updates {
				switch key {
				case settings.LocaleKey, settings.TimeZoneKey, settings.TelemetryKey,
					settings.SmartRoutingKey, settings.SplitTunnelKey, settings.SplitTunnelPolicyKey,
					settings.AdBlockKey, settings.ProxylessKey, settings.AutoConnectKey, settings.PeerShareEnabledKey,
					settings.PeerManualPortKey, settings.PeerServePoolKey, settings.UnboundedKey,
					settings.LogLevelKey, settings.SendLogsToSigNozKey:
				default:
					http.Error(w, "permission denied", http.StatusForbidden)
					return
				}
			}
		}
		if err := s.backend(r.Context()).PatchSettings(updates); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fallthrough
	case http.MethodGet:
		writeJSON(w, http.StatusOK, settings.GetAll())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *localapi) userMessageHandler(w http.ResponseWriter, r *http.Request) {
	message, err := s.backend(r.Context()).CurrentUserMessage()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, CurrentUserMessageResponse{Message: message})
}

func (s *localapi) userMessageEventsHandler(w http.ResponseWriter, r *http.Request) {
	sseStateStream[clientmessage.AvailableEvent](w, r, func() (struct{}, bool) {
		return struct{}{}, true
	})
}

func (s *localapi) userMessageRefreshHandler(w http.ResponseWriter, r *http.Request) {
	s.backend(r.Context()).RefreshUserMessages()
	w.WriteHeader(http.StatusNoContent)
}

func (s *localapi) userMessageAcknowledgeHandler(w http.ResponseWriter, r *http.Request) {
	var request UserMessageAcknowledgeRequest
	if err := decodeJSON(r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.backend(r.Context()).AcknowledgeUserMessage(request.DisplayID, request.AccountID); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, clientmessage.ErrMessageNotPending) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *localapi) userMessageActivityHandler(w http.ResponseWriter, r *http.Request) {
	var request UserMessageActivityRequest
	if err := decodeJSON(r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.backend(r.Context()).SetUserMessageActivity(request.Active)
	w.WriteHeader(http.StatusNoContent)
}

func (s *localapi) envHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPatch:
		var updates map[string]string
		if err := decodeJSON(r, &updates); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range updates {
			env.Set(k, v)
			switch k {
			case env.Country.String():
				err := settings.Set(settings.CountryCodeKey, v)
				// A failed save still applies the live value.
				if b := s.backend(r.Context()); b != nil {
					b.CountryCodeChanged()
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			case env.FeatureOverrides.String():
				if err := settings.Set(settings.FeatureOverridesKey, v); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
		fallthrough
	case http.MethodGet:
		writeJSON(w, http.StatusOK, env.GetAll())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

/////////////////
// Split Tunnel //
/////////////////

// splitTunnelHandler handles GET (read), POST (add), and DELETE (remove) on /split-tunnel.
func (s *localapi) splitTunnelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.backend(r.Context()).SplitTunnelFilters())
		return
	}
	var items vpn.SplitTunnelFilter
	if err := decodeJSON(r, &items); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var err error
	switch r.Method {
	case http.MethodPost:
		err = s.backend(r.Context()).AddSplitTunnelItems(items)
	case http.MethodDelete:
		err = s.backend(r.Context()).RemoveSplitTunnelItems(items)
	}
	if err != nil {
		http.Error(w, err.Error(), splitTunnelStatus(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func splitTunnelStatus(err error) int {
	if errors.Is(err, vpn.ErrInvalidSplitTunnelFilter) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

/////////////
// Account //
/////////////

func (s *localapi) accountNewUserHandler(w http.ResponseWriter, r *http.Request) {
	userData, err := s.backend(r.Context()).NewUser(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, userData)
}

func (s *localapi) accountLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req EmailPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userData, err := s.backend(r.Context()).Login(r.Context(), req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, userData)
}

func (s *localapi) accountLogoutHandler(w http.ResponseWriter, r *http.Request) {
	var req EmailRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userData, err := s.backend(r.Context()).Logout(r.Context(), req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, userData)
}

func (s *localapi) accountUserDataHandler(w http.ResponseWriter, r *http.Request) {
	var userData *account.UserData
	var err error
	if r.URL.Query().Get("fetch") == "true" {
		userData, err = s.backend(r.Context()).FetchUserData(r.Context())
	} else {
		userData, err = s.backend(r.Context()).UserData()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, userData)
}

// accountDevicesHandler handles GET /account/devices (list) and DELETE /account/devices/{deviceID} (remove).
func (s *localapi) accountDevicesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		resp, err := s.backend(r.Context()).RemoveDevice(r.Context(), r.PathValue("deviceID"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	devices, err := s.backend(r.Context()).UserDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

// accountSignupHandler handles POST /account/signup, /account/signup/confirm, and /account/signup/resend.
func (s *localapi) accountSignupHandler(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		var req EmailCodeRequest
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.backend(r.Context()).SignupEmailConfirmation(r.Context(), req.Email, req.Code); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	case "resend":
		var req EmailRequest
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.backend(r.Context()).SignupEmailResendCode(r.Context(), req.Email); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		var req EmailPasswordRequest
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		salt, resp, err := s.backend(r.Context()).SignUp(r.Context(), req.Email, req.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, SignupResponse{Salt: salt, Response: resp})
	}
}

// accountVerifyPasswordHandler handles POST /account/verify-password.
func (s *localapi) accountVerifyPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req EmailPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.backend(r.Context()).VerifyPassword(r.Context(), req.Email, req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// accountEmailHandler handles POST /account/email/{action} for start and complete.
func (s *localapi) accountEmailHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.PathValue("action") {
	case "start":
		var req ChangeEmailStartRequest
		if err = decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = s.backend(r.Context()).StartChangeEmail(r.Context(), req.NewEmail, req.Password)
	case "complete":
		var req ChangeEmailCompleteRequest
		if err = decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = s.backend(r.Context()).CompleteChangeEmail(r.Context(), req.NewEmail, req.Password, req.Code)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// accountRecoveryHandler handles POST /account/recovery/{action} for start, complete, and validate.
func (s *localapi) accountRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.PathValue("action") {
	case "start":
		var req EmailRequest
		if err = decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = s.backend(r.Context()).StartRecoveryByEmail(r.Context(), req.Email)
	case "complete":
		var req RecoveryCompleteRequest
		if err = decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = s.backend(r.Context()).CompleteRecoveryByEmail(r.Context(), req.Email, req.NewPassword, req.Code)
	case "validate":
		var req EmailCodeRequest
		if err = decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = s.backend(r.Context()).ValidateEmailRecoveryCode(r.Context(), req.Email, req.Code)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) accountDeleteHandler(w http.ResponseWriter, r *http.Request) {
	var req EmailPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userData, err := s.backend(r.Context()).DeleteAccount(r.Context(), req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, userData)
}

// accountOAuthHandler handles GET /account/oauth (login URL) and POST /account/oauth (callback).
func (s *localapi) accountOAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req OAuthTokenRequest
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		userData, err := s.backend(r.Context()).OAuthLoginCallback(r.Context(), req.OAuthToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, userData)
		return
	}
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		http.Error(w, "provider is required", http.StatusBadRequest)
		return
	}
	u, err := s.backend(r.Context()).OAuthLoginURL(r.Context(), provider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, URLResponse{URL: u})
}

func (s *localapi) accountOAuthDeviceLimitHandler(w http.ResponseWriter, r *http.Request) {
	var req OAuthTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.OAuthToken == "" {
		http.Error(w, "oAuthToken is required", http.StatusBadRequest)
		return
	}
	if err := s.backend(r.Context()).OAuthDeviceLimitCallback(r.Context(), req.OAuthToken); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, account.ErrInvalidToken) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) accountDataCapHandler(w http.ResponseWriter, r *http.Request) {
	info, err := s.backend(r.Context()).DataCapInfo(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *localapi) accountDataCapStreamHandler(w http.ResponseWriter, r *http.Request) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	ch := s.backend(r.Context()).DataCapUpdates()
	for {
		select {
		case info := <-ch:
			data, err := json.Marshal(info)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

///////////////////
// Subscriptions //
///////////////////

func (s *localapi) subscriptionActivationHandler(w http.ResponseWriter, r *http.Request) {
	var req ActivationRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.backend(r.Context()).ActivationCode(r.Context(), req.Email, req.ResellerCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *localapi) subscriptionStripeHandler(w http.ResponseWriter, r *http.Request) {
	var req StripeSubscriptionRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientSecret, err := s.backend(r.Context()).NewStripeSubscription(r.Context(), req.Email, req.PlanID, req.CouponCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, ClientSecretResponse{ClientSecret: clientSecret})
}

func (s *localapi) subscriptionPaymentRedirectHandler(w http.ResponseWriter, r *http.Request) {
	var req account.PaymentRedirectData
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := s.backend(r.Context()).PaymentRedirect(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, URLResponse{URL: u})
}

func (s *localapi) subscriptionReferralHandler(w http.ResponseWriter, r *http.Request) {
	var req CodeRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.backend(r.Context()).ReferralAttach(r.Context(), req.Code, req.Channel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *localapi) subscriptionBillingPortalHandler(w http.ResponseWriter, r *http.Request) {
	u, err := s.backend(r.Context()).StripeBillingPortalURL(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, URLResponse{URL: u})
}

func (s *localapi) subscriptionPaymentRedirectURLHandler(w http.ResponseWriter, r *http.Request) {
	var req account.PaymentRedirectData
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := s.backend(r.Context()).SubscriptionPaymentRedirectURL(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, URLResponse{URL: u})
}

func (s *localapi) subscriptionPlansHandler(w http.ResponseWriter, r *http.Request) {
	plans, err := s.backend(r.Context()).SubscriptionPlans(r.Context(), r.URL.Query().Get("channel"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, PlansResponse{Plans: plans})
}

func (s *localapi) subscriptionVerifyHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifySubscriptionRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.backend(r.Context()).VerifySubscription(r.Context(), req.Service, req.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, ResultResponse{Result: result})
}

func (s *localapi) subscriptionRestoreHandler(w http.ResponseWriter, r *http.Request) {
	var req RestoreSubscriptionRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.backend(r.Context()).RestoreSubscription(r.Context(), req.Service, req.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

///////////
// Issue //
///////////

func (s *localapi) issueReportHandler(w http.ResponseWriter, r *http.Request) {
	req, err := decodeIssueReport(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.backend(r.Context()).ReportIssue(r.Context(), req.IssueType, req.Description, req.Email, req.AdditionalAttachments, req.Attachments); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func decodeIssueReport(r *http.Request) (IssueReportRequest, error) {
	var req IssueReportRequest
	if err := decodeJSON(r, &req); err != nil {
		return req, err
	}
	if peer, ok := r.Context().Value(peerKey{}).(usr); ok && !peer.isAdmin {
		// An unprivileged caller cannot choose files for the service to read.
		req.AdditionalAttachments = nil
	}
	return req, nil
}

///////////
// Logs  //
///////////

func (s *localapi) logsStreamHandler(w http.ResponseWriter, r *http.Request) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	ch, unsub := rlog.Subscribe()
	defer unsub()
	for {
		select {
		case entry := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", entry)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

const maxHelperRelayRequest = 64 << 10

// helperRelayHandler relays one helper-invite request for the app. Its
// errors are fixed text: they reach logs and must not quote a body.
func (s *localapi) helperRelayHandler(w http.ResponseWriter, r *http.Request) {
	var req HelperRelayRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHelperRelayRequest)).Decode(&req); err != nil {
		http.Error(w, "bad helper relay request", http.StatusBadRequest)
		return
	}
	res, err := s.backend(r.Context()).HelperRelay(r.Context(), req.Op, req.Body)
	switch {
	case errors.Is(err, helper.ErrUnknownOp):
		http.Error(w, "unknown helper operation", http.StatusBadRequest)
	case err != nil:
		http.Error(w, "helper relay failed", http.StatusBadGateway)
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

const maxHelperPairingKeysRequest = 256 << 10

// helperPairingKeysHandler replaces the backend's helper pairing keys. Its
// error is fixed text: it reaches logs and must not quote a key or pairing ID.
func (s *localapi) helperPairingKeysHandler(w http.ResponseWriter, r *http.Request) {
	var req HelperPairingKeysRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHelperPairingKeysRequest)).Decode(&req); err != nil {
		http.Error(w, "bad helper pairing keys request", http.StatusBadRequest)
		return
	}
	s.backend(r.Context()).SetHelperPairingKeys(req.Keys)
	w.WriteHeader(http.StatusOK)
}

func (s *localapi) helperActivityHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.backend(r.Context()).HelperActivity())
}

func (s *localapi) helperLiveHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.backend(r.Context()).HelperLive())
}

func (s *localapi) helperPersonalProxiesHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.backend(r.Context()).PersonalProxyStatus())
}

func (s *localapi) helperPersonalProxyFallbackHandler(w http.ResponseWriter, r *http.Request) {
	flusher := sseWriter(w)
	if flusher == nil {
		return
	}
	ch := make(chan []byte, 16)
	sub := events.Subscribe(func(evt vpn.PersonalProxyFallbackEvent) {
		data, err := json.Marshal(evt)
		if err != nil {
			return
		}
		select {
		case ch <- data:
		default:
		}
	})
	defer sub.Unsubscribe()
	for {
		select {
		case data := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
