// Package servers provides management of server configurations, such as option.Endpoints and
// option.Outbounds,and integration with remote server managers for adding, inviting, and revoking
// private servers
package servers

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	box "github.com/getlantern/lantern-box"
	lbA "github.com/getlantern/lantern-box/adapter"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/hashicorp/go-retryablehttp"
	"go.opentelemetry.io/otel"

	C "github.com/getlantern/common"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/internal/hostaccess"
	"github.com/getlantern/radiance/internal/logsafe"
	"github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/traces"

	"github.com/getlantern/pluriconfig"
	"github.com/getlantern/pluriconfig/model"
	_ "github.com/getlantern/pluriconfig/provider/singbox"
	_ "github.com/getlantern/pluriconfig/provider/url"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// Thresholds for flagging slow operations on the servers Manager.
//
// These instrument the lock/marshal/disk path. saveServers must not hold the
// write lock across disk I/O or it starves cgo-callback readers in
// AllServers/GetServerByTag.
const (
	// saveSlowThreshold: log a WARN with per-phase breakdown if saveServers
	// exceeds this. Normal operation is well under 100ms.
	saveSlowThreshold = 2 * time.Second
	// saveCriticalThreshold: additionally dump all goroutine stacks if
	// saveServers exceeds this. Useful for forensics when something really
	// pathological is happening (e.g., fsync stall, GC back-pressure).
	saveCriticalThreshold = 15 * time.Second

	// readerWaitThreshold: log a WARN with a goroutine stack dump if a
	// reader (AllServers / GetServerByTag) waits longer than this to
	// acquire the RLock. Direct evidence of reader starvation.
	readerWaitThreshold = 1 * time.Second
)

// dumpAllGoroutines returns a formatted string of all current goroutine
// stacks. Used when a lock wait or save duration is pathologically long —
// lets us see what's actually holding the lock or hogging the CPU at the
// time. Callers should gate this behind a rare threshold since it stops
// the world briefly.
func dumpAllGoroutines() string {
	buf := make([]byte, 1<<20) // 1 MiB is enough for most crashes
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

const tracerName = "github.com/getlantern/radiance/servers"

// ServerCredentials holds the access token and invite status for a private server.
type ServerCredentials struct {
	AccessToken string `json:"access_token,omitempty"`
	Port        int    `json:"port,omitempty"`
	IsJoined    bool   `json:"is_joined,omitempty"` // whether the user has joined the server (i.e. accepted the invite)
}

type Server struct {
	Tag              string             `json:"tag"`
	Type             string             `json:"type"`
	IsLantern        bool               `json:"isLantern"`
	Options          any                `json:"options"`
	Location         C.ServerLocation   `json:"location,omitempty"`
	Credentials      *ServerCredentials `json:"credentials,omitempty"`
	SelectionHistory *SelectionHistory  `json:"selection_history,omitempty"`
}

// serverJSON is the on-wire representation of a Server. The Options field is split into
// explicit Outbound/Endpoint fields so that the sing-box context-aware JSON marshaler can
// properly serialize/deserialize the typed options (e.g. SamizdatOutboundOptions).
type serverJSON struct {
	Tag              string             `json:"tag"`
	Type             string             `json:"type"`
	IsLantern        bool               `json:"isLantern"`
	Outbound         *option.Outbound   `json:"outbound,omitempty"`
	Endpoint         *option.Endpoint   `json:"endpoint,omitempty"`
	Location         C.ServerLocation   `json:"location,omitempty"`
	Credentials      *ServerCredentials `json:"credentials,omitempty"`
	SelectionHistory *SelectionHistory  `json:"selection_history,omitempty"`
}

func (s Server) MarshalJSON() ([]byte, error) {
	sj := serverJSON{
		Tag:              s.Tag,
		Type:             s.Type,
		IsLantern:        s.IsLantern,
		Location:         s.Location,
		Credentials:      s.Credentials,
		SelectionHistory: s.SelectionHistory,
	}
	switch opts := s.Options.(type) {
	case option.Outbound:
		sj.Outbound = &opts
	case option.Endpoint:
		sj.Endpoint = &opts
	}
	return json.MarshalContext(box.Context(context.Background()), sj)
}

func (s *Server) UnmarshalJSON(data []byte) error {
	sj, err := json.UnmarshalExtendedContext[serverJSON](box.Context(context.Background()), data)
	if err != nil {
		return err
	}
	s.Tag = sj.Tag
	s.Type = sj.Type
	s.IsLantern = sj.IsLantern
	s.Location = sj.Location
	s.Credentials = sj.Credentials
	s.SelectionHistory = sj.SelectionHistory
	if sj.Outbound != nil {
		s.Options = *sj.Outbound
	} else if sj.Endpoint != nil {
		s.Options = *sj.Endpoint
	}
	return nil
}

func (s *Server) Clone() *Server {
	cp := *s
	if s.Credentials != nil {
		c := *s.Credentials
		cp.Credentials = &c
	}
	if cp.SelectionHistory != nil {
		h := *cp.SelectionHistory
		if len(h.UserFailures) > 0 {
			h.UserFailures = slices.Clone(h.UserFailures)
		}
		cp.SelectionHistory = &h
	}
	return &cp
}

// CheckHostAccess returns an error wrapping [hostaccess.ErrDenied] if the
// server's options would let it act on the host beyond making network
// connections.
func (s *Server) CheckHostAccess() error {
	switch opts := s.Options.(type) {
	case option.Outbound:
		return hostaccess.CheckOutbound(opts)
	case option.Endpoint:
		return hostaccess.CheckEndpoint(opts)
	}
	return nil
}

// ServerList is a batch of servers with optional URL overrides for bulk operations.
type ServerList struct {
	Servers      []*Server         `json:"servers"`
	URLOverrides map[string]string `json:"url_overrides,omitempty"`
	// AutoSelectOptions, when set, carries a Lantern config's auto-select
	// options, and the tunnel applies their probe timeouts. Nil, as on
	// user-added servers, leaves the current probe timeouts in place.
	AutoSelectOptions *lbO.MutableAutoSelectOutboundOptions `json:"auto_select_options,omitempty"`
}

func (sl ServerList) Tags() []string {
	tags := make([]string, 0, len(sl.Servers))
	for _, s := range sl.Servers {
		tags = append(tags, s.Tag)
	}
	return tags
}

func (sl ServerList) Outbounds() []option.Outbound {
	var out []option.Outbound
	for _, s := range sl.Servers {
		if o, ok := s.Options.(option.Outbound); ok {
			out = append(out, o)
		}
	}
	return out
}

func (sl ServerList) Endpoints() []option.Endpoint {
	var eps []option.Endpoint
	for _, s := range sl.Servers {
		if e, ok := s.Options.(option.Endpoint); ok {
			eps = append(eps, e)
		}
	}
	return eps
}

// Manager manages server configurations, including endpoints and outbounds.
type Manager struct {
	access  sync.RWMutex
	servers map[string]*Server // tag -> Server

	// saveMu serializes disk writes in saveServers. This is separate from access
	// so that readers (e.g. AllServers) aren't blocked during disk I/O — only
	// during the brief JSON marshalling step.
	saveMu sync.Mutex

	logger      *slog.Logger
	serversFile string
	httpClient  *http.Client

	// regCtx holds the sing-box registries and should not be mutated after
	// initialization. It is used for JSON marshalling/unmarshalling of server
	// options. Read it through regContext, which supplies a fallback when a
	// Manager is built without NewManager.
	regCtx context.Context
}

// NewManager creates a new Manager instance, loading server options from disk.
//
// The returned Manager is always usable, even when the error is non-nil:
// loadServers salvages every parseable server, so a partial load (e.g. an
// on-disk entry this build can't decode after a downgrade) yields a working
// Manager plus an error describing what was dropped.
func NewManager(dataPath string, logger *slog.Logger) (*Manager, error) {
	mgr := &Manager{
		servers:     make(map[string]*Server),
		serversFile: filepath.Join(dataPath, internal.ServersFileName),
		logger:      logger,
		// Use the bypass proxy dialer to route requests outside the VPN tunnel.
		// This client is only used to access private servers the user has created.
		httpClient: retryableHTTPClient(logger).StandardClient(),
		regCtx:     box.Context(context.Background()),
	}

	mgr.logger.Debug("Loading servers", "file", mgr.serversFile)
	if err := mgr.loadServers(); err != nil {
		return mgr, fmt.Errorf("failed to load servers from file: %w", err)
	}
	mgr.logger.Log(nil, log.LevelTrace, "Loaded servers")
	return mgr, nil
}

// regContext returns the sing-box registry context used to (un)marshal server
// options. It falls back to a fresh registry context when regCtx is unset, so
// a Manager built without NewManager (e.g. in tests) still (un)marshals rather
// than dereferencing a nil context.
func (m *Manager) regContext() context.Context {
	if m.regCtx != nil {
		return m.regCtx
	}
	return box.Context(context.Background())
}

func retryableHTTPClient(logger *slog.Logger) *retryablehttp.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           bypass.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := retryablehttp.NewClient()
	client.HTTPClient = &http.Client{
		Transport: transport,
	}

	client.RetryMax = 10
	client.RetryWaitMin = 1 * time.Second
	client.RetryWaitMax = 10 * time.Second
	client.Logger = queryStrippingLogger{logger}
	return client
}

// queryStrippingLogger strips URL queries from the strings and errors retryablehttp
// logs, whatever logger it wraps: private-server request URLs carry the access token in
// the query, and retryablehttp masks only userinfo passwords.
type queryStrippingLogger struct {
	logger *slog.Logger
}

func (l queryStrippingLogger) Error(msg string, keysAndValues ...any) {
	l.logger.Error(msg, stripQueries(keysAndValues)...)
}

func (l queryStrippingLogger) Warn(msg string, keysAndValues ...any) {
	l.logger.Warn(msg, stripQueries(keysAndValues)...)
}

func (l queryStrippingLogger) Info(msg string, keysAndValues ...any) {
	l.logger.Info(msg, stripQueries(keysAndValues)...)
}

func (l queryStrippingLogger) Debug(msg string, keysAndValues ...any) {
	l.logger.Debug(msg, stripQueries(keysAndValues)...)
}

func stripQueries(values []any) []any {
	stripped := make([]any, len(values))
	for i, value := range values {
		switch v := value.(type) {
		case string:
			stripped[i] = logsafe.StripQueries(v)
		case error:
			stripped[i] = logsafe.StripQueries(v.Error())
		default:
			stripped[i] = value
		}
	}
	return stripped
}

// AllServers returns a deep-copied slice of all servers.
func (m *Manager) AllServers() []*Server {
	start := time.Now()
	m.access.RLock()
	wait := time.Since(start)
	defer m.access.RUnlock()
	warnIfReaderStarved("AllServers", wait)
	result := make([]*Server, 0, len(m.servers))
	for _, srv := range m.servers {
		result = append(result, srv.Clone())
	}
	return result
}

// SelectionHistory is the on-disk shape for a server's selection history.
type SelectionHistory = lbA.TagHistory

// UpdateSelectionHistory updates the selection history for servers
// matching the provided tags and persists the change to disk.
func (m *Manager) UpdateSelectionHistory(results map[string]SelectionHistory) error {
	func() {
		m.access.Lock()
		defer m.access.Unlock()
		for tag, result := range results {
			if srv, exists := m.servers[tag]; exists {
				r := result
				srv.SelectionHistory = &r
			}
		}
	}()
	return m.saveServers()
}

// GetServerByTag returns the server configuration for a given tag and a boolean indicating whether
// the server was found.
// HasOptions reports whether the manager holds a server tagged srv.Tag with
// the options AddServers would store for srv.
func (m *Manager) HasOptions(srv *Server) bool {
	stored, exists := m.GetServerByTag(srv.Tag)
	if !exists {
		return false
	}
	have, err := m.marshalOptions(stored.Options)
	if err != nil {
		return false
	}
	want, err := m.marshalOptions(srv.WithTLSVerification().Options)
	return err == nil && bytes.Equal(have, want)
}

// marshalOptions encodes server options. The sing-box encoder writes an
// outbound's or endpoint's typed options only through a pointer to it.
func (m *Manager) marshalOptions(opts any) ([]byte, error) {
	switch o := opts.(type) {
	case option.Outbound:
		opts = &o
	case option.Endpoint:
		opts = &o
	}
	return json.MarshalContext(m.regContext(), opts)
}

func (m *Manager) GetServerByTag(tag string) (*Server, bool) {
	start := time.Now()
	m.access.RLock()
	wait := time.Since(start)
	defer m.access.RUnlock()
	warnIfReaderStarved("GetServerByTag", wait)
	s, exists := m.servers[tag]
	if !exists {
		return nil, false
	}
	return s.Clone(), true
}

// warnIfReaderStarved logs a WARN with a goroutine stack dump when a reader
// waited too long to acquire the RLock — direct evidence of lock contention
// or writer starvation. Stack dump lets us see what's holding things up.
func warnIfReaderStarved(caller string, wait time.Duration) {
	if wait < readerWaitThreshold {
		return
	}
	slog.Warn("servers.Manager reader RLock wait exceeded threshold",
		"caller", caller,
		"wait", wait,
		"goroutines", dumpAllGoroutines(),
	)
}

// AddServers adds new servers. If force is true, it will overwrite any
// existing servers with the same tags. If force is false, it returns an error
// if any of the tags already exist. If a server fails [Server.CheckHostAccess]
// or a user server fails [Server.CheckTLSIdentity], none are added. A user
// server's embedded outbound or endpoint tag is set to its tag in list itself,
// so a caller that passes list on to the tunnel uses the same tag.
func (m *Manager) AddServers(list ServerList, force bool) error {
	if len(list.Servers) == 0 {
		return nil
	}
	for _, srv := range list.Servers {
		normalizeUserTag(srv)
		if err := checkUserTag(srv); err != nil {
			return err
		}
		if err := srv.CheckHostAccess(); err != nil {
			return fmt.Errorf("server %q: %w", srv.Tag, err)
		}
		if !srv.IsLantern {
			if err := srv.CheckTLSIdentity(); err != nil {
				return fmt.Errorf("server %q: %w", srv.Tag, err)
			}
		}
	}

	// Perform the in-memory mutation under the write lock, then release it
	// before saving to disk (saveServers acquires its own locks). Scoped
	// in a closure so defer Unlock is robust against future early returns.
	if err := func() error {
		m.access.Lock()
		defer m.access.Unlock()
		if !force {
			for _, srv := range list.Servers {
				if _, exists := m.servers[srv.Tag]; exists {
					return fmt.Errorf("server %q already exists", srv.Tag)
				}
			}
		}
		for _, srv := range list.Servers {
			m.servers[srv.Tag] = srv.WithTLSVerification()
		}
		return nil
	}(); err != nil {
		return err
	}
	// saveServers acquires its own locks; don't hold the write lock across it.
	return m.saveServers()
}

// RemoveServer removes a server config by its tag.
func (m *Manager) RemoveServer(tag string) error {
	_, err := m.RemoveServers([]string{tag})
	return err
}

// RemoveServers removes multiple server configs by their tags and returns the
// removed servers. They are removed in memory before the save, so a failed save
// returns them with its error: they are gone until the next successful save.
func (m *Manager) RemoveServers(tags []string) ([]*Server, error) {
	// Perform the in-memory mutation under the write lock, then release it
	// before saving to disk (saveServers acquires its own locks). Scoped in
	// a closure so defer Unlock is robust against future early returns.
	removed := func() []*Server {
		m.access.Lock()
		defer m.access.Unlock()
		r := make([]*Server, 0, len(tags))
		for _, tag := range tags {
			if srv, exists := m.servers[tag]; exists {
				r = append(r, srv)
				delete(m.servers, tag)
			}
		}
		return r
	}()
	// saveServers acquires its own locks; don't hold the write lock across it.
	if err := m.saveServers(); err != nil {
		return removed, fmt.Errorf("failed to save servers: %w", err)
	}
	return removed, nil
}

// saveServers marshals the current server state to JSON and writes it to disk.
//
// The access write lock is NOT held across this function; only a brief RLock
// around marshalling. saveMu serializes the full marshal+write sequence so
// concurrent callers can't reorder and overwrite a newer snapshot with an
// older one. Readers (e.g. AllServers) are not blocked by the disk write —
// only by the brief marshal window.
//
// Each phase (saveMu wait, RLock+marshal, disk write) is timed so we can
// root-cause any future slow case.
func (m *Manager) saveServers() error {
	start := time.Now()

	// Hold saveMu across the whole marshal+write so two concurrent saves
	// can't write out-of-order snapshots. (Marshal(A), Marshal(B), Write(B),
	// Write(A) would leave stale data on disk.)
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	saveMuWait := time.Since(start)

	marshalStart := time.Now()
	m.access.RLock()
	rlockWait := time.Since(marshalStart)
	servers := make([]*Server, 0, len(m.servers))
	for _, srv := range m.servers {
		servers = append(servers, srv)
	}
	buf, err := json.MarshalContext(m.regContext(), servers)
	m.access.RUnlock()
	marshalDur := time.Since(marshalStart) - rlockWait
	if err != nil {
		return fmt.Errorf("marshal servers: %w", err)
	}

	writeStart := time.Now()
	werr := atomicfile.WriteFile(m.serversFile, buf, fileperm.File)
	writeDur := time.Since(writeStart)

	total := time.Since(start)
	slog.Log(nil, log.LevelTrace, "saveServers timing",
		"file", m.serversFile,
		"size", len(buf),
		"total_ms", total.Milliseconds(),
		"save_mu_wait_ms", saveMuWait.Milliseconds(),
		"rlock_wait_ms", rlockWait.Milliseconds(),
		"marshal_ms", marshalDur.Milliseconds(),
		"write_ms", writeDur.Milliseconds(),
	)

	switch {
	case total >= saveCriticalThreshold:
		slog.Warn("saveServers critically slow — dumping all goroutines",
			"total", total,
			"save_mu_wait", saveMuWait,
			"rlock_wait", rlockWait,
			"marshal", marshalDur,
			"write", writeDur,
			"size", len(buf),
			"goroutines", dumpAllGoroutines(),
		)
	case total >= saveSlowThreshold:
		slog.Warn("saveServers slow",
			"total", total,
			"save_mu_wait", saveMuWait,
			"rlock_wait", rlockWait,
			"marshal", marshalDur,
			"write", writeDur,
			"size", len(buf),
		)
	}
	return werr
}

const (
	modeLantern = "lantern"
	modeUser    = "user"
)

// loadServers reads servers.json into the in-memory map, salvaging every
// parseable, allowed entry. A single unparseable server (e.g. an outbound type
// or option field this build's sing-box doesn't recognize after a version
// downgrade) or one denied by [Server.CheckHostAccess] is skipped rather than
// discarding the whole file.
//
// It returns a non-nil error enumerating any skipped entries (or a wholly
// unparseable file); the in-memory state is still valid when it does.
func (m *Manager) loadServers() error {
	rawServersFile, err := atomicfile.ReadFile(m.serversFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil // file doesn't exist
	}
	if err != nil {
		return fmt.Errorf("read servers file %q: %w", m.serversFile, err)
	}
	rawServersFile = bytes.TrimSpace(rawServersFile)
	if len(rawServersFile) == 0 {
		return nil
	}

	if rawServersFile[0] == '[' {
		return m.loadServerList(rawServersFile)
	}

	return m.loadOldFormat(rawServersFile)
}

// loadServerList handles the current array-based on-disk format and salvages
// every entry that can still be decoded by this build and passes
// [Server.CheckHostAccess].
func (m *Manager) loadServerList(buf []byte) error {
	var rawServers []stdjson.RawMessage
	if err := stdjson.Unmarshal(buf, &rawServers); err != nil {
		m.quarantineInvalidServers(buf)
		return fmt.Errorf("servers file is not a valid JSON array: %w", err)
	}

	var skippedErrors []error
	for _, rawServer := range rawServers {
		srv := new(Server)
		if err := srv.UnmarshalJSON(rawServer); err != nil {
			skippedErrors = append(skippedErrors, fmt.Errorf("server %q: %w", serverTag(rawServer), err))
			continue
		}
		if err := srv.CheckHostAccess(); err != nil {
			skippedErrors = append(skippedErrors, fmt.Errorf("server %q: %w", srv.Tag, err))
			continue
		}
		m.servers[srv.Tag] = srv.WithTLSVerification()
	}

	if len(skippedErrors) > 0 {
		m.quarantineInvalidServers(buf)
		return fmt.Errorf("skipped %d of %d server(s): %w",
			len(skippedErrors), len(rawServers), errors.Join(skippedErrors...))
	}

	return nil
}

// loadOldFormat loads the legacy map layout and saves it in the current format.
// Decode failures quarantine the file without loading entries. Entries denied
// by [Server.CheckHostAccess] are skipped and reported as errors after migration,
// and the original file is quarantined.
//
// TODO: remove once the legacy map layout no longer appears on disk in the field.
func (m *Manager) loadOldFormat(buf []byte) error {
	type oldOptions struct {
		Outbounds   []option.Outbound            `json:"outbounds,omitempty"`
		Endpoints   []option.Endpoint            `json:"endpoints,omitempty"`
		Locations   map[string]C.ServerLocation  `json:"locations,omitempty"`
		Credentials map[string]ServerCredentials `json:"credentials,omitempty"`
	}
	old, err := json.UnmarshalExtendedContext[map[string]oldOptions](m.regContext(), buf)
	if err != nil {
		m.quarantineInvalidServers(buf)
		return fmt.Errorf("unmarshal legacy server options: %w", err)
	}
	var deniedErrors []error
	add := func(srv *Server) {
		if err := srv.CheckHostAccess(); err != nil {
			deniedErrors = append(deniedErrors, fmt.Errorf("server %q: %w", srv.Tag, err))
			return
		}
		m.servers[srv.Tag] = srv.WithTLSVerification()
	}
	for group, opts := range old {
		isLantern := group == modeLantern
		for _, out := range opts.Outbounds {
			srv := &Server{
				Tag: out.Tag, Type: out.Type, IsLantern: isLantern,
				Options: out, Location: opts.Locations[out.Tag],
			}
			if creds, ok := opts.Credentials[out.Tag]; ok {
				srv.Credentials = &creds
			}
			add(srv)
		}
		for _, ep := range opts.Endpoints {
			srv := &Server{
				Tag: ep.Tag, Type: ep.Type, IsLantern: isLantern,
				Options: ep, Location: opts.Locations[ep.Tag],
			}
			if creds, ok := opts.Credentials[ep.Tag]; ok {
				srv.Credentials = &creds
			}
			add(srv)
		}
	}
	if len(deniedErrors) > 0 {
		m.quarantineInvalidServers(buf)
	}
	if err := m.saveServers(); err != nil {
		return fmt.Errorf("re-saving migrated servers in new format: %w", err)
	}
	if len(deniedErrors) > 0 {
		return fmt.Errorf("skipped %d server(s): %w", len(deniedErrors), errors.Join(deniedErrors...))
	}
	return nil
}

// serverTag extracts just the tag from a raw server entry to label the
// skipped-entry error when the full entry failed to parse. Returns
// "<unknown>" if even the tag is unreadable.
func serverTag(raw []byte) string {
	var tag struct {
		Tag string `json:"tag"`
	}
	_ = stdjson.Unmarshal(raw, &tag)
	if tag.Tag == "" {
		return "<unknown>"
	}
	return tag.Tag
}

// quarantineInvalidServers copies the unparseable servers file aside for
// diagnostics. servers.json is intentionally left in place so entries skipped
// by this build remain available to a later re-upgrade.
func (m *Manager) quarantineInvalidServers(buf []byte) {
	invalidPath := filepath.Join(filepath.Dir(m.serversFile), internal.ServersInvalidFileName)
	if err := atomicfile.WriteFile(invalidPath, buf, fileperm.File); err != nil {
		m.logger.Error("Writing invalid servers copy", "path", invalidPath, "error", err)
		return
	}
	m.logger.Warn("Preserved unparseable servers file for diagnostics", "path", invalidPath)
}

// Lantern Server Manager Integration

// AddPrivateServer fetches VPN connection info from a remote server manager and adds it as a server.
func (m *Manager) AddPrivateServer(tag, ip string, port int, accessToken string, loc C.ServerLocation, joined bool) error {
	if err := checkUserTag(&Server{Tag: tag}); err != nil {
		return err
	}
	resp, err := m.privateServerRequest(http.MethodGet, ip, port, "/api/v1/connect-config", accessToken)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to get connect config, unexpected status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	type remoteConfig struct {
		Outbounds []option.Outbound `json:"outbounds,omitempty"`
		Endpoints []option.Endpoint `json:"endpoints,omitempty"`
	}
	cfg, err := json.UnmarshalExtendedContext[remoteConfig](m.regContext(), body)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(cfg.Outbounds) == 0 {
		if len(cfg.Endpoints) == 0 {
			return fmt.Errorf("no endpoints or outbounds in response")
		}
		return fmt.Errorf("endpoints-only private server responses are not supported")
	}
	if len(cfg.Endpoints) > 0 {
		m.logger.Warn("Ignoring endpoints in private server response", "tag", tag, "endpoints", len(cfg.Endpoints))
	}

	cfg.Outbounds[0].Tag = tag
	srv := &Server{
		Tag:       tag,
		Type:      cfg.Outbounds[0].Type,
		IsLantern: false,
		Options:   cfg.Outbounds[0],
		Location:  loc,
		Credentials: &ServerCredentials{
			AccessToken: accessToken, Port: port, IsJoined: joined,
		},
	}
	slog.Info("Adding private server from remote manager", "tag", tag, "country", loc.CountryCode, "is_joined", joined)
	list := ServerList{Servers: []*Server{srv}}
	return m.AddServers(list, false)
}

// InviteToPrivateServer invites another user to the server manager instance and returns a connection
// token. The server must be added to the user's servers first.
func (m *Manager) InviteToPrivateServer(ip string, port int, accessToken string, inviteName string) (string, error) {
	resp, err := m.privateServerRequest(http.MethodGet, ip, port, "/api/v1/share-link/"+inviteName, accessToken)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get connect config, invalid status code: %d", resp.StatusCode)
	}
	type tokenResp struct {
		Token string
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var cs tokenResp
	if err = json.Unmarshal(body, &cs); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return cs.Token, nil
}

// RevokePrivateServerInvite will revoke an invite to the server manager instance. The server must
// be added to the user's servers first.
func (m *Manager) RevokePrivateServerInvite(ip string, port int, accessToken string, inviteName string) error {
	resp, err := m.privateServerRequest(http.MethodPost, ip, port, "/api/v1/revoke/"+inviteName, accessToken)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to revoke invite, invalid status code: %d", resp.StatusCode)
	}
	return nil
}

// redactError returns an error carrying err's message with URL query components
// removed. The result does not wrap err, whose chain may still carry the access
// token.
func redactError(err error) error {
	return errors.New(logsafe.StripQueries(err.Error()))
}

// privateServerRequest sends a bodyless request to the server manager at
// ip:port. Returned errors omit the access token.
func (m *Manager) privateServerRequest(method, ip string, port int, path, accessToken string) (*http.Response, error) {
	u := &url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(ip, strconv.Itoa(port)),
		Path:     path,
		RawQuery: url.Values{"token": {accessToken}}.Encode(),
	}
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", redactError(err))
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", redactError(err))
	}
	return resp, nil
}

type serverConfig struct {
	Outbounds []option.Outbound `json:"outbounds,omitempty"`
	Endpoints []option.Endpoint `json:"endpoints,omitempty"`
}

// AddServersByJSON adds any outbounds and endpoints defined in the provided sing-box JSON config.
func (m *Manager) AddServersByJSON(ctx context.Context, config []byte) (*ServerList, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "Manager.AddServerBySingboxJSON")
	defer span.End()
	cfg, err := json.UnmarshalExtendedContext[serverConfig](m.regContext(), config)
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("failed to parse config: %w", err))
	}
	return m.addServerConfig(ctx, cfg)
}

func (m *Manager) addServerConfig(ctx context.Context, cfg serverConfig) (*ServerList, error) {
	if len(cfg.Endpoints) == 0 && len(cfg.Outbounds) == 0 {
		return nil, traces.RecordError(ctx, fmt.Errorf("no endpoints or outbounds found in the provided configuration"))
	}
	servers := make([]*Server, 0, len(cfg.Outbounds)+len(cfg.Endpoints))
	for _, out := range cfg.Outbounds {
		if out.Tag == "" {
			return nil, traces.RecordError(ctx, fmt.Errorf("outbound missing tag"))
		}
		servers = append(servers, &Server{Tag: out.Tag, Type: out.Type, Options: out})
	}
	for _, ep := range cfg.Endpoints {
		if ep.Tag == "" {
			return nil, traces.RecordError(ctx, fmt.Errorf("endpoint missing tag"))
		}
		servers = append(servers, &Server{Tag: ep.Tag, Type: ep.Type, Options: ep})
	}
	list := ServerList{Servers: servers}
	if err := m.AddServers(list, false); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("failed to add servers: %w", err))
	}
	for i, server := range list.Servers {
		list.Servers[i] = server.WithTLSVerification()
	}
	return &list, nil
}

// AddServersByURL imports server URLs; the legacy certificate-bypass flag is ignored.
func (m *Manager) AddServersByURL(ctx context.Context, urls []string, _ bool) (*ServerList, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "Manager.AddServerByURLs")
	defer span.End()
	urlProvider, loaded := pluriconfig.GetProvider(string(model.ProviderURL))
	if !loaded {
		return nil, traces.RecordError(ctx, fmt.Errorf("URL config provider not loaded"))
	}
	cfg, err := urlProvider.Parse(ctx, []byte(strings.Join(urls, "\n")))
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("failed to parse URLs: %w", err))
	}
	cfgURLs, ok := cfg.Options.([]url.URL)
	if !ok || len(cfgURLs) == 0 {
		return nil, traces.RecordError(ctx, fmt.Errorf("no valid URLs found in the provided configuration"))
	}

	bypass := make([]bool, len(cfgURLs))
	for i, u := range cfgURLs {
		bypass[i], err = urlRequestsTLSBypass(u)
		if err != nil {
			return nil, traces.RecordError(ctx, fmt.Errorf("URL %d: %w", i+1, err))
		}
	}

	singBoxProvider, loaded := pluriconfig.GetProvider(string(model.ProviderSingBox))
	if !loaded {
		return nil, traces.RecordError(ctx, fmt.Errorf("singbox config provider not loaded"))
	}
	singBoxCfg, err := singBoxProvider.Serialize(ctx, cfg)
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("failed to serialize sing-box config: %w", err))
	}
	options, err := json.UnmarshalExtendedContext[serverConfig](m.regContext(), singBoxCfg)
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("failed to parse converted config: %w", err))
	}
	if len(options.Outbounds) != len(cfgURLs) || len(options.Endpoints) != 0 {
		return nil, traces.RecordError(ctx, errors.New("URL conversion produced an unexpected server count"))
	}
	for i, insecure := range bypass {
		if !insecure {
			continue
		}
		wrapper, ok := options.Outbounds[i].Options.(option.OutboundTLSOptionsWrapper)
		if !ok || wrapper.TakeOutboundTLSOptions() == nil || !wrapper.TakeOutboundTLSOptions().Enabled {
			return nil, traces.RecordError(ctx, fmt.Errorf("URL %d: %w", i+1, errTLSIdentityRequired))
		}
		// Preserve the bypass request even when a URL parser drops the flag.
		wrapper.TakeOutboundTLSOptions().Insecure = true
	}
	list, err := m.addServerConfig(ctx, options)
	if err != nil {
		return nil, err
	}
	m.logger.Info("Added servers based on URLs", "serverCount", len(cfgURLs))
	return list, nil
}
