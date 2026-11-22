//go:build android || ios || (darwin && !standalone)

package ipc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	wire "github.com/getlantern/common/usermessage"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/issue"
	rlog "github.com/getlantern/radiance/log"
)

type Client struct {
	http      *http.Client
	localapi  *localapi
	ctx       context.Context
	opts      backend.Options
	localOnly bool // when true, serve all requests in-process; never attempt the IPC socket
	mu        sync.RWMutex
}

// NewClient creates an IPC client with an in-process backend fallback.
func NewClient(ctx context.Context, opts backend.Options) (*Client, error) {
	opts = cloneBackendOptions(opts)
	b, err := backend.NewLocalBackend(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("create local backend: %w", err)
	}
	b.Start()
	c := newClient()
	c.ctx = ctx
	c.opts = opts
	c.localapi = newLocalAPI(b, false)
	return c, nil
}

// NewRemoteClient creates a socket-only client that never starts or owns a backend.
// An unavailable IPC server produces ErrIPCNotRunning instead of a local fallback.
func NewRemoteClient() *Client {
	return newClient()
}

// NewLoopbackClient creates a Client that serves all requests in-process
// through the given LocalBackend without attempting IPC socket connections.
// The backend is NOT owned by this client — Close will not shut it down.
// Event streams are not consumed on a loopback client; their localOnly
// branches are defensive.
func NewLoopbackClient(b *backend.LocalBackend) *Client {
	c := newClient()
	c.localapi = newLocalAPI(b, false)
	c.localOnly = true
	return c
}

// Close releases resources held by the client, including any local backend.
func (c *Client) Close() {
	if c.localOnly {
		return
	}
	c.stopLocal()
	c.http.CloseIdleConnections()
}

func (c *Client) stopLocal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.localapi == nil {
		return
	}
	if be := c.localapi.setBackend(nil); be != nil {
		be.Close()
	}
}

// do executes an HTTP request with an optional JSON body and returns the raw response body. If
// body needs to be marshaled using sing/json, it should be pre-marshaled to []byte before passing
// to do. do returns an error if the response status is >= 400.
func (c *Client) do(ctx context.Context, method, endpoint string, body any) ([]byte, error) {
	bodyReader, err := marshalBody(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, apiURL+endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.localOnly {
		return c.doLocal(req)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if isConnectionError(err) {
			if c.localapi == nil {
				return nil, fmt.Errorf("ipc request %s %s: %w: %w", method, endpoint, ErrIPCNotRunning, err)
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if be := c.localapi.be.Load(); be == nil {
				opts := c.fallbackOptions()
				be, err = backend.NewLocalBackend(c.ctx, opts)
				if err != nil {
					return nil, fmt.Errorf("create local backend: %w", err)
				}
				be.Start()
				c.localapi.setBackend(be)
			}
			if br, ok := bodyReader.(*bytes.Reader); ok {
				br.Seek(0, io.SeekStart)
			}
			req, _ = http.NewRequestWithContext(ctx, method, apiURL+endpoint, bodyReader)
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			return c.doLocal(req)
		}
		return nil, fmt.Errorf("ipc request %s %s: %w", method, endpoint, err)
	}
	c.stopLocal() // IPC is reachable; shut down local backend if still running
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, &Error{
			Status:  resp.StatusCode,
			Message: strings.TrimSpace(string(respBody)),
		}
	}
	return respBody, nil
}

// fallbackOptions returns a copy of the client options with runtime settings refreshed for an in-process backend.
func (c *Client) fallbackOptions() backend.Options {
	opts := cloneBackendOptions(c.opts)
	opts.DataDir = settings.GetString(settings.DataPathKey)
	opts.LogDir = settings.GetString(settings.LogPathKey)
	opts.Locale = settings.GetString(settings.LocaleKey)
	opts.TimeZone = settings.GetString(settings.TimeZoneKey)
	opts.DeviceID = settings.GetString(settings.DeviceIDKey)
	opts.LogLevel = settings.GetString(settings.LogLevelKey)
	opts.TelemetryConsent = settings.GetBool(settings.TelemetryKey)
	return opts
}

// cloneBackendOptions copies mutable map and slice fields so changes to them do not affect opts.
func cloneBackendOptions(opts backend.Options) backend.Options {
	cloned := opts
	cloned.UserMessageCapabilities.Surfaces = append(
		[]wire.Surface(nil), opts.UserMessageCapabilities.Surfaces...,
	)
	cloned.UserMessageCapabilities.Actions = append(
		[]wire.ActionType(nil), opts.UserMessageCapabilities.Actions...,
	)
	if opts.EnvOverrides != nil {
		cloned.EnvOverrides = make(map[string]string, len(opts.EnvOverrides))
		for key, value := range opts.EnvOverrides {
			cloned.EnvOverrides[key] = value
		}
	}
	return cloned
}

// reportIssue assembles and sends the report in this process rather than over IPC.
//
// Building the archive reads logs into memory. On iOS the IPC peer can be the network extension,
// which the OS may kill for a footprint spike; the UI process has the roomier budget and can read
// the shared logs and settings without starting a backend.
func (c *Client) reportIssue(ctx context.Context, issueType issue.IssueType, description, email string, additionalAttachments []string, attachments []*issue.Attachment) error {
	if err := settings.Reload(); err != nil {
		slog.Warn("Reporting issue with possibly stale settings", "error", err)
	}

	var be *backend.LocalBackend
	c.mu.RLock()
	if c.localapi != nil {
		be = c.localapi.be.Load()
	}
	c.mu.RUnlock()
	return be.ReportIssue(ctx, issueType, description, email, additionalAttachments, attachments)
}

// doLocal serves the request through the given in-process handler.
func (c *Client) doLocal(req *http.Request) ([]byte, error) {
	rec := httptest.NewRecorder()
	c.localapi.ServeHTTP(rec, req)

	body := rec.Body.Bytes()
	if rec.Code >= 400 {
		return nil, &Error{
			Status:  rec.Code,
			Message: strings.TrimSpace(string(body)),
		}
	}
	return body, nil
}

// TailLogs connects to the log stream endpoint and calls handler for each log
// entry received until ctx is cancelled or the connection is closed.
func (c *Client) TailLogs(ctx context.Context, handler func(rlog.LogEntry)) error {
	merged := make(chan rlog.LogEntry, 64)

	// Always tail local logs.
	localCh, unsub := rlog.Subscribe()
	defer unsub()
	go func() {
		for {
			select {
			case entry := <-localCh:
				select {
				case merged <- entry:
				default:
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Tail server logs whenever the IPC server is reachable.
	go func() {
		for ctx.Err() == nil {
			c.sseStream(ctx, logsStreamEndpoint, func(data []byte) {
				select {
				case merged <- string(data):
				default:
				}
			}, nil)
			// Server unavailable or disconnected; wait before retrying.
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case entry := <-merged:
			handler(entry)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// sseStream connects to an SSE endpoint and calls handler for each event data line.
// Blocks until ctx is cancelled or the connection is closed. onOpen, if non-nil, is called once
// the server accepts the stream, before any event, with the time its response arrived.
func (c *Client) sseStream(ctx context.Context, endpoint string, handler func([]byte), onOpen func(time.Time)) error {
	if c.localOnly {
		return ErrIPCNotRunning
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+endpoint, nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.http.Do(req)
	if err != nil {
		if isConnectionError(err) {
			return fmt.Errorf("SSE connect %s: %w: %w", endpoint, ErrIPCNotRunning, err)
		}
		return fmt.Errorf("SSE connect %s: %w", endpoint, err)
	}
	responded := time.Now()
	c.stopLocal() // IPC is reachable; shut down local backend if still running
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	if onOpen != nil {
		onOpen(responded)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			handler([]byte(data))
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("SSE %s: read: %w", endpoint, err)
	}
	return nil
}
