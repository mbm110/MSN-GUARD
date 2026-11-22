//go:build (!android && !ios && !darwin) || (darwin && standalone)

package ipc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getlantern/radiance/issue"
	rlog "github.com/getlantern/radiance/log"
)

// Client communicates with the IPC server over a local socket.
type Client struct {
	http *http.Client
}

// NewClient creates a new IPC client that communicates exclusively through the IPC server.
func NewClient() *Client {
	return newClient()
}

// Close releases resources held by the client, including any local backend.
func (c *Client) Close() {
	c.http.CloseIdleConnections()
}

// reportIssue hands the report to the daemon, which owns the logs and live backend state.
func (c *Client) reportIssue(ctx context.Context, issueType issue.IssueType, description, email string, additionalAttachments []string, attachments []*issue.Attachment) error {
	_, err := c.do(ctx, http.MethodPost, issueEndpoint,
		IssueReportRequest{
			IssueType:             issueType,
			Description:           description,
			Email:                 email,
			AdditionalAttachments: additionalAttachments,
			Attachments:           attachments,
		})
	return err
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

	resp, err := c.http.Do(req)
	if err != nil {
		if isConnectionError(err) {
			return nil, fmt.Errorf("ipc request %s %s: %w: %w", method, endpoint, ErrIPCNotRunning, err)
		}
		return nil, fmt.Errorf("ipc request %s %s: %w", method, endpoint, err)
	}
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

// TailLogs connects to the log stream endpoint and calls handler for each log
// entry received until ctx is cancelled or the connection is closed.
func (c *Client) TailLogs(ctx context.Context, handler func(rlog.LogEntry)) error {
	return c.sseStream(ctx, logsStreamEndpoint, func(data []byte) {
		handler(string(data))
	}, nil)
}

// sseStream connects to an SSE endpoint and calls handler for each event data line.
// Blocks until ctx is cancelled or the connection is closed. onOpen, if non-nil, is called once
// the server accepts the stream, before any event, with the time its response arrived.
func (c *Client) sseStream(ctx context.Context, endpoint string, handler func([]byte), onOpen func(time.Time)) error {
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
			data = strings.TrimSpace(data)
			if data != "" {
				// [vpn-state-trace] hop=sse_parsed — moment the client side
				// got a full SSE event from the named pipe. The gap to
				// ssehandler_flushed measures pipe-transit + bufio.Scanner
				// buffering on Windows.
				if endpoint == vpnStatusEventsEndpoint {
					slog.Info("[vpn-state-trace]", "hop", "sse_parsed", "data", string(data), "ts_ms", time.Now().UnixMilli())
				}
				handler([]byte(data))
			}
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("SSE %s: read: %w", endpoint, err)
	}
	return nil
}
