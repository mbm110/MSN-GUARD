// Package usermessage retrieves and retains presentation-ready user messages.
package usermessage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	wire "github.com/getlantern/common/usermessage"
	"github.com/getlantern/kindling"

	"github.com/getlantern/radiance/common"
)

const maxResponseBytes = 32 * 1024

var errCredentialsUnavailable = errors.New("user-message credentials are unavailable")

// ClientContext is the authenticated and presentation context for one fetch.
type ClientContext struct {
	UserID     string
	ProToken   string
	Locale     string
	Platform   string
	AppVersion string
}

func (c ClientContext) valid() bool {
	userID, err := strconv.ParseInt(c.UserID, 10, 64)
	return err == nil && userID > 0 && strconv.FormatInt(userID, 10) == c.UserID &&
		c.ProToken != "" && len(c.ProToken) <= 4096 &&
		c.Locale != "" && c.Platform != "" && c.AppVersion != ""
}

// httpStatusError lets the polling service distinguish endpoint status
// failures from transport and decoding errors.
type httpStatusError struct {
	statusCode int
}

func (err *httpStatusError) Error() string {
	return fmt.Sprintf("unexpected status %d", err.statusCode)
}

// Fetcher resolves at most one message for a client context.
type Fetcher interface {
	Fetch(context.Context, ClientContext, []string) (wire.UserMessageResponse, error)
}

// HTTPFetcher implements Fetcher using Lantern Cloud's public endpoint.
type HTTPFetcher struct {
	client       *http.Client
	endpoint     string
	capabilities wire.ClientCapabilities
}

// NewHTTPFetcher creates a fetcher for endpoint.
func NewHTTPFetcher(
	client *http.Client,
	endpoint string,
	capabilities wire.ClientCapabilities,
) *HTTPFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	capabilities.Surfaces = append([]wire.Surface(nil), capabilities.Surfaces...)
	capabilities.Actions = append([]wire.ActionType(nil), capabilities.Actions...)
	return &HTTPFetcher{
		client:       client,
		endpoint:     endpoint,
		capabilities: capabilities,
	}
}

// Fetch returns the decoded response without applying presentation policy.
func (f *HTTPFetcher) Fetch(
	ctx context.Context,
	clientContext ClientContext,
	seenDisplayIDs []string,
) (wire.UserMessageResponse, error) {
	if !clientContext.valid() {
		return wire.UserMessageResponse{}, errCredentialsUnavailable
	}
	request := wire.UserMessageRequest{
		Locale:         clientContext.Locale,
		Platform:       clientContext.Platform,
		AppVersion:     clientContext.AppVersion,
		Capabilities:   f.capabilities,
		SeenDisplayIDs: seenDisplayIDs,
	}
	if err := request.Validate(); err != nil {
		return wire.UserMessageResponse{}, fmt.Errorf("validate user-message request: %w", err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return wire.UserMessageResponse{}, fmt.Errorf("marshal user-message request: %w", err)
	}
	req, err := common.NewRequestWithHeaders(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return wire.UserMessageResponse{}, fmt.Errorf("create user-message request: %w", err)
	}
	req.Header.Set(common.ContentTypeHeader, "application/json")
	req.Header.Set(common.AcceptHeader, "application/json")
	req.Header.Set(common.UserIDHeader, clientContext.UserID)
	req.Header.Set(common.ProTokenHeader, clientContext.ProToken)
	req.Header.Set(common.PlatformHeader, clientContext.Platform)
	req.Header.Set(common.AppVersionHeader, clientContext.AppVersion)
	req.Header.Set(common.VersionHeader, clientContext.AppVersion)
	req.Header.Set(common.AppNameHeader, common.Name)
	req.Header.Set(kindling.IdempotentHeader, "1")

	resp, err := f.client.Do(req)
	if err != nil {
		return wire.UserMessageResponse{}, fmt.Errorf("fetch user message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wire.UserMessageResponse{}, fmt.Errorf(
			"fetch user message: %w", &httpStatusError{statusCode: resp.StatusCode},
		)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return wire.UserMessageResponse{}, fmt.Errorf("read user-message response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return wire.UserMessageResponse{}, errors.New("user-message response exceeds size limit")
	}
	var response wire.UserMessageResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return wire.UserMessageResponse{}, fmt.Errorf("decode user-message response: %w", err)
	}
	return response, nil
}

// Endpoint returns the public user-message endpoint under baseURL.
func Endpoint(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + "/user-messages"
}
