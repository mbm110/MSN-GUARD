// Package account provides a client for communicating with the account server to perform operations
// such as user authentication, subscription management, and account information retrieval.
package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/internal/logsafe"
)

const tracerName = "github.com/getlantern/radiance/account"

// Client is an account client that communicates with the account server to perform operations such as
// user authentication, subscription management, and account information retrieval.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	// proURL and authURL override the default server URLs. Used for testing.
	proURL  string
	authURL string

	salt     []byte
	saltPath string
	mu       sync.RWMutex
}

// NewClient returns a Client that caches its salt under dataDir. A nil logger
// uses [slog.Default].
func NewClient(httpClient *http.Client, dataDir string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	path := filepath.Join(dataDir, saltFileName)
	salt, err := readSalt(path)
	if err != nil {
		logger.Warn("failed to read salt", "error", err)
	}
	return &Client{
		httpClient: httpClient,
		logger:     logger,
		salt:       salt,
		saltPath:   path,
	}
}

func (a *Client) getSaltCached() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.salt
}

func (a *Client) setSalt(salt []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.salt = salt
}

func (a *Client) proBaseURL() string {
	if a.proURL != "" {
		return a.proURL
	}
	return common.GetProServerURL()
}

func (a *Client) baseURL() string {
	if a.authURL != "" {
		return a.authURL
	}
	return common.GetBaseURL()
}

// withoutURL returns the error a *url.Error in err wraps, dropping the request URL,
// which can carry the device ID and query values such as the email. Other errors are
// returned unchanged.
func withoutURL(err error) error {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		return urlErr.Err
	}
	return err
}

func redactDeviceID(path string) string {
	if id := settings.GetString(settings.DeviceIDKey); id != "" {
		return strings.ReplaceAll(path, id, "[device-id]")
	}
	return path
}

// sendRequest sends an HTTP request to the specified URL with the given method, query parameters,
// headers, and body. If the URL is relative, the base URL will be prepended.
//
// A non-2xx response returns an error whose message includes the response body.
func (a *Client) sendRequest(
	ctx context.Context,
	method, url string,
	queryParams, headers map[string]string,
	body any,
) ([]byte, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = a.baseURL() + url
	}

	// Bound the request with a timeout to prevent hanging indefinitely due to network issues or 502 Bad Gateway loops.
	timeoutCtx, cancel := context.WithTimeout(ctx, common.DefaultHTTPTimeout)
	defer cancel()

	var bodyReader io.Reader
	contentType := ""
	if body != nil {
		if pb, ok := body.(proto.Message); ok {
			data, err := proto.Marshal(pb)
			if err != nil {
				return nil, fmt.Errorf("marshaling protobuf request: %w", err)
			}
			bodyReader = bytes.NewReader(data)
			contentType = "application/x-protobuf"
		} else {
			data, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("marshaling JSON request: %w", err)
			}
			bodyReader = bytes.NewReader(data)
			contentType = "application/json"
		}
	}
	req, err := http.NewRequestWithContext(timeoutCtx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set(common.AppNameHeader, common.Name)
	req.Header.Set(common.AppVersionHeader, common.GetVersion())
	req.Header.Set(common.VersionHeader, common.GetVersion())
	req.Header.Set(common.PlatformHeader, common.Platform)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Accept", contentType)
	}
	if len(queryParams) > 0 {
		q := req.URL.Query()
		for k, v := range queryParams {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	if env.GetBool(env.PrintCurl) || common.Stage() {
		a.logger.Debug("CURL command", "curl", curlFromRequest(req))
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", withoutURL(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		a.logger.Debug("error response", "path", redactDeviceID(req.URL.Path), "status", resp.StatusCode)
		return nil, fmt.Errorf("unexpected status %v body %s", resp.StatusCode, sanitizeResponseBody(respBody))
	}

	if len(respBody) == 0 {
		return nil, nil
	}
	if contentType := resp.Header.Get("Content-Type"); strings.Contains(contentType, "application/json") {
		return sanitizeResponseBody(respBody), nil
	}
	return respBody, nil
}

// sendProRequest sends a request to the Pro server, automatically adding the required headers,
// including the device ID, user ID, and Pro token from settings, if available. If the URL is relative,
// the Pro server base URL will be prepended.
func (a *Client) sendProRequest(
	ctx context.Context,
	method, url string,
	queryParams, additionalheaders map[string]string,
	body any,
) ([]byte, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = a.proBaseURL() + url
	}
	headers := map[string]string{
		common.DeviceIDHeader: settings.GetString(settings.DeviceIDKey),
	}
	if tok := settings.GetString(settings.TokenKey); tok != "" {
		headers[common.ProTokenHeader] = tok
	}
	if uid := settings.GetString(settings.UserIDKey); uid != "" {
		headers[common.UserIDHeader] = uid
	}
	maps.Copy(headers, additionalheaders)
	return a.sendRequest(ctx, method, url, queryParams, headers, body)
}

// curlFromRequest renders req as a curl command, replacing req.Body with an unread copy
// of the same bytes. Secret headers, secret JSON body fields and the device ID are
// redacted, and a body that isn't JSON is replaced by its size.
func curlFromRequest(req *http.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "curl -X %s", req.Method)

	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range req.Header[k] {
			if logsafe.IsSecretKey(k) {
				v = logsafe.Redacted
			}
			fmt.Fprintf(&b, " -H '%s: %s'", k, v)
		}
	}

	if req.Body != nil {
		buf, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(buf))
		body := fmt.Sprintf("[REDACTED %d bytes]", len(buf))
		if json.Valid(buf) {
			if r := logsafe.RedactJSONFields(buf); r != nil {
				body = string(r)
			} else {
				body = string(buf)
			}
			body = redactDeviceID(body)
		}
		fmt.Fprintf(&b, " -d '%s'", shellEscape(body))
	}

	fmt.Fprintf(&b, " '%s'", redactDeviceID(req.URL.String()))
	return b.String()
}

func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

func sanitizeResponseBody(data []byte) []byte {
	var out bytes.Buffer
	r := bytes.NewReader(data)
	for {
		ch, size, err := r.ReadRune()
		if err != nil {
			break
		}
		if ch == utf8.RuneError && size == 1 {
			continue
		}
		if unicode.IsControl(ch) && ch != '\n' && ch != '\r' && ch != '\t' {
			continue
		}
		out.WriteRune(ch)
	}
	return out.Bytes()
}
