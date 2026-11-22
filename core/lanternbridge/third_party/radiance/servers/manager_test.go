package servers

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	C "github.com/getlantern/common"
	box "github.com/getlantern/lantern-box"
	"github.com/hashicorp/go-retryablehttp"

	_ "github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/log"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateServerIntegration(t *testing.T) {
	manager := testManager(t)
	manager.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	srv := newLanternServerManagerMock()
	defer srv.Close()
	parsedURL, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(parsedURL.Port())

	t.Run("convert a token into a custom server", func(t *testing.T) {
		require.NoError(t, manager.AddPrivateServer("s1", parsedURL.Hostname(), port, "rootToken", C.ServerLocation{}, false))
		_, exists := manager.servers["s1"]
		require.True(t, exists, "server should be added to the manager")
	})

	t.Run("invite user", func(t *testing.T) {
		inviteToken, err := manager.InviteToPrivateServer(parsedURL.Hostname(), port, "rootToken", "invite1")
		assert.NoError(t, err)
		assert.NotEmpty(t, inviteToken)

		require.NoError(t, manager.AddPrivateServer("s2", parsedURL.Hostname(), port, inviteToken, C.ServerLocation{}, true))
		_, exists := manager.servers["s2"]
		require.True(t, exists, "server should be added for the invited user")

		t.Run("revoke user access", func(t *testing.T) {
			delete(manager.servers, "s1")
			require.NoError(t, manager.RevokePrivateServerInvite(parsedURL.Hostname(), port, "rootToken", "invite1"))
			// trying to access again with the same token should fail
			assert.Error(t, manager.AddPrivateServer("s1", parsedURL.Hostname(), port, inviteToken, C.ServerLocation{}, true))
			_, exists := manager.servers["s1"]
			assert.False(t, exists, "server should not be added after revoking invite")
		})
	})

}

func TestAddPrivateServerResponse(t *testing.T) {
	for _, tt := range []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "endpoints only",
			body:    `{"endpoints":[{"type":"wireguard","tag":"remote"}]}`,
			wantErr: "endpoints-only private server responses are not supported",
		},
		{
			name:    "empty",
			body:    `{}`,
			wantErr: "no endpoints or outbounds in response",
		},
		{
			name: "outbound",
			body: `{"outbounds":[{"type":"direct","tag":"remote"}]}`,
		},
		{
			name: "outbound and endpoint",
			body: `{"outbounds":[{"type":"direct","tag":"remote"}],"endpoints":[{"type":"wireguard","tag":"endpoint"}]}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/connect-config", r.URL.Path)
				_, err := w.Write([]byte(tt.body))
				assert.NoError(t, err)
			}))
			t.Cleanup(srv.Close)
			u, err := url.Parse(srv.URL)
			require.NoError(t, err)
			port, err := strconv.Atoi(u.Port())
			require.NoError(t, err)

			m := testManager(t)
			m.httpClient = srv.Client()
			err = m.AddPrivateServer("local", u.Hostname(), port, "token", C.ServerLocation{}, true)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, m.servers)
				assert.NoFileExists(t, m.serversFile)
				return
			}
			require.NoError(t, err)
			require.Len(t, m.servers, 1)
			server := m.servers["local"]
			require.NotNil(t, server)
			assert.Equal(t, "local", server.Tag)
			assert.Equal(t, "local", server.Options.(option.Outbound).Tag)
			assert.FileExists(t, m.serversFile)
		})
	}
}

type lanternServerManagerMock struct {
	users      map[string]string
	testConfig string
}

func newLanternServerManagerMock() *httptest.Server {
	testConfig := `
{
	"outbounds": [
		{
			"tag": "testing-out",
			"type": "shadowsocks",
			"server": "127.0.0.1",
			"server_port": 1080,
			"method": "chacha20-ietf-poly1305",
			"password": "<PASSWORD>",
		}
	]
}
`
	srv := httptest.NewUnstartedServer(&lanternServerManagerMock{
		testConfig: testConfig,
		users: map[string]string{
			"rootToken": testConfig,
		},
	})
	srv.StartTLS()
	return srv
}

func (s *lanternServerManagerMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if r.URL.Path == "/api/v1/connect-config" {
		if s.users[token] != "" {
			_, _ = w.Write([]byte(s.users[token]))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/share-link/") {
		if token != "rootToken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inviteName := strings.TrimPrefix(r.URL.Path, "/api/v1/share-link/")
		s.users[inviteName] = s.testConfig
		_, _ = w.Write([]byte(fmt.Sprintf(`{"token":"%s"}`, inviteName)))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/revoke/") {
		if token != "rootToken" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inviteName := strings.TrimPrefix(r.URL.Path, "/api/v1/revoke/")
		delete(s.users, inviteName)
		_, _ = w.Write([]byte("OK"))
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func TestAddServersByJSON(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		testConfig := []byte(`
{
	"outbounds": [
		{
			"tag": "out",
			"type": "shadowsocks",
			"server": "127.0.0.1",
			"server_port": 1080,
			"method": "chacha20-ietf-poly1305",
			"password": "<PASSWORD>",
		}
	]
}`)
		type singboxConfig struct {
			Outbounds []option.Outbound `json:"outbounds,omitempty"`
		}
		cfg, err := json.UnmarshalExtendedContext[singboxConfig](box.BaseContext(), testConfig)
		require.NoError(t, err, "failed to unmarshal test config")
		want := &Server{
			Tag:       "out",
			Type:      "shadowsocks",
			IsLantern: false,
			Options:   cfg.Outbounds[0],
		}
		m := testManager(t)
		list, err := m.AddServersByJSON(t.Context(), testConfig)
		require.NoError(t, err)
		assert.Equal(t, []string{"out"}, list.Tags())
		got, exists := m.GetServerByTag("out")
		assert.True(t, exists, "server was not added")
		assert.Equal(t, want.Tag, got.Tag)
		assert.Equal(t, want.Type, got.Type)
		assert.Equal(t, want.IsLantern, got.IsLantern)
	})
	t.Run("empty config", func(t *testing.T) {
		m := testManager(t)
		_, err := m.AddServersByJSON(t.Context(), []byte("{}"))
		assert.Error(t, err)
		assert.Empty(t, m.servers, "no servers should have been added")
	})
}

func TestAddServersByURL(t *testing.T) {
	urls := []string{
		"vless://uuid@host:443?encryption=none&security=tls&type=ws&host=example.com&path=/vless#VLESS+over+WS+with+TLS",
		"trojan://password@host:443?security=tls&sni=example.com#Trojan+with+TLS",
	}
	t.Run("valid urls", func(t *testing.T) {
		m := testManager(t)
		list, err := m.AddServersByURL(t.Context(), urls, false)
		require.NoError(t, err)
		assert.Len(t, list.Tags(), 2)
		_, exists := m.GetServerByTag("VLESS+over+WS+with+TLS")
		assert.True(t, exists, "VLESS server should be added")
		_, exists = m.GetServerByTag("Trojan+with+TLS")
		assert.True(t, exists, "Trojan server should be added")
	})
	t.Run("legacy certificate bypass", func(t *testing.T) {
		m := testManager(t)
		_, err := m.AddServersByURL(t.Context(), urls, true)
		require.NoError(t, err)
		server, exists := m.GetServerByTag("Trojan+with+TLS")
		require.True(t, exists, "Trojan server should be added")

		options := server.Options.(option.Outbound).Options
		require.IsType(t, &option.TrojanOutboundOptions{}, options)
		trojanOpts := options.(*option.TrojanOutboundOptions)
		require.NotNil(t, trojanOpts.TLS)
		assert.False(t, trojanOpts.TLS.Insecure)
	})
	t.Run("empty urls", func(t *testing.T) {
		m := testManager(t)
		_, err := m.AddServersByURL(t.Context(), []string{}, false)
		assert.Error(t, err)
		assert.Empty(t, m.servers, "no servers should have been added")
	})
}

// TestSaveServersConcurrent verifies that concurrent saves don't leave stale
// state on disk. Regression test for getlantern/engineering#3176 — with the
// previous implementation, two concurrent saveServers calls could reorder
// their marshal/write sequence and leave the older snapshot on disk.
func TestSaveServersConcurrent(t *testing.T) {
	mgr := testManager(t)

	// Run many concurrent mutations.
	const concurrency = 20
	const opsPerGoroutine = 10
	done := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < opsPerGoroutine; j++ {
				tag := fmt.Sprintf("concurrent-%d-%d", id, j)
				list := ServerList{
					Servers: []*Server{{
						Tag:  tag,
						Type: "shadowsocks",
						Options: option.Outbound{
							Tag:  tag,
							Type: "shadowsocks",
							Options: &option.ShadowsocksOutboundOptions{
								ServerOptions: option.ServerOptions{Server: "9.9.9.9", ServerPort: 443},
								Method:        "chacha20-ietf-poly1305",
								Password:      "pw",
							},
						},
						Location: C.ServerLocation{Country: "US", City: "X", CountryCode: "US"},
					}},
				}
				_ = mgr.AddServers(list, true)
			}
		}(i)
	}
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// After all concurrent operations, force a save and reload into a fresh
	// manager. The reloaded state must have exactly the same servers as the
	// original — if saves can reorder, the file would lag behind.
	require.NoError(t, mgr.saveServers())

	mgr2 := testManager(t)
	mgr2.serversFile = mgr.serversFile
	require.NoError(t, mgr2.loadServers())
	assert.Equal(t, len(mgr.AllServers()), len(mgr2.AllServers()),
		"reloaded server count must match in-memory count")

	for _, srv := range mgr.AllServers() {
		_, ok := mgr2.GetServerByTag(srv.Tag)
		assert.True(t, ok, "server %q must survive save/reload", srv.Tag)
	}
}

func TestRetryableHTTPClient(t *testing.T) {
	cli := retryableHTTPClient(log.NoOpLogger()).StandardClient()
	request, err := http.NewRequest(http.MethodGet, "https://www.gstatic.com/generate_204", http.NoBody)
	require.NoError(t, err)
	resp, err := cli.Do(request)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// validServerJSON returns the on-wire JSON for a parseable shadowsocks server
// with the given tag.
func validServerJSON(t *testing.T, tag string) []byte {
	t.Helper()
	srv := &Server{
		Tag:  tag,
		Type: "shadowsocks",
		Options: option.Outbound{
			Tag:  tag,
			Type: "shadowsocks",
			Options: &option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "9.9.9.9", ServerPort: 443},
				Method:        "chacha20-ietf-poly1305",
				Password:      "pw",
			},
		},
	}
	b, err := srv.MarshalJSON()
	require.NoError(t, err)
	return b
}

func TestLoadServersSalvagesParseableEntries(t *testing.T) {
	mgr := testManager(t)
	// One valid entry and one whose outbound type this build can't decode (the
	// shape a downgrade produces). The invalidServerJSON entry must not discard the good one.
	invalidServerJSON := []byte(`{"tag":"bad","type":"future-proto","outbound":{"tag":"bad","type":"future-proto"}}`)
	serverJSON := []byte("[" + string(validServerJSON(t, "good")) + "," + string(invalidServerJSON) + "]")
	require.NoError(t, os.WriteFile(mgr.serversFile, serverJSON, 0o600))

	err := mgr.loadServers()
	require.Error(t, err, "skipped entries must be reported to the caller")
	assert.Contains(t, err.Error(), "skipped 1 of 2")

	_, found := mgr.GetServerByTag("good")
	assert.True(t, found, "parseable server must be loaded")
	_, found = mgr.GetServerByTag("bad")
	assert.False(t, found, "unparseable server must be skipped")

	invalidPath := filepath.Join(filepath.Dir(mgr.serversFile), internal.ServersInvalidFileName)
	assert.FileExists(t, invalidPath, "skipped entries must be preserved for diagnostics")
	assert.FileExists(t, mgr.serversFile, "servers.json must be left in place for re-upgrade")
}

func TestLoadServersMalformedListStartsEmpty(t *testing.T) {
	mgr := testManager(t)
	require.NoError(t, os.WriteFile(mgr.serversFile, []byte("[ this is not json"), 0o600))

	require.Error(t, mgr.loadServers(), "a malformed file must be reported to the caller")
	assert.Empty(t, mgr.AllServers(), "no servers should be loaded from a malformed file")

	invalidPath := filepath.Join(filepath.Dir(mgr.serversFile), internal.ServersInvalidFileName)
	assert.FileExists(t, invalidPath, "malformed file must be quarantined for diagnostics")
}

func TestLoadServersMissingFileIsClean(t *testing.T) {
	mgr := testManager(t)
	require.NoError(t, mgr.loadServers(), "a missing servers file is not an error")
	assert.Empty(t, mgr.AllServers())
	invalidPath := filepath.Join(filepath.Dir(mgr.serversFile), internal.ServersInvalidFileName)
	assert.NoFileExists(t, invalidPath, "nothing to quarantine when there is no file")
}

func TestNewManagerReturnsUsableManagerOnLoadError(t *testing.T) {
	dataDir := t.TempDir()
	invalidServerJSON := []byte(`{"tag":"bad","type":"future-proto","outbound":{"tag":"bad","type":"future-proto"}}`)
	serverJSON := []byte("[" + string(validServerJSON(t, "good")) + "," + string(invalidServerJSON) + "]")
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, internal.ServersFileName), serverJSON, 0o600))

	mgr, err := NewManager(dataDir, log.NoOpLogger())
	require.Error(t, err, "a partial load must surface an error")
	require.NotNil(t, mgr, "manager must be usable despite the load error")
	_, found := mgr.GetServerByTag("good")
	assert.True(t, found, "salvaged server must be available from the returned manager")
}

func testManager(t *testing.T) *Manager {
	return &Manager{
		servers:     make(map[string]*Server),
		serversFile: filepath.Join(t.TempDir(), internal.ServersFileName),
		logger:      log.NoOpLogger(),
	}
}

func TestAddPrivateServerPersistsLocationAndJoined(t *testing.T) {
	manager := testManager(t)
	manager.httpClient = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	srv := newLanternServerManagerMock()
	defer srv.Close()
	parsedURL, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(parsedURL.Port())

	loc := C.ServerLocation{City: "Frankfurt", CountryCode: "DE"}
	require.NoError(t, manager.AddPrivateServer("de", parsedURL.Hostname(), port, "rootToken", loc, true))

	// In memory.
	got, ok := manager.servers["de"]
	require.True(t, ok)
	assert.Equal(t, loc, got.Location)
	assert.True(t, got.Credentials.IsJoined)

	// On disk, as the IPC /servers response would serialize it.
	raw, err := os.ReadFile(manager.serversFile)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"country_code":"DE"`)
	assert.Contains(t, string(raw), `"city":"Frankfurt"`)
	assert.Contains(t, string(raw), `"is_joined":true`)

	// Reloaded by a fresh manager.
	reloaded := testManager(t)
	reloaded.serversFile = manager.serversFile
	require.NoError(t, reloaded.loadServers())
	got, ok = reloaded.servers["de"]
	require.True(t, ok)
	assert.Equal(t, loc, got.Location)
	assert.True(t, got.Credentials.IsJoined)
}

// failingTransport fails every request with a fixed error, which http.Client wraps in
// a *url.Error that quotes the request URL.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestPrivateServerErrorOmitsAccessToken(t *testing.T) {
	const accessToken = "SECRET-ACCESS-TOKEN"

	m := testManager(t)
	m.httpClient = &http.Client{Transport: failingTransport{}}

	_, err := m.InviteToPrivateServer("127.0.0.1", 8443, accessToken, "invite1")
	require.Error(t, err, "expected a transport failure")
	assert.NotContains(t, err.Error(), accessToken, "access token leaked through the returned error")
	assert.Contains(t, err.Error(), "share-link", "redaction removed the request path, leaving an undiagnosable error")
	var urlErr *url.Error
	assert.False(t, errors.As(err, &urlErr), "the token-bearing *url.Error is reachable through the error chain")
}

func TestRetryableHTTPClientLogsOmitAccessToken(t *testing.T) {
	const accessToken = "SECRET-ACCESS-TOKEN"

	// A logger that does no redaction of its own.
	var logs bytes.Buffer
	client := retryableHTTPClient(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	client.HTTPClient.Transport = failingTransport{}
	client.RetryMax = 0
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://127.0.0.1:8443/share-link?token="+accessToken, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err, "expected a transport failure")

	assert.Contains(t, logs.String(), "request failed")
	assert.Contains(t, logs.String(), "share-link")
	assert.NotContains(t, logs.String(), accessToken)
}
