//go:build novpn

package backend

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	C "github.com/getlantern/common"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/internal/testutil"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn"
)

func TestAddPrivateServerUpdatesTunnel(t *testing.T) {
	const childEnv = "RADIANCE_PRIVATE_SERVER_TEST_CHILD"
	if os.Getenv(childEnv) != "1" {
		defer testutil.LockBypassPort()()
		// Fallback roots are process-wide and cannot be reset between tests.
		ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAddPrivateServerUpdatesTunnel$", "-test.timeout=30s", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/connect-config", r.URL.Path)
		switch r.URL.Query().Get("token") {
		case "valid":
			_, _ = w.Write([]byte(`{"outbounds":[{"type":"block","tag":"remote"}]}`))
		case "invalid-outbound":
			_, _ = w.Write([]byte(`{"outbounds":[{"type":"socks","tag":"remote","server":"127.0.0.1","server_port":1,"version":"invalid"}]}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	x509.SetFallbackRoots(roots)
	t.Setenv("RADIANCE_SOCKS_ADDRESS", "127.0.0.1:0")
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	for _, tt := range []struct {
		name          string
		connected     bool
		token         string
		wantErr       string
		wantSaved     bool
		wantOverrides bool
	}{
		{name: "disconnected", token: "valid", wantSaved: true},
		{name: "connected", connected: true, token: "valid", wantSaved: true},
		{name: "preserves bandit overrides", connected: true, token: "valid", wantSaved: true, wantOverrides: true},
		{name: "registration failure", connected: true, token: "revoked", wantErr: "unexpected status: 401"},
		{name: "outbound failure", connected: true, token: "invalid-outbound", wantErr: "failed to add private server to VPN client", wantSaved: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			var overrides map[string]string
			if tt.wantOverrides {
				overrides = map[string]string{"existing": "https://probe.invalid/callback"}
				writeCachedConfig(t, dir, &config.Config{BanditURLOverrides: overrides})
			}
			r := newCachedConfigBackend(t, dir)
			t.Cleanup(func() { assert.NoError(t, r.vpnClient.Disconnect()) })
			if tt.connected {
				require.NoError(t, r.vpnClient.Connect(t.Context(), vpn.BoxOptions{
					BasePath:           dir,
					InitialServer:      "existing",
					BanditURLOverrides: overrides,
					Options: option.Options{Outbounds: []option.Outbound{{
						Type: "block", Tag: "existing", Options: &option.StubOptions{},
					}}},
				}))
			}
			if tt.wantOverrides {
				require.Eventually(t, func() bool {
					history := r.vpnClient.HistoryStorage().Load("existing")
					return history != nil && !history.LastOutcomeAt.IsZero()
				}, time.Second, time.Millisecond)
			}
			location := C.ServerLocation{City: "Amsterdam", CountryCode: "NL"}
			err := r.AddPrivateServer("joined", u.Hostname(), port, tt.token, location, true)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tt.wantOverrides {
				assert.False(t, r.vpnClient.HistoryStorage().Load("existing").LastOutcomeAt.IsZero(), "adding a private server cleared an existing bandit override")
			}
			server, found := r.GetServerByTag("joined")
			require.Equal(t, tt.wantSaved, found)
			if found {
				assert.Equal(t, location, server.Location)
				require.NotNil(t, server.Credentials)
				assert.True(t, server.Credentials.IsJoined)
			}
			if !tt.connected {
				return
			}
			selected, err := r.vpnClient.CurrentSelectedServer()
			require.NoError(t, err)
			assert.Equal(t, "existing", selected)
			if tt.wantErr != "" {
				return
			}
			require.NoError(t, r.vpnClient.SelectServer("joined"))
			selected, err = r.vpnClient.CurrentSelectedServer()
			require.NoError(t, err)
			assert.Equal(t, "joined", selected)
			require.ErrorContains(t, r.AddPrivateServer("joined", u.Hostname(), port, tt.token, location, true), `server "joined" already exists`)
			selected, err = r.vpnClient.CurrentSelectedServer()
			require.NoError(t, err)
			assert.Equal(t, "joined", selected)
		})
	}

	t.Run("registration during config refresh", func(t *testing.T) {
		dir := t.TempDir()
		r := newCachedConfigBackend(t, dir)
		t.Cleanup(func() { assert.NoError(t, r.vpnClient.Disconnect()) })
		existing := option.Outbound{Type: "block", Tag: "existing", Options: &option.StubOptions{}}
		require.NoError(t, r.AddServers(servers.ServerList{Servers: []*servers.Server{{Tag: existing.Tag, Type: existing.Type, Options: existing}}}))
		require.NoError(t, r.vpnClient.Connect(t.Context(), vpn.BoxOptions{
			BasePath: dir, InitialServer: existing.Tag, Options: option.Options{Outbounds: []option.Outbound{existing}},
		}))
		start := make(chan struct{})
		errs := make(chan error, 21)
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Go(func() {
				<-start
				errs <- r.AddPrivateServer(fmt.Sprintf("joined-%d", i), u.Hostname(), port, "valid", C.ServerLocation{}, true)
			})
		}
		wg.Go(func() {
			<-start
			for range 100 {
				if err := r.updateServers(servers.ServerList{}, false); err != nil {
					errs <- err
					return
				}
			}
		})
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		reloaded := newCachedConfigBackend(t, dir)
		for i := range 20 {
			tag := fmt.Sprintf("joined-%d", i)
			require.NoError(t, r.vpnClient.SelectServer(tag))
			_, found := reloaded.GetServerByTag(tag)
			require.True(t, found, "%s was not persisted", tag)
		}
	})
}
