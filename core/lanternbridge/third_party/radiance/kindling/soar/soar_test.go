package soar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/kindling"
	"github.com/getlantern/soar"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
)

func TestUnconfiguredBuild(t *testing.T) {
	Zone, PublicKey = "", ""
	require.False(t, Configured())
	_, err := New(t.TempDir())
	require.Error(t, err)
}

func TestBadPublicKey(t *testing.T) {
	t.Cleanup(func() { Zone, PublicKey = "", "" })
	Zone, PublicKey = "t.example.com", "not-base64!"
	_, err := New(t.TempDir())
	require.Error(t, err)
}

func TestFileCacheRoundTrip(t *testing.T) {
	c := &fileCache{path: filepath.Join(t.TempDir(), "soar_resolvers.json")}
	require.Empty(t, c.Load())
	c.Store([]string{"1.2.3.4:53", "5.6.7.8:53"})
	require.Equal(t, []string{"1.2.3.4:53", "5.6.7.8:53"}, c.Load())
}

func TestFileCacheLoadIsBounded(t *testing.T) {
	c := &fileCache{path: filepath.Join(t.TempDir(), "soar_resolvers.json")}
	c.Store([]string{"1.1.1.1:53", "2.2.2.2:53", "3.3.3.3:53", "4.4.4.4:53", "5.5.5.5:53", "6.6.6.6:53"})
	require.Len(t, c.Load(), maxCachedResolvers)
}

// A configured build reaches a Soar server and fetches through it.
func TestConfiguredBuildTunnels(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go soar.Serve(ctx, pc, soar.ServerConfig{Zone: "t.example.com", PrivateKey: priv,
		Dial: (&net.Dialer{}).DialContext})
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "through soar")
	}))
	t.Cleanup(hs.Close)

	t.Cleanup(func() { Zone, PublicKey = "", "" })
	Zone, PublicKey = "t.example.com", base64.StdEncoding.EncodeToString(pub)
	// Seed the per-device cache with the local server, as a returning user's would be: discovery
	// vets cached resolvers first. The country is pinned so New picks the same cache key on any
	// host, whatever its time zone.
	t.Cleanup(func() { settings.Set(settings.CountryCodeKey, "") })
	settings.Set(settings.CountryCodeKey, "US")
	dataDir := t.TempDir()
	(&fileCache{path: filepath.Join(dataDir, "soar_resolvers.json"), country: "US"}).Store([]string{pc.LocalAddr().String()})

	sc, err := New(dataDir)
	require.NoError(t, err)
	defer sc.Close()
	rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer rcancel()
	rt, err := sc.NewRoundTripper(rctx, strings.TrimPrefix(hs.URL, "http://"))
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: rt, Timeout: 20 * time.Second}).Get(hs.URL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, "through soar", string(body))
}

func TestCountryFallsBackToTimeZone(t *testing.T) {
	t.Cleanup(func() { settings.Set(settings.CountryCodeKey, "") })
	settings.Set(settings.CountryCodeKey, "")
	require.Equal(t, "IR", country("Asia/Tehran"))
	require.Equal(t, "RU", country("Asia/Novosibirsk"))
	require.Equal(t, "", country("America/New_York"))
	settings.Set(settings.CountryCodeKey, "CN")
	require.Equal(t, "CN", country("Asia/Tehran"), "the known country wins over the zone")
}

// Resolvers verified under a time-zone guess must be found once config confirms the country.
func TestFileCacheKeyFollowsDiscoveryCountry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "soar_resolvers.json")
	(&fileCache{path: path, country: "IR"}).Store([]string{"1.2.3.4:53"})
	require.Equal(t, []string{"1.2.3.4:53"}, (&fileCache{path: path, country: "ir"}).Load())
	require.Empty(t, (&fileCache{path: path}).Load())
}

func TestFileCacheSurvivesNullFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "soar_resolvers.json")
	require.NoError(t, os.WriteFile(path, []byte("null"), 0o600))
	c := &fileCache{path: path}
	require.Empty(t, c.Load())
	c.Store([]string{"1.2.3.4:53"})
	require.Equal(t, []string{"1.2.3.4:53"}, c.Load())
}

// kindling keeps streaming requests off a tunnel whose IsStreamable is false. Unbounded's
// signaling sends freddie requests as event streams, many a second on some peers: on Soar they
// filled every stream the session has, and other requests failing over to Soar got none.
func TestTunnelStaysOffStreamingRequests(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	t.Cleanup(func() { Zone, PublicKey = "", "" })
	Zone, PublicKey = "t.example.com", base64.StdEncoding.EncodeToString(pub)
	c, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	var tunnel kindling.DNSTunnel = c
	streamable, ok := tunnel.(interface{ IsStreamable() bool })
	require.True(t, ok, "the tunnel must tell kindling whether it can stream")
	require.False(t, streamable.IsStreamable())
}
