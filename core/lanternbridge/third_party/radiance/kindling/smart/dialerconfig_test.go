package smart

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/configurl"
	"gopkg.in/yaml.v3"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/internal/testsocks"
)

// dialerConfigYAML mirrors the schema outline-sdk's strategy finder unmarshals
// DialerConfig into. Its own type is unexported, so a test that wants to assert
// on what the finder will see has to restate it.
type dialerConfigYAML struct {
	DNS      []dnsEntryYAML `yaml:"dns"`
	TLS      []string       `yaml:"tls"`
	Fallback []string       `yaml:"fallback"`
}

type dnsEntryYAML struct {
	System *struct{}       `yaml:"system"`
	HTTPS  *dnsServerYAML  `yaml:"https"`
	TLS    *dnsServerYAML  `yaml:"tls"`
	UDP    *dnsAddressYAML `yaml:"udp"`
	TCP    *dnsAddressYAML `yaml:"tcp"`
}

type dnsServerYAML struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

type dnsAddressYAML struct {
	Address string `yaml:"address"`
}

const testServerName = "smart-dialer-test"

func parseDialerConfig(t *testing.T) dialerConfigYAML {
	t.Helper()
	var cfg dialerConfigYAML
	dec := yaml.NewDecoder(strings.NewReader(string(DialerConfig)))
	// Strict: a key outline-sdk doesn't know is silently dropped at runtime, so
	// a typo would disable a strategy or resolver without any signal.
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&cfg))
	return cfg
}

func TestDialerConfigParses(t *testing.T) {
	cfg := parseDialerConfig(t)
	assert.NotEmpty(t, cfg.DNS, "a config with no resolver cannot complete a search")
	assert.NotEmpty(t, cfg.TLS, "a config with no TLS strategy cannot complete a search")
}

// TestDialerConfigResolversAreEncrypted covers why radiance drops kindling's
// system DNS entry. A system entry that wins the resolver race makes outline-sdk
// demand a base dialer of exactly *transport.TCPDialer, which
// bypass.StreamDialer never is. A udp entry
// resolves through the packet dialer, which has no bypass path and loops back
// into the tunnel; a tcp entry keeps the bypass path but resolves in the clear.
func TestDialerConfigResolversAreEncrypted(t *testing.T) {
	for i, entry := range parseDialerConfig(t).DNS {
		assert.Nil(t, entry.System, "dns entry %d: system resolver", i)
		assert.Nil(t, entry.UDP, "dns entry %d: plaintext UDP resolver", i)
		assert.Nil(t, entry.TCP, "dns entry %d: plaintext TCP resolver", i)
		assert.True(t, entry.HTTPS != nil || entry.TLS != nil, "dns entry %d: neither DoH nor DoT", i)
	}
}

// TestDisorderPrecedesTheWrappersItFeeds guards the one ordering constraint in
// the strategy list: disorder requires a raw *net.TCPConn from whatever is to
// its left, so any wrapper placed before it makes the strategy unusable.
func TestDisorderPrecedesTheWrappersItFeeds(t *testing.T) {
	for _, strategy := range parseDialerConfig(t).TLS {
		for i, part := range strings.Split(strategy, "|") {
			if strings.HasPrefix(strings.TrimSpace(part), "disorder") {
				assert.Zero(t, i, "%q: disorder must be the leftmost element", strategy)
			}
		}
	}
}

// needsRawSocket reports whether a strategy fails outright without a
// *net.TCPConn from the base dialer. Only disorder does; tlsfrag also
// type-asserts one but degrades to a buffered write.
func needsRawSocket(strategy string) bool {
	return strings.Contains(strategy, "disorder")
}

// newTLSServer returns the listener's address and a pool trusting its
// self-signed certificate. tlsfrag cuts on TLS record boundaries, so a bare TCP
// echo cannot stand in for a real ClientHello.
func newTLSServer(t *testing.T) (string, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{testServerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).HandshakeContext(context.Background())
			}()
		}
	}()
	return ln.Addr().String(), roots
}

func handshakeThrough(t *testing.T, base transport.StreamDialer, strategy, addr string, roots *x509.CertPool, serverName string) error {
	t.Helper()

	providers := configurl.NewDefaultProviders()
	providers.StreamDialers.BaseInstance = base
	dialer, err := providers.NewStreamDialer(context.Background(), strategy)
	require.NoError(t, err, "strategy %q is not a valid outline-sdk config", strategy)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := dialer.DialStream(ctx, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, RootCAs: roots})
	defer tlsConn.Close()
	return tlsConn.HandshakeContext(ctx)
}

// TestStrategiesHandshakeOverTCPDialer is the platform-independent floor: every
// strategy has to work against the plain TCP dialer, or it is simply misspelled.
func TestStrategiesHandshakeOverTCPDialer(t *testing.T) {
	addr, roots := newTLSServer(t)
	for _, strategy := range parseDialerConfig(t).TLS {
		t.Run(strategyName(strategy), func(t *testing.T) {
			assert.NoError(t, handshakeThrough(t, &transport.TCPDialer{}, strategy, addr, roots, testServerName))
		})
	}
}

// TestStrategiesHandshakeOverDirectBypassDial covers the shape radiance has
// before its own tunnel is up — bypass.StreamDialer falls through to a direct
// dial, so every strategy including disorder must work.
func TestStrategiesHandshakeOverDirectBypassDial(t *testing.T) {
	requireNoBypassProxy(t)
	addr, roots := newTLSServer(t)
	for _, strategy := range parseDialerConfig(t).TLS {
		t.Run(strategyName(strategy), func(t *testing.T) {
			assert.NoError(t, handshakeThrough(t, bypass.StreamDialer(), strategy, addr, roots, testServerName))
		})
	}
}

// TestStrategiesHandshakeThroughBypassProxy covers the shape radiance runs in
// whenever its tunnel is up: the base dialer hands back a masked loopback
// socket rather than a *net.TCPConn.
//
// disorder is expected to fail there and the assertion is deliberate rather
// than a skip. Unmasking the socket would let it pass while setting TTL on the
// loopback leg to the bypass proxy — a strategy that wins the search and
// circumvents nothing.
func TestStrategiesHandshakeThroughBypassProxy(t *testing.T) {
	requireNoBypassProxy(t)
	testsocks.Listen(t, bypassProxyAddr())
	addr, roots := newTLSServer(t)

	var usable int
	for _, strategy := range parseDialerConfig(t).TLS {
		t.Run(strategyName(strategy), func(t *testing.T) {
			err := handshakeThrough(t, bypass.StreamDialer(), strategy, addr, roots, testServerName)
			if needsRawSocket(strategy) {
				assert.ErrorContains(t, err, "TCPConn",
					"the only accepted reason for a strategy to fail behind the bypass proxy is the masked socket")
				return
			}
			assert.NoError(t, err)
			usable++
		})
	}
	assert.GreaterOrEqual(t, usable, 2,
		"a tunnelled search needs more than one survivor, or a single blocked strategy leaves it nothing")
}

func bypassProxyAddr() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(bypass.ProxyPort))
}

// requireNoBypassProxy skips when something already holds the fixed bypass port
// — a running Lantern on a developer machine — since the test would otherwise
// dial the real tunnel and assert on the wrong dialer shape.
func requireNoBypassProxy(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", bypassProxyAddr(), time.Second)
	if err == nil {
		conn.Close()
		t.Skipf("something is already listening on the bypass port %s", bypassProxyAddr())
	}
}

// strategyName labels the empty direct strategy, which would otherwise produce
// an unnamed subtest.
func strategyName(strategy string) string {
	if strategy == "" {
		return "direct"
	}
	return strategy
}
