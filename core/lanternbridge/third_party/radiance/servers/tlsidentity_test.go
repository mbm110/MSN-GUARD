package servers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/getlantern/common"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const insecureHTTP = `{"tag":"private","type":"http","server":"example.com","server_port":443,"tls":{"enabled":true,"insecure":true}}`

func TestURLImportsRejectUnauthenticatedTLS(t *testing.T) {
	for _, uri := range []string{
		"trojan://password@example.com:443?allowInsecure=1#private",
		"vless://uuid@example.com:443?security=tls&allowInsecure=true#private",
		"vless://tcp+tls:uuid@example.com:443?allowInsecure=1#private",
		"vmess://tcp+tls:00000000-0000-0000-0000-000000000000-0@example.com:443?insecure=true#private",
		"hysteria://example.com:443?insecure=1#private",
		"hy2://password@example.com:443?insecure=true#private",
		"hy2://password@example.com:443?allowInsecure=1#private",
		"trojan://password@example.com:443?insecure=1#private",
		"hy2://password@example.com:443?insecure=false&insecure=true#private",
		"trojan://password@example.com:443?allowInsecure=false&insecure=1#private",
	} {
		for _, legacySkip := range []bool{false, true} {
			manager := testManager(t)
			var logs bytes.Buffer
			manager.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			list, err := manager.AddServersByURL(t.Context(), []string{uri}, legacySkip)
			require.ErrorIs(t, err, errTLSIdentityRequired)
			assert.Nil(t, list)
			assert.Empty(t, logs.String())
			assert.NotContains(t, logs.String(), uri)
			assert.NotContains(t, logs.String(), "password")
			assert.NotContains(t, logs.String(), "uuid")
			assert.NotContains(t, err.Error(), "password")
			assert.NotContains(t, err.Error(), "uuid")
			assert.Empty(t, manager.AllServers())
			assert.NoFileExists(t, manager.serversFile)
		}
	}
}

func TestJSONImportsRejectUnauthenticatedTLS(t *testing.T) {
	manager := testManager(t)
	verified := strings.ReplaceAll(insecureHTTP, `"insecure":true`, `"insecure":false`)
	verified = strings.ReplaceAll(verified, `"private"`, `"working"`)
	list, err := manager.AddServersByJSON(t.Context(), []byte(`{"outbounds":[`+verified+`,`+insecureHTTP+`]}`))
	require.ErrorIs(t, err, errTLSIdentityRequired)
	assert.Nil(t, list)
	assert.Empty(t, manager.AllServers())
	assert.NoFileExists(t, manager.serversFile)
}

func TestAddServersChecksTLSIdentityWithoutMutatingInput(t *testing.T) {
	ca := tlsIdentityTestCertificate(t)
	for _, test := range []struct {
		name         string
		tls          option.OutboundTLSOptions
		wantError    bool
		wantInsecure bool
	}{
		{name: "system trust", tls: option.OutboundTLSOptions{Enabled: true}},
		{name: "unauthenticated", tls: option.OutboundTLSOptions{Enabled: true, Insecure: true}, wantError: true},
		{name: "inline CA", tls: option.OutboundTLSOptions{Enabled: true, Insecure: true, Certificate: []string{ca}}},
		{name: "empty CA", tls: option.OutboundTLSOptions{Enabled: true, Insecure: true, Certificate: []string{""}}, wantError: true},
		{name: "public key pin", tls: option.OutboundTLSOptions{Enabled: true, Insecure: true, CertificatePublicKeySHA256: [][]byte{make([]byte, sha256.Size)}}, wantInsecure: true},
		{name: "Reality", tls: option.OutboundTLSOptions{Enabled: true, Insecure: true, Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: "key"}}, wantInsecure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := option.HTTPOutboundOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &test.tls}}
			original := test.tls
			for _, value := range []any{options, &options} {
				manager := testManager(t)
				server := &Server{Tag: "private", Type: "http", Options: option.Outbound{Tag: "private", Type: "http", Options: value}}
				err := manager.AddServers(ServerList{Servers: []*Server{server}}, false)
				if test.wantError {
					require.Error(t, err)
					assert.Empty(t, manager.AllServers())
					assert.NoFileExists(t, manager.serversFile)
				} else {
					require.NoError(t, err)
					stored, found := manager.GetServerByTag("private")
					require.True(t, found)
					normalized := stored.Options.(option.Outbound).Options
					switch opts := normalized.(type) {
					case option.HTTPOutboundOptions:
						assert.Equal(t, test.wantInsecure, opts.TLS.Insecure)
					case *option.HTTPOutboundOptions:
						assert.Equal(t, test.wantInsecure, opts.TLS.Insecure)
					default:
						t.Fatalf("unexpected options type %T", normalized)
					}
				}
				assert.Equal(t, original, test.tls)
			}
		})
	}
}

func TestURLImportsPreserveSupportedTLSIdentity(t *testing.T) {
	for _, test := range []struct{ name, url string }{
		{name: "system trust", url: "hy2://password@example.com:443?insecure=0#private"},
		{name: "inline CA", url: "trojan://password@example.com:443?allowInsecure=1&cert=" + url.QueryEscape(tlsIdentityTestCertificate(t)) + "#private"},
		{name: "Reality", url: "vless://uuid@example.com:443?security=reality&pbk=key&allowInsecure=true#private"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := testManager(t)
			list, err := manager.AddServersByURL(t.Context(), []string{test.url}, true)
			require.NoError(t, err)
			require.Len(t, list.Servers, 1)
			require.NoError(t, list.Servers[0].CheckTLSIdentity())
			stored, found := manager.GetServerByTag("private")
			require.True(t, found)
			require.NoError(t, stored.CheckTLSIdentity())
		})
	}
}

func TestURLImportsRejectLostTLSOptionsAtomically(t *testing.T) {
	for _, query := range []string{
		"pinSHA256=certificate-fingerprint",
		"insecure=true&pinSHA256=certificate-fingerprint",
		"insecure=invalid-secret",
		"insecure=true;invalid-secret",
	} {
		manager := testManager(t)
		_, err := manager.AddServersByURL(t.Context(), []string{
			"trojan://safe@example.com:443#working",
			"hy2://private-password@example.com:443?" + query + "#private",
		}, false)
		require.ErrorContains(t, err, "URL 2")
		assert.NotContains(t, err.Error(), "private-password")
		assert.NotContains(t, err.Error(), "certificate-fingerprint")
		assert.NotContains(t, err.Error(), "invalid-secret")
		assert.Empty(t, manager.AllServers())
		assert.NoFileExists(t, manager.serversFile)
	}
}

func TestVMessJSONURLRequiresTLSIdentity(t *testing.T) {
	for _, test := range []struct {
		name      string
		flag      any
		wantError bool
	}{
		{name: "verified", flag: false},
		{name: "boolean bypass", flag: true, wantError: true},
		{name: "string bypass", flag: "true", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(map[string]any{
				"v": "2", "ps": "private", "add": "example.com", "port": "443",
				"id": "00000000-0000-0000-0000-000000000000", "aid": "0",
				"net": "tcp", "type": "none", "tls": "tls", "allowInsecure": test.flag,
			})
			require.NoError(t, err)
			manager := testManager(t)
			list, err := manager.AddServersByURL(t.Context(), []string{"vmess://" + base64.StdEncoding.EncodeToString(data)}, false)
			if test.wantError {
				require.ErrorIs(t, err, errTLSIdentityRequired)
				assert.Nil(t, list)
				assert.Empty(t, manager.AllServers())
				assert.NoFileExists(t, manager.serversFile)
			} else {
				require.NoError(t, err)
				require.Len(t, list.Servers, 1)
				assertVerifiedTLS(t, list.Servers[0])
			}
		})
	}
}

func tlsIdentityTestCertificate(t *testing.T) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAddServersPreservesMetadataAndInput(t *testing.T) {
	opts := &option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled: true, Insecure: true, ServerName: "example.com", Certificate: []string{"trusted certificate"},
		}},
	}
	srv := &Server{
		Tag: "proxy", Type: "hysteria2", IsLantern: true,
		Options:          option.Outbound{Tag: "proxy", Type: "hysteria2", Options: opts},
		Location:         C.ServerLocation{CountryCode: "DE", City: "Frankfurt"},
		Credentials:      &ServerCredentials{AccessToken: "token", Port: 443, IsJoined: true},
		SelectionHistory: &SelectionHistory{ConsecutiveFailures: 2, UpdatedAt: time.Unix(1, 0).UTC()},
	}
	mgr := testManager(t)
	require.NoError(t, mgr.AddServers(ServerList{Servers: []*Server{srv}}, false))
	assert.True(t, opts.TLS.Insecure)
	stored, exists := mgr.GetServerByTag(srv.Tag)
	require.True(t, exists)
	assertVerifiedTLS(t, stored)
	want := srv.Clone()
	want.Options = stored.Options
	assert.Equal(t, want, stored)
	assert.NotSame(t, srv.Credentials, stored.Credentials)
	assert.NotSame(t, srv.SelectionHistory, stored.SelectionHistory)
	storedTLS := stored.Options.(option.Outbound).Options.(*option.Hysteria2OutboundOptions).TLS
	assert.Equal(t, opts.TLS.ServerName, storedTLS.ServerName)
	assert.Equal(t, opts.TLS.Certificate, storedTLS.Certificate)
	assert.NotSame(t, opts.TLS, storedTLS)
	raw, err := os.ReadFile(mgr.serversFile)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"insecure":true`)
}

func TestLoadServersRequiresTLSVerification(t *testing.T) {
	outbound := `{"type":"hysteria2","tag":"proxy","server":"example.com","server_port":443,"tls":{"enabled":true,"insecure":true}}`
	for name, data := range map[string]string{
		"current": `[{"tag":"proxy","type":"hysteria2","isLantern":true,"outbound":` + outbound + `}]`,
		"legacy":  `{"lantern":{"outbounds":[` + outbound + `]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			mgr := testManager(t)
			require.NoError(t, os.WriteFile(mgr.serversFile, []byte(data), 0o600))
			require.NoError(t, mgr.loadServers())
			srv, exists := mgr.GetServerByTag("proxy")
			require.True(t, exists)
			assert.True(t, srv.IsLantern)
			assertVerifiedTLS(t, srv)
			require.NoError(t, mgr.saveServers())
			raw, err := os.ReadFile(mgr.serversFile)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), `"insecure":true`)
		})
	}
}

func assertVerifiedTLS(t *testing.T, srv *Server) {
	t.Helper()
	tls := srv.Options.(option.Outbound).Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
	require.NotNil(t, tls)
	assert.True(t, tls.Enabled)
	assert.False(t, tls.Insecure)
}

func TestDecodeServerPreservesTLSOptions(t *testing.T) {
	var srv Server
	require.NoError(t, json.Unmarshal([]byte(`{"tag":"private","type":"http","outbound":`+insecureHTTP+`}`), &srv))
	tls := srv.Options.(option.Outbound).Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
	require.NotNil(t, tls)
	assert.True(t, tls.Insecure)
}
