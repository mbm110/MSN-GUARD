package tlsidentity

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	boxlog "github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptionsDoesNotMutateInput(t *testing.T) {
	input := option.HTTPOutboundOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
		TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"},
	}}
	for _, input := range []any{input, &input} {
		got := Options(input)
		var tls *option.OutboundTLSOptions
		switch options := got.(type) {
		case option.HTTPOutboundOptions:
			tls = options.TLS
		case *option.HTTPOutboundOptions:
			tls = options.TLS
		default:
			t.Fatalf("unexpected options type %T", got)
		}
		assert.False(t, tls.Insecure)
		assert.Equal(t, "example.com", tls.ServerName)
	}
	assert.True(t, input.TLS.Insecure)
	assert.Nil(t, Options(nil))
	var typedNil *option.HTTPOutboundOptions
	assert.Equal(t, typedNil, Options(typedNil))
}

func TestOptionsPreservesIndependentVerification(t *testing.T) {
	for _, tls := range []*option.OutboundTLSOptions{
		{Enabled: true, Insecure: true, CertificatePublicKeySHA256: [][]byte{make([]byte, sha256.Size)}},
		{Enabled: true, Insecure: true, Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: "key"}},
	} {
		input := &option.HTTPOutboundOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls}}
		assert.Same(t, input, Options(input))
	}
}

func TestTLSIdentityHandshake(t *testing.T) {
	testTLSIdentityHandshake(t, false)
}

func testTLSIdentityHandshake(t *testing.T, useUTLS bool) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.Certificate()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	wrongPin := sha256.Sum256([]byte("untrusted key"))
	for _, test := range []struct {
		name      string
		tls       option.OutboundTLSOptions
		wantError bool
	}{
		{name: "self signed", tls: option.OutboundTLSOptions{ServerName: "example.com"}, wantError: true},
		{name: "wrong hostname", tls: option.OutboundTLSOptions{ServerName: "wrong.example", Certificate: []string{ca}}, wantError: true},
		{name: "trusted certificate", tls: option.OutboundTLSOptions{ServerName: "example.com", Certificate: []string{ca}}},
		{name: "pinned without SNI", tls: option.OutboundTLSOptions{ServerName: "cover.example", DisableSNI: true, CertificatePublicKeySHA256: [][]byte{pin[:]}}},
		{name: "wrong pin without SNI", tls: option.OutboundTLSOptions{ServerName: "cover.example", DisableSNI: true, CertificatePublicKeySHA256: [][]byte{wrongPin[:]}}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.tls.Enabled = true
			test.tls.Insecure = true
			test.tls.UTLS = &option.OutboundUTLSOptions{Enabled: useUTLS, Fingerprint: "chrome"}
			input := &option.HTTPOutboundOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &test.tls}}
			normalized := Options(input).(*option.HTTPOutboundOptions)
			cfg, err := boxtls.NewClient(t.Context(), boxlog.NOP(), "127.0.0.1", *normalized.TLS)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			require.NoError(t, err)
			defer raw.Close()
			conn, err := boxtls.ClientHandshake(ctx, raw, cfg)
			if conn != nil {
				conn.Close()
			}
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
