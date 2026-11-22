package vpn

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	box "github.com/getlantern/lantern-box"
	lbO "github.com/getlantern/lantern-box/option"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/servers"
)

func TestBuildOptionsVerifiesTLSWithoutChangingReferences(t *testing.T) {
	for _, source := range []string{"fresh", "cached"} {
		t.Run(source, func(t *testing.T) {
			input := O.Options{Outbounds: []O.Outbound{
				{Tag: "helper", Type: C.TypeDirect, Options: &O.DirectOutboundOptions{}},
				{Tag: "proxy", Type: C.TypeHTTP, Options: &O.HTTPOutboundOptions{
					DialerOptions: O.DialerOptions{Detour: "helper"},
					ServerOptions: O.ServerOptions{Server: "example.com", ServerPort: 443},
					OutboundTLSOptionsContainer: O.OutboundTLSOptionsContainer{TLS: &O.OutboundTLSOptions{
						Enabled: true, Insecure: true, ServerName: "example.com",
					}},
				}},
				{Tag: "group", Type: C.TypeSelector, Options: &O.SelectorOutboundOptions{
					Outbounds: []string{"proxy", "helper"}, Default: "proxy",
				}},
			}, Route: &O.RouteOptions{Rules: []O.Rule{{
				Type: C.RuleTypeDefault, DefaultOptions: O.DefaultRule{
					RawDefaultRule: O.RawDefaultRule{Domain: []string{"example.com"}},
					RuleAction:     O.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: O.RouteActionOptions{Outbound: "group"}},
				},
			}}}}
			if source == "cached" {
				ctx := box.Context(t.Context())
				encoded, err := json.MarshalContext(ctx, input)
				require.NoError(t, err)
				input, err = json.UnmarshalExtendedContext[O.Options](ctx, encoded)
				require.NoError(t, err)
			}
			options, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: input, NonSelectableOutbounds: []string{"helper"}})
			require.NoError(t, err)
			found := make(map[string]O.Outbound)
			for _, out := range options.Outbounds {
				found[out.Tag] = out
			}
			for _, out := range input.Outbounds {
				require.Contains(t, found, out.Tag)
			}
			proxy := found["proxy"].Options.(*O.HTTPOutboundOptions)
			assert.False(t, proxy.TLS.Insecure)
			assert.Equal(t, "helper", proxy.Detour)
			assert.Equal(t, input.Outbounds[2], found["group"])
			assert.Contains(t, options.Route.Rules, input.Route.Rules[0])
			assert.ElementsMatch(t, []string{"proxy", "group"}, found[ManualSelectTag].Options.(*lbO.MutableSelectorOutboundOptions).Outbounds)
			assert.ElementsMatch(t, []string{"proxy", "group"}, found[AutoSelectTag].Options.(*lbO.MutableAutoSelectOutboundOptions).Outbounds)
			assert.True(t, input.Outbounds[1].Options.(*O.HTTPOutboundOptions).TLS.Insecure)
		})
	}
}

func TestLiveOutboundsRequireTLSIdentity(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	address := M.ParseSocksaddr(server.Listener.Addr().String())
	for _, operation := range []string{"add", "update", "helper"} {
		t.Run(operation, func(t *testing.T) {
			tun := startPolicyTestTunnel(t)
			tun.outboundMgr = service.FromContext[adapter.OutboundManager](tun.ctx)
			out := O.Outbound{Tag: "proxy", Type: C.TypeHTTP, Options: &O.HTTPOutboundOptions{
				ServerOptions: O.ServerOptions{Server: address.AddrString(), ServerPort: address.Port},
				OutboundTLSOptionsContainer: O.OutboundTLSOptionsContainer{TLS: &O.OutboundTLSOptions{
					Enabled: true, Insecure: true, ServerName: "example.com",
				}},
			}}
			list := servers.ServerList{Servers: []*servers.Server{{Tag: out.Tag, Type: out.Type, Options: out}}}
			var err error
			switch operation {
			case "add":
				err = tun.addOutbounds(list)
			case "update":
				err = tun.updateOutbounds(list)
			case "helper":
				err = tun.updateNonSelectableOutbounds(list)
			}
			require.NoError(t, err)
			outbound, found := tun.outboundMgr.Outbound(out.Tag)
			require.True(t, found)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddr("target.invalid:443"))
			if conn != nil {
				conn.Close()
			}
			require.ErrorContains(t, err, "certificate")
			assert.True(t, out.Options.(*O.HTTPOutboundOptions).TLS.Insecure)
		})
	}
}

func TestHysteria2VerifiesTLSIdentity(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	certServer := httptest.NewTLSServer(nil)
	t.Cleanup(certServer.Close)
	cert := certServer.Certificate()
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	key, err := x509.MarshalPKCS8PrivateKey(certServer.TLS.Certificates[0].PrivateKey)
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(packet.LocalAddr().(*net.UDPAddr).Port)
	require.NoError(t, packet.Close())
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	server, err := sbox.New(sbox.Options{Context: box.Context(t.Context()), Options: O.Options{
		Log: &O.LogOptions{Disabled: true},
		Inbounds: []O.Inbound{{Type: C.TypeHysteria2, Tag: "hy2", Options: &O.Hysteria2InboundOptions{
			ListenOptions: O.ListenOptions{Listen: &listen, ListenPort: port},
			Users:         []O.Hysteria2User{{Password: "test"}},
			InboundTLSOptionsContainer: O.InboundTLSOptionsContainer{TLS: &O.InboundTLSOptions{
				Enabled: true, Certificate: []string{certPEM}, Key: []string{keyPEM},
			}},
		}}},
	}})
	if errors.Is(err, C.ErrQUICNotIncluded) {
		t.Skip("requires with_quic")
	}
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	require.NoError(t, server.Start())
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	wrongPin := sha256.Sum256([]byte("different key"))
	for _, tc := range []struct {
		name       string
		ca         []string
		serverName string
		pin        []byte
		wantError  string
	}{
		{name: "untrusted", serverName: "example.com", wantError: "unknown authority"},
		{name: "trusted certificate", ca: []string{certPEM}, serverName: "example.com"},
		{name: "wrong name", ca: []string{certPEM}, serverName: "wrong.example", wantError: "certificate"},
		{name: "matching pin", serverName: "wrong.example", pin: pin[:]},
		{name: "wrong pin", serverName: "example.com", pin: wrongPin[:], wantError: "public key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tls := &O.OutboundTLSOptions{Enabled: true, Insecure: true, Certificate: tc.ca, ServerName: tc.serverName}
			if tc.pin != nil {
				tls.CertificatePublicKeySHA256 = [][]byte{tc.pin}
			}
			out := O.Outbound{Tag: "proxy", Type: C.TypeHysteria2, Options: &O.Hysteria2OutboundOptions{
				ServerOptions: O.ServerOptions{Server: "127.0.0.1", ServerPort: port}, Password: "test",
				OutboundTLSOptionsContainer: O.OutboundTLSOptionsContainer{TLS: tls},
			}}
			client, err := sbox.New(sbox.Options{Context: box.Context(t.Context()), Options: O.Options{
				Log: &O.LogOptions{Disabled: true}, Outbounds: allowedOutbounds([]O.Outbound{out}),
			}})
			require.NoError(t, err)
			t.Cleanup(func() { client.Close() })
			require.NoError(t, client.Start())
			proxy, found := client.Outbound().Outbound(out.Tag)
			require.True(t, found)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Listener.Addr().String()))
			if conn != nil {
				defer conn.Close()
			}
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
			req, err := http.NewRequest(http.MethodGet, target.URL, nil)
			require.NoError(t, err)
			require.NoError(t, req.Write(conn))
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	}
}
