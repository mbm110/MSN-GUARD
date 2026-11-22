package servers

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	C "github.com/getlantern/common"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/internal/hostaccess"
)

const torConfig = `{"outbounds":[{"tag":"tor-out","type":"tor","executable_path":"/tmp/payload"}]}`

func torServer(tag string) *Server {
	return &Server{
		Tag:  tag,
		Type: "tor",
		Options: option.Outbound{
			Tag:     tag,
			Type:    "tor",
			Options: &option.TorOutboundOptions{ExecutablePath: "/tmp/payload"},
		},
	}
}

func TestAddServersRejectsHostAccess(t *testing.T) {
	mgr := testManager(t)
	good := &Server{Tag: "good", Type: "shadowsocks", Options: option.Outbound{
		Tag: "good", Type: "shadowsocks", Options: &option.ShadowsocksOutboundOptions{},
	}}

	err := mgr.AddServers(ServerList{Servers: []*Server{good, torServer("tor-out")}}, false)
	require.ErrorIs(t, err, hostaccess.ErrDenied)
	assert.Empty(t, mgr.AllServers(), "a denied server must reject the whole batch")
	assert.NoFileExists(t, mgr.serversFile, "a rejected batch must not be saved")
}

func TestAddServersByJSONRejectsHostAccess(t *testing.T) {
	mgr := testManager(t)
	_, err := mgr.AddServersByJSON(context.Background(), []byte(torConfig))
	require.ErrorIs(t, err, hostaccess.ErrDenied)
	assert.Empty(t, mgr.AllServers())
}

func TestAddPrivateServerRejectsHostAccess(t *testing.T) {
	mgr := testManager(t)
	mgr.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	srv := newLanternServerManagerMock()
	defer srv.Close()
	srv.Config.Handler.(*lanternServerManagerMock).users["rootToken"] = torConfig
	parsedURL, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(parsedURL.Port())

	err := mgr.AddPrivateServer("p1", parsedURL.Hostname(), port, "rootToken", C.ServerLocation{}, false)
	require.ErrorIs(t, err, hostaccess.ErrDenied)
	assert.Empty(t, mgr.AllServers())
}

func TestLoadServersSkipsHostAccess(t *testing.T) {
	mgr := testManager(t)
	denied, err := torServer("tor-out").MarshalJSON()
	require.NoError(t, err)
	serverJSON := []byte("[" + string(validServerJSON(t, "good")) + "," + string(denied) + "]")
	require.NoError(t, os.WriteFile(mgr.serversFile, serverJSON, 0o600))

	err = mgr.loadServers()
	require.ErrorIs(t, err, hostaccess.ErrDenied)
	_, found := mgr.GetServerByTag("good")
	assert.True(t, found, "allowed server must still be loaded")
	_, found = mgr.GetServerByTag("tor-out")
	assert.False(t, found, "denied server must be skipped")
	assert.FileExists(t, filepath.Join(filepath.Dir(mgr.serversFile), internal.ServersInvalidFileName))
}

func TestLoadOldFormatSkipsHostAccess(t *testing.T) {
	mgr := testManager(t)
	old := `{"user":{"outbounds":[` +
		`{"tag":"good","type":"shadowsocks","server":"9.9.9.9","server_port":443,"method":"chacha20-ietf-poly1305","password":"pw"},` +
		`{"tag":"tor-out","type":"tor","executable_path":"/tmp/payload"}]}}`
	require.NoError(t, os.WriteFile(mgr.serversFile, []byte(old), 0o600))

	err := mgr.loadServers()
	require.ErrorIs(t, err, hostaccess.ErrDenied)
	_, found := mgr.GetServerByTag("good")
	assert.True(t, found)
	_, found = mgr.GetServerByTag("tor-out")
	assert.False(t, found)
	assert.FileExists(t, filepath.Join(filepath.Dir(mgr.serversFile), internal.ServersInvalidFileName))
}
