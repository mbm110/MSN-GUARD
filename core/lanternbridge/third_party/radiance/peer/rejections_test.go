package peer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/getlantern/lantern-box/tracker/peerconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRejectionTally_GroupsByRegistrableDomain(t *testing.T) {
	tally := newRejectionTally("")
	tally.record("rr1---sn-abc.googlevideo.com:443")
	tally.record("rr2---sn-def.googlevideo.com:443")
	tally.record("RR2---SN-DEF.googlevideo.com.:443")
	tally.record("scontent-iad3-1.cdninstagram.com:443")
	tally.record("149.154.167.51:443")
	tally.record("[2001:b28:f23d:f001::a]:5222")
	tally.record("bare-host.example")
	tally.record(":443")

	total, domains := tally.counts()
	assert.Equal(t, int64(7), total)
	assert.Equal(t, 5, domains, "googlevideo.com's two hosts count as one domain")
	for host, domain := range map[string]string{
		"rr1---sn-abc.googlevideo.com":     "googlevideo.com",
		"scontent-iad3-1.cdninstagram.com": "cdninstagram.com",
		"149.154.167.51":                   "149.154.167.51",
		"2001:b28:f23d:f001::a":            "2001:b28:f23d:f001::a",
		"bare-host.example":                "bare-host.example",
	} {
		assert.Equal(t, domain, registrableDomain(host), host)
	}
	assert.NotNil(t, tally.state.Hosts["bare-host.example"], "a destination without a port is still counted")

	h := tally.state.Hosts["rr2---sn-def.googlevideo.com"]
	require.NotNil(t, h, "host case and trailing dot are normalized")
	assert.Equal(t, map[string]int64{"443": 2}, h.Ports)
	assert.Equal(t, map[string]int64{"5222": 1}, tally.state.Hosts["2001:b28:f23d:f001::a"].Ports)
}

func TestRejectionTally_CapsHostsAndCountsOverflow(t *testing.T) {
	tally := newRejectionTally("")
	for i := range maxRejectedHosts + 5 {
		tally.record(fmt.Sprintf("h%d.example.com:443", i))
	}
	tally.record("h0.example.com:443")
	assert.Len(t, tally.state.Hosts, maxRejectedHosts)
	assert.Equal(t, int64(5), tally.state.Overflow)
	assert.Equal(t, int64(2), tally.state.Hosts["h0.example.com"].Count, "known hosts still count past the cap")
	total, _ := tally.counts()
	assert.Equal(t, int64(maxRejectedHosts+6), total)
}

func TestRejectionTally_PersistsAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer-rejections.json")
	tally := newRejectionTally(path)
	tally.flush()
	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist, "an unchanged tally is not written")

	tally.record("pbs.twimg.com:443")
	tally.record("pbs.twimg.com:443")
	tally.flush()

	reloaded := newRejectionTally(path)
	total, domains := reloaded.counts()
	assert.Equal(t, int64(2), total)
	assert.Equal(t, 1, domains)

	reloaded.record("pbs.twimg.com:443")
	reloaded.flush()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var onDisk rejectionState
	require.NoError(t, json.Unmarshal(raw, &onDisk))
	assert.Equal(t, int64(3), onDisk.Hosts["pbs.twimg.com"].Count)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	leftovers, err := filepath.Glob(path + ".tmp*")
	require.NoError(t, err)
	assert.Empty(t, leftovers)
}

func TestRejectionTally_CorruptFileStartsFresh(t *testing.T) {
	tooMany := `{"hosts":{`
	for i := range maxRejectedHosts + 1 {
		if i > 0 {
			tooMany += ","
		}
		tooMany += fmt.Sprintf(`"h%d.example.com":{"count":1,"ports":{}}`, i)
	}
	tooMany += `}}`
	for name, saved := range map[string]string{
		"not json":                     `{not json`,
		"null host":                    `{"hosts":{"x.example.com":null}}`,
		"null ports":                   `{"hosts":{"x.example.com":{"count":3,"ports":null}}}`,
		"negative count":               `{"hosts":{"x.example.com":{"count":-1,"ports":{}}}}`,
		"too many hosts":               tooMany,
		"negative port":                `{"hosts":{"x.example.com":{"count":1,"ports":{"443":-1}}}}`,
		"ports past cap without other": `{"hosts":{"x.example.com":{"count":17,"ports":{"1000":1,"1001":1,"1002":1,"1003":1,"1004":1,"1005":1,"1006":1,"1007":1,"1008":1,"1009":1,"1010":1,"1011":1,"1012":1,"1013":1,"1014":1,"1015":1,"1016":1}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "peer-rejections.json")
			require.NoError(t, os.WriteFile(path, []byte(saved), 0o600))
			tally := newRejectionTally(path)
			tally.record("x.example.com:443")
			total, domains := tally.counts()
			assert.Equal(t, int64(1), total)
			assert.Equal(t, 1, domains)
		})
	}
}

// A port scan against one host must not grow its breakdown without bound.
func TestRejectionTally_CapsPortsPerHost(t *testing.T) {
	tally := newRejectionTally("")
	for port := range maxPortsPerHost + 10 {
		tally.record(fmt.Sprintf("scanned.example.com:%d", 1000+port))
	}
	tally.record("scanned.example.com:1000")
	h := tally.state.Hosts["scanned.example.com"]
	assert.Len(t, h.Ports, maxPortsPerHost+1)
	assert.Equal(t, int64(10), h.Ports[otherPorts])
	assert.Equal(t, int64(2), h.Ports["1000"], "known ports still count past the cap")
	assert.Equal(t, int64(maxPortsPerHost+11), h.Count)

	// The capped breakdown must survive a restart.
	path := filepath.Join(t.TempDir(), "peer-rejections.json")
	tally.path = path
	tally.flush()
	reloaded := newRejectionTally(path)
	assert.Equal(t, h.Ports, reloaded.state.Hosts["scanned.example.com"].Ports)
}

func TestRejectionTally_FailedWriteRetriesOnNextFlush(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	tally := newRejectionTally(filepath.Join(dir, "peer-rejections.json"))
	tally.record("example.com:443")
	tally.flush()
	assert.True(t, tally.dirty, "a failed write keeps the tally dirty")

	require.NoError(t, os.Mkdir(dir, 0o700))
	tally.flush()
	assert.False(t, tally.dirty)
	_, err := os.Stat(filepath.Join(dir, "peer-rejections.json"))
	assert.NoError(t, err)
}

// Only close events the inbound marked Rejected reach the tally, and Stop
// flushes it so a session's refusals are not lost.
func TestClient_TalliesRejectedCloseEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer-rejections.json")
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	c := newTestClient(t, fwd, &fakeBoxService{}, newStubServer(t), func(cfg *Config) {
		cfg.RejectionsPath = path
	})
	ctx := context.Background()
	require.NoError(t, c.Start(ctx))

	peerconn.Notify(peerconn.Event{State: +1, Source: "198.51.100.9:5000", Destination: "allowed.example:443"})
	peerconn.Notify(peerconn.Event{State: -1, Source: "198.51.100.9:5000"})
	peerconn.Notify(peerconn.Event{State: +1, Source: "198.51.100.9:5001", Destination: "rr1---sn-abc.googlevideo.com:443"})
	peerconn.Notify(peerconn.Event{State: -1, Source: "198.51.100.9:5001", Destination: "rr1---sn-abc.googlevideo.com:443", Rejected: true})
	require.NoError(t, c.Stop(ctx))

	reloaded := newRejectionTally(path)
	total, _ := reloaded.counts()
	assert.Equal(t, int64(1), total)
	assert.Contains(t, reloaded.state.Hosts, "rr1---sn-abc.googlevideo.com")
}
