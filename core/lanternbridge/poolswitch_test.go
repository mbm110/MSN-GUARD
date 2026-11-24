//go:build probe

// MSN 3.4.12: pin the Server Pool switch's partition contract in Go. The
// 3.4.11 field report: picking Global while running still showed the same
// four Iran rows — the manager kept BOTH pools and the button never changed
// the live list. SwitchPool must evict exactly the OTHER pool's Lantern
// servers (helpers and user-added servers stay) so the picker and the auto
// group hold only the selected pool.
package lanternbridge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getlantern/radiance/servers"
)

func TestSwitchPoolEvictsTheOtherPoolOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("backend test")
	}
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Init is once per process: reuse the backend when the traffic probe
	// (same probe build tag) already initialized it in this binary. CI runs
	// each probe as its own `go test` invocation, so this is belt-and-braces.
	if b := currentBackend(); b == nil {
		if err := Init(dataDir, logDir, "127.0.0.1:18390", "en-US"); err != nil {
			t.Fatalf("Init: %v", err)
		}
	}
	t.Cleanup(func() { _ = Disconnect() })

	b := currentBackend()
	if b == nil {
		t.Fatal("backend must be initialized")
	}

	irTag := "shadowsocks-out-ss2022-triangle-lightsail-fra-ir-free-9dafabd3"
	worldwideTag := "shadowsocks-out-ss2022-cardiff-oci-free-vps-c5211bf5"
	userTag := "my-own-server"
	helperTag := "helper-0123456789ab"

	// Stage the way the product does. Lantern members arrive via the config
	// draw path (updateServers — exposed for the probe as
	// ProbeStageLanternServers; IsLantern stays true, exactly like a fetch),
	// NOT via AddServers: that is the user-supplied path and deliberately
	// clears IsLantern, so a Lantern member staged through it is
	// indistinguishable from a user server and must NOT be evicted — the
	// first CI run failed exactly there. The helper's exemption is judged
	// by its tag (lbA.IsHelperTag), which is what SwitchPool checks.
	draw := servers.ServerList{Servers: []*servers.Server{
		{Tag: irTag, Type: "shadowsocks", IsLantern: true},
		{Tag: worldwideTag, Type: "shadowsocks", IsLantern: true},
	}}
	if err := b.ProbeStageLanternServers(draw); err != nil {
		t.Fatalf("stage draw: %v", err)
	}
	userList := servers.ServerList{Servers: []*servers.Server{
		{Tag: userTag, Type: "direct"},
	}}
	if err := b.AddServers(userList); err != nil {
		t.Fatalf("add user server: %v", err)
	}
	helperList := servers.ServerList{Servers: []*servers.Server{
		{Tag: helperTag, Type: "direct"},
	}}
	if err := b.AddServers(helperList); err != nil {
		t.Fatalf("add helper: %v", err)
	}

	tags := func() map[string]bool {
		got := map[string]bool{}
		for _, srv := range b.AllServers() {
			got[srv.Tag] = true
		}
		return got
	}

	// 1) Switch to global: only the ir-free member leaves.
	if err := SwitchPool("global"); err != nil {
		t.Fatalf("SwitchPool(global): %v", err)
	}
	after := tags()
	if after[irTag] {
		t.Error("global must evict the ir-free server")
	}
	if !after[worldwideTag] {
		t.Error("global must keep the worldwide server")
	}
	if !after[userTag] {
		t.Error("user-added servers are never pool members")
	}
	if !after[helperTag] {
		t.Error("helper pairings are never pool members")
	}

	// 2) Switch back to iran: the worldwide member leaves.
	if err := SwitchPool("iran"); err != nil {
		t.Fatalf("SwitchPool(iran): %v", err)
	}
	after = tags()
	if after[worldwideTag] {
		t.Error("iran must evict the worldwide server")
	}
	if !after[userTag] || !after[helperTag] {
		t.Error("user servers and helpers must survive both directions")
	}

	// 3) A pool with nothing to evict is a no-op success.
	if err := SwitchPool("iran"); err != nil {
		t.Fatalf("SwitchPool(iran) on an already-clean manager: %v", err)
	}
}
