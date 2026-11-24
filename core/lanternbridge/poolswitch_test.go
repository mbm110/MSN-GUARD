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
	// Init is once per process: when the traffic probe (same probe build
	// tag) already initialized the backend, reuse it instead of failing.
	if b := currentBackend(); b == nil {
		if err := Init(dataDir, logDir, "127.0.0.1:18390", "en-US"); err != nil {
			t.Fatalf("Init: %v", err)
		}
		if b = currentBackend(); b == nil {
			t.Fatal("backend must be initialized")
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

	// Stage one Lantern server of each pool, one user server, one helper.
	irList := servers.ServerList{Servers: []*servers.Server{
		{Tag: irTag, IsLantern: true},
	}}
	if err := b.AddServers(irList); err != nil {
		t.Fatalf("add ir-free: %v", err)
	}
	worldwideList := servers.ServerList{Servers: []*servers.Server{
		{Tag: worldwideTag, IsLantern: true},
	}}
	if err := b.AddServers(worldwideList); err != nil {
		t.Fatalf("add worldwide: %v", err)
	}
	userList := servers.ServerList{Servers: []*servers.Server{
		{Tag: userTag},
	}}
	if err := b.AddServers(userList); err != nil {
		t.Fatalf("add user server: %v", err)
	}
	helperList := servers.ServerList{Servers: []*servers.Server{
		{Tag: helperTag, IsLantern: true},
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

	// 2) Switch back to iran: the worldwide member leaves, and the held
	// ir-free set is whatever a later iran draw brings — here nothing, so
	// the manager is left empty rather than holding the other pool.
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
