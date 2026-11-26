//go:build probe

// MSN 3.4.12: pin the Server Pool switch's partition contract in Go. The
// 3.4.11 field report: picking Global while running still showed the same
// four Iran rows — the manager kept BOTH pools and the button never changed
// the live list. SwitchPool must evict exactly the OTHER pool's Lantern
// servers (helpers and user-added servers stay) so the picker and the auto
// group hold only the selected pool.
package lanternbridge

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/getlantern/radiance/servers"
)

// TestSwitchPoolEvictsTheOtherPoolOnly: the CI flake (run 45780407888) was
// nothing the test asserts — all SwitchPool claims passed and the failure
// came AFTER the test body, when t.TempDir() tried to RemoveAll the data
// dir while Radiance's async goroutines (the config draw's saveServers and
// prewarmOfflineURLTests) were still writing inside it
// ("unlinkat .../data: directory not empty"). Init is once per process, so
// the probe binary keeps its backend alive — a backend with civilians in
// the directory under test. TempDir cleanup must own the tree alone.
//
// Fix: OWN data dir, still fresh per run (name + pid), cleaned best-effort
// BEFORE Init — because currentBackend() is nil until Init runs, this test's
// dir is pristine and the run under test is the only one that ever writes
// there — and not removed by the framework afterwards: a leftover is a log
// line on the runner, never a red X on a passing assertion.
func switchPoolDataDir(t *testing.T) (dataDir, logDir string) {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "msn-poolswitch-probe", filepath.Base(t.Name()), fmt.Sprintf("%d", os.Getpid()))
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("reset probe dir: %v", err)
	}
	dataDir = filepath.Join(dir, "data")
	logDir = filepath.Join(dir, "logs")
	for _, d := range []string{dataDir, logDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	return dataDir, logDir
}

func TestSwitchPoolEvictsTheOtherPoolOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("backend test")
	}
	dataDir, logDir := switchPoolDataDir(t)
	// switchPoolDataDir already made both; keep the belt-and-braces MkdirAll
	// the original had, harmless on an existing dir.
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
