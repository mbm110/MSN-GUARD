//go:build probe

// The traffic-counters probe (manual, CI-only — never part of an APK build).
//
// Field report 3.3.0: a Lantern session on Android carries traffic (Telegram
// loads, the reachability probe passes) while Down/Up/Speed sit at 0. The
// chain is: sing-box mixed SOCKS inbound → Router.RouteConnectionEx →
// connTracker.RoutedConnection wraps the conn → TrafficJSON sums the active
// records → the sidecar's /traffic → LanternEngine.trafficCountersOrNull →
// updateTrafficNotification. Every link reads correct in source, so this
// probe measures the actual runtime: it starts Radiance in-process (novpn,
// loopback SOCKS), connects to the public servers, pushes real bytes through
// the SOCKS inbound, and reports what TrafficJSON sees at each step.
//
// Run (from core/lanternbridge):
//
//	go test -tags="novpn,with_gvisor,with_quic,with_wireguard,with_utls,with_grpc,probe" \
//	  -run TestProbeTrafficThroughSocksInbound -v -timeout 420s . -count=1
package lanternbridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func probeDialSocks(t *testing.T, socksAddr, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS inbound: %v", err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	// Greeting: one auth method, no-auth.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("socks greeting reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("socks greeting refused: %x", reply)
	}
	// CONNECT by domain so the mixed inbound routes it like Hev does.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("socks connect: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("socks connect reply: %v", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("socks connect rejected: code %d", head[1])
	}
	switch head[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			t.Fatalf("socks bound ipv4: %v", err)
		}
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			t.Fatalf("socks bound domain len: %v", err)
		}
		rest := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			t.Fatalf("socks bound domain: %v", err)
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			t.Fatalf("socks bound ipv6: %v", err)
		}
	}
	return conn
}

func probeTrafficTotals(t *testing.T) (tx, rx int64, raw string) {
	t.Helper()
	raw = TrafficJSON()
	var parsed struct {
		Tx int64 `json:"tx"`
		Rx int64 `json:"rx"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("TrafficJSON not JSON: %q (%v)", raw, err)
	}
	return parsed.Tx, parsed.Rx, raw
}

// probeFetch pushes one HTTP round trip through the SOCKS inbound and reports
// how many bytes crossed.
func probeFetch(t *testing.T, socksAddr, host, path string) (up, down int64) {
	t.Helper()
	conn := probeDialSocks(t, socksAddr, host, 80)
	defer conn.Close()
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: msn-traffic-probe\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("http write: %v", err)
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("http read: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	body := make([]byte, 32*1024)
	n, err := io.ReadFull(reader, body)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		t.Fatalf("http body: %v", err)
	}
	up = int64(len(request))
	down = int64(n)
	t.Logf("probe fetch %s%s: pushed %d bytes up, read %d bytes down", host, path, up, down)
	return up, down
}

func TestProbeTrafficThroughSocksInbound(t *testing.T) {
	if testing.Short() {
		t.Skip("network probe")
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
	socksAddr := "127.0.0.1:18310"
	if err := Init(dataDir, logDir, socksAddr); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = Disconnect() })

	// ORDER (fixed): connect FIRST, then wait for the listener. The box — and
	// with it the SOCKS inbound — is created per tunnel, at ConnectVPN: waiting
	// for the listener before connecting waits forever (that is exactly how the
	// first CI run failed: "SOCKS inbound never listened" with no connect ever
	// attempted). The app does the same: Hev starts only after a successful
	// LanternEngine.connect().
	if err := Connect(180); err != nil {
		t.Fatalf("Connect: %v (status %q, last error %q)", err, Status(), LastError())
	}
	t.Logf("connected; status=%q", Status())

	// The tunnel is up; the mixed inbound binds with it.
	deadline := time.Now().Add(60 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", socksAddr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SOCKS inbound never listened: %v (status %q, last error %q)",
				err, Status(), LastError())
		}
		time.Sleep(300 * time.Millisecond)
	}

	tx0, rx0, raw0 := probeTrafficTotals(t)
	t.Logf("counters before any traffic: %s", raw0)

	up1, down1 := probeFetch(t, socksAddr, "www.example.com", "/")
	up2, down2 := probeFetch(t, socksAddr, "www.example.com", "/")

	// Give the counter conns a moment to settle their final accounting.
	time.Sleep(2 * time.Second)

	tx1, rx1, raw1 := probeTrafficTotals(t)
	t.Logf("counters after %d fetches: %s", 2, raw1)
	grewTx, grewRx := tx1-tx0, rx1-rx0
	t.Logf("delta: tx=%d rx=%d (bytes actually pushed: up=%d down=%d)",
		grewTx, grewRx, up1+up2, down1+down2)

	// The tracker counts full connection payloads including SOCKS and TLS-ish
	// overhead, so the counters must at least cover the raw bytes we pushed.
	if grewTx < up1+up2 || grewRx < down1+down2 {
		t.Errorf("TRAFFIC COUNTERS DID NOT FOLLOW THE SOCKS INBOUND: "+
			"tx delta %d < up %d or rx delta %d < down %d — the zero-speed "+
			"report is reproducible in-process", grewTx, up1+up2, grewRx, down1+down2)
	} else {
		t.Logf("TRAFFIC COUNTERS FOLLOW THE SOCKS INBOUND — the sing-box→TrafficJSON chain works; look at the sidecar/Kotlin layers")
	}
}
