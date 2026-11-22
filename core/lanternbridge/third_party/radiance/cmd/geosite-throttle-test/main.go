// Command geosite-throttle-test checks whether TLS fragmentation lets a full
// geosite-cn.srs download complete from a real CN residential IP — i.e. whether
// the GFW throttle that kills the plain `direct` fetch is SNI-triggered (and so
// defeated by fragmenting the ClientHello) or IP/flow-based.
//
// It routes the outline-sdk fragmentation dialers' inner dial through an oxylabs
// CN-residential HTTPS CONNECT exit, then fetches each candidate .srs over HTTPS
// with each strategy and reports bytes/time. `direct` is the control (expected
// to stall); `tlsfrag` is the experiment.
//
// NOTE on method: tlsfrag is *TLS-record* fragmentation — it survives the
// CONNECT proxy (record boundaries are application-layer). `split` is *TCP-write*
// splitting, which a CONNECT proxy may coalesce, so a split failure here is not
// conclusive; a tlsfrag result IS.
//
// Requires OXY_USER / OXY_PASS in the environment: OXY_USER is the bare Oxylabs
// customer ID (sessUser adds the "customer-" prefix and session modifiers),
// OXY_PASS is the proxy password. Then: go run ./cmd/geosite-throttle-test
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/split"
	"golang.getoutline.org/sdk/transport/tlsfrag"
)

const (
	oxyHost    = "pr.oxylabs.io"
	oxyGateway = oxyHost + ":7777"
	oxyCC      = "cn"
)

// connectDialer tunnels through the oxylabs CONNECT proxy so the TCP connection
// to the target originates from a CN residential exit. The proxy hop itself is
// TLS, so the Proxy-Authorization credential isn't sent in cleartext. Resolution
// happens at the exit (CONNECT carries the hostname).
type connectDialer struct{ user, pass string }

// DialStream returns a stream to addr that exits from a CN residential IP.
func (d connectDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	raw, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", oxyGateway)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: oxyHost})
	// Bound the TLS handshake + CONNECT exchange; cleared once the tunnel is up so
	// it doesn't cap the subsequent download.
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy TLS handshake: %w", err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(d.user + ":" + d.pass))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", addr, addr, auth); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT resp: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{}) // clear — the per-request timeout governs the transfer
	return &bufConn{StreamConn: tlsStreamConn{conn}, r: br}, nil
}

// tlsStreamConn adapts *tls.Conn to transport.StreamConn: tls.Conn has
// CloseWrite (via net.Conn half-close on the underlying TCP) but no CloseRead.
type tlsStreamConn struct{ *tls.Conn }

// CloseRead falls back to a full close: *tls.Conn can't close only the read
// half, so a no-op would falsely report success without changing state.
func (c tlsStreamConn) CloseRead() error { return c.Close() }

// bufConn preserves any bytes the reader buffered past the CONNECT response.
type bufConn struct {
	transport.StreamConn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// sessUser formats an Oxylabs CN residential session username from a bare
// customer ID.
func sessUser(base string) string {
	return fmt.Sprintf("customer-%s-cc-%s-sessid-%d-sesstime-10", base, oxyCC, time.Now().UnixNano()%1000000)
}

func fetch(dialer transport.StreamDialer, url string) (int64, time.Duration, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialStream(ctx, addr)
		},
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		// Count wire bytes: don't let the transport request+decode gzip, or the
		// reported size would be the decompressed body, not what crossed the GFW.
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{NextProtos: []string{"http/1.1"}},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
		// Don't follow redirects — measure the URL we asked for, not a hop that
		// might land on a different (unthrottled) host. A 3xx then trips the
		// non-2xx check below.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil && (resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) {
		err = fmt.Errorf("http %d", resp.StatusCode)
	}
	return n, time.Since(start), err
}

func main() {
	oxyUser, oxyPass := os.Getenv("OXY_USER"), os.Getenv("OXY_PASS")
	if oxyUser == "" || oxyPass == "" {
		fmt.Fprintln(os.Stderr, "OXY_USER and OXY_PASS must be set (oxylabs residential proxy credentials)")
		os.Exit(1)
	}

	targets := []struct {
		name, url string
		size      int64
	}{
		{"fastly", "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs", 0},
		{"raw.githubusercontent", "https://raw.githubusercontent.com/getlantern/rulesets/681577d4c825397df1521337f90ea5d3a3383c77/srs/geosite-cn.srs", 454323},
	}

	strats := []struct {
		name string
		wrap func(transport.StreamDialer) (transport.StreamDialer, error)
	}{
		{"direct", func(b transport.StreamDialer) (transport.StreamDialer, error) { return b, nil }},
		{"tlsfrag:1", func(b transport.StreamDialer) (transport.StreamDialer, error) {
			return tlsfrag.NewFixedLenStreamDialer(b, 1)
		}},
		{"tlsfrag:5", func(b transport.StreamDialer) (transport.StreamDialer, error) {
			return tlsfrag.NewFixedLenStreamDialer(b, 5)
		}},
		{"split:1", func(b transport.StreamDialer) (transport.StreamDialer, error) {
			return split.NewStreamDialer(b, split.NewFixedSplitIterator(1))
		}},
	}

	const runsPerStrategy = 2
	for _, t := range targets {
		fmt.Printf("\n===== %s — %s =====\n", t.name, t.url)
		// One Oxylabs session per iteration, reused across strategies, so e.g.
		// direct #1 and tlsfrag #1 measure the same residential exit — a fair
		// per-strategy comparison instead of one confounded by exit variance.
		sessions := make([]string, runsPerStrategy)
		for i := range sessions {
			sessions[i] = sessUser(oxyUser)
		}
		for _, s := range strats {
			for i := 1; i <= runsPerStrategy; i++ {
				base := connectDialer{user: sessions[i-1], pass: oxyPass}
				d, err := s.wrap(base)
				if err != nil {
					fmt.Printf("  %-10s #%d  build-err: %v\n", s.name, i, err)
					continue
				}
				n, dur, err := fetch(d, t.url)
				status := "OK"
				switch {
				case err != nil:
					status = "ERR: " + err.Error()
				case t.size > 0 && n < t.size:
					status = fmt.Sprintf("PARTIAL (%d/%d)", n, t.size)
				}
				fmt.Printf("  %-10s #%d  bytes=%-7d time=%-8s %s\n", s.name, i, n, dur.Round(time.Millisecond), status)
			}
		}
	}
}
