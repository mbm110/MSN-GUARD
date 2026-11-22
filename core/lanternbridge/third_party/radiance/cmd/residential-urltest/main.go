// residential-urltest is a standalone reproduction tool: it url-tests a v9
// Lantern client's sing-box outbounds from a chosen country's *residential* IP,
// to reproduce "connected but no traffic" reports (proxies the app was offered
// but couldn't actually reach from the user's network/region).
//
// It reuses the exact v9 stack (lantern-box outbound registry + sing-box
// MutableURLTest) so custom protocols (samizdat, reflex, shadowsocks, vless…)
// are constructed the same way the client builds them. Every proxy's *server
// dial* is routed through a residential HTTP-CONNECT gateway (oxylabs by
// default; --provider selects brightdata or packetstream, each with its own
// gateway and login format) via a pool of `http` outbounds set as each
// proxy's `detour`, one session id per pool entry — a distinct sticky
// residential IP on session-based providers; packetstream ignores it and
// rotates IP per connection.
//
// Usage:
//
//	export OXY_USER=... OXY_PASS=...           # oxylabs residential creds
//	go run ./cmd/residential-urltest --config /path/to/debug-box-options.json --country ru
//
// Input is either a marshaled sing-box options file (top-level "outbounds") or
// any JSON with an "outbounds" array. Output: per-outbound REACHABLE(latency)/
// UNREACHABLE from the residential vantage.
//
// NOTE: the HTTP-CONNECT detour carries TCP only — UDP-based protocols
// (hysteria/hysteria2/tuic) are skipped and reported as such.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	O "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"

	"github.com/getlantern/radiance/internal/hostaccess"
)

// infra/non-proxy outbound types to skip.
var skipTypes = map[string]bool{
	"direct": true, "block": true, "dns": true, "selector": true, "urltest": true,
	lbC.TypeMutableURLTest: true, lbC.TypeMutableSelector: true,
}

// UDP-based protocols that can't be carried over an HTTP-CONNECT (TCP) detour.
var udpTypes = map[string]bool{"hysteria": true, "hysteria2": true, "tuic": true}

func main() {
	cfgPath := flag.String("config", "", "path to box options JSON (top-level \"outbounds\") or servers JSON")
	country := flag.String("country", "ru", "residential country code (ru, cn, ir, ...)")
	provider := flag.String("provider", "oxylabs", "residential provider: oxylabs, brightdata, packetstream")
	gw := flag.String("gw", "", "override gateway host:port (default: per-provider)")
	poolN := flag.Int("pool", 8, "number of distinct residential IPs (sessions) to spread dials across")
	timeoutS := flag.Int("timeout", 25, "overall url-test timeout (seconds)")
	direct := flag.Bool("direct", false, "method-validity control: dial proxies directly (no residential detour)")
	debug := flag.Bool("debug", false, "enable sing-box trace logging (shows per-outbound failure reasons)")
	throughput := flag.Bool("throughput", false, "after url-test, measure SUSTAINED download throughput through each reachable outbound — catches data-plane throttling (e.g. RU TSPU) that a short url-test sails past")
	dlBytes := flag.Int("download-bytes", 8_000_000, "throughput test: bytes to download per outbound")
	flag.Parse()

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "need --config")
		os.Exit(2)
	}
	if !*direct && *poolN <= 0 {
		fatal("--pool must be > 0 when using a residential detour")
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		fatal("read config: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		fatal("parse config json: %v", err)
	}
	obsRaw := top["outbounds"]
	if obsRaw == nil {
		obsRaw = top["servers"]
	}
	if obsRaw == nil {
		fatal("config has no \"outbounds\" or \"servers\" array")
	}
	var obs []map[string]any
	if err := json.Unmarshal(obsRaw, &obs); err != nil {
		fatal("parse outbounds: %v", err)
	}

	// Classify outbounds; stamp detour on TCP proxies, round-robin across the pool.
	var keep []map[string]any
	var tags []string
	var skippedUDP []string
	for _, ob := range obs {
		t, _ := ob["type"].(string)
		tag, _ := ob["tag"].(string)
		if t == "" || tag == "" || skipTypes[t] {
			continue
		}
		if _, hasServer := ob["server"]; !hasServer {
			continue
		}
		if udpTypes[t] {
			skippedUDP = append(skippedUDP, tag+" ("+t+")")
			continue
		}
		if !*direct {
			ob["detour"] = fmt.Sprintf("residential-%d", len(tags)%*poolN)
		}
		keep = append(keep, ob)
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		fatal("no testable (TCP) proxy outbounds found")
	}

	// Residential proxy outbound pool, each a distinct sticky session => distinct RU/CN IP.
	if !*direct {
		gwHost, gwPort, mkLogin, secret, err := providerGateway(*provider, *gw, *country)
		if err != nil {
			fatal("%v", err)
		}
		gwIPs, err := net.LookupHost(gwHost)
		if err != nil || len(gwIPs) == 0 {
			fatal("resolve gateway %s: %v", gwHost, err)
		}
		seed := rand.Int63()
		for i := 0; i < *poolN; i++ {
			keep = append(keep, map[string]any{
				"type": "http", "tag": fmt.Sprintf("residential-%d", i),
				"server": gwIPs[0], "server_port": gwPort,
				"username": mkLogin(fmt.Sprintf("%d%d", seed, i)), "password": secret,
			})
		}
	}

	wrapped, _ := json.Marshal(map[string]any{"outbounds": keep})
	// Configs come from users' issue reports, so the box refuses options that
	// grant host access.
	ctx := hostaccess.Context(context.Background())
	opts, err := singjson.UnmarshalExtendedContext[O.Options](ctx, wrapped)
	if err != nil {
		fatal("build sing-box options: %v", err)
	}
	var skippedHostAccess []string
	denied := make(map[string]bool)
	opts.Outbounds = slices.DeleteFunc(opts.Outbounds, func(o O.Outbound) bool {
		err := hostaccess.CheckOutbound(o)
		if err == nil {
			return false
		}
		skippedHostAccess = append(skippedHostAccess, err.Error())
		denied[o.Tag] = true
		return true
	})
	tags = slices.DeleteFunc(tags, func(tag string) bool { return denied[tag] })
	if len(tags) == 0 {
		fatal("no testable proxy outbounds left once those granting host access are skipped")
	}
	opts.Log = &O.LogOptions{Disabled: true}
	if *debug {
		opts.Log = &O.LogOptions{Level: "trace"}
	}
	opts.Outbounds = append(opts.Outbounds, urlTestOutbound("offline-test", tags))

	// URLTestGroup requires a history storage and a filemanager entry in ctx
	// (nil filemanager is fine for a one-shot CLI run).
	ctx = service.ContextWith[filemanager.Manager](ctx, nil)
	hist := urltest.NewHistoryStorage()
	ctx = service.ContextWithPtr(ctx, hist)
	// The instance ctx must outlive the whole run: a deadline here would kill
	// outbounds mid-loop during sequential throughput downloads and report
	// them as STALLED. --timeout scopes only the URLTest call below;
	// throughput requests carry their own per-request client timeout.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	inst, err := sbox.New(sbox.Options{Context: ctx, Options: opts})
	if err != nil {
		fatal("create sing-box: %v", err)
	}
	defer inst.Close()
	if err := inst.PreStart(); err != nil {
		fatal("prestart: %v", err)
	}
	ob, found := inst.Outbound().Outbound("offline-test")
	if !found {
		fatal("offline-test outbound not registered")
	}
	tester, ok := ob.(adapter.URLTestGroup)
	if !ok {
		fatal("offline-test is not a URLTestGroup")
	}
	utCtx, utCancel := context.WithTimeout(ctx, time.Duration(*timeoutS)*time.Second)
	results, err := tester.URLTest(utCtx)
	utCancel()
	if err != nil {
		fatal("url test: %v", err)
	}

	// Report.
	type row struct {
		tag string
		ms  uint16
	}
	var ok2, bad []row
	for _, tag := range tags {
		if d, present := results[tag]; present && d > 0 {
			ok2 = append(ok2, row{tag, d})
		} else {
			bad = append(bad, row{tag, 0})
		}
	}
	sort.Slice(ok2, func(i, j int) bool { return ok2[i].ms < ok2[j].ms })
	mode := fmt.Sprintf("residential provider=%s country=%s pool=%d", *provider, *country, *poolN)
	if *direct {
		mode = "DIRECT (no residential detour — method-validity control)"
	}
	fmt.Printf("\n===== url-test: %s =====\n", mode)
	fmt.Printf("REACHABLE: %d/%d   UNREACHABLE: %d   (UDP skipped: %d)\n", len(ok2), len(tags), len(bad), len(skippedUDP))
	for _, r := range ok2 {
		fmt.Printf("  OK    %5dms  %s\n", r.ms, r.tag)
	}
	for _, r := range bad {
		fmt.Printf("  FAIL          %s\n", r.tag)
	}
	if len(skippedUDP) > 0 {
		fmt.Printf("  (skipped UDP-only, can't test via HTTP detour: %v)\n", skippedUDP)
	}
	if len(skippedHostAccess) > 0 {
		fmt.Printf("  (skipped, options grant host access: %s)\n", strings.Join(skippedHostAccess, "; "))
	}

	// Throughput phase. A url-test only proves the handshake + first byte work —
	// which sails past a censor that THROTTLES the data plane (RU TSPU's signature:
	// "connects, then chokes to ~1 KB/s"). Pull several MB through each reachable
	// outbound and report achieved goodput. Compare against --direct (no-detour
	// control from the operator's own network)
	// and prefer oxylabs (stable exit bandwidth) over packetstream (noisy peers)
	// so a low number reflects path throttling, not a slow residential peer.
	if *throughput && len(ok2) > 0 {
		thURL := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", *dlBytes)
		fmt.Printf("\n===== throughput: %.1f MB/outbound via %s =====\n", float64(*dlBytes)/1e6, thURL)
		fmt.Printf("(handshake-OK + low KB/s here = throttled data plane, not unreachable)\n")
		for _, r := range ok2 {
			ob2, found := inst.Outbound().Outbound(r.tag)
			if !found {
				fmt.Printf("  MISSING   %s — outbound not registered, skipping\n", r.tag)
				continue
			}
			kbps, n, dur, terr := measureThroughput(ob2, thURL, *dlBytes)
			if terr != nil {
				fmt.Printf("  STALLED   %s — %v (%.2f MB in %s)\n", r.tag, terr, float64(n)/1e6, dur.Round(time.Millisecond))
				continue
			}
			fmt.Printf("  %9.1f KB/s  %s  (%.2f MB in %s; handshake %dms)\n", kbps, r.tag, float64(n)/1e6, dur.Round(time.Millisecond), r.ms)
		}
	}
}

// measureThroughput downloads up to maxBytes through ob's dialer (which carries
// the residential detour) and returns achieved goodput. The TLS handshake to the
// target runs over the tunnel too, so this is end-to-end client→server→target.
func measureThroughput(ob adapter.Outbound, url string, maxBytes int) (kbps float64, got int64, dur time.Duration, err error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return ob.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 120 * time.Second}
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return 0, 0, time.Since(start), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return 0, 0, time.Since(start), fmt.Errorf("throughput target returned %s", resp.Status)
	}
	got, err = io.Copy(io.Discard, io.LimitReader(resp.Body, int64(maxBytes)))
	dur = time.Since(start)
	if dur > 0 {
		kbps = float64(got) / 1024.0 / dur.Seconds()
	}
	return kbps, got, dur, err
}

func urlTestOutbound(tag string, outbounds []string) O.Outbound {
	return O.Outbound{
		Type: lbC.TypeMutableURLTest,
		Tag:  tag,
		Options: &lbO.MutableURLTestOutboundOptions{
			Outbounds: outbounds,
			// Same URL the v9 client url-tests with — www. would behave
			// differently under DNS/SNI filtering.
			URL:         "https://google.com/generate_204",
			Interval:    badoption.Duration(time.Minute),
			IdleTimeout: badoption.Duration(5 * time.Minute),
		},
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

// providerGateway returns the residential gateway host/port, a per-session login
// builder, and the shared secret for the chosen provider. Login formats match
// the formats lantern-cloud's pinger uses in production, so credentials
// validated there work here unchanged. Creds come from env.
func providerGateway(provider, gwOverride, country string) (string, int, func(string) string, string, error) {
	cc := strings.ToLower(country)
	host, port := "", 0
	if gwOverride != "" {
		h, ps, err := net.SplitHostPort(gwOverride)
		if err != nil {
			return "", 0, nil, "", fmt.Errorf("bad --gw: %w", err)
		}
		host = h
		port, err = parsePort("--gw", ps)
		if err != nil {
			return "", 0, nil, "", err
		}
	}
	switch strings.ToLower(provider) {
	case "brightdata", "brd":
		cust, zone, pw := os.Getenv("BRD_CUSTOMER_ID"), os.Getenv("BRD_ZONE"), os.Getenv("BRD_PASSWORD")
		if cust == "" || zone == "" || pw == "" {
			return "", 0, nil, "", fmt.Errorf("brightdata needs BRD_CUSTOMER_ID/BRD_ZONE/BRD_PASSWORD env")
		}
		if host == "" {
			host, port = "brd.superproxy.io", 33335
			if p := os.Getenv("BRD_PORT"); p != "" {
				bp, err := parsePort("BRD_PORT", p)
				if err != nil {
					return "", 0, nil, "", err
				}
				port = bp
			}
		}
		mk := func(sess string) string {
			return fmt.Sprintf("brd-customer-%s-zone-%s-country-%s-session-%s", cust, zone, cc, sess)
		}
		return host, port, mk, pw, nil
	case "packetstream", "ps":
		user, key := os.Getenv("PS_USER"), os.Getenv("PS_AUTH_KEY")
		if user == "" || key == "" {
			return "", 0, nil, "", fmt.Errorf("packetstream needs PS_USER/PS_AUTH_KEY env")
		}
		if host == "" {
			host, port = "proxy.packetstream.io", 31112
		}
		pw := fmt.Sprintf("%s_country-%s", key, countryName(cc))
		mk := func(sess string) string { return user } // PacketStream rotates IP per connection; no session field
		return host, port, mk, pw, nil
	case "oxylabs", "oxy":
		user, pass := os.Getenv("OXY_USER"), os.Getenv("OXY_PASS")
		if user == "" || pass == "" {
			return "", 0, nil, "", fmt.Errorf("oxylabs needs OXY_USER/OXY_PASS env")
		}
		if host == "" {
			host, port = "pr.oxylabs.io", 7777
		}
		mk := func(sess string) string {
			return fmt.Sprintf("customer-%s-cc-%s-sessid-%s-sesstime-10", user, cc, sess)
		}
		return host, port, mk, pass, nil
	default:
		return "", 0, nil, "", fmt.Errorf("unknown --provider %q (want oxylabs, brightdata, or packetstream)", provider)
	}
}

func parsePort(name, value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("%s must be a valid TCP port, got %q", name, value)
	}
	return port, nil
}

func countryName(cc string) string {
	m := map[string]string{"ru": "Russia", "cn": "China", "ir": "Iran", "us": "United States", "de": "Germany", "gb": "United Kingdom"}
	if n, ok := m[cc]; ok {
		return n
	}
	return strings.ToUpper(cc)
}
