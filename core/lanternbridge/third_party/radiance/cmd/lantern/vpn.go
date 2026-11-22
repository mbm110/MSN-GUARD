package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/getlantern/radiance/ipc"
	"github.com/getlantern/radiance/vpn"
)

type ConnectCmd struct {
	Name string `arg:"-n,--name" default:"auto" help:"server name to connect to"`
	Wait bool   `arg:"-w,--wait" default:"false" help:"wait for IP change after connecting"`
}

type DisconnectCmd struct{}

type ClearTunnelCacheCmd struct{}

type StatusCmd struct {
	JSON bool `arg:"--json" help:"output JSON"`
}

type ThroughputCmd struct {
	JSON bool `arg:"--json" help:"output JSON"`
}

func vpnConnect(ctx context.Context, c *ipc.Client, tag string, wait bool) error {
	tctx, tcancel := context.WithTimeout(ctx, 5*time.Second)
	var prevIP string
	if wait {
		prevIP, _ = getPublicIP(tctx)
	}
	tcancel()

	status, err := c.VPNStatus(ctx)
	if err != nil {
		return err
	}
	switch status {
	case vpn.Connected:
		if err := c.SelectServer(ctx, tag); err != nil {
			return err
		}
	case vpn.Disconnected:
		if err := c.ConnectVPN(ctx, tag); err != nil {
			return err
		}
	default:
		return fmt.Errorf("busy with VPN status: %s", status)
	}

	fmt.Printf("Connected (tag: %s)\n", tag)
	if !wait {
		return nil
	}

	fmt.Print("Waiting for IP change...")
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	start := time.Now()
	ip, err := waitForIPChange(waitCtx, prevIP, 100*time.Millisecond)
	if err == nil && ip != "" {
		fmt.Printf("\rPublic IP: %s (took %v)\n", ip, time.Since(start).Truncate(time.Millisecond))
	} else {
		fmt.Printf("\rIP change not detected after %v\n", time.Since(start).Truncate(time.Second))
	}
	return nil
}

func runClearTunnelCache(ctx context.Context, c *ipc.Client) error {
	if err := c.ClearTunnelCache(ctx); err != nil {
		return err
	}
	fmt.Println("Tunnel cache cleared")
	return nil
}

func waitForIPChange(ctx context.Context, current string, interval time.Duration) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", nil
		case <-time.After(interval):
			ip, err := getPublicIP(ctx)
			if err != nil {
				return "", nil
			}
			if ip != current {
				return ip, nil
			}
		}
	}
}

func vpnThroughput(ctx context.Context, c *ipc.Client, cmd *ThroughputCmd) error {
	s, err := c.VPNThroughput(ctx)
	if err != nil {
		return err
	}
	if cmd.JSON {
		return printJSON(s)
	}
	printThroughput(s)
	return nil
}

func printThroughput(s vpn.ThroughputSnapshot) {
	fmt.Printf("Global  ↓ %s   ↑ %s   (%d active)\r\n",
		formatBitsPerSec(s.Global.Down), formatBitsPerSec(s.Global.Up), s.ActiveConnections)

	tagSet := make(map[string]struct{}, len(s.PerOutbound)+len(s.ActivePerOutbound))
	for tag := range s.PerOutbound {
		tagSet[tag] = struct{}{}
	}
	for tag := range s.ActivePerOutbound {
		tagSet[tag] = struct{}{}
	}
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		if isGroupTag(tag) {
			continue
		}
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		return
	}
	sort.Strings(tags)
	fmt.Print("\r\n")
	for _, tag := range tags {
		sp := s.PerOutbound[tag]
		name := tag
		if name == "" {
			name = "(unrouted)"
		}
		fmt.Printf("  %-32s ↓ %s   ↑ %s   (%d active)\r\n",
			name, formatBitsPerSec(sp.Down), formatBitsPerSec(sp.Up), s.ActivePerOutbound[tag])
	}
}

func formatBitsPerSec(bps int64) string {
	const (
		kbit = 1_000
		mbit = 1_000_000
		gbit = 1_000_000_000
	)
	switch {
	case bps >= gbit:
		return fmt.Sprintf("%6.2f Gbps", float64(bps)/gbit)
	case bps >= mbit:
		return fmt.Sprintf("%6.2f Mbps", float64(bps)/mbit)
	case bps >= kbit:
		return fmt.Sprintf("%6.2f Kbps", float64(bps)/kbit)
	default:
		return fmt.Sprintf("%6d bps ", bps)
	}
}

func vpnStatus(ctx context.Context, c *ipc.Client, cmd *StatusCmd) error {
	snap, err := fetchStatus(ctx, c)
	if err != nil {
		return err
	}
	return renderStatus(snap, cmd.JSON)
}

type statusSnapshot struct {
	Status    vpn.VPNStatus `json:"status"`
	Server    string        `json:"server,omitempty"`
	Location  string        `json:"location,omitempty"`
	LatencyMs uint32        `json:"latency_ms,omitempty"`
	IP        string        `json:"ip,omitempty"`
}

func fetchStatus(ctx context.Context, c *ipc.Client) (statusSnapshot, error) {
	status, err := c.VPNStatus(ctx)
	if err != nil {
		return statusSnapshot{}, err
	}
	snap := statusSnapshot{Status: status}
	if status == vpn.Connected {
		if sel, exists, err := c.SelectedServer(ctx); err == nil && exists && sel != nil {
			snap.Server = sel.Tag
			snap.Location = joinNonEmpty(", ", sel.Location.City, sel.Location.Country)
			snap.LatencyMs = sel.SelectionHistory.LatestSuccessDelay()
		}
	}
	tctx, tcancel := context.WithTimeout(ctx, 5*time.Second)
	if ip, err := getPublicIP(tctx); err == nil {
		snap.IP = ip
	}
	tcancel()
	return snap, nil
}

func renderStatus(snap statusSnapshot, asJSON bool) error {
	if asJSON {
		return printJSON(snap)
	}
	s := string(snap.Status)
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	fmt.Println(s)
	if snap.Server != "" {
		line := "Server: " + snap.Server
		if snap.Location != "" {
			line += " (" + snap.Location + ")"
		}
		if snap.LatencyMs > 0 {
			line += fmt.Sprintf(" — %dms", snap.LatencyMs)
		}
		fmt.Println(line)
	}
	if snap.IP != "" {
		fmt.Println("IP: " + snap.IP)
	}
	return nil
}
