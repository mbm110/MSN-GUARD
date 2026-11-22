package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/getlantern/publicip"
)

var (
	// list of extra public IP services to query in addition to the default ones provided by the publicip package
	ipURLs = []string{
		"https://ip.me",
		"https://ifconfig.me/ip",
		"https://checkip.amazonaws.com",
		"https://ifconfig.io/ip",
		"https://ident.me",
		"https://ipinfo.io/ip",
	}

	publicIPCfg = &publicip.Config{
		Timeout:      5 * time.Second,
		MinConsensus: 2,
		Methods:      publicip.DefaultMethods(),
	}
)

func init() {
	for _, url := range ipURLs {
		publicIPCfg.Methods = append(publicIPCfg.Methods, publicip.NewHTTP(url, publicip.FormatPlainText))
	}
}

type IPCmd struct {
	JSON bool `arg:"--json" help:"output JSON"`
}

func runIP(ctx context.Context, cmd *IPCmd) error {
	tctx, tcancel := context.WithTimeout(ctx, 10*time.Second)
	defer tcancel()
	ip, err := getPublicIP(tctx)
	if err != nil {
		return err
	}
	if cmd.JSON {
		return printJSON(struct {
			IP string `json:"ip"`
		}{IP: ip})
	}
	fmt.Println(ip)
	return nil
}

// fakeIPRange is the CIDR used by sing-box's fake-ip DNS. Addresses in this
// range can briefly appear as the "public IP" right after the VPN connects,
// before the tunnel is fully established.
var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// getPublicIP fetches the public IP address, rejecting private, loopback,
// unspecified, and fake-ip results as not a valid public IP.
func getPublicIP(ctx context.Context) (string, error) {
	result, err := publicip.Detect(ctx, publicIPCfg)
	if err != nil {
		return "", err
	}
	ip := result.IP
	addr, ok := netip.AddrFromSlice(ip)
	if ok {
		addr = addr.Unmap() // normalize IPv4-mapped IPv6 to IPv4
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || (ok && fakeIPRange.Contains(addr)) {
		return "", fmt.Errorf("detected IP is not a valid public IP: %s", ip.String())
	}
	return ip.String(), nil
}
