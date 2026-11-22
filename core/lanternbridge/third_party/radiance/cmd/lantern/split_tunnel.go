package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/ipc"
	"github.com/getlantern/radiance/vpn"
)

type SplitTunnelCmd struct {
	List   *SplitTunnelListCmd   `arg:"subcommand:list" help:"list current filters"`
	Add    *SplitTunnelAddCmd    `arg:"subcommand:add" help:"add a filter"`
	Remove *SplitTunnelRemoveCmd `arg:"subcommand:remove" help:"remove a filter"`
}

type SplitTunnelListCmd struct{}

type SplitTunnelAddCmd struct {
	Type  string `arg:"-t,--type,required" help:"filter type: domain, domain-suffix, domain-keyword, domain-regex, process-name, process-path, process-path-regex, package-name, package-name-regex"`
	Value string `arg:"-v,--value,required" help:"filter value (e.g. example.com)"`
}

type SplitTunnelRemoveCmd struct {
	Type  string `arg:"-t,--type,required" help:"filter type: domain, domain-suffix, domain-keyword, domain-regex, process-name, process-path, process-path-regex, package-name, package-name-regex"`
	Value string `arg:"-v,--value,required" help:"filter value (e.g. example.com)"`
}

func runSplitTunnel(ctx context.Context, c *ipc.Client, cmd *SplitTunnelCmd) error {
	switch {
	case cmd.Add != nil:
		typ := filterTypeFromArg(cmd.Add.Type)
		return c.AddSplitTunnelItems(ctx, buildFilter(typ, cmd.Add.Value))
	case cmd.Remove != nil:
		typ := filterTypeFromArg(cmd.Remove.Type)
		return c.RemoveSplitTunnelItems(ctx, buildFilter(typ, cmd.Remove.Value))
	default:
		return splitTunnelList(ctx, c)
	}
}

func splitTunnelList(ctx context.Context, c *ipc.Client) error {
	s, err := c.Settings(ctx)
	if err != nil {
		return err
	}
	enabled, _ := strconv.ParseBool(fmt.Sprintf("%v", s[settings.SplitTunnelKey]))
	fmt.Printf("Split tunneling: %v\n", enabled)
	policy := vpn.SplitTunnelPolicy(fmt.Sprintf("%v", orString(s[settings.SplitTunnelPolicyKey])))
	if !policy.Valid() {
		policy = vpn.SplitTunnelPolicyExclude
	}
	fmt.Printf("Policy: %v\n", policy)
	filters, err := c.SplitTunnelFilters(ctx)
	if err != nil {
		return err
	}
	printFilters(filters)
	return nil
}

func printFilters(f vpn.SplitTunnelFilter) {
	type entry struct {
		label  string
		values []string
	}
	entries := []entry{
		{"domain", f.Domain},
		{"domain-suffix", f.DomainSuffix},
		{"domain-keyword", f.DomainKeyword},
		{"domain-regex", f.DomainRegex},
		{"process-name", f.ProcessName},
		{"process-path", f.ProcessPath},
		{"process-path-regex", f.ProcessPathRegex},
		{"package-name", f.PackageName},
		{"package-name-regex", f.PackageNameRegex},
	}
	hasAny := false
	for _, e := range entries {
		for _, v := range e.values {
			if !hasAny {
				fmt.Println("Filters:")
				hasAny = true
			}
			fmt.Printf("  %s: %s\n", e.label, v)
		}
	}
	if !hasAny {
		fmt.Println("Filters: none")
	}
}

// parseFilter splits "TYPE:VALUE" into the internal filter type and value.
func parseFilter(spec string) (string, string, error) {
	typ, val, ok := strings.Cut(spec, ":")
	if !ok || val == "" {
		return "", "", fmt.Errorf("filter format: TYPE:VALUE (e.g. domain-suffix:example.com)")
	}
	return filterTypeFromArg(typ), val, nil
}

// filterTypeFromArg converts a CLI arg like "domain-suffix" to the internal type "domainSuffix".
func filterTypeFromArg(a string) string {
	words := strings.Split(a, "-")
	for i := 1; i < len(words); i++ {
		if w := words[i]; w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, "")
}

func buildFilter(filterType, value string) vpn.SplitTunnelFilter {
	var f vpn.SplitTunnelFilter
	switch filterType {
	case vpn.TypeDomain:
		f.Domain = []string{value}
	case vpn.TypeDomainSuffix:
		f.DomainSuffix = []string{value}
	case vpn.TypeDomainKeyword:
		f.DomainKeyword = []string{value}
	case vpn.TypeDomainRegex:
		f.DomainRegex = []string{value}
	case vpn.TypeProcessName:
		f.ProcessName = []string{value}
	case vpn.TypeProcessPath:
		f.ProcessPath = []string{value}
	case vpn.TypeProcessPathRegex:
		f.ProcessPathRegex = []string{value}
	case vpn.TypePackageName:
		f.PackageName = []string{value}
	case vpn.TypePackageNameRegex:
		f.PackageNameRegex = []string{value}
	}
	return f
}
