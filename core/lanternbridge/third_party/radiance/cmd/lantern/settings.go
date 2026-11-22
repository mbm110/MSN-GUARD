package main

import (
	"context"
	"fmt"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/ipc"
	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/vpn"
)

type FeaturesCmd struct{}

func runFeatures(ctx context.Context, c *ipc.Client) error {
	f, err := c.Features(ctx)
	if err != nil {
		return err
	}
	for k, v := range f {
		fmt.Printf("%s: %v\n", k, v)
	}
	return nil
}

var settingNames = []string{
	"smart-routing", "proxyless", "ad-block", "telemetry", "split-tunnel", "split-tunnel-policy",
	"fetch-config", "log-level", "feature-overrides", "country",
}

func settingValue(name string, s settings.Settings) (any, bool) {
	switch name {
	case "smart-routing":
		return orBool(s[settings.SmartRoutingKey]), true
	case "proxyless":
		// Unset means on.
		if v, ok := s[settings.ProxylessKey]; ok && v != nil {
			return orBool(v), true
		}
		return true, true
	case "ad-block":
		return orBool(s[settings.AdBlockKey]), true
	case "telemetry":
		return orBool(s[settings.TelemetryKey]), true
	case "split-tunnel":
		return orBool(s[settings.SplitTunnelKey]), true
	case "split-tunnel-policy":
		p := vpn.SplitTunnelPolicy(fmt.Sprintf("%v", orString(s[settings.SplitTunnelPolicyKey])))
		if !p.Valid() {
			p = vpn.SplitTunnelPolicyExclude
		}
		return string(p), true
	case "fetch-config":
		return !toBool(s[settings.ConfigFetchDisabledKey]), true
	case "log-level":
		return orString(s[settings.LogLevelKey]), true
	case "feature-overrides":
		return orString(s[settings.FeatureOverridesKey]), true
	case "country":
		return orString(s[settings.CountryCodeKey]), true
	}
	return nil, false
}

type SetCmd struct {
	SmartRouting      *bool   `arg:"--smart-routing" help:"enable or disable smart routing (true|false)"`
	Proxyless         *bool   `arg:"--proxyless" help:"with smart routing, reach unblocked sites directly, without a proxy (true|false)"`
	AdBlock           *bool   `arg:"--ad-block" help:"enable or disable ad blocking (true|false)"`
	Telemetry         *bool   `arg:"--telemetry" help:"enable or disable telemetry (true|false)"`
	SplitTunnel       *bool   `arg:"--split-tunnel" help:"enable or disable split tunneling (true|false)"`
	SplitTunnelPolicy *string `arg:"--split-tunnel-policy" help:"split-tunnel policy: exclude matches from the VPN, or include only matches in the VPN (exclude|include)"`
	FetchConfig       *bool   `arg:"--fetch-config" help:"enable or disable periodic config fetching (true|false)"`
	LogLevel          *string `arg:"--log-level" help:"log level (trace|debug|info|warn|error|fatal|panic|disable)"`
	FeatureOverrides  *string `arg:"--feature-overrides" help:"comma-separated feature flags to force-enable via the X-Lantern-Feature-Override header (empty string clears)"`
	Country           *string `arg:"--country" help:"override the client country code sent to the config server (empty string clears)"`
}

func runSet(ctx context.Context, c *ipc.Client, cmd *SetCmd) error {
	updates := settings.Settings{}
	if cmd.SmartRouting != nil {
		updates[settings.SmartRoutingKey] = *cmd.SmartRouting
	}
	if cmd.Proxyless != nil {
		updates[settings.ProxylessKey] = *cmd.Proxyless
	}
	if cmd.AdBlock != nil {
		updates[settings.AdBlockKey] = *cmd.AdBlock
	}
	if cmd.Telemetry != nil {
		updates[settings.TelemetryKey] = *cmd.Telemetry
	}
	if cmd.SplitTunnel != nil {
		updates[settings.SplitTunnelKey] = *cmd.SplitTunnel
	}
	if cmd.SplitTunnelPolicy != nil {
		policy := vpn.SplitTunnelPolicy(*cmd.SplitTunnelPolicy)
		if !policy.Valid() {
			return fmt.Errorf("invalid --split-tunnel-policy %q (want exclude|include)", *cmd.SplitTunnelPolicy)
		}
		updates[settings.SplitTunnelPolicyKey] = string(policy)
	}
	if cmd.FetchConfig != nil {
		updates[settings.ConfigFetchDisabledKey] = !*cmd.FetchConfig
	}
	if cmd.LogLevel != nil {
		if _, err := rlog.ParseLogLevel(*cmd.LogLevel); err != nil {
			return err
		}
		updates[settings.LogLevelKey] = *cmd.LogLevel
	}
	envUpdates := map[string]string{}
	if cmd.FeatureOverrides != nil {
		envUpdates[env.FeatureOverrides.String()] = *cmd.FeatureOverrides
	}
	if cmd.Country != nil {
		envUpdates[env.Country.String()] = *cmd.Country
	}
	if len(updates) == 0 && len(envUpdates) == 0 {
		return fmt.Errorf("no settings provided; pass one or more flags (see `lantern set --help`)")
	}
	if len(updates) > 0 {
		if _, err := c.PatchSettings(ctx, updates); err != nil {
			return err
		}
	}
	if len(envUpdates) > 0 {
		if _, err := c.PatchEnvVars(ctx, envUpdates); err != nil {
			return err
		}
	}
	return nil
}

type GetCmd struct {
	Name string `arg:"positional" help:"setting name (smart-routing, ad-block, telemetry, split-tunnel, split-tunnel-policy, fetch-config, log-level, feature-overrides, country); omit to list all"`
}

func runGet(ctx context.Context, c *ipc.Client, cmd *GetCmd) error {
	s, err := c.Settings(ctx)
	if err != nil {
		return err
	}
	if cmd.Name == "" {
		for _, name := range settingNames {
			v, _ := settingValue(name, s)
			fmt.Printf("%s: %v\n", name, v)
		}
		return nil
	}
	v, ok := settingValue(cmd.Name, s)
	if !ok {
		return fmt.Errorf("unknown setting %q", cmd.Name)
	}
	fmt.Printf("%s: %v\n", cmd.Name, v)
	return nil
}

func orBool(v any) any {
	if v == nil {
		return false
	}
	return v
}

func orString(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func selectionMode(s settings.Settings) string {
	if toBool(s[settings.AutoConnectKey]) {
		return "auto"
	}
	if s[settings.SelectedServerKey] != nil {
		return "manual"
	}
	return "auto"
}

func toBool(v any) bool {
	if v == nil {
		return false
	}
	return fmt.Sprintf("%v", v) == "true"
}
