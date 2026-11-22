package vpn

import (
	"errors"
	"fmt"
	"strings"
)

// splitTunnelTag is the route rule-set tag the split-tunnel filter is bound to.
// It is shared across builds so the novpn build can reference the same tag when
// asserting the rule-set is absent.
const splitTunnelTag = "split-tunnel"

// SplitTunnelPolicy selects how the split-tunnel filter list is interpreted.
//
// The values describe the user-facing behavior: whether matching filters are
// excluded from the VPN tunnel or are the only traffic included in it. An empty
// filter list keeps all traffic in the tunnel regardless of the policy.
type SplitTunnelPolicy string

const (
	// SplitTunnelPolicyExclude makes matching apps/domains bypass the VPN and
	// routes everything else through it.
	SplitTunnelPolicyExclude SplitTunnelPolicy = "exclude"
	// SplitTunnelPolicyInclude routes only matching apps/domains through the VPN
	// and sends everything else direct.
	SplitTunnelPolicyInclude SplitTunnelPolicy = "include"
)

func (p SplitTunnelPolicy) Valid() bool {
	return p == SplitTunnelPolicyExclude || p == SplitTunnelPolicyInclude
}

// Filter type identifiers accepted by SplitTunnel.AddItems/RemoveItems and exposed
// through the backend and CLI. Defined here (rather than alongside the real
// implementation) so the novpn build, which compiles an inert SplitTunnel, still
// exports the same identifiers to callers.
const (
	TypeDomain           = "domain"
	TypeDomainSuffix     = "domainSuffix"
	TypeDomainKeyword    = "domainKeyword"
	TypeDomainRegex      = "domainRegex"
	TypeProcessName      = "processName"
	TypeProcessPath      = "processPath"
	TypeProcessPathRegex = "processPathRegex"
	TypePackageName      = "packageName"
	TypePackageNameRegex = "packageNameRegex"
)

// ErrInvalidSplitTunnelFilter means a filter item was rejected and the filter
// left unchanged; adding the same item again fails the same way.
var ErrInvalidSplitTunnelFilter = errors.New("invalid split-tunnel filter")

// SplitTunnelFilter is the set of domains, processes, and packages a user has
// configured for split-tunnel routing.
type SplitTunnelFilter struct {
	Domain           []string
	DomainSuffix     []string
	DomainKeyword    []string
	DomainRegex      []string
	ProcessName      []string
	ProcessPath      []string
	ProcessPathRegex []string
	PackageName      []string
	PackageNameRegex []string
}

func (f SplitTunnelFilter) len() int {
	return len(f.Domain) + len(f.DomainSuffix) + len(f.DomainKeyword) + len(f.DomainRegex) +
		len(f.ProcessName) + len(f.ProcessPath) + len(f.ProcessPathRegex) +
		len(f.PackageName) + len(f.PackageNameRegex)
}

func (f SplitTunnelFilter) String() string {
	var str []string
	if len(f.Domain) > 0 {
		str = append(str, fmt.Sprintf("domain: %v", f.Domain))
	}
	if len(f.DomainSuffix) > 0 {
		str = append(str, fmt.Sprintf("domainSuffix: %v", f.DomainSuffix))
	}
	if len(f.DomainKeyword) > 0 {
		str = append(str, fmt.Sprintf("domainKeyword: %v", f.DomainKeyword))
	}
	if len(f.DomainRegex) > 0 {
		str = append(str, fmt.Sprintf("domainRegex: %v", f.DomainRegex))
	}
	if len(f.ProcessName) > 0 {
		str = append(str, fmt.Sprintf("processName: %v", f.ProcessName))
	}
	if len(f.ProcessPath) > 0 {
		str = append(str, fmt.Sprintf("processPath: %v", f.ProcessPath))
	}
	if len(f.ProcessPathRegex) > 0 {
		str = append(str, fmt.Sprintf("processPathRegex: %v", f.ProcessPathRegex))
	}
	if len(f.PackageName) > 0 {
		str = append(str, fmt.Sprintf("packageName: %v", f.PackageName))
	}
	if len(f.PackageNameRegex) > 0 {
		str = append(str, fmt.Sprintf("packageNameRegex: %v", f.PackageNameRegex))
	}
	return "{" + strings.Join(str, ", ") + "}"
}
