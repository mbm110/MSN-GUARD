//go:build !novpn

package vpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/log"
)

const splitTunnelFile = internal.SplitTunnelFileName

// SplitTunnel manages split tunneling for configured domains, processes, and
// packages.
type SplitTunnel struct {
	rule         O.LogicalHeadlessRule
	activeFilter *O.LogicalHeadlessRule
	ruleFile     string
	ruleMap      map[string]*O.DefaultHeadlessRule
	enabled      *atomic.Bool
	inverted     *atomic.Bool
	access       sync.Mutex
	logger       *slog.Logger
}

// NewSplitTunnelHandler creates a SplitTunnel handler, loading the saved rule
// set from disk.
//
// The returned handler is always usable, even when the error is non-nil: an
// unreadable or invalid rule file falls back to the default no-op rule.
func NewSplitTunnelHandler(dataPath string, logger *slog.Logger) (*SplitTunnel, error) {
	s := newSplitTunnel(dataPath, logger)
	if err := s.loadRule(); err != nil {
		return s, fmt.Errorf("loading split tunnel rule file %s: %w", s.ruleFile, err)
	}
	return s, nil
}

func newSplitTunnel(path string, logger *slog.Logger) *SplitTunnel {
	rule := defaultRule()
	s := &SplitTunnel{
		rule:         rule,
		ruleFile:     filepath.Join(path, splitTunnelFile),
		activeFilter: &(rule.Rules[1].LogicalOptions),
		ruleMap:      make(map[string]*O.DefaultHeadlessRule),
		enabled:      &atomic.Bool{},
		inverted:     &atomic.Bool{},
		logger:       logger,
	}
	s.initRuleMap()
	if _, err := os.Stat(s.ruleFile); errors.Is(err, fs.ErrNotExist) {
		logger.Debug("Creating initial split tunnel rule file", "file", s.ruleFile)
		s.access.Lock()
		if err := s.saveLocked(); err != nil {
			logger.Error("Writing initial split tunnel rule file", "file", s.ruleFile, "error", err)
		}
		s.access.Unlock()
	}
	return s
}

// SetEnabled enables or disables split tunneling, persisting the change to
// disk. It is a no-op when already in the requested state.
func (s *SplitTunnel) SetEnabled(enabled bool) error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.enabled.Load() == enabled {
		return nil
	}
	mode := C.LogicalTypeAnd
	if enabled {
		mode = C.LogicalTypeOr
	}
	prev := s.rule.Mode
	s.rule.Mode = mode
	if err := s.saveLocked(); err != nil {
		s.rule.Mode = prev
		return fmt.Errorf("writing rule to %s: %w", s.ruleFile, err)
	}
	s.enabled.Store(enabled)
	s.logger.Log(context.Background(), log.LevelTrace, "Updated split-tunneling", "enabled", enabled)
	return nil
}

func (s *SplitTunnel) IsEnabled() bool {
	return s.enabled.Load()
}

// SetPolicy changes how the split-tunnel filter is interpreted and persists it.
// Invalid policies default to [SplitTunnelPolicyExclude].
//
// Empty filters serialize without a filter rule, so traffic remains tunneled in
// either policy.
func (s *SplitTunnel) SetPolicy(policy SplitTunnelPolicy) error {
	if !policy.Valid() {
		policy = SplitTunnelPolicyExclude
	}
	invert := policy == SplitTunnelPolicyInclude
	s.access.Lock()
	defer s.access.Unlock()
	if s.inverted.Load() == invert {
		return nil
	}
	prev := s.activeFilter.Invert
	s.activeFilter.Invert = invert
	if err := s.saveLocked(); err != nil {
		s.activeFilter.Invert = prev
		return fmt.Errorf("writing rule to %s: %w", s.ruleFile, err)
	}
	s.inverted.Store(invert)
	s.logger.Log(context.Background(), log.LevelTrace, "Updated split-tunnel policy", "policy", policy)
	return nil
}

// Policy reports the current split-tunnel filter interpretation.
func (s *SplitTunnel) Policy() SplitTunnelPolicy {
	if s.inverted.Load() {
		return SplitTunnelPolicyInclude
	}
	return SplitTunnelPolicyExclude
}

func (s *SplitTunnel) Filters() SplitTunnelFilter {
	s.access.Lock()
	defer s.access.Unlock()
	return SplitTunnelFilter{
		Domain:           slices.Clone(s.ruleMap[TypeDomain].Domain),
		DomainSuffix:     slices.Clone(s.ruleMap[TypeDomainSuffix].DomainSuffix),
		DomainKeyword:    slices.Clone(s.ruleMap[TypeDomainKeyword].DomainKeyword),
		DomainRegex:      slices.Clone(s.ruleMap[TypeDomainRegex].DomainRegex),
		ProcessName:      slices.Clone(s.ruleMap[TypeProcessName].ProcessName),
		ProcessPath:      slices.Clone(s.ruleMap[TypeProcessPath].ProcessPath),
		ProcessPathRegex: slices.Clone(s.ruleMap[TypeProcessPathRegex].ProcessPathRegex),
		PackageName:      slices.Clone(s.ruleMap[TypePackageName].PackageName),
		PackageNameRegex: slices.Clone(s.ruleMap[TypePackageNameRegex].PackageNameRegex),
	}
}

// AddItem adds a new item to the filter of the given type. It returns an error
// wrapping [ErrInvalidSplitTunnelFilter] if item is a regex that fails to compile.
func (s *SplitTunnel) AddItem(filterType, item string) error {
	if err := validateRegex(filterType, item); err != nil {
		return err
	}
	s.access.Lock()
	defer s.access.Unlock()
	if err := s.updateFilterLocked(filterType, item, merge); err != nil {
		return err
	}
	s.logger.Debug("added item to filter", "filterType", filterType)
	if err := s.saveLocked(); err != nil {
		return fmt.Errorf("writing rule to %s: %w", s.ruleFile, err)
	}
	return nil
}

// RemoveItem removes an item from the filter of the given type. The item is not
// validated, so a saved regex that fails to compile can still be removed.
func (s *SplitTunnel) RemoveItem(filterType, item string) error {
	s.access.Lock()
	defer s.access.Unlock()
	if err := s.updateFilterLocked(filterType, item, remove); err != nil {
		return err
	}
	s.logger.Debug("removed item from filter", "filterType", filterType)
	if err := s.saveLocked(); err != nil {
		return fmt.Errorf("writing rule to %s: %w", s.ruleFile, err)
	}
	return nil
}

// AddItems adds multiple items to the filter. It returns an error wrapping
// [ErrInvalidSplitTunnelFilter] if any regex item fails to compile.
func (s *SplitTunnel) AddItems(items SplitTunnelFilter) error {
	for filterType, exprs := range map[string][]string{
		TypeDomainRegex:      items.DomainRegex,
		TypeProcessPathRegex: items.ProcessPathRegex,
		TypePackageNameRegex: items.PackageNameRegex,
	} {
		for _, expr := range exprs {
			if err := validateRegex(filterType, expr); err != nil {
				return err
			}
		}
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.updateFiltersLocked(items, merge)
	s.logger.Debug("added items to filter", "items", items.len())
	return s.saveLocked()
}

// RemoveItems removes multiple items from the filter. Items are not validated,
// so a saved regex that fails to compile can still be removed.
func (s *SplitTunnel) RemoveItems(items SplitTunnelFilter) error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateFiltersLocked(items, remove)
	s.logger.Debug("removed items from filter", "items", items.len())
	return s.saveLocked()
}

// validateRegex rejects regex items that sing-box would fail to compile, which
// would make the split-tunnel rule set, and with it every tunnel start, fail.
func validateRegex(filterType, item string) error {
	switch filterType {
	case TypeDomainRegex, TypeProcessPathRegex, TypePackageNameRegex:
		if _, err := regexp.Compile(item); err != nil {
			return fmt.Errorf("%w: %s %q: %w", ErrInvalidSplitTunnelFilter, filterType, item, err)
		}
	}
	return nil
}

type actionFn func(slice []string, items []string) []string

// updateFilterLocked applies fn to the filter of the given type. The caller
// must hold s.access.
func (s *SplitTunnel) updateFilterLocked(filterType string, item string, fn actionFn) error {
	rule, exist := s.ruleMap[filterType]
	if !exist {
		return fmt.Errorf("unsupported filter type: %s", filterType)
	}

	items := []string{item}
	switch filterType {
	case TypeDomain:
		rule.Domain = fn(rule.Domain, items)
	case TypeDomainSuffix:
		rule.DomainSuffix = fn(rule.DomainSuffix, items)
	case TypeDomainKeyword:
		rule.DomainKeyword = fn(rule.DomainKeyword, items)
	case TypeDomainRegex:
		rule.DomainRegex = fn(rule.DomainRegex, items)
	case TypeProcessName:
		rule.ProcessName = fn(rule.ProcessName, items)
	case TypeProcessPath:
		rule.ProcessPath = fn(rule.ProcessPath, items)
	case TypeProcessPathRegex:
		rule.ProcessPathRegex = fn(rule.ProcessPathRegex, items)
	case TypePackageName:
		rule.PackageName = fn(rule.PackageName, items)
	case TypePackageNameRegex:
		rule.PackageNameRegex = fn(rule.PackageNameRegex, items)
	}
	return nil
}

// updateFiltersLocked applies fn to every filter category present in diff. The
// caller must hold s.access.
func (s *SplitTunnel) updateFiltersLocked(diff SplitTunnelFilter, fn actionFn) {
	s.ruleMap[TypeDomain].Domain = fn(s.ruleMap[TypeDomain].Domain, diff.Domain)
	s.ruleMap[TypeDomainSuffix].DomainSuffix = fn(s.ruleMap[TypeDomainSuffix].DomainSuffix, diff.DomainSuffix)
	s.ruleMap[TypeDomainKeyword].DomainKeyword = fn(s.ruleMap[TypeDomainKeyword].DomainKeyword, diff.DomainKeyword)
	s.ruleMap[TypeDomainRegex].DomainRegex = fn(s.ruleMap[TypeDomainRegex].DomainRegex, diff.DomainRegex)
	s.ruleMap[TypeProcessName].ProcessName = fn(s.ruleMap[TypeProcessName].ProcessName, diff.ProcessName)
	s.ruleMap[TypeProcessPath].ProcessPath = fn(s.ruleMap[TypeProcessPath].ProcessPath, diff.ProcessPath)
	s.ruleMap[TypeProcessPathRegex].ProcessPathRegex = fn(s.ruleMap[TypeProcessPathRegex].ProcessPathRegex, diff.ProcessPathRegex)
	s.ruleMap[TypePackageName].PackageName = fn(s.ruleMap[TypePackageName].PackageName, diff.PackageName)
	s.ruleMap[TypePackageNameRegex].PackageNameRegex = fn(s.ruleMap[TypePackageNameRegex].PackageNameRegex, diff.PackageNameRegex)
}

func merge(slice []string, items []string) []string {
	return append(slice, items...)
}

// remove removes all items in items from s.
func remove(s []string, items []string) []string {
	i := slices.IndexFunc(s, func(v string) bool {
		return slices.Contains(items, v)
	})
	if i == -1 {
		return s // no items to remove
	}
	for j := i + 1; j < len(s); j++ {
		if v := s[j]; !slices.Contains(items, v) {
			s[i] = v
			i++
		}
	}

	clear(s[i:])
	return s[:i]
}

// saveLocked serializes the current rule set to disk. The caller must hold
// s.access: it reads activeFilter.Rules and rule.Mode, which the mutators
// modify under the same lock, so an unsynchronized save can marshal a
// half-updated rule set.
func (s *SplitTunnel) saveLocked() error {
	// Build a serialization-only copy of the rules, filtering out empty entries
	// without mutating the live activeFilter/ruleMap state.
	filterRules := make([]O.HeadlessRule, 0, len(s.activeFilter.Rules))
	for _, r := range s.activeFilter.Rules {
		if !isEmptyRule(r.DefaultOptions) {
			filterRules = append(filterRules, r)
		}
	}
	if s.includeDNSGuardedLocked() {
		filterRules = append(filterRules, includeDNSGuard())
	}

	outerRules := []O.HeadlessRule{s.rule.Rules[0]} // disable rule
	if len(filterRules) > 0 {
		outerRules = append(outerRules, O.HeadlessRule{
			Type: s.rule.Rules[1].Type,
			LogicalOptions: O.LogicalHeadlessRule{
				Mode:   s.activeFilter.Mode,
				Rules:  filterRules,
				Invert: s.activeFilter.Invert,
			},
		})
	}

	rs := O.PlainRuleSetCompat{
		Version: 3,
		Options: O.PlainRuleSet{
			Rules: []O.HeadlessRule{
				{
					Type: "logical",
					LogicalOptions: O.LogicalHeadlessRule{
						Mode:  s.rule.Mode,
						Rules: outerRules,
					},
				},
			},
		},
	}
	buf, err := json.Marshal(rs)
	if err != nil {
		return fmt.Errorf("marshalling rule set: %w", err)
	}
	// Every write reloads the tunnel's rule set, which closes all connections.
	if cur, err := os.ReadFile(s.ruleFile); err == nil && bytes.Equal(cur, buf) {
		return nil
	}
	if err := atomicfile.WriteFile(s.ruleFile, buf, fileperm.File); err != nil {
		return fmt.Errorf("writing rule file %s: %w", s.ruleFile, err)
	}
	return nil
}

// includeDNSGuard is added to an include-policy filter so the inverted filter
// never matches A or AAAA queries. Inverted, the filter matches nearly every
// lookup, including an included app's, which the OS resolver usually sends, so
// each would first wait on the system resolver. Route evaluation has no query
// type, so routing is unaffected.
func includeDNSGuard() O.HeadlessRule {
	return O.HeadlessRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: O.DefaultHeadlessRule{
			QueryType: badoption.Listable[O.DNSQueryType]{O.DNSQueryType(dns.TypeA), O.DNSQueryType(dns.TypeAAAA)},
		},
	}
}

func isIncludeDNSGuard(r O.HeadlessRule) bool {
	return reflect.DeepEqual(r, includeDNSGuard())
}

// includeDNSGuardedLocked reports whether saveLocked writes [includeDNSGuard]
// for the current filter. The caller must hold s.access.
func (s *SplitTunnel) includeDNSGuardedLocked() bool {
	return s.activeFilter.Invert && slices.ContainsFunc(s.activeFilter.Rules, func(r O.HeadlessRule) bool {
		return !isEmptyRule(r.DefaultOptions)
	})
}

func isEmptyRule(rule O.DefaultHeadlessRule) bool {
	return len(rule.Domain) == 0 && len(rule.DomainSuffix) == 0 &&
		len(rule.DomainKeyword) == 0 && len(rule.DomainRegex) == 0 &&
		len(rule.ProcessName) == 0 && len(rule.PackageName) == 0 &&
		len(rule.ProcessPath) == 0 && len(rule.ProcessPathRegex) == 0 &&
		len(rule.PackageNameRegex) == 0
}

func validateSplitTunnelRule(rules []O.HeadlessRule) error {
	if len(rules) != 1 || rules[0].Type != C.RuleTypeLogical {
		return errors.New("expected a single logical split tunnel rule")
	}
	root := rules[0].LogicalOptions
	if root.Invert || (root.Mode != C.LogicalTypeAnd && root.Mode != C.LogicalTypeOr) {
		return errors.New("invalid split tunnel rule mode")
	}
	if len(root.Rules) < 1 || len(root.Rules) > 2 ||
		!reflect.DeepEqual(root.Rules[0], defaultRule().Rules[0]) {
		return errors.New("invalid split tunnel disable rule")
	}
	if len(root.Rules) == 2 {
		filter := root.Rules[1]
		switch filter.Type {
		case C.RuleTypeDefault:
		case C.RuleTypeLogical:
			if filter.LogicalOptions.Mode != C.LogicalTypeOr {
				return errors.New("invalid split tunnel filter mode")
			}
			for _, rule := range filter.LogicalOptions.Rules {
				if rule.Type != C.RuleTypeDefault {
					return errors.New("invalid split tunnel filter rule")
				}
			}
		default:
			return errors.New("invalid split tunnel filter type")
		}
	}
	return nil
}

func (s *SplitTunnel) loadRule() error {
	rawRuleSet, err := atomicfile.ReadFile(s.ruleFile)
	// the file should exist at this point, so we don't need to check for fs.ErrNotExist
	if err != nil {
		return fmt.Errorf("reading rule file %s: %w", s.ruleFile, err)
	}
	ruleSet, err := json.UnmarshalExtended[O.PlainRuleSetCompat](rawRuleSet)
	if err != nil {
		s.quarantineInvalidRuleSet(rawRuleSet)
		return fmt.Errorf("unmarshalling rule file %s: %w", s.ruleFile, err)
	}
	rules := ruleSet.Options.Rules
	if err := validateSplitTunnelRule(rules); err != nil {
		s.quarantineInvalidRuleSet(rawRuleSet)
		return fmt.Errorf("validating rule file %s: %w", s.ruleFile, err)
	}

	s.rule = rules[0].LogicalOptions
	if len(s.rule.Rules) == 1 {
		s.rule.Rules = append(s.rule.Rules, O.HeadlessRule{
			Type: C.RuleTypeLogical,
			LogicalOptions: O.LogicalHeadlessRule{
				Mode:  C.LogicalTypeOr,
				Rules: []O.HeadlessRule{},
			},
		})
	} else if s.rule.Rules[1].Type == C.RuleTypeDefault {
		// TODO: drop this migration once all persisted rules use the LogicalOptions
		// format; kept for now to stay compatible with configs written by older builds.
		s.logger.Debug("Migrating legacy split tunnel rule format")
		legacyRule := s.rule.Rules[1].DefaultOptions
		s.rule.Rules[1] = O.HeadlessRule{
			Type: C.RuleTypeLogical,
			LogicalOptions: O.LogicalHeadlessRule{
				Mode:  C.LogicalTypeOr,
				Rules: []O.HeadlessRule{},
			},
		}
		if len(legacyRule.Domain) > 0 ||
			len(legacyRule.DomainSuffix) > 0 ||
			len(legacyRule.DomainKeyword) > 0 ||
			len(legacyRule.DomainRegex) > 0 {
			s.rule.Rules[1].LogicalOptions.Rules = append(s.rule.Rules[1].LogicalOptions.Rules, O.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{
					Domain:        legacyRule.Domain,
					DomainSuffix:  legacyRule.DomainSuffix,
					DomainKeyword: legacyRule.DomainKeyword,
					DomainRegex:   legacyRule.DomainRegex,
				},
			})
		}
		if len(legacyRule.PackageName) > 0 {
			s.rule.Rules[1].LogicalOptions.Rules = append(s.rule.Rules[1].LogicalOptions.Rules, O.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{
					PackageName: legacyRule.PackageName,
				},
			})
		}
		if len(legacyRule.ProcessName) > 0 {
			s.rule.Rules[1].LogicalOptions.Rules = append(s.rule.Rules[1].LogicalOptions.Rules, O.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{
					ProcessName: legacyRule.ProcessName,
				},
			})
		}
		if len(legacyRule.ProcessPath) > 0 {
			s.rule.Rules[1].LogicalOptions.Rules = append(s.rule.Rules[1].LogicalOptions.Rules, O.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{
					ProcessPath: legacyRule.ProcessPath,
				},
			})
		}
		if len(legacyRule.ProcessPathRegex) > 0 {
			s.rule.Rules[1].LogicalOptions.Rules = append(s.rule.Rules[1].LogicalOptions.Rules, O.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{
					ProcessPathRegex: legacyRule.ProcessPathRegex,
				},
			})
		}
	}
	filter := &s.rule.Rules[1].LogicalOptions
	guarded := slices.ContainsFunc(filter.Rules, isIncludeDNSGuard)
	filter.Rules = slices.DeleteFunc(filter.Rules, isIncludeDNSGuard)
	// Only the guard may carry a query type: routing never matches a rule that
	// has one.
	strayQueryType := false
	for i := range filter.Rules {
		if len(filter.Rules[i].DefaultOptions.QueryType) > 0 {
			filter.Rules[i].DefaultOptions.QueryType = nil
			strayQueryType = true
		}
	}
	s.activeFilter = filter
	s.initRuleMap()
	s.enabled.Store(s.rule.Mode == C.LogicalTypeOr)
	s.inverted.Store(s.activeFilter.Invert)

	// The tunnel reads the file directly, so a file whose query types don't
	// match its policy must be rewritten before the tunnel uses it.
	s.access.Lock()
	if strayQueryType || guarded != s.includeDNSGuardedLocked() {
		if err := s.saveLocked(); err != nil {
			s.logger.Error("Rewriting split tunnel rule file", "file", s.ruleFile, "error", err)
		}
	}
	s.access.Unlock()

	s.logger.Log(context.Background(), log.LevelTrace, "loaded split tunnel rules",
		"file", s.ruleFile, "filters", s.Filters().len(),
		"enabled", s.IsEnabled(), "policy", s.Policy(),
	)
	return nil
}

// quarantineInvalidRuleSet copies content to split-tunnel.invalid.json without modifying the rule
// file, so the invalid rules survive the next save that replaces it.
func (s *SplitTunnel) quarantineInvalidRuleSet(content []byte) {
	invalidPath := filepath.Join(filepath.Dir(s.ruleFile), internal.SplitTunnelInvalidFileName)
	if err := atomicfile.WriteFile(invalidPath, content, fileperm.File); err != nil {
		s.logger.Error("Writing invalid split tunnel copy", "path", invalidPath, "error", err)
		return
	}
	s.logger.Warn("Saved invalid split tunnel rules for diagnostics", "path", invalidPath)
}

func defaultRule() O.LogicalHeadlessRule {
	// We use the logical rule type, here, like a logic gate. The first rule (inner logical rule)
	// acts as the "disable" state and the second is the actual filter. The "disable" rule basically
	// equates to "isEqual && !isEqual", which is always false. Switching the outter logical rule
	// mode between "or" and "and", effectively enables or disables split tunneling, respectively.
	return O.LogicalHeadlessRule{
		Mode: C.LogicalTypeAnd,
		Rules: []O.HeadlessRule{
			{
				Type: C.RuleTypeLogical,
				LogicalOptions: O.LogicalHeadlessRule{
					Mode: C.LogicalTypeAnd,
					Rules: []O.HeadlessRule{
						{
							Type:           C.RuleTypeDefault,
							DefaultOptions: O.DefaultHeadlessRule{Domain: []string{"disable.rule"}},
						},
						{
							Type:           C.RuleTypeDefault,
							DefaultOptions: O.DefaultHeadlessRule{Domain: []string{"disable.rule"}, Invert: true},
						},
					},
				},
			},
			{
				Type: C.RuleTypeLogical,
				LogicalOptions: O.LogicalHeadlessRule{
					Mode:  C.LogicalTypeOr,
					Rules: []O.HeadlessRule{},
				},
			},
		},
	}
}

func (s *SplitTunnel) initRuleMap() {
	s.ruleMap = make(map[string]*O.DefaultHeadlessRule)

	categories := []string{TypeDomain, TypeProcessName, TypeProcessPath, TypeProcessPathRegex, TypePackageName, TypePackageNameRegex}

	// First pass: find which categories already have rules, and ensure empty
	// rules exist for the rest. All appends happen before any pointers are
	// stored so that slice reallocation cannot invalidate them.
	found := make(map[string]bool, len(categories))
	for i := range s.activeFilter.Rules {
		rule := &s.activeFilter.Rules[i].DefaultOptions
		if len(rule.Domain) > 0 || len(rule.DomainSuffix) > 0 ||
			len(rule.DomainKeyword) > 0 || len(rule.DomainRegex) > 0 {
			found[TypeDomain] = true
		}
		if len(rule.ProcessName) > 0 {
			found[TypeProcessName] = true
		}
		if len(rule.ProcessPath) > 0 {
			found[TypeProcessPath] = true
		}
		if len(rule.ProcessPathRegex) > 0 {
			found[TypeProcessPathRegex] = true
		}
		if len(rule.PackageName) > 0 {
			found[TypePackageName] = true
		}
		if len(rule.PackageNameRegex) > 0 {
			found[TypePackageNameRegex] = true
		}
	}
	for _, cat := range categories {
		if !found[cat] {
			s.activeFilter.Rules = append(s.activeFilter.Rules, O.HeadlessRule{
				Type:           C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{},
			})
		}
	}

	// Second pass: the slice is now stable — store pointers into ruleMap.
	// Empty rules are assigned to the first unmatched category.
	emptyIdx := 0
	missing := make([]string, 0, len(categories))
	for _, cat := range categories {
		if !found[cat] {
			missing = append(missing, cat)
		}
	}
	for i := range s.activeFilter.Rules {
		rule := &s.activeFilter.Rules[i].DefaultOptions
		matched := false
		if len(rule.Domain) > 0 || len(rule.DomainSuffix) > 0 ||
			len(rule.DomainKeyword) > 0 || len(rule.DomainRegex) > 0 {
			s.ruleMap[TypeDomain] = rule
			matched = true
		}
		if len(rule.ProcessName) > 0 {
			s.ruleMap[TypeProcessName] = rule
			matched = true
		}
		if len(rule.ProcessPath) > 0 {
			s.ruleMap[TypeProcessPath] = rule
			matched = true
		}
		if len(rule.ProcessPathRegex) > 0 {
			s.ruleMap[TypeProcessPathRegex] = rule
			matched = true
		}
		if len(rule.PackageName) > 0 {
			s.ruleMap[TypePackageName] = rule
			matched = true
		}
		if len(rule.PackageNameRegex) > 0 {
			s.ruleMap[TypePackageNameRegex] = rule
			matched = true
		}
		if !matched && emptyIdx < len(missing) {
			s.ruleMap[missing[emptyIdx]] = rule
			emptyIdx++
		}
	}

	s.ruleMap[TypeDomainKeyword] = s.ruleMap[TypeDomain]
	s.ruleMap[TypeDomainRegex] = s.ruleMap[TypeDomain]
	s.ruleMap[TypeDomainSuffix] = s.ruleMap[TypeDomain]
}
