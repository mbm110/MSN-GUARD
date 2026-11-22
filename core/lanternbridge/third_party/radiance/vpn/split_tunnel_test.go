//go:build !novpn

package vpn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	O "github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/internal"
	rlog "github.com/getlantern/radiance/log"
)

func TestNewSplitTunnelHandlerQuarantinesInvalidRuleFile(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, internal.SplitTunnelFileName)
	// A rule file this build's sing-box can't decode — the shape a downgrade
	// leaves behind. Staged before construction so newSplitTunnel won't replace it.
	require.NoError(t, atomicfile.WriteFile(ruleFile,
		[]byte(`{"version":3,"rules":[{"unknown_field":true}]}`), 0o600))

	st, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.Error(t, err, "an unparseable rule file must be reported to the caller")
	require.NotNil(t, st, "handler must be usable despite the load error")

	// Falls back to the default no-op rule.
	assert.Empty(t, st.Filters().Domain)
	assert.False(t, st.IsEnabled())

	invalidPath := filepath.Join(tmpDir, internal.SplitTunnelInvalidFileName)
	assert.FileExists(t, invalidPath, "the unparseable file must be preserved for diagnostics")
	assert.FileExists(t, ruleFile, "loading must not remove the source file")
}

func TestInvalidCopySurvivesSave(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		wantErr string
	}{
		{"unparseable", `{"version":3,"rules":[{"unknown_field":true}]}`, "unmarshalling rule file"},
		{"invalid envelope", `{"version":3,"rules":[{"domain":"example.com"}]}`, "validating rule file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, internal.SplitTunnelFileName)
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))
			st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
			require.ErrorContains(t, err, tt.wantErr)
			require.NotNil(t, st)

			require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))
			assert.Equal(t, SplitTunnelPolicyInclude, st.Policy())
			assert.False(t, st.IsEnabled())
			assert.Empty(t, st.Filters().Domain)
			current, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.NotEqual(t, tt.content, string(current))
			_, err = json.UnmarshalExtended[O.PlainRuleSetCompat](current)
			require.NoError(t, err)
			saved, err := os.ReadFile(filepath.Join(dir, internal.SplitTunnelInvalidFileName))
			require.NoError(t, err)
			assert.Equal(t, tt.content, string(saved))
		})
	}
}

func writeRuleSet(t *testing.T, dir string, rs O.PlainRuleSet) []byte {
	t.Helper()
	content, err := json.Marshal(O.PlainRuleSetCompat{Version: 3, Options: rs})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, internal.SplitTunnelFileName), content, 0o600))
	return content
}

func TestRejectInvalidEnvelope(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*O.PlainRuleSet)
	}{
		{"no root", func(rs *O.PlainRuleSet) { rs.Rules = nil }},
		{"plain root", func(rs *O.PlainRuleSet) {
			rs.Rules[0] = O.HeadlessRule{
				Type: C.RuleTypeDefault, DefaultOptions: O.DefaultHeadlessRule{Domain: []string{"example.com"}},
			}
		}},
		{"multiple roots", func(rs *O.PlainRuleSet) { rs.Rules = append(rs.Rules, rs.Rules[0]) }},
		{"empty logical root", func(rs *O.PlainRuleSet) { rs.Rules[0].LogicalOptions.Rules = nil }},
		{"inverted root", func(rs *O.PlainRuleSet) { rs.Rules[0].LogicalOptions.Invert = true }},
		{"invalid root mode", func(rs *O.PlainRuleSet) { rs.Rules[0].LogicalOptions.Mode = "xor" }},
		{"missing disable rule", func(rs *O.PlainRuleSet) {
			rs.Rules[0].LogicalOptions.Rules = rs.Rules[0].LogicalOptions.Rules[1:]
		}},
		{"invalid disable rule", func(rs *O.PlainRuleSet) {
			rs.Rules[0].LogicalOptions.Rules[0].LogicalOptions.Mode = C.LogicalTypeOr
		}},
		{"extra child", func(rs *O.PlainRuleSet) {
			root := &rs.Rules[0].LogicalOptions
			root.Rules = append(root.Rules, root.Rules[1])
		}},
		{"invalid filter mode", func(rs *O.PlainRuleSet) {
			rs.Rules[0].LogicalOptions.Rules[1].LogicalOptions.Mode = C.LogicalTypeAnd
		}},
		{"nested filter", func(rs *O.PlainRuleSet) {
			root := &rs.Rules[0].LogicalOptions
			root.Rules[1].LogicalOptions.Rules = []O.HeadlessRule{root.Rules[0]}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rs := O.PlainRuleSet{Rules: []O.HeadlessRule{{Type: C.RuleTypeLogical, LogicalOptions: defaultRule()}}}
			tt.edit(&rs)
			dir := t.TempDir()
			content := writeRuleSet(t, dir, rs)
			_, err := json.UnmarshalExtended[O.PlainRuleSetCompat](content)
			require.NoError(t, err, "fixture must decode before envelope validation")

			st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
			require.ErrorContains(t, err, "validating rule file")
			require.NotNil(t, st)
			assert.False(t, st.IsEnabled())
			assert.Equal(t, SplitTunnelPolicyExclude, st.Policy())
			assert.Empty(t, st.Filters().Domain)
			for _, name := range []string{internal.SplitTunnelFileName, internal.SplitTunnelInvalidFileName} {
				got, err := os.ReadFile(filepath.Join(dir, name))
				require.NoError(t, err)
				assert.Equal(t, content, got)
			}
			require.NoError(t, st.AddItem(TypeDomain, "example.org"))
			assert.Equal(t, []string{"example.org"}, st.Filters().Domain)
		})
	}
}

func TestLoadEquivalentDisableRule(t *testing.T) {
	content := `{"version":3,"rules":[{"type":"logical","mode":"or","rules":[
		{"type":"logical","mode":"and","invert":false,"rules":[
			{"domain":"disable.rule","domain_suffix":[]},
			{"domain":["disable.rule"],"domain_suffix":[],"invert":true}
		]},
		{"type":"logical","mode":"or","rules":[{"domain":"example.com"}]}
	]}]}`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, internal.SplitTunnelFileName), []byte(content), 0o600))

	st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.True(t, st.IsEnabled())
	assert.Equal(t, []string{"example.com"}, st.Filters().Domain)
	assert.NoFileExists(t, filepath.Join(dir, internal.SplitTunnelInvalidFileName))
}

func TestLoadEmptyEnvelope(t *testing.T) {
	for _, children := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d children", children), func(t *testing.T) {
			root := defaultRule()
			root.Mode = C.LogicalTypeOr
			root.Rules = root.Rules[:children]
			dir := t.TempDir()
			writeRuleSet(t, dir, O.PlainRuleSet{Rules: []O.HeadlessRule{{Type: C.RuleTypeLogical, LogicalOptions: root}}})

			st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
			require.NoError(t, err)
			assert.True(t, st.IsEnabled())
			assert.Empty(t, st.Filters().Domain)
			require.NoError(t, st.AddItem(TypeDomain, "example.org"))
			reloaded, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
			require.NoError(t, err)
			assert.Equal(t, []string{"example.org"}, reloaded.Filters().Domain)
		})
	}
}

func TestEnableDisableIsEnabled(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())

	if assert.NoError(t, st.SetEnabled(false)) {
		assert.False(t, st.IsEnabled(), "split tunnel should be disabled")
	}
	if assert.NoError(t, st.SetEnabled(true)) {
		assert.True(t, st.IsEnabled(), "split tunnel should be enabled")
	}
}

func TestAddRemoveItem(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())

	domain := "example.com"
	domain2 := "example2.com"
	packageName := "com.example"

	t.Run("adding domain item must update domain filter", func(t *testing.T) {
		require.NoError(t, st.AddItem(TypeDomain, domain))
		f := st.Filters()
		assert.Equal(t, []string{domain}, f.Domain)
	})

	t.Run("adding second domain must update the filter and contain both domains", func(t *testing.T) {
		require.NoError(t, st.AddItem(TypeDomain, domain2))
		f := st.Filters()
		assert.Equal(t, []string{domain, domain2}, f.Domain)
	})

	t.Run("adding package domain must update package filter", func(t *testing.T) {
		require.NoError(t, st.AddItem(TypePackageName, packageName))
		f := st.Filters()
		assert.Equal(t, []string{packageName}, f.PackageName)
	})

	t.Run("removing domain must update domain filter", func(t *testing.T) {
		require.NoError(t, st.RemoveItem(TypeDomain, domain))
		f := st.Filters()
		assert.NotContains(t, f.Domain, domain)
		assert.NotEmpty(t, f.PackageName)
	})
}

func TestRemoveItems(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())

	require.NoError(t, st.RemoveItems(SplitTunnelFilter{Domain: []string{"a.com"}, ProcessName: []string{"proc"}}))
	f := st.Filters()
	assert.Empty(t, f.Domain)
	assert.Empty(t, f.ProcessName)
}

func TestAddRemoveItems(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())

	items := SplitTunnelFilter{
		Domain:       []string{"a.com", "b.com"},
		DomainSuffix: []string{"suffix"},
		ProcessName:  []string{"proc"},
		PackageName:  []string{"pkg"},
	}
	err := st.AddItems(items)
	require.NoError(t, err)
	f := st.Filters()
	assert.ElementsMatch(t, []string{"a.com", "b.com"}, f.Domain)
	assert.Equal(t, []string{"suffix"}, f.DomainSuffix)
	assert.Equal(t, []string{"proc"}, f.ProcessName)
	assert.Equal(t, []string{"pkg"}, f.PackageName)

	err = st.RemoveItems(SplitTunnelFilter{Domain: []string{"a.com"}, ProcessName: []string{"proc"}})
	require.NoError(t, err)
	f = st.Filters()
	assert.Equal(t, []string{"b.com"}, f.Domain)
	assert.Empty(t, f.ProcessName)
}

// TestConcurrentMutationPersistsParseableRuleSet drives the mutators
// concurrently: they share activeFilter.Rules and rule.Mode, so without holding
// s.access across the mutate and the subsequent save, saveLocked reads those
// fields while another goroutine modifies them — flagged by -race and capable
// of serializing a torn rule set.
func TestConcurrentMutationPersistsParseableRuleSet(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	record := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}
	for i := range 20 {
		wg.Go(func() {
			domain := fmt.Sprintf("d%d.example.com", i)
			record(st.AddItems(SplitTunnelFilter{Domain: []string{domain}, ProcessName: []string{fmt.Sprintf("p%d", i)}}))
			record(st.SetEnabled(i%2 == 0))
			record(st.RemoveItems(SplitTunnelFilter{Domain: []string{domain}}))
		})
	}
	wg.Wait()
	assert.Empty(t, errs, "concurrent mutations must all succeed")

	_, err = NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err, "rule set persisted under concurrent mutation must still parse")
}

func TestFilterPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	require.NoError(t, st.AddItem("domain", "example.com"))

	f := st.Filters()
	assert.Equal(t, []string{"example.com"}, f.Domain)

	st, err = NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	f = st.Filters()
	assert.Equal(t, []string{"example.com"}, f.Domain, "expected filters to persist after reloading from file")
}

func TestFilterPersistenceAfterLoad(t *testing.T) {
	tmpDir := t.TempDir()
	// Simulate the daemon path: NewSplitTunnelHandler (newSplitTunnel + loadRule), then AddItems
	st, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)

	require.NoError(t, st.AddItems(SplitTunnelFilter{Domain: []string{"example.com"}}))
	f := st.Filters()
	assert.Equal(t, []string{"example.com"}, f.Domain, "filter should be set in memory after AddItems")

	// Reload from disk to verify persistence
	st2, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	f = st2.Filters()
	assert.Equal(t, []string{"example.com"}, f.Domain, "filter should persist to disk after AddItems")
}

func TestUpdateFilterUnsupportedType(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	err := st.AddItem("unsupported", "foo")
	assert.Error(t, err)
}

func TestRemoveEdgeCases(t *testing.T) {
	// Remove from empty slice
	out := remove([]string{}, []string{"a"})
	assert.Empty(t, out)
	// Remove with empty items
	out = remove([]string{"a"}, []string{})
	assert.Equal(t, []string{"a"}, out)
	// Remove non-existent item
	out = remove([]string{"a"}, []string{"b"})
	assert.Equal(t, []string{"a"}, out)
	// Remove existing item
	out = remove([]string{"a", "b"}, []string{"a"})
	assert.Len(t, out, 1)
	assert.NotContains(t, out, "a")
	// Remove multiple items
	out = remove([]string{"a", "b", "c"}, []string{"a", "c"})
	assert.Equal(t, []string{"b"}, out)
}

func TestMatch(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.NoError(t, st.AddItem("domain", "example.com"))

	ruleOpts := O.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: O.DefaultRule{
			RawDefaultRule: O.RawDefaultRule{
				RuleSet: []string{splitTunnelTag},
			},
			RuleAction: O.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: O.RouteActionOptions{
					Outbound: "direct",
				},
			},
		},
	}
	rsetOpts := O.RuleSet{
		Type: C.RuleSetTypeLocal,
		Tag:  badoption.Listable[string]{splitTunnelTag},
		LocalOptions: O.LocalRuleSet{
			Path: st.ruleFile,
		},
		Format: C.RuleSetFormatSource,
	}

	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().Logger()

	router := &mockRouter{}
	service.MustRegister[adapter.Router](ctx, router)
	service.MustRegister(ctx, new(adapter.NetworkManager))

	ruleSet, err := R.NewRuleSet(ctx, logger, splitTunnelTag, rsetOpts)
	require.NoError(t, err)
	require.NoError(t, ruleSet.StartContext(ctx, new(adapter.HTTPStartContext)))
	defer ruleSet.Close()

	router.ruleSet = ruleSet

	rule, err := R.NewRule(ctx, logger, ruleOpts, false)
	require.NoError(t, err)
	require.NoError(t, rule.Start())
	defer rule.Close()

	metadata := &adapter.InboundContext{Domain: "example.com"}

	rsStr := ruleSet.String()
	require.NoError(t, st.SetEnabled(true))
	require.Eventually(t, func() bool {
		return ruleSet.String() != rsStr
	}, time.Second, 50*time.Millisecond, "timed out waiting for rule reload")

	assert.True(t, rule.Match(metadata), "rule should match when split tunnel is enabled")

	rsStr = ruleSet.String()
	require.NoError(t, st.SetEnabled(false))
	require.Eventually(t, func() bool {
		return ruleSet.String() != rsStr
	}, time.Second, 50*time.Millisecond, "timed out waiting for rule reload")

	assert.False(t, rule.Match(metadata), "rule should not match when split tunnel is not enabled")
}

type mockRouter struct {
	adapter.Router
	ruleSet adapter.RuleSet
}

func (r *mockRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	return r.ruleSet, r.ruleSet != nil
}

// splitTunnelMatcher builds a live route rule from st's saved rule file.
// waitReload blocks until the rule set reflects the latest saved state.
// A match means the connection is routed direct.
func splitTunnelMatcher(t *testing.T, st *SplitTunnel) (rule adapter.Rule, waitReload func()) {
	t.Helper()
	ruleOpts := O.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: O.DefaultRule{
			RawDefaultRule: O.RawDefaultRule{RuleSet: []string{splitTunnelTag}},
			RuleAction: O.RuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: O.RouteActionOptions{Outbound: "direct"},
			},
		},
	}
	rsetOpts := O.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Tag:          badoption.Listable[string]{splitTunnelTag},
		LocalOptions: O.LocalRuleSet{Path: st.ruleFile},
		Format:       C.RuleSetFormatSource,
	}

	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().Logger()
	router := &mockRouter{}
	service.MustRegister[adapter.Router](ctx, router)
	service.MustRegister(ctx, new(adapter.NetworkManager))

	ruleSet, err := R.NewRuleSet(ctx, logger, splitTunnelTag, rsetOpts)
	require.NoError(t, err)
	require.NoError(t, ruleSet.StartContext(ctx, new(adapter.HTTPStartContext)))
	t.Cleanup(func() { ruleSet.Close() })
	router.ruleSet = ruleSet

	rule, err = R.NewRule(ctx, logger, ruleOpts, false)
	require.NoError(t, err)
	require.NoError(t, rule.Start())
	t.Cleanup(func() { rule.Close() })

	last := ruleSet.String()
	waitReload = func() {
		t.Helper()
		require.Eventually(t, func() bool {
			return ruleSet.String() != last
		}, time.Second, 50*time.Millisecond, "timed out waiting for rule reload")
		last = ruleSet.String()
	}
	return rule, waitReload
}

func TestPackageNameRegex(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	require.NoError(t, st.SetEnabled(true))
	require.NoError(t, st.AddItems(SplitTunnelFilter{
		PackageName:      []string{"com.example.exact"},
		PackageNameRegex: []string{`^org\.telegram\.`},
	}))

	reloaded, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	f := reloaded.Filters()
	assert.Equal(t, []string{"com.example.exact"}, f.PackageName)
	assert.Equal(t, []string{`^org\.telegram\.`}, f.PackageNameRegex)

	rule, waitReload := splitTunnelMatcher(t, st)
	owner := func(pkg string) *adapter.InboundContext {
		return &adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{AndroidPackageNames: []string{pkg}}}
	}
	assert.True(t, rule.Match(owner("org.telegram.messenger")))
	assert.True(t, rule.Match(owner("com.example.exact")))
	assert.False(t, rule.Match(owner("com.example.other")))

	require.NoError(t, st.RemoveItems(SplitTunnelFilter{PackageNameRegex: []string{`^org\.telegram\.`}}))
	waitReload()
	assert.False(t, rule.Match(owner("org.telegram.messenger")))
	assert.True(t, rule.Match(owner("com.example.exact")))

	require.NoError(t, st.AddItem(TypePackageNameRegex, `^com\.bank\.`))
	waitReload()
	assert.True(t, rule.Match(owner("com.bank.app")))
	require.NoError(t, st.RemoveItem(TypePackageNameRegex, `^com\.bank\.`))
	waitReload()
	assert.False(t, rule.Match(owner("com.bank.app")))
	assert.Empty(t, st.Filters().PackageNameRegex)
}

func TestRejectInvalidRegex(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.NoError(t, st.SetEnabled(true))
	require.NoError(t, st.AddItem(TypeDomain, "kept.com"))
	want := st.Filters()

	for _, typ := range []string{TypeDomainRegex, TypeProcessPathRegex, TypePackageNameRegex} {
		assert.ErrorIs(t, st.AddItem(typ, "*.example.com"), ErrInvalidSplitTunnelFilter, typ)
	}
	for _, f := range []SplitTunnelFilter{
		{Domain: []string{"added.com"}, DomainRegex: []string{"("}},
		{ProcessName: []string{"proc"}, ProcessPathRegex: []string{"["}},
		{PackageName: []string{"com.pkg"}, PackageNameRegex: []string{"*"}},
	} {
		assert.ErrorIs(t, st.AddItems(f), ErrInvalidSplitTunnelFilter, f.String())
	}
	assert.Equal(t, want, st.Filters())

	// The saved rule set must still load in sing-box.
	rule, _ := splitTunnelMatcher(t, st)
	assert.True(t, rule.Match(&adapter.InboundContext{Domain: "kept.com"}))
}

func TestRemoveSavedInvalidRegex(t *testing.T) {
	dir := t.TempDir()
	older := newSplitTunnel(dir, rlog.NoOpLogger())
	require.NoError(t, older.SetEnabled(true))
	require.NoError(t, older.AddItem(TypeDomain, "kept.com"))
	older.access.Lock()
	older.ruleMap[TypeDomainRegex].DomainRegex = append(older.ruleMap[TypeDomainRegex].DomainRegex, "*.example.com")
	require.NoError(t, older.saveLocked())
	older.access.Unlock()

	st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	require.Equal(t, []string{"*.example.com"}, st.Filters().DomainRegex)
	require.NoError(t, st.RemoveItem(TypeDomainRegex, "*.example.com"))

	rule, _ := splitTunnelMatcher(t, st)
	assert.True(t, rule.Match(&adapter.InboundContext{Domain: "kept.com"}))
}

func TestPolicyInvertsMatch(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.NoError(t, st.AddItem(TypeDomain, "example.com"))

	rule, waitReload := splitTunnelMatcher(t, st)
	matched := &adapter.InboundContext{Domain: "example.com"}
	unmatched := &adapter.InboundContext{Domain: "other.com"}

	require.NoError(t, st.SetEnabled(true))
	waitReload()

	assert.True(t, rule.Match(matched), "exclude: matched should route direct")
	assert.False(t, rule.Match(unmatched), "exclude: unmatched should stay tunneled")

	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))
	waitReload()

	assert.False(t, rule.Match(matched), "include: matched should stay tunneled")
	assert.True(t, rule.Match(unmatched), "include: unmatched should route direct")
}

func TestEmptyFilterModeInert(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.NoError(t, st.SetEnabled(true))
	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))

	// Build the matcher after the state is set; an empty filter serializes to a
	// disable-only rule set whose stringified form doesn't change on the
	// enable/policy toggle, so there is no reload edge to wait on.
	rule, _ := splitTunnelMatcher(t, st)

	assert.False(t, rule.Match(&adapter.InboundContext{Domain: "anything.com"}),
		"empty include filter should tunnel everything (route nothing direct)")
}

func TestPolicyPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	require.Equal(t, SplitTunnelPolicyExclude, st.Policy(), "default policy should be exclude")

	require.NoError(t, st.AddItem(TypeDomain, "example.com"))
	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))

	st2, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.Equal(t, SplitTunnelPolicyInclude, st2.Policy(), "policy should persist across reload")
	assert.ElementsMatch(t, []string{"example.com"}, st2.Filters().Domain)
}

func TestEmptyFilterPolicyReloadAndReconcile(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude)) // empty filter

	st2, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	require.Equal(t, SplitTunnelPolicyExclude, st2.Policy(), "empty-filter policy is not persisted across reload")

	// Reconcile from the durable intent, then add an item so it persists.
	require.NoError(t, st2.SetPolicy(SplitTunnelPolicyInclude))
	require.NoError(t, st2.AddItem(TypeDomain, "example.com"))

	st3, err := NewSplitTunnelHandler(tmpDir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.Equal(t, SplitTunnelPolicyInclude, st3.Policy(), "policy persists once the filter is non-empty")
}

func TestSetPolicyIdempotentAndDefaults(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.Equal(t, SplitTunnelPolicyExclude, st.Policy())

	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))
	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude)) // no-op when already in policy
	assert.Equal(t, SplitTunnelPolicyInclude, st.Policy())

	require.NoError(t, st.SetPolicy(SplitTunnelPolicyExclude))
	assert.Equal(t, SplitTunnelPolicyExclude, st.Policy())

	require.NoError(t, st.SetPolicy(SplitTunnelPolicy("bogus")), "unrecognized policy is treated as exclude")
	assert.Equal(t, SplitTunnelPolicyExclude, st.Policy())
}

func TestMigration(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())

	// Create a legacy format rule file
	legacyRule := O.LogicalHeadlessRule{
		Mode: C.LogicalTypeOr,
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
				Type: C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{
					Domain:           []string{"example.com", "test.com"},
					DomainSuffix:     []string{".org"},
					DomainKeyword:    []string{"keyword"},
					DomainRegex:      []string{".*\\.io$"},
					PackageName:      []string{"com.example.app"},
					ProcessName:      []string{"chrome"},
					ProcessPath:      []string{"/usr/bin/firefox"},
					ProcessPathRegex: []string{"/opt/.*"},
				},
			},
		},
	}

	// Write legacy format to file
	rs := O.PlainRuleSetCompat{
		Version: 3,
		Options: O.PlainRuleSet{
			Rules: []O.HeadlessRule{
				{
					Type:           "logical",
					LogicalOptions: legacyRule,
				},
			},
		},
	}
	buf, err := json.Marshal(rs)
	require.NoError(t, err)
	err = atomicfile.WriteFile(st.ruleFile, buf, 0644)
	require.NoError(t, err)

	// Load the legacy format
	err = st.loadRule()
	require.NoError(t, err)
	want := `{
	"type": "logical",
	"mode": "or",
	"rules": [
		{
			"type": "logical",
			"mode": "and",
			"rules": [
				{
					"domain": "disable.rule"
				},
				{
					"domain": "disable.rule",
					"invert": true
				}
			]
		},
		{
			"type": "logical",
			"mode": "or",
			"rules": [
				{
					"domain": ["example.com", "test.com"],
					"domain_suffix": ".org",
					"domain_keyword": "keyword",
					"domain_regex": ".*\\.io$"
				},
				{
					"package_name": "com.example.app"
				},
				{
					"process_name": "chrome"
				},
				{
					"process_path": "/usr/bin/firefox"
				},
				{
					"process_path_regex": "/opt/.*"
				},
				{}
			]
		}
	]
}
`
	rule, _ := json.UnmarshalExtended[O.LogicalHeadlessRule]([]byte(want))
	assert.Equal(t, rule, st.rule)
}

// splitTunnelDNSMatcher builds a matcher with the conditions of the
// split-tunnel evaluate rule, against st's saved rule file. A match means the
// query is sent to the system resolver.
func splitTunnelDNSMatcher(t *testing.T, st *SplitTunnel) adapter.DNSRule {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().Logger()
	router := &mockRouter{}
	service.MustRegister[adapter.Router](ctx, router)
	service.MustRegister(ctx, new(adapter.NetworkManager))

	ruleSet, err := R.NewRuleSet(ctx, logger, splitTunnelTag, O.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Tag:          badoption.Listable[string]{splitTunnelTag},
		LocalOptions: O.LocalRuleSet{Path: st.ruleFile},
		Format:       C.RuleSetFormatSource,
	})
	require.NoError(t, err)
	require.NoError(t, ruleSet.StartContext(ctx, new(adapter.HTTPStartContext)))
	t.Cleanup(func() { ruleSet.Close() })
	router.ruleSet = ruleSet

	rules := splitTunnelDNSRules()
	require.Len(t, rules, 2)
	require.Equal(t, C.RuleActionTypeEvaluate, rules[0].DefaultOptions.DNSRuleAction.Action)
	// Without server checking, NewDNSRule builds a sub-rule, where evaluate is
	// rejected; the action doesn't affect matching.
	evaluate := rules[0]
	evaluate.DefaultOptions.DNSRuleAction = O.DNSRuleAction{
		Action:       C.RuleActionTypeRoute,
		RouteOptions: O.DNSRouteActionOptions{Server: systemDNSTag},
	}
	rule, err := R.NewDNSRule(ctx, logger, evaluate, false, false)
	require.NoError(t, err)
	require.NoError(t, rule.Start())
	t.Cleanup(func() { rule.Close() })
	return rule
}

func TestSplitTunnelDNSRule(t *testing.T) {
	query := func(domain string, qtype uint16) *adapter.InboundContext {
		return &adapter.InboundContext{Domain: domain, QueryType: qtype}
	}
	tests := []struct {
		name    string
		policy  SplitTunnelPolicy
		filter  SplitTunnelFilter
		matches map[*adapter.InboundContext]bool
	}{
		{
			name:   "exclude domain",
			policy: SplitTunnelPolicyExclude,
			filter: SplitTunnelFilter{DomainSuffix: []string{"example.com"}},
			matches: map[*adapter.InboundContext]bool{
				query("www.example.com", dns.TypeA):     true,
				query("www.example.com", dns.TypeAAAA):  true,
				query("www.example.com", dns.TypeMX):    false,
				query("www.example.com", dns.TypeHTTPS): false,
				query("www.example.com", dns.TypeSVCB):  false,
				query("other.com", dns.TypeA):           false,
			},
		},
		{
			name:   "include domain",
			policy: SplitTunnelPolicyInclude,
			filter: SplitTunnelFilter{DomainSuffix: []string{"example.com"}},
			matches: map[*adapter.InboundContext]bool{
				query("other.com", dns.TypeA):        false,
				query("other.com", dns.TypeAAAA):     false,
				query("other.com", dns.TypeHTTPS):    false,
				query("other.com", dns.TypeMX):       false,
				query("www.example.com", dns.TypeMX): false,
			},
		},
		{
			name:   "include app",
			policy: SplitTunnelPolicyInclude,
			filter: SplitTunnelFilter{ProcessName: []string{"app"}},
			matches: map[*adapter.InboundContext]bool{
				query("other.com", dns.TypeA):    false,
				query("other.com", dns.TypeAAAA): false,
				query("other.com", dns.TypeMX):   false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
			require.NoError(t, st.AddItems(tt.filter))
			require.NoError(t, st.SetPolicy(tt.policy))
			require.NoError(t, st.SetEnabled(true))

			rule := splitTunnelDNSMatcher(t, st)
			for metadata, want := range tt.matches {
				assert.Equal(t, want, rule.Match(metadata), "%s %s", metadata.Domain, dns.TypeToString[metadata.QueryType])
			}
		})
	}
}

// savedFilterRules returns the rule set saved in path and its filter rule.
func savedFilterRules(t *testing.T, path string) (rs O.PlainRuleSetCompat, filter *O.LogicalHeadlessRule) {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	rs, err = json.UnmarshalExtended[O.PlainRuleSetCompat](content)
	require.NoError(t, err)
	outer := rs.Options.Rules[0].LogicalOptions.Rules
	require.Len(t, outer, 2)
	return rs, &outer[1].LogicalOptions
}

func fileHasIncludeDNSGuard(t *testing.T, path string) bool {
	t.Helper()
	_, filter := savedFilterRules(t, path)
	return slices.ContainsFunc(filter.Rules, isIncludeDNSGuard)
}

func TestIncludeDNSGuardPersistence(t *testing.T) {
	dir := t.TempDir()
	st := newSplitTunnel(dir, rlog.NoOpLogger())
	require.NoError(t, st.AddItem(TypeDomain, "example.com"))
	guarded := func() bool { return fileHasIncludeDNSGuard(t, st.ruleFile) }

	assert.False(t, guarded(), "exclude policy is not guarded")
	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))
	assert.True(t, guarded(), "include policy is guarded")

	loaded, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.Equal(t, SplitTunnelFilter{Domain: []string{"example.com"}}, loaded.Filters())
	for _, r := range loaded.activeFilter.Rules {
		assert.Empty(t, r.DefaultOptions.QueryType, "guard must not survive load")
	}
	require.NoError(t, loaded.SetPolicy(SplitTunnelPolicyExclude))
	assert.False(t, guarded(), "switching back to exclude drops the guard")
}

func TestLoadRewritesStaleIncludeDNSGuard(t *testing.T) {
	for _, policy := range []SplitTunnelPolicy{SplitTunnelPolicyInclude, SplitTunnelPolicyExclude} {
		t.Run(string(policy), func(t *testing.T) {
			dir := t.TempDir()
			st := newSplitTunnel(dir, rlog.NoOpLogger())
			require.NoError(t, st.AddItem(TypeProcessName, "app"))
			require.NoError(t, st.SetPolicy(policy))
			require.NoError(t, st.SetEnabled(true))
			want := policy == SplitTunnelPolicyInclude
			require.Equal(t, want, fileHasIncludeDNSGuard(t, st.ruleFile))

			// Flip the guard to the state an older build or a stale file would have.
			rs, filter := savedFilterRules(t, st.ruleFile)
			if want {
				filter.Rules = slices.DeleteFunc(filter.Rules, isIncludeDNSGuard)
			} else {
				filter.Rules = append(filter.Rules, includeDNSGuard())
			}
			buf, err := json.Marshal(rs)
			require.NoError(t, err)
			require.NoError(t, atomicfile.WriteFile(st.ruleFile, buf, 0o644))
			require.NotEqual(t, want, fileHasIncludeDNSGuard(t, st.ruleFile))

			loaded, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
			require.NoError(t, err)
			assert.Equal(t, want, fileHasIncludeDNSGuard(t, st.ruleFile), "load must rewrite the guard")
			assert.Equal(t, SplitTunnelFilter{ProcessName: []string{"app"}}, loaded.Filters())
			assert.Equal(t, policy, loaded.Policy())
			assert.True(t, loaded.IsEnabled())
		})
	}
}

func TestLoadStripsStrayQueryTypes(t *testing.T) {
	for _, policy := range []SplitTunnelPolicy{SplitTunnelPolicyInclude, SplitTunnelPolicyExclude} {
		t.Run(string(policy), func(t *testing.T) {
			dir := t.TempDir()
			st := newSplitTunnel(dir, rlog.NoOpLogger())
			require.NoError(t, st.AddItem(TypeDomainSuffix, "example.com"))
			require.NoError(t, st.SetPolicy(policy))

			// Replace the guard with an incomplete one and add a query type to the filter rule.
			rs, filter := savedFilterRules(t, st.ruleFile)
			filter.Rules = slices.DeleteFunc(filter.Rules, isIncludeDNSGuard)
			require.Len(t, filter.Rules, 1)
			filter.Rules[0].DefaultOptions.QueryType = badoption.Listable[O.DNSQueryType]{O.DNSQueryType(dns.TypeMX)}
			filter.Rules = append(filter.Rules, O.HeadlessRule{
				Type:           C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{QueryType: badoption.Listable[O.DNSQueryType]{O.DNSQueryType(dns.TypeA)}},
			})
			buf, err := json.Marshal(rs)
			require.NoError(t, err)
			require.NoError(t, atomicfile.WriteFile(st.ruleFile, buf, 0o644))

			loaded, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
			require.NoError(t, err)
			assert.Equal(t, SplitTunnelFilter{DomainSuffix: []string{"example.com"}}, loaded.Filters())

			_, filter = savedFilterRules(t, st.ruleFile)
			want := []O.HeadlessRule{{
				Type:           C.RuleTypeDefault,
				DefaultOptions: O.DefaultHeadlessRule{DomainSuffix: badoption.Listable[string]{"example.com"}},
			}}
			if policy == SplitTunnelPolicyInclude {
				want = append(want, includeDNSGuard())
			}
			assert.Equal(t, want, filter.Rules, "load must strip stray query types and restore the guard")
		})
	}
}

func TestSplitTunnelDNSRespondsOnlyPrivate(t *testing.T) {
	rules := splitTunnelDNSRules()
	require.Len(t, rules, 2)
	ctx := service.ContextWithDefaultRegistry(context.Background())
	rule, err := R.NewDNSRule(ctx, log.NewNOPFactory().Logger(), rules[1], false, false)
	require.NoError(t, err)
	require.NoError(t, rule.Start())
	t.Cleanup(func() { rule.Close() })
	require.Equal(t, C.RuleActionTypeRespond, rule.Action().Type())

	answer := func(addr string) *dns.Msg {
		rr, err := dns.NewRR("example.com. 60 IN A " + addr)
		require.NoError(t, err)
		return &dns.Msg{Answer: []dns.RR{rr}}
	}
	evaluated := func(response *dns.Msg) *adapter.InboundContext {
		return &adapter.InboundContext{
			Domain:            "example.com",
			QueryType:         dns.TypeA,
			NamedDNSResponses: map[string]*dns.Msg{splitTunnelTag: response},
		}
	}
	assert.True(t, rule.Match(evaluated(answer("192.168.9.138"))), "private answer is returned")
	assert.False(t, rule.Match(evaluated(answer("203.0.113.10"))), "public answer falls through to fake IP")
	assert.False(t, rule.Match(&adapter.InboundContext{Domain: "example.com", QueryType: dns.TypeA}),
		"no evaluated response must not respond")
}

type countingDNSRouter struct {
	adapter.DNSRouter
	clears atomic.Int32
}

func (r *countingDNSRouter) ClearCache() { r.clears.Add(1) }

// A reload of the split-tunnel rule set clears the DNS cache and closes the
// connections opened under the previous rules, until the closer unregisters it.
func TestResetOnSplitTunnelReload(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	ctx := service.ContextWithDefaultRegistry(context.Background())
	router := &mockRouter{}
	service.MustRegister[adapter.Router](ctx, router)
	service.MustRegister(ctx, new(adapter.NetworkManager))
	ruleSet, err := R.NewRuleSet(ctx, log.NewNOPFactory().Logger(), splitTunnelTag, O.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Tag:          badoption.Listable[string]{splitTunnelTag},
		LocalOptions: O.LocalRuleSet{Path: st.ruleFile},
		Format:       C.RuleSetFormatSource,
	})
	require.NoError(t, err)
	require.NoError(t, ruleSet.StartContext(ctx, new(adapter.HTTPStartContext)))
	t.Cleanup(func() { ruleSet.Close() })
	router.ruleSet = ruleSet

	ct := newConnTracker()
	dns := &countingDNSRouter{}
	unregister := resetOnSplitTunnelReload(router, dns, ct)
	require.NotNil(t, unregister)

	// Registered after the closer's callback, so it fires once that callback has run.
	reloaded := make(chan struct{}, 1)
	ruleSet.RegisterCallback(func(adapter.RuleSet) { reloaded <- struct{}{} })
	waitReload := func() {
		t.Helper()
		select {
		case <-reloaded:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for rule reload")
		}
	}

	conn := joinClosable(ct, "srv-a", time.Now())
	require.NoError(t, st.SetEnabled(true))
	waitReload()
	assert.True(t, conn.closed.Load(), "enabling split tunneling must close existing connections")
	assert.Equal(t, int32(1), dns.clears.Load(), "enabling split tunneling must clear the DNS cache")

	// The policy is persisted only with a non-empty filter.
	require.NoError(t, st.AddItem(TypeDomain, "example.com"))
	waitReload()
	conn = joinClosable(ct, "direct", time.Now())
	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))
	waitReload()
	assert.True(t, conn.closed.Load(), "switching policy must close existing connections")
	assert.Equal(t, int32(3), dns.clears.Load(), "every reload must clear the DNS cache")

	require.NoError(t, unregister.Close())
	conn = joinClosable(ct, "srv-a", time.Now())
	require.NoError(t, st.SetEnabled(false))
	waitReload()
	assert.False(t, conn.closed.Load(), "an unregistered callback must not close connections")
	assert.Equal(t, int32(3), dns.clears.Load(), "an unregistered callback must not clear the DNS cache")
}

// capturingRuleSet keeps every registered callback, as a reload's snapshot does
// after the callback is unregistered.
type capturingRuleSet struct {
	adapter.RuleSet
	callbacks    list.List[adapter.RuleSetUpdateCallback]
	unregistered chan struct{}
}

func (r *capturingRuleSet) RegisterCallback(cb adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	return r.callbacks.PushBack(cb)
}

func (r *capturingRuleSet) UnregisterCallback(*list.Element[adapter.RuleSetUpdateCallback]) {
	if r.unregistered != nil {
		close(r.unregistered)
	}
}

func TestResetOnSplitTunnelReloadIgnoresCallbackAfterClose(t *testing.T) {
	ruleSet := &capturingRuleSet{}
	ct := newConnTracker()
	dns := &countingDNSRouter{}
	unregister := resetOnSplitTunnelReload(&mockRouter{ruleSet: ruleSet}, dns, ct)
	require.NotNil(t, unregister)
	require.NoError(t, unregister.Close())

	conn := joinClosable(ct, "srv-a", time.Now())
	for _, cb := range ruleSet.callbacks.Array() {
		cb(ruleSet)
	}
	assert.False(t, conn.closed.Load(), "a callback run after close must not close connections")
	assert.Zero(t, dns.clears.Load(), "a callback run after close must not clear the DNS cache")
}

type blockingDNSRouter struct {
	adapter.DNSRouter
	entered, release chan struct{}
}

func (r *blockingDNSRouter) ClearCache() {
	close(r.entered)
	<-r.release
}

func TestResetOnSplitTunnelReloadCloseWaitsForRunningReset(t *testing.T) {
	ruleSet := &capturingRuleSet{unregistered: make(chan struct{})}
	ct := newConnTracker()
	dns := &blockingDNSRouter{entered: make(chan struct{}), release: make(chan struct{})}
	unregister := resetOnSplitTunnelReload(&mockRouter{ruleSet: ruleSet}, dns, ct)
	require.NotNil(t, unregister)
	conn := joinClosable(ct, "srv-a", time.Now())

	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(dns.release) }) }
	t.Cleanup(release)
	await := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s", what)
		}
	}

	go ruleSet.callbacks.Array()[0](ruleSet)
	await(dns.entered, "the reset to start")
	closed := make(chan error, 1)
	go func() { closed <- unregister.Close() }()
	await(ruleSet.unregistered, "Close to start")

	select {
	case <-closed:
		t.Fatal("Close returned while a reset was running")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Close")
	}
	assert.True(t, conn.closed.Load(), "the running reset must finish before Close returns")
}

func TestResetOnSplitTunnelReloadWithoutRuleSet(t *testing.T) {
	assert.Nil(t, resetOnSplitTunnelReload(&mockRouter{}, &countingDNSRouter{}, newConnTracker()))
}

// A save that leaves the rule file's content unchanged must not rewrite it,
// since any write reloads the rule set and closes every connection.
func TestSaveSkipsUnchangedRuleFile(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	before, err := os.Stat(st.ruleFile)
	require.NoError(t, err)

	// An empty filter doesn't persist the policy, so this save is byte-identical.
	require.NoError(t, st.SetPolicy(SplitTunnelPolicyInclude))
	after, err := os.Stat(st.ruleFile)
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after), "an unchanged save must not replace the rule file")

	require.NoError(t, st.SetEnabled(true))
	after, err = os.Stat(st.ruleFile)
	require.NoError(t, err)
	assert.False(t, os.SameFile(before, after), "a changed save must replace the rule file")
}
