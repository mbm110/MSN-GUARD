package vpn

import (
	"slices"
	"testing"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
)

func TestNormalizeLocale(t *testing.T) {
	tests := []struct {
		name     string
		locale   string
		expected string
	}{
		{
			name:     "lowercase with hyphen",
			locale:   "zh-cn",
			expected: "ZHCN",
		},
		{
			name:     "lowercase with underscore",
			locale:   "ru_ru",
			expected: "RURU",
		},
		{
			name:     "mixed case with hyphen",
			locale:   "en-US",
			expected: "ENUS",
		},
		{
			name:     "all uppercase",
			locale:   "FAIR",
			expected: "FAIR",
		},
		{
			name:     "all lowercase",
			locale:   "fair",
			expected: "FAIR",
		},
		{
			name:     "multiple hyphens and underscores",
			locale:   "en-US_test",
			expected: "ENUSTEST",
		},
		{
			name:     "empty string",
			locale:   "",
			expected: "",
		},
		{
			name:     "only hyphens and underscores",
			locale:   "-_-_",
			expected: "",
		},
		{
			name:     "numbers and letters",
			locale:   "abc123",
			expected: "ABC123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeLocale(tt.locale)
			assert.Equalf(t, tt.expected, result, "normalizeLocale(%q) should return %q", tt.locale, tt.expected)
		})
	}
}
func TestLocalDNSIP(t *testing.T) {
	tests := []struct {
		name     string
		locale   string
		expected string
	}{
		{
			name:     "FAIR locale returns AliDNS",
			locale:   "FAIR",
			expected: aliDNS,
		},
		{
			name:     "fair lowercase returns AliDNS",
			locale:   "fair",
			expected: aliDNS,
		},
		{
			name:     "ZHCN locale returns AliDNS",
			locale:   "ZHCN",
			expected: aliDNS,
		},
		{
			name:     "zh-cn with hyphen returns AliDNS",
			locale:   "zh-cn",
			expected: aliDNS,
		},
		{
			name:     "zh_cn with underscore returns AliDNS",
			locale:   "zh_cn",
			expected: aliDNS,
		},
		{
			name:     "RURU locale returns AliDNS",
			locale:   "RURU",
			expected: yandexDNS,
		},
		{
			name:     "ru-ru with hyphen returns AliDNS",
			locale:   "ru-ru",
			expected: yandexDNS,
		},
		{
			name:     "en-US returns Quad9",
			locale:   "en-US",
			expected: quad9DNS,
		},
		{
			name:     "enus returns Quad9",
			locale:   "enus",
			expected: quad9DNS,
		},
		{
			name:     "empty locale returns Quad9",
			locale:   "",
			expected: quad9DNS,
		},
		{
			name:     "unknown locale returns Quad9",
			locale:   "fr-FR",
			expected: quad9DNS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: Set the locale in settings
			t.Cleanup(settings.Reset)
			settings.Set(settings.LocaleKey, tt.locale)

			result := localDNSIP()
			assert.Equalf(t, tt.expected, result, "localDNSIP() with locale %q should return %q", tt.locale, tt.expected)
		})
	}
}

func TestBuildDNSRules_SuppressesAAAA(t *testing.T) {
	rules := buildDNSRules()

	var fakeIP, aaaa *option.DefaultDNSRule
	for i := range rules {
		d := &rules[i].DefaultOptions
		switch {
		case d.Action == constant.RuleActionTypeRoute && d.RouteOptions.Server == "dns_fakeip":
			fakeIP = d
		case slices.Contains(d.QueryType, option.DNSQueryType(dns.TypeAAAA)):
			aaaa = d
		}
	}

	require.NotNil(t, fakeIP, "expected a fake-IP route rule")
	assert.Contains(t, fakeIP.QueryType, option.DNSQueryType(dns.TypeA), "fake-IP rule should handle A queries")
	assert.NotContains(t, fakeIP.QueryType, option.DNSQueryType(dns.TypeAAAA), "fake-IP rule must not handle AAAA — AAAA is suppressed")

	require.NotNil(t, aaaa, "expected an AAAA suppression rule")
	assert.Equal(t, constant.RuleActionTypePredefined, aaaa.Action, "AAAA rule should use the predefined action")
	require.NotNil(t, aaaa.PredefinedOptions.Rcode, "AAAA predefined rule must set an rcode")
	assert.Equal(t, dns.RcodeSuccess, int(*aaaa.PredefinedOptions.Rcode), "AAAA suppression must return NODATA (NOERROR), not NXDOMAIN")
	assert.Empty(t, aaaa.PredefinedOptions.Answer, "AAAA suppression must return no answer records (NODATA)")
}
