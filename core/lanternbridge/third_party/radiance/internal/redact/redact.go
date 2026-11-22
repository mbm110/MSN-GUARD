// Package redact removes what a client must not export about its helper
// pairings from text it logs, uploads or reports: helper- outbound tags, which
// are client-side pseudonyms for pairings, and the addresses of the helpers
// those outbounds dial.
package redact

import (
	"bytes"
	"net"
	"regexp"
	"strings"

	lbA "github.com/getlantern/lantern-box/adapter"

	"github.com/getlantern/radiance/internal/logsafe"
)

// PersonalProxiesTag is the tag of radiance's url-test group over a paired
// inviter's helper outbounds (vpn.PersonalProxiesTag). It marks a device as
// having personal proxies wherever outbound tags are recorded, so it is
// exported only as "helper", like a helper tag.
const PersonalProxiesTag = "personal-proxies"

// PersonalProxyTag is the tag of radiance's url-test group over one paired
// friend's outbounds (vpn.PersonalProxyTag). It is exported only as "helper",
// like PersonalProxiesTag.
const PersonalProxyTag = "personal-proxy"

// ReversePortalTag is the tag of the VPN box's inbound that serves an
// inviter's reverse outbounds. Its options hold the masquerade domain the
// portal answers probes with, which a client must not export.
const ReversePortalTag = "samizdat-portal"

var groupTags = strings.NewReplacer(PersonalProxiesTag, "helper", PersonalProxyTag, "helper")

// Tag returns s with every helper tag, PersonalProxiesTag and PersonalProxyTag
// replaced by "helper". Unlike Helper it leaves addresses alone, for values
// that are only outbound tags or rules, such as metric attributes.
func Tag(s string) string {
	return groupTags.Replace(lbA.RedactHelperTags(s))
}

var (
	// helperNamed matches text that may name a helper outbound: a helper tag,
	// or the word "helper" that lbA.RedactHelperTags leaves in its place.
	// lantern-box redacts tags before radiance sees most lines, leaving forms
	// such as "outbound/samizdat[helper]", "outbound/helper[samizdat]",
	// "outbound helper", outbound="helper" and "helper_failed", so the word
	// itself is the marker. Matching it in unrelated text only redacts more.
	helperNamed = regexp.MustCompile(`\bhelper(?:\b|_)`)
	// ipCandidate matches text that may be an IP address, with or without a
	// port: a bracketed host, or a run of hex digits, dots and colons. Each
	// match is checked with net.ParseIP before it is replaced.
	ipCandidate = regexp.MustCompile(`\[[0-9A-Fa-f:.]+(?:%[0-9A-Za-z_.\-]+)?\](?::[0-9]{1,5})?|[0-9A-Fa-f]*[.:][0-9A-Fa-f.:]*(?:%[0-9A-Za-z_.\-]+)?`)
)

// Helper returns s with helper tags replaced by "helper" and, on every line
// that names a helper outbound, every IP address (with any port) replaced by
// [logsafe.Redacted]. Lines that name no helper outbound keep their addresses.
func Helper(s string) string {
	if !NamesHelper(s) {
		return s
	}
	lines := strings.SplitAfter(s, "\n")
	for i, line := range lines {
		if NamesHelper(line) {
			lines[i] = Addresses(line)
		}
	}
	return Tag(strings.Join(lines, ""))
}

// NamesHelper reports whether s may name a helper outbound: by its tag, by
// a group over them (PersonalProxiesTag, PersonalProxyTag), or by the
// "helper" a redaction left in its place.
func NamesHelper(s string) bool {
	return strings.Contains(s, PersonalProxiesTag) || strings.Contains(s, PersonalProxyTag) ||
		(strings.Contains(s, "helper") && helperNamed.MatchString(s))
}

// Addresses returns s with every IP address (with any port) replaced by
// [logsafe.Redacted], for text that belongs with something naming a helper outbound,
// such as the attributes of a span event that does.
func Addresses(s string) string {
	return ipCandidate.ReplaceAllStringFunc(s, redactIP)
}

// HelperBytes is Helper for a byte slice. It returns b itself when there is
// nothing to redact.
func HelperBytes(b []byte) []byte {
	if !bytes.Contains(b, []byte("helper")) && !bytes.Contains(b, []byte(PersonalProxiesTag)) &&
		!bytes.Contains(b, []byte(PersonalProxyTag)) {
		return b
	}
	return []byte(Helper(string(b)))
}

// redactIP replaces the IP address in m with [logsafe.Redacted]. The candidate pattern
// can take in dots and colons from the surrounding text on either side
// ("peer:203.0.113.7:443", "… to 2001:db8::." or "203.0.113.7: refused"), so
// redactIP tries m whole and then from just after each dot or colon, leftmost
// first so the longest address wins ("::1" stays whole). At each start, the
// rest is checked whole first, since "::" can end a valid IPv6 address, then
// with one trailing dot or colon at a time set aside. Other punctuation never
// enters a candidate.
func redactIP(m string) string {
	for start := 0; start < len(m); start++ {
		if start > 0 && m[start-1] != '.' && m[start-1] != ':' {
			continue
		}
		if r, ok := redactTrailing(m[start:]); ok {
			return m[:start] + r
		}
	}
	return m
}

func redactTrailing(m string) (string, bool) {
	for core := m; core != ""; core = core[:len(core)-1] {
		if isIPAddr(core) {
			return logsafe.Redacted + m[len(core):], true
		}
		if last := core[len(core)-1]; last != '.' && last != ':' {
			return m, false
		}
	}
	return m, false
}

// isIPAddr reports whether s is an IP address, optionally bracketed, zoned or
// followed by a port.
func isIPAddr(s string) bool {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return false
		}
		return parseIP(s[1:end])
	}
	if parseIP(s) {
		return true
	}
	host, port, err := net.SplitHostPort(s)
	return err == nil && port != "" && parseIP(host)
}

func parseIP(s string) bool {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	return net.ParseIP(s) != nil
}
