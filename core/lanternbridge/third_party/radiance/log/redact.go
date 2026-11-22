package log

import (
	"bytes"
	"context"
	"encoding"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/getlantern/radiance/internal/logsafe"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/getlantern/radiance/internal/redact"
)

func redactAttr(groups []string, a slog.Attr) slog.Attr {
	if logsafe.IsSecretKey(a.Key) || slices.ContainsFunc(groups, logsafe.IsSecretKey) {
		a.Value = slog.StringValue(logsafe.Redacted)
		return a
	}
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(redactString(a.Value.String()))
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			s, ok := errorString(v)
			if !ok {
				// slog prints it through fmt, which recovers, as "<nil>" for a nil pointer.
				break
			}
			r := redactString(s)
			_, formatter := v.(fmt.Formatter)
			_, marshaler := v.(encoding.TextMarshaler)
			// slog would call Error again to print an error that formats only through it.
			if r != s || !formatter && !marshaler {
				a.Value = slog.StringValue(r)
			}
		default:
			if !isLoggableAny(v) {
				a.Value = slog.StringValue(fmt.Sprintf("[REDACTED %T]", v))
			} else if r, changed := redactLoggableAny(v); changed {
				a.Value = slog.AnyValue(r)
			}
		}
	}
	return a
}

// errorString returns err.Error(), or false if it panics, as it can on a nil pointer.
func errorString(err error) (s string, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return err.Error(), true
}

// redactLoggableAny redacts the values under secret map keys in v, a value that
// satisfies isLoggableAny, and its strings as redactString does. It returns a
// redacted string, []string or map[string]any and true if anything changed, or v
// and false otherwise.
func redactLoggableAny(v any) (any, bool) {
	t := reflect.TypeOf(v)
	if t == nil {
		return v, false
	}
	rv := reflect.ValueOf(v)
	switch t.Kind() {
	case reflect.String:
		if s := redactString(rv.String()); s != rv.String() {
			return s, true
		}
	case reflect.Map:
		if t.Key().Kind() != reflect.String && t.Elem().Kind() != reflect.String {
			return v, false
		}
		for it := rv.MapRange(); it.Next(); {
			if mapEntryChanges(it.Key(), it.Value()) {
				return redactMap(rv), true
			}
		}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() != reflect.String {
			return v, false
		}
		var s []string
		for i := range rv.Len() {
			orig := rv.Index(i).String()
			r := redactString(orig)
			if s == nil {
				if r == orig {
					continue
				}
				s = make([]string, rv.Len())
				for j := range i {
					s[j] = rv.Index(j).String()
				}
			}
			s[i] = r
		}
		if s != nil {
			return s, true
		}
	}
	return v, false
}

func mapEntryChanges(k, v reflect.Value) bool {
	orig := mapKeyString(k)
	key := redactString(orig)
	return key != orig || logsafe.IsSecretKey(key) || v.Kind() == reflect.String && redactString(v.String()) != v.String()
}

func redactMap(rv reflect.Value) map[string]any {
	m := make(map[string]any, rv.Len())
	for it := rv.MapRange(); it.Next(); {
		key, val := redactString(mapKeyString(it.Key())), it.Value()
		switch {
		case logsafe.IsSecretKey(key):
			m[key] = logsafe.Redacted
		case val.Kind() == reflect.String:
			m[key] = redactString(val.String())
		default:
			m[key] = val.Interface()
		}
	}
	return m
}

func mapKeyString(k reflect.Value) string {
	if k.Kind() == reflect.String {
		return k.String()
	}
	//logleak:ok keys are scalars; only isLoggableAny maps reach here
	return fmt.Sprint(k.Interface())
}

// maxJSONRedactionLen bounds the text redactString rewrites field by field, which costs
// about 0.1 ms per KiB.
const maxJSONRedactionLen = 8 << 10

// redactString strips URL queries from s and redacts the secret fields of JSON in it.
// Text longer than maxJSONRedactionLen that may hold a secret field is replaced whole.
func redactString(s string) string {
	s = logsafe.StripQueries(s)
	if !mayHoldSecretJSON(s) {
		return s
	}
	if len(s) > maxJSONRedactionLen {
		return fmt.Sprintf("[REDACTED %d bytes]", len(s))
	}
	if r := logsafe.RedactJSONFields([]byte(s)); r != nil {
		return string(r)
	}
	return s
}

func mayHoldSecretJSON(s string) bool {
	return strings.IndexByte(s, '{') >= 0 && strings.IndexByte(s, '"') >= 0 && logsafe.MayHoldSecretField(s)
}

// isLoggableAny reports whether v may be logged by value. Structs, pointers and
// other composites may carry credentials.
func isLoggableAny(v any) bool {
	if v == nil {
		return true
	}
	t := reflect.TypeOf(v)
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		// Raw bytes are request and response bodies more often than not.
		return t.Elem().Kind() != reflect.Uint8 && isScalarKind(t.Elem().Kind())
	case reflect.Map:
		return isScalarKind(t.Key().Kind()) && isScalarKind(t.Elem().Kind())
	default:
		return isScalarKind(t.Kind())
	}
}

func isScalarKind(k reflect.Kind) bool {
	switch k {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return true
	}
	return false
}

// redactDestinations replaces each dotted name or IP address in s that
// destinationPlaceholder maps to a placeholder, keeping any port.
func redactDestinations(s string) string {
	if !strings.ContainsAny(s, ".:") {
		return s
	}
	var b strings.Builder
	last := 0
	for start := 0; start < len(s); {
		if isTokenDelim(s[start]) {
			start++
			continue
		}
		end := start
		for end < len(s) && !isTokenDelim(s[end]) {
			end++
		}
		if host, addr, ok := tokenHost(s[start:end]); ok {
			if placeholder := destinationPlaceholder(host, addr); placeholder != "" {
				if b.Len() == 0 {
					b.Grow(len(s))
				}
				b.WriteString(s[last:start])
				b.WriteString(placeholder)
				last = start + len(host)
			}
		}
		start = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func isTokenDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '"', '\'', ',', '(', ')', '[', ']', '{', '}', '<', '>', '=', ';', '/':
		return true
	}
	return false
}

// tokenHost returns the host part of tok, and its address if it is an IP address, and
// reports whether tok is a hostname or IP address, optionally followed by a numeric
// port and trailing punctuation.
func tokenHost(tok string) (string, netip.Addr, bool) {
	if !strings.ContainsAny(tok, ".:") {
		return "", netip.Addr{}, false
	}
	host := strings.TrimRight(tok, ".,;!?-")
	// Trailing colons may end a compressed IPv6 address, such as "fe80::".
	if addr, err := netip.ParseAddr(host); err == nil {
		return host, addr, true
	}
	host = strings.TrimRight(host, ":.,;!?-")
	if i := strings.IndexByte(host, ':'); i > 0 && strings.Count(host, ":") == 1 && isDigits(host[i+1:]) {
		// A fully qualified name keeps its root dot before the port.
		host = strings.TrimSuffix(host[:i], ".")
	}
	if isHostname(host) {
		return host, netip.Addr{}, true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return host, addr, true
	}
	return "", netip.Addr{}, false
}

var lanternDomains = []string{"iantem.io", "getiantem.org", "lantern.io", "lantr.net"}

// fakeIPs is the range the tunnel's fake-IP DNS server assigns from. It is reserved
// for benchmarking (RFC 2544), so it never names a destination even if the server's
// range changes.
var fakeIPs = netip.MustParsePrefix("198.18.0.0/15")

// destinationPlaceholder returns what replaces host, a DNS name or, if addr is valid,
// that IP address, or "" to keep a host that names no user destination.
func destinationPlaceholder(host string, addr netip.Addr) string {
	if addr.IsValid() {
		addr = addr.Unmap()
		switch {
		case addr.IsLoopback(), addr.IsMulticast(), addr.IsUnspecified():
			return ""
		case !addr.Is4():
			// A link-local or ULA interface ID can embed the device's MAC address.
			return "[ipv6]"
		case addr.IsPrivate(), addr.IsLinkLocalUnicast(), fakeIPs.Contains(addr):
			return ""
		default:
			return "[ipv4]"
		}
	}
	host = strings.ToLower(host)
	for _, domain := range lanternDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return ""
		}
	}
	return "[domain]"
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isHostname reports whether s looks like a DNS name. Requiring the last label to
// start with a letter keeps versions and durations such as "1.13.20" and "0.123s".
func isHostname(s string) bool {
	i := strings.LastIndexByte(s, '.')
	if i < 0 || !M.IsDomainName(s) {
		return false
	}
	tld := s[i+1:]
	return len(tld) >= 2 && isLetter(tld[0])
}

func isLetter(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// processInfoPrefixes start sing-box's messages that report which local process,
// package or OS user owns a connection.
var processInfoPrefixes = []string{"found process path: ", "found package name: ", "found user: ", "found user id: "}

var (
	// processRuleItem matches the start of a sing-box rule item, printed as key=value or
	// key=[value ...] in rule-match messages, whose value names a local process,
	// package or OS user.
	processRuleItem = regexp.MustCompile(`(?:^|[ (])(?:process_name|process_path|process_path_regex|package_name|user|user_id)=`)
	// ruleItemEnd matches what follows a rule item's value. Values such as paths can
	// hold spaces, so a value runs to the next item, logical operator or rule action.
	ruleItemEnd = regexp.MustCompile(` (?:[a-z][a-z_]*=|&& |\|\| |=> )`)
)

func redactConnectionInfo(s string) string {
	for _, prefix := range processInfoPrefixes {
		if strings.HasPrefix(s, prefix) {
			return prefix + logsafe.Redacted
		}
	}
	return redactDestinations(redactProcessRuleItems(s))
}

func redactProcessRuleItems(s string) string {
	if strings.IndexByte(s, '=') < 0 {
		return s
	}
	var b strings.Builder
	for {
		item := processRuleItem.FindStringIndex(s)
		if item == nil {
			if b.Len() == 0 {
				return s
			}
			b.WriteString(s)
			return b.String()
		}
		start, end := item[1], len(s)
		if next := ruleItemEnd.FindStringIndex(s[start:]); next != nil {
			end = start + next[0]
		}
		// A path can hold parentheses, so only an unbalanced ")" closes an enclosing
		// group such as "!(...)".
		for end > start && s[end-1] == ')' && strings.Count(s[start:end], ")") > strings.Count(s[start:end], "(") {
			end--
		}
		b.WriteString(s[:start])
		b.WriteString(logsafe.Redacted)
		s = s[end:]
	}
}

type connectionInfoHandler struct {
	slog.Handler
}

// RedactConnectionInfo returns a handler that redacts connection details from each
// record's message before passing the record to h. Dotted names and IP addresses
// become "[domain]", "[ipv4]" or "[ipv6]", keeping any port, except Lantern's own
// domains, loopback, multicast and unspecified addresses, and private, link-local and
// fake IPv4 addresses. The process, package or OS user that sing-box reports for a
// connection, or prints in a matched rule, is replaced.
func RedactConnectionInfo(h slog.Handler) slog.Handler {
	return connectionInfoHandler{Handler: h}
}

func (h connectionInfoHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Message = redactConnectionInfo(r.Message)
	return h.Handler.Handle(ctx, r)
}

func (h connectionInfoHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return connectionInfoHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h connectionInfoHandler) WithGroup(name string) slog.Handler {
	return connectionInfoHandler{Handler: h.Handler.WithGroup(name)}
}

var (
	helperWord          = []byte("helper")
	personalProxiesWord = []byte(redact.PersonalProxiesTag)
	personalProxyWord   = []byte(redact.PersonalProxyTag)
)

// redactingWriter applies redact.HelperBytes on the way to every log sink: the
// log file (which issue reports upload), stdout and the publisher that
// streams logs to the UI. A helper tag is a client-side pseudonym for one of
// the user's pairings, and a line naming a helper outbound may carry the
// helper's address; clients must export neither. slog's handlers write one
// record per Write.
type redactingWriter struct {
	w io.Writer
}

func newRedactingWriter(w io.Writer) io.Writer {
	return &redactingWriter{w: w}
}

// Write redacts p and reports len(p) on success, as io.Writer requires, even
// though fewer bytes may reach the sink.
func (r *redactingWriter) Write(p []byte) (int, error) {
	if !bytes.Contains(p, helperWord) && !bytes.Contains(p, personalProxiesWord) &&
		!bytes.Contains(p, personalProxyWord) {
		return r.w.Write(p)
	}
	if _, err := r.w.Write(redact.HelperBytes(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}
