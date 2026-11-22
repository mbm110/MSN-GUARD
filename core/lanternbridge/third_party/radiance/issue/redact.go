package issue

import (
	"bytes"
	"regexp"
	"slices"

	"github.com/getlantern/radiance/internal/logsafe"
)

// logField matches a key=value attribute, a Go struct's Field:value, a Go map's
// key:value or a Dart map's key: value, or a header in a logged curl command's
// -H 'key: value'. A braced value without nested braces is matched whole so that
// the "{" stays the anchor of its first field.
var logField = regexp.MustCompile(`(^|[\s{(']|map\[)([A-Za-z0-9_.-]+)(=|: ?)("(?:[^"\\]|\\.)*"|(?:\[[^\]]*\]|\{[^}]*\}|[^\s"}),])+)`)

var urlSchemeSep = []byte("://")

// redactLog redacts secret fields and strips URL queries in log text, which other
// processes and older builds write unredacted.
func redactLog(data []byte) []byte {
	var out []byte
	written, pos := 0, 0
	for line := range bytes.Lines(data) {
		next := pos + len(line)
		if r := redactLine(line); r != nil {
			if out == nil {
				out = make([]byte, 0, len(data))
			}
			out = append(out, data[written:pos]...)
			out = append(out, r...)
			written = next
		}
		pos = next
	}
	if out == nil {
		return data
	}
	return append(out, data[written:]...)
}

// redactLine returns line with the values of secret fields redacted and URL queries
// stripped, or nil if it has neither.
func redactLine(line []byte) []byte {
	changed := false
	if logsafe.MayHoldSecretField(line) {
		for _, redact := range []func([]byte) []byte{logsafe.RedactJSONFields, redactLogFields} {
			if r := redact(line); r != nil {
				line, changed = r, true
			}
		}
	}
	if bytes.Contains(line, urlSchemeSep) {
		s := string(line)
		if r := logsafe.StripQueries(s); r != s {
			line, changed = []byte(r), true
		}
	}
	if !changed {
		return nil
	}
	return line
}

// redactLogFields returns data with the values of fields whose key satisfies
// logsafe.IsSecretKey redacted, or nil if it has none.
func redactLogFields(data []byte) []byte {
	return redactFields(data, 0)
}

// redactFields redacts as redactLogFields does in data, which starts depth brackets or
// braces deep. Brackets and braces inside quoted text don't count.
func redactFields(data []byte, depth int) []byte {
	var out []byte
	last, scanned, quoted := 0, 0, false
	for _, m := range logField.FindAllSubmatchIndex(data, -1) {
		for ; scanned < m[4]; scanned++ {
			switch c := data[scanned]; {
			case c == '\\' && scanned+1 < m[4]:
				scanned++
			case c == '"':
				quoted = !quoted
			case quoted:
			case c == '[' || c == '{':
				depth++
			case (c == ']' || c == '}') && depth > 0:
				depth--
			}
		}
		if m[0] < last {
			continue
		}
		key := data[m[4]:m[5]]
		value, end := data[m[8]:m[9]], m[9]
		if logsafe.IsSecretKey(string(key)) {
			value = []byte(logsafe.Redacted)
			switch {
			case data[m[8]] == '"':
			case bytes.HasPrefix(data[m[8]:], escapedQuote):
				end = logsafe.EscapedStringEnd(data, m[8])
			case depth > 0:
				end = containedValueEnd(data, end)
			case isAuthScheme(data[m[8]:m[9]]) || isAuthorizationKey(key):
				if n := authCredentials.FindIndex(data[end:]); n != nil {
					end += n[1]
				}
			}
			if m[3] > m[2] && data[m[2]] == '\'' && data[end-1] == '\'' {
				// Keep the quote that closes a curl header.
				end--
			}
		} else if !logsafe.ContainsSecretKey(value) {
			// Without a secret word, no nested field needs redacting.
			continue
		} else if value = redactNestedFields(value, depth); value == nil {
			continue
		}
		out = append(out, data[last:m[8]]...)
		out = append(out, value...)
		last = end
	}
	if out == nil {
		return nil
	}
	return append(out, data[last:]...)
}

var goMapOpen = []byte("map[")

// authCredentials matches the credentials that follow an Authorization scheme.
var authCredentials = regexp.MustCompile(`^[ \t]+[^\s"\\,\]}]+`)

func isAuthScheme(value []byte) bool {
	return bytes.EqualFold(value, []byte("Bearer")) || bytes.EqualFold(value, []byte("Basic"))
}

func isAuthorizationKey(key []byte) bool {
	return len(key) >= len(authorization) && bytes.EqualFold(key[len(key)-len(authorization):], authorization)
}

var (
	authorization = []byte("authorization")
	escapedQuote  = []byte(`\"`)
)

// nextField matches the separator and key that start a field following another in a
// Go map or struct, or a Dart map.
var nextField = regexp.MustCompile(`(?:\s+|,\s*)[A-Za-z0-9_.-]+(?:=|: ?)`)

// containedValueEnd returns the end of an unquoted value that continues at i inside a
// Go map or struct, or a Dart map, whose values can hold spaces: where the next field
// starts, or at the bracket, brace or quote that closes what holds the value.
func containedValueEnd(data []byte, i int) int {
	end := len(data)
	if loc := nextField.FindIndex(data[i:]); loc != nil {
		end = i + loc[0]
	}
	depth := 0
	for j := i; j < end; j++ {
		switch data[j] {
		case '[', '{':
			depth++
		case ']', '}':
			if depth == 0 {
				return j
			}
			depth--
		case '"':
			if depth == 0 {
				return j
			}
		}
	}
	return end
}

// redactNestedFields returns value, quoted or not and starting depth brackets or braces
// deep, with the values of fields inside it redacted as by redactLogFields, or nil if
// it has none.
func redactNestedFields(value []byte, depth int) []byte {
	var prefix []byte
	switch {
	case len(value) >= 2 && value[0] == '"':
		prefix = value[:1]
	// Unwrapping keeps the map's closing bracket out of its last entry's value.
	case bytes.HasPrefix(value, goMapOpen) && closedAtEnd(value):
		prefix = goMapOpen
		depth++
	default:
		return redactFields(value, depth)
	}
	inner := redactNestedFields(value[len(prefix):len(value)-1], depth)
	if inner == nil {
		return nil
	}
	return slices.Concat(prefix, inner, value[len(value)-1:])
}

// closedAtEnd reports whether the first '[' in value is closed by its last byte.
func closedAtEnd(value []byte) bool {
	depth := 0
	for i, c := range value {
		switch c {
		case '[':
			depth++
		case ']':
			if depth--; depth == 0 {
				return i == len(value)-1
			}
		}
	}
	return false
}

func redactJSONValue(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, val := range v {
			if logsafe.IsSecretField(k) {
				v[k] = logsafe.Redacted
			} else {
				v[k] = redactJSONValue(val)
			}
		}
	case []any:
		for i, val := range v {
			v[i] = redactJSONValue(val)
		}
	case string:
		return logsafe.StripQueries(v)
	}
	return v
}
