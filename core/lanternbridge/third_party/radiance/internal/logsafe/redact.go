package logsafe

import (
	"bytes"
	"regexp"
	"strings"
)

// Redacted is the placeholder that replaces a redacted value.
const Redacted = "[REDACTED]"

// IsSecretField reports whether values under a JSON object field named name are
// secrets. Unlike [IsSecretKey], it matches "key", the field sing-box TLS options
// carry an inline private key under.
func IsSecretField(name string) bool {
	return IsSecretKey(name) || strings.EqualFold(name, "key")
}

// MayHoldSecretField reports whether text has a word that [IsSecretField] could match.
// A false result means [RedactJSONFields] would leave text unchanged.
func MayHoldSecretField[T ~string | ~[]byte](text T) bool {
	return ContainsSecretKey(text) || hasKeyWord(text)
}

// hasKeyWord reports whether text has the word "key", which IsSecretField matches but
// ContainsSecretKey does not.
func hasKeyWord[T ~string | ~[]byte](text T) bool {
	for i := 0; i+3 <= len(text); i++ {
		if text[i]|0x20 == 'k' && text[i+1]|0x20 == 'e' && text[i+2]|0x20 == 'y' &&
			(i == 0 || !isWordChar(text[i-1])) && (i+3 == len(text) || !isWordChar(text[i+3])) {
			return true
		}
	}
	return false
}

func isWordChar(c byte) bool {
	return byteClasses[c] != classDelim
}

// jsonKey matches a JSON object key and its colon, including one escaped inside a
// quoted string, where group 1 holds the escaping backslash.
var jsonKey = regexp.MustCompile(`(\\?)"([A-Za-z0-9_.-]+)\\?"\s*:\s*`)

// RedactJSONFields returns data with the value of each field that satisfies
// [IsSecretField] replaced by [Redacted], or nil if it has none. It also redacts
// fields of JSON escaped inside a quoted string. An unescaped array or object may span
// lines; any other value, or one that is not closed, as in truncated text, can't extend
// past its line.
func RedactJSONFields(data []byte) []byte {
	var out []byte
	last := 0
	for _, m := range jsonKey.FindAllSubmatchIndex(data, -1) {
		if m[0] < last || !IsSecretField(string(data[m[4]:m[5]])) {
			continue
		}
		escaped := m[3] > m[2]
		lineEnd := len(data)
		if n := bytes.IndexAny(data[m[1]:], "\r\n"); n >= 0 {
			lineEnd = m[1] + n
		}
		// An escaped value sits inside a quoted string, which ends with its line.
		limit := len(data)
		if escaped {
			limit = lineEnd
		}
		end, closed := jsonValueEnd(data[:limit], m[1], escaped)
		if !closed && limit != lineEnd {
			end, _ = jsonValueEnd(data[:lineEnd], m[1], escaped)
		}
		if end < 0 {
			continue
		}
		out = append(out, data[last:m[1]]...)
		out = append(out, Redacted...)
		last = end
	}
	if out == nil {
		return nil
	}
	return append(out, data[last:]...)
}

// jsonValueEnd returns the end of the JSON string, number, array or object that
// starts at i, or -1 if none does, and whether the value is closed. An escaped value
// sits inside a quoted string, so each of its quotes and backslashes carries an extra
// backslash, and it also ends where that string does. A value that is not closed ends
// at the end of data, or, for a string, at a line break, which JSON strings can't hold.
func jsonValueEnd(data []byte, i int, escaped bool) (int, bool) {
	if i >= len(data) {
		return -1, false
	}
	switch c := data[i]; {
	case c == '-' || isDigit(c):
		j := i + 1
		for j < len(data) && (isDigit(data[j]) || strings.IndexByte(".eE+-", data[j]) >= 0) {
			j++
		}
		return j, true
	case c == '[' || c == '{':
		return jsonContainerEnd(data, i, escaped)
	default:
		return jsonStringEnd(data, i, escaped)
	}
}

func jsonContainerEnd(data []byte, i int, escaped bool) (int, bool) {
	depth := 0
	for j := i; j < len(data); {
		switch c := data[j]; {
		case c == '[' || c == '{':
			depth++
			j++
		case c == ']' || c == '}':
			depth--
			j++
			if depth == 0 {
				return j, true
			}
		case c == '"' || c == '\\':
			end, closed := jsonStringEnd(data, j, escaped)
			switch {
			case end >= 0 && !closed:
				return len(data), false
			case end >= 0:
				j = end
			case c == '"':
				// An unescaped quote in an escaped value closes the enclosing string.
				return j, true
			default:
				j++
			}
		default:
			j++
		}
	}
	return len(data), false
}

// EscapedStringEnd returns the end of the string that starts with an escaped quote at
// i, inside a quoted string, or -1 if none starts there. A string that is not closed
// ends where the enclosing string does, at a line break or at the end of data.
func EscapedStringEnd(data []byte, i int) int {
	end, _ := jsonStringEnd(data, i, true)
	return end
}

func jsonStringEnd(data []byte, i int, escaped bool) (int, bool) {
	quote := []byte{'"'}
	if escaped {
		quote = []byte{'\\', '"'}
	}
	if !bytes.HasPrefix(data[i:], quote) {
		return -1, false
	}
	j := i + len(quote)
	for j < len(data) {
		switch {
		case data[j] == '\n' || data[j] == '\r':
			return j, false
		case escaped && bytes.HasPrefix(data[j:], []byte{'\\', '\\'}):
			// A JSON escape: the escaped character is itself escaped if it is a
			// quote or a backslash.
			k := j + 2
			if bytes.HasPrefix(data[k:], []byte{'\\', '"'}) || bytes.HasPrefix(data[k:], []byte{'\\', '\\'}) {
				j = k + 2
			} else {
				j = k + 1
			}
		case bytes.HasPrefix(data[j:], quote):
			return j + len(quote), true
		case data[j] == '\\' && j+1 < len(data) && data[j+1] != '\n' && data[j+1] != '\r':
			j += 2
		case escaped && data[j] == '"':
			return j, true
		default:
			j++
		}
	}
	return len(data), false
}

func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// StripQueries returns s with the query, and anything after it, removed from each
// URL. A URL starts after "://" and ends at whitespace, a quote, an escaped quote, '<'
// or '>', so one quoted or escaped inside a log value keeps its closing quote.
func StripQueries(s string) string {
	var b strings.Builder
	last := 0
	for i := 0; ; {
		n := strings.Index(s[i:], "://")
		if n < 0 {
			break
		}
		start := i + n + len("://")
		end := start
		for end < len(s) && !urlEndsAt(s, end) {
			end++
		}
		if q := strings.IndexByte(s[start:end], '?'); q >= 0 {
			b.WriteString(s[last : start+q])
			last = end
		}
		i = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func urlEndsAt(s string, i int) bool {
	switch s[i] {
	case ' ', '\t', '\n', '\r', '\f', '"', '\'', '<', '>':
		return true
	case '\\':
		// Only an escaped quote ends a URL; json.Marshal escapes '&' as \u0026.
		for i < len(s) && s[i] == '\\' {
			i++
		}
		return i == len(s) || s[i] == '"'
	}
	return false
}
