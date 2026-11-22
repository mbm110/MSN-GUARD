// Package logsafe identifies credentials, user identifiers and URL queries in log
// text and redacts them.
package logsafe

// secretKeys holds keys, spelled with lowercase letters a-z only, whose values are
// credentials or user identifiers.
var secretKeys = newKeyTrie(
	"password", "passwd", "privatekeypassphrase", "secret",
	"token", "jwt", "jwttoken", "protoken", "accesstoken", "legacytoken",
	"authtoken", "authtokens", "apitoken", "securitytoken", "zonetoken",
	"authorization", "proxyauthorization", "bearer", "cookie", "auth", "authstr", "authkey", "credentials",
	"uuid", "privatekey", "presharedkey", "psk", "meshpsk",
	"shortid", "shortids", "ticketkey", "mackey", "keypem", "clientkey", "accesskeysecret",
	"deviceid", "userid", "legacyid", "legacyuserid", "email", "useremail",
	"userdata", "banditreporttokens", "xmeekauth",
	"xlanternprotoken", "xlanterndeviceid", "xlanternuserid", "xlanternconfigclientip",
)

// IsSecretKey reports whether values under key are credentials or user identifiers
// that must not be logged. Matching ignores case, '_' and '-'. A dotted key, such as a
// flattened settings path, matches when any of its parts does.
func IsSecretKey(key string) bool {
	return hasSecretPart(key, true)
}

// ContainsSecretKey reports whether text has a word, a maximal run of ASCII letters,
// digits, '_' and '-', that satisfies [IsSecretKey].
func ContainsSecretKey[T ~string | ~[]byte](text T) bool {
	return hasSecretPart(text, false)
}

// hasSecretPart reports whether a part of text is a secret key. Parts are separated
// by '.' if dotted, where any other delimiter spoils its part, or else by every
// delimiter.
func hasSecretPart[T ~string | ~[]byte](text T, dotted bool) bool {
	n := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if dotted && c == '.' || !dotted && byteClasses[c] == classDelim {
			if n >= 0 && secretKeys[n].terminal {
				return true
			}
			n = 0
		} else if n >= 0 {
			n = secretKeys.next(n, c)
		}
	}
	return n >= 0 && secretKeys[n].terminal
}

type keyTrie []trieNode

type trieNode struct {
	// next holds the child index for each letter; 0 means none, as the root is never a child.
	next     [26]uint16
	terminal bool
}

func newKeyTrie(keys ...string) keyTrie {
	t := keyTrie{{}}
	for _, key := range keys {
		n := 0
		for i := 0; i < len(key); i++ {
			c := key[i] - 'a'
			if t[n].next[c] == 0 {
				t = append(t, trieNode{})
				t[n].next[c] = uint16(len(t) - 1)
			}
			n = int(t[n].next[c])
		}
		t[n].terminal = true
	}
	return t
}

// next returns the node that c leads to from node n, or -1 if no key continues with c.
func (t keyTrie) next(n int, c byte) int {
	switch class := byteClasses[c]; class {
	case classIgnored:
		return n
	case classDelim, classDigit:
		return -1
	default:
		if child := t[n].next[class-classLetter]; child != 0 {
			return int(child)
		}
		return -1
	}
}

const (
	// classDelim must be zero: every byte byteClasses does not list is a delimiter.
	classDelim = iota
	classIgnored
	classDigit
	// classLetter+i is the class of letter 'a'+i, in either case.
	classLetter
)

var byteClasses = func() (classes [256]uint8) {
	for c := byte('a'); c <= 'z'; c++ {
		classes[c] = classLetter + c - 'a'
		classes[c-'a'+'A'] = classLetter + c - 'a'
	}
	for c := byte('0'); c <= '9'; c++ {
		classes[c] = classDigit
	}
	classes['_'], classes['-'] = classIgnored, classIgnored
	return classes
}()
