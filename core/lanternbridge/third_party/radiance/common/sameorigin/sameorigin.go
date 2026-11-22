// Package sameorigin keeps an HTTP client from following a redirect to
// another origin. net/http would otherwise replay a 307 or 308'd request
// body to whatever origin the redirect names, even over plain HTTP.
package sameorigin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// MaxRedirects matches net/http's default redirect limit.
const MaxRedirects = 10

// Client returns a shallow copy of c, or of a zero client if c is nil, with
// its CheckRedirect replaced by CheckRedirect(name).
func Client(c *http.Client, name string) *http.Client {
	out := &http.Client{}
	if c != nil {
		*out = *c
	}
	out.CheckRedirect = CheckRedirect(name)
	return out
}

// CheckRedirect returns an http.Client CheckRedirect that follows at most
// MaxRedirects redirects, each only within the origin (scheme, host and
// port) of the request it came from. Its errors begin with name.
func CheckRedirect(name string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return fmt.Errorf("%s: stopped after %d redirects", name, MaxRedirects)
		}
		if len(via) > 0 && !sameOrigin(via[len(via)-1].URL, req.URL) {
			return errors.New(name + ": refusing a redirect to another origin")
		}
		return nil
	}
}

// sameOrigin reports whether a and b share scheme, host and port, with each
// scheme's default port made explicit.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	}
	return ""
}
