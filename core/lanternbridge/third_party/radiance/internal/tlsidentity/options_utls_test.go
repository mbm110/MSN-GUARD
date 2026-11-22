//go:build with_utls

package tlsidentity

import "testing"

func TestUTLSIdentityHandshake(t *testing.T) {
	testTLSIdentityHandshake(t, true)
}
