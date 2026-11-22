package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/servers"
)

func TestRedactServerOmitsCredentials(t *testing.T) {
	srv := &servers.Server{
		Tag:       "private-1",
		Type:      "shadowsocks",
		IsLantern: false,
		Options:   map[string]any{"password": "outbound-password"},
		Credentials: &servers.ServerCredentials{
			AccessToken: "access-token",
			Port:        8080,
			IsJoined:    true,
		},
	}

	out, err := json.Marshal(redactServer(srv))
	require.NoError(t, err)
	printed := string(out)
	for _, secret := range []string{"access-token", "outbound-password"} {
		assert.NotContains(t, printed, secret, "credential leaked into the printed server")
	}
	for _, want := range []string{"private-1", "shadowsocks", "8080"} {
		assert.Contains(t, printed, want, "redaction dropped a field")
	}
}

func TestRedactServerNil(t *testing.T) {
	assert.Zero(t, redactServer(nil))
}
