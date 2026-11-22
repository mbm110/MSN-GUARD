package ipc

import (
	"testing"

	box "github.com/getlantern/lantern-box"
	LO "github.com/getlantern/lantern-box/option"
	O "github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/servers"
)

// TestSamizdatOptionsRoundTrip verifies that samizdat outbound options
// (specifically public_key) survive JSON serialization/deserialization
// through the IPC path. This was the root cause of the "public_key must
// be 64 hex characters (32 bytes), got len=0" bug -- standard encoding/json
// doesn't preserve typed Options on option.Outbound's any interface.
func TestSamizdatOptionsRoundTrip(t *testing.T) {
	const testPubKey = "20ebb18d5fdf9bff27fe32ef9501035d8f0bb8dfb481a0a2363181560e0e8115"
	const testShortID = "3b1a8fc7f1edf914"

	outbound := O.Outbound{
		Type: "samizdat",
		Tag:  "samizdat-out-test-route",
		Options: &LO.SamizdatOutboundOptions{
			ServerOptions: O.ServerOptions{
				Server:     "1.2.3.4",
				ServerPort: 443,
			},
			PublicKey:  testPubKey,
			ShortID:    testShortID,
			ServerName: "example.com",
		},
	}

	// Verify that outbound options survive round-trip through sing-box context JSON
	// when used within a ServerList (the transfer type for IPC).
	t.Run("singbox_json_preserves_public_key_in_serverlist", func(t *testing.T) {
		ctx := box.BaseContext()

		list := servers.ServerList{
			Servers: []*servers.Server{
				{
					Tag:       outbound.Tag,
					Type:      outbound.Type,
					IsLantern: true,
					Options:   outbound,
				},
			},
		}

		buf, err := singjson.MarshalContext(ctx, list)
		require.NoError(t, err)

		// Verify public_key is in the serialized JSON
		assert.Contains(t, string(buf), testPubKey, "serialized JSON should contain public_key")

		decoded, err := singjson.UnmarshalExtendedContext[servers.ServerList](ctx, buf)
		require.NoError(t, err)

		require.Len(t, decoded.Servers, 1)
		outOpts, ok := decoded.Servers[0].Options.(O.Outbound)
		require.True(t, ok, "sing-box json should preserve typed Outbound Options")

		samOpts, ok := outOpts.Options.(*LO.SamizdatOutboundOptions)
		require.True(t, ok, "sing-box json should preserve typed SamizdatOutboundOptions")
		assert.Equal(t, testPubKey, samOpts.PublicKey, "public_key should survive round-trip")
		assert.Equal(t, testShortID, samOpts.ShortID, "short_id should survive round-trip")
		assert.Equal(t, "example.com", samOpts.ServerName, "server_name should survive round-trip")
	})
}
