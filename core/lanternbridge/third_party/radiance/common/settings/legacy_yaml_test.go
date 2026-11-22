package settings

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTranslateLegacyYAML_Desktop(t *testing.T) {
	t.Run("pro user with all fields", func(t *testing.T) {
		// Shape mirrors what the pre-9.x desktop client (flashlight +
		// lantern-client) wrote into ~/.lantern/settings.yaml /
		// %APPDATA%\Lantern\settings.yaml / ~/.config/lantern/settings.yaml.
		yaml := []byte(`userID: 3580849
deviceID: 84e9c7b2-2a54-44f3-9ec6-276086017e49
userPro: true
userToken: abc123token
emailAddress: derek@example.com
userFirstVisit: true
otherStuff: ignored
`)

		out, err := translateLegacyYAML(yaml, "desktop")
		require.NoError(t, err)

		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		assert.Equal(t, float64(3580849), got["user_id"])
		assert.Equal(t, "84e9c7b2-2a54-44f3-9ec6-276086017e49", got["device_id"])
		assert.Equal(t, "pro", got["user_level"])
		assert.Equal(t, "abc123token", got["token"])
		assert.Equal(t, "derek@example.com", got["email"])
	})

	t.Run("free user with id is marked free", func(t *testing.T) {
		yaml := []byte(`userID: 100
deviceID: dev-abc
userPro: false
userToken: tok
`)
		out, err := translateLegacyYAML(yaml, "desktop")
		require.NoError(t, err)
		assert.Equal(t, "free", userLevelInJSON(out),
			"a known but non-pro user should translate to user_level=free")
	})

	t.Run("anonymous (no user id) leaves user_level empty", func(t *testing.T) {
		yaml := []byte(`userPro: false
userToken: ""
`)
		out, err := translateLegacyYAML(yaml, "desktop")
		require.NoError(t, err)
		assert.Equal(t, "", userLevelInJSON(out),
			"no user_id means we shouldn't claim 'free'; let next login decide")
	})

	t.Run("malformed yaml errors", func(t *testing.T) {
		_, err := translateLegacyYAML([]byte("\tnot: a [valid yaml: doc\n"), "desktop")
		assert.Error(t, err)
	})
}

func TestTranslateLegacyYAML_iOS(t *testing.T) {
	yaml := []byte(`AppName: lantern
DeviceID: ios-device-9000
UserID: 7777
Token: ios-token
Language: en
Country: US
`)
	out, err := translateLegacyYAML(yaml, "ios")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, float64(7777), got["user_id"])
	assert.Equal(t, "ios-device-9000", got["device_id"])
	assert.Equal(t, "ios-token", got["token"])
	// iOS yaml didn't carry user_level — should be omitted, not "free".
	_, hasLevel := got["user_level"]
	assert.False(t, hasLevel, "iOS yaml should not produce a user_level field")
}

func TestTranslateLegacyYAML_UnknownLayout(t *testing.T) {
	_, err := translateLegacyYAML([]byte(`userID: 1`), "android")
	assert.Error(t, err)
}
