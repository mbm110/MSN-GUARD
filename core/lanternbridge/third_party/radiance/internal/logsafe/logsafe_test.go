package logsafe

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canary = "canary-7f3a"

func TestIsSecretKey(t *testing.T) {
	for _, key := range []string{
		"password", "deviceId", "device_id", "Device-ID", "jwt_token", "PRO_TOKEN", "uuid", "private_key",
		"updates.token", "user_data.legacyUserData.phone", "bandit_report_tokens", "X-Meek-Auth", "Proxy-Authorization", "Bearer", "X-Lantern-Pro-Token", "X-Lantern-Config-Client-IP",
	} {
		assert.True(t, IsSecretKey(key), key)
	}
	for _, key := range []string{
		"tag", "level", "error", "key", "JWTTokenSet", "", "updates.locale", "token2.x", ".",
	} {
		assert.False(t, IsSecretKey(key), key)
	}
}

func TestContainsSecretKey(t *testing.T) {
	for _, text := range []string{
		"password=x", `{"Pro_Token":"x"}`, "--device-id x", "user uuid", "p_a_s_s_w_o_r_d___________________________=x",
	} {
		assert.True(t, ContainsSecretKey([]byte(text)), text)
	}
	for _, text := range []string{
		"", "passwords=x", "token2=x", "monkey key", "JWTTokenSet=true", "pass\xc3\xa9word", "auth0",
	} {
		assert.False(t, ContainsSecretKey([]byte(text)), text)
	}
}

func TestMayHoldSecretField(t *testing.T) {
	for _, text := range []string{"password=x", "key", `{"Key":"x"}`, "tls KEY=x"} {
		assert.True(t, MayHoldSecretField(text), text)
	}
	for _, text := range []string{"", "ke", "monkey", "keys", "key_id", "k-ey", "token2=x"} {
		assert.False(t, MayHoldSecretField(text), text)
	}
}

func TestRedactJSONFields(t *testing.T) {
	var escaped bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&escaped, nil))
	for _, password := range []string{`pre"` + canary, `pre\` + canary, `pre\"` + canary + `\\`} {
		raw, err := json.Marshal(map[string]string{"password": password, "tag": "hy2"})
		require.NoError(t, err)
		logger.Info("Auto location server:", "server", string(raw))
		escaped.WriteString(string(raw) + "\n")
	}
	for _, tt := range []struct {
		name string
		in   string
		gone string
		kept map[string]int
	}{
		{
			name: "containers",
			in:   `{"tls":{"key":["` + canary + `"]},"short_id":["` + canary + `"],"users":{"uuid":{"x":"` + canary + `"}},"tag":"hy2"}`,
			kept: map[string]int{`"tag":"hy2"}`: 1},
		},
		{
			name: "escaped array holding a bracket",
			in:   `server="{\"reality\":{\"short_ids\":[\"` + canary + `\",\"]\"]},\"tag\":\"hy2\"}"`,
			kept: map[string]int{`\"tag\":\"hy2\"}"`: 1},
		},
		{
			name: "unclosed escaped array ends at the line",
			in:   `server="{\"short_ids\":[\"` + canary + `\"` + "\nnext line ok",
			kept: map[string]int{"\nnext line ok": 1},
		},
		{
			name: "unclosed string ends at the line",
			in:   `a {"password":"` + canary + "\\\nnext line ok",
			kept: map[string]int{"\nnext line ok": 1},
		},
		{
			name: "dotted key",
			in:   `{"settings.token":"` + canary + `","tag":"hy2"}`,
			kept: map[string]int{`"tag":"hy2"}`: 1},
		},
		{
			name: "container spanning lines",
			in:   "{\n  \"tls\": {\n    \"key\": [\n      \"" + canary + "\"\n    ]\n  },\n  \"tag\": \"hy2\"\n}",
			kept: map[string]int{`"tag": "hy2"`: 1},
		},
		{
			name: "escaped value ends at its line",
			in:   `msg="cfg {\"credentials\":{\"a\":\"` + canary + `\",\"b\":1` + "\n" + `time=2 level=INFO msg="next line" x=1`,
			kept: map[string]int{"\n" + `time=2 level=INFO msg="next line" x=1`: 1},
		},
		{
			name: "number",
			in:   `b {"token": 1.5e3, "tag":"hy2"}`,
			gone: "1.5e3",
			kept: map[string]int{`"tag":"hy2"`: 1},
		},
		{
			name: "escaped quotes and backslashes",
			in:   escaped.String(),
			kept: map[string]int{`\"tag\":\"hy2\"`: 3, `"tag":"hy2"`: 3},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := string(RedactJSONFields([]byte(tt.in)))
			assert.NotContains(t, out, canary)
			if tt.gone != "" {
				assert.NotContains(t, out, tt.gone)
			}
			for kept, n := range tt.kept {
				assert.Equal(t, n, strings.Count(out, kept), kept)
			}
		})
	}
}

func TestStripQueries(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.example/x?token=t next":                              "https://a.example/x next",
		`Get "https://a.example/x?token=t": refused`:                    `Get "https://a.example/x": refused`,
		`{\"url\":\"https://a.example/?k=v\"}`:                          `{\"url\":\"https://a.example/\"}`,
		"what? https://a.example/?k=v#f":                                "what? https://a.example/",
		`{"url":"https://a.example/x?a=1\u0026token=t"}`:                `{"url":"https://a.example/x"}`,
		`{"cfg":"{\"url\":\"https://a.example/x?a=1\\u0026token=t\"}"}`: `{"cfg":"{\"url\":\"https://a.example/x\"}"}`,
		"no url?x": "no url?x",
	} {
		assert.Equal(t, want, StripQueries(in), in)
	}
}
