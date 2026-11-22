package issue

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/log"
)

const canary = "canary-7f3a"

func TestRedactLog(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []string
		gone []string
		kept []string
	}{
		{
			name: "fields",
			in: []string{
				`level=DEBUG msg="Auto location server:" server="{\"tag\":\"hy2\",\"password\":\"` + canary + `\",\"tls\":{\"insecure\":true}}"`,
				`level=INFO msg="Setting up Radiance" opts="{DataDir:/data Deviceid:` + canary + ` LogLevel:trace}"`,
				`level=INFO opts="{Tag:hy2 ShortIDs:[` + canary + ` ` + canary + `] LogLevel:debug}"`,
				`level=INFO msg="Logout request" deviceId=` + canary + ` JWTTokenSet=true`,
				`level=TRACE msg="Patching settings" updates.token="` + canary + `" updates.locale=en-US`,
				`level=DEBUG msg="user data" data="{\"userId\":7311,\"tag\":\"hy2\"}"`,
			},
			gone: []string{"7311"},
			kept: []string{`\"tag\":\"hy2\"`, "LogLevel:trace}", "LogLevel:debug}", "JWTTokenSet=true", "updates.locale=en-US"},
		},
		{
			name: "go maps",
			in: []string{
				`level=TRACE msg="Patching settings" updates=map[token:` + canary + `]`,
				`level=TRACE msg="Patching settings" updates="map[token:` + canary + ` locale:en-US]" current=map[locale:en]`,
				`level=INFO opts="{Updates:map[user_data:map[email:` + canary + `] locale:fr] Tag:hy2}"`,
				`level=DEBUG msg="cfg map[token:` + canary + ` user:x]"`,
				`level=WARN err=map[Authorization:[Bearer ` + canary + `]]`,
				`level=WARN headers=map[Accept:[json] Authorization:[Bearer ` + canary + `]] tag=x`,
				`level=WARN cfg=map[a:map[token:` + canary + ` b:c]]`,
				`level=INFO password=ab[` + canary,
			},
			kept: []string{
				"updates=map[token:[REDACTED]]\n",
				`updates="map[token:[REDACTED] locale:en-US]" current=map[locale:en]`,
				"opts=\"{Updates:map[user_data:[REDACTED] locale:fr] Tag:hy2}\"",
				"err=map[Authorization:[REDACTED]]\n",
				"cfg=map[a:map[token:[REDACTED] b:c]]\n",
			},
		},
		{
			name: "dart maps",
			in: []string{
				`message=Got the userdata: {id: , legacyID: 387646722, legacyToken: ` + canary + `, userId: 7311, tag: hy2}`,
				`message=Got the config: {legacyToken: ` + canary + `, tag: hy2}`,
				`message={id: , legacyID: 387646722, email: ` + canary + `@example.com, userId: 7311, tag: hy2}`,
				`opts={Password:` + canary + ` Tag:hy2}`,
				`password=ab{` + canary,
			},
			gone: []string{"387646722", "7311"},
			kept: []string{
				"Got the userdata: [REDACTED]\n",
				"Got the config: {legacyToken: [REDACTED], tag: hy2}\n",
				"message={id: , legacyID: [REDACTED], email: [REDACTED], userId: [REDACTED], tag: hy2}\n",
				"opts={Password:[REDACTED] Tag:hy2}\n",
			},
		},
		{
			name: "values with spaces",
			in: []string{
				`level=INFO headers="map[Authorization:Bearer ` + canary + `]"`,
				`level=INFO headers=map[Accept:json Authorization:Bearer ` + canary + ` X:y]`,
				`level=INFO opts="{Tag:hy2 Token:Bearer ` + canary + ` LogLevel:trace}"`,
				`level=INFO opts={Token:Bearer ` + canary + ` Tag:hy2}`,
				`message={legacyToken: Bearer ` + canary + `, tag: hy2}`,
				`level=INFO msg="a}" headers=map[Authorization:Bearer ` + canary + `]`,
				`level=INFO msg="done]" opts="{Token:Bearer ` + canary + ` Tag:hy2}"`,
				`level=INFO msg="retry [1" password=abc some=words tag=x`,
				`message=Request headers Authorization: Bearer ` + canary + ` next=1`,
				`level=INFO header="Authorization: Basic ` + canary + `"`,
				`level=INFO header="Proxy-Authorization: Token ` + canary + `"`,
				`level=INFO opts="log.opts{Password:\"abc ` + canary + `\", Tag:\"x\"}"`,
				`level=INFO opts="{Token:\"a \\\" ` + canary + `\" Tag:\"x\"}"`,
				`level=INFO msg="retry token=\"a ` + canary + `\" after 1s"`,
			},
			kept: []string{
				`msg="a}" headers=map[Authorization:[REDACTED]]`,
				`msg="done]" opts="{Token:[REDACTED] Tag:hy2}"`,
				`password=[REDACTED] some=words tag=x`,
				"Authorization: [REDACTED] next=1",
				`header="Authorization: [REDACTED]"`,
				`header="Proxy-Authorization: [REDACTED]"`,
				`log.opts{Password:[REDACTED], Tag:\"x\"}"`,
				`{Token:[REDACTED] Tag:\"x\"}"`,
				`msg="retry token=[REDACTED] after 1s"`,
				`headers="map[Authorization:[REDACTED]]"`,
				"Authorization:[REDACTED] X:y]",
				"Token:[REDACTED] LogLevel:trace}",
				"{Token:[REDACTED] Tag:hy2}",
				"{legacyToken: [REDACTED], tag: hy2}",
			},
		},
		{
			name: "curl headers",
			in: []string{
				`level=DEBUG msg="CURL command" curl="curl -X GET -H 'Accept: */*' -H 'X-Lantern-Pro-Token: ` + canary +
					`' -H 'Authorization: Bearer ` + canary + `' 'https://df.iantem.io/api/v1/user'"`,
			},
			kept: []string{
				`-H 'Accept: */*' -H 'X-Lantern-Pro-Token: [REDACTED]' -H 'Authorization: [REDACTED]' 'https://df.iantem.io/api/v1/user'`,
			},
		},
		{
			name: "url queries",
			in: []string{
				`level=INFO url="https://example.com/v1?token=` + canary + `" next=1`,
				`level=DEBUG msg="what?" cfg="{\"url\":\"https://example.com/cb?k=` + canary + `\"}"`,
			},
			kept: []string{`url="https://example.com/v1" next=1`, `msg="what?" cfg="{\"url\":\"https://example.com/cb\"}"`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := string(redactLog([]byte(strings.Join(tt.in, "\n") + "\n")))
			for _, gone := range append(tt.gone, canary) {
				assert.NotContains(t, out, gone)
			}
			for _, kept := range tt.kept {
				assert.Contains(t, out, kept)
			}
		})
	}
}

func TestRedactJSON(t *testing.T) {
	in := `{"options":{"outbounds":[{"type":"hysteria2","tag":"hy2","password":"` + canary + `",
		"tls":{"enabled":true,"key":["` + canary + `"]},"users":[{"uuid":"` + canary + `"}]},
		{"type":"meek","tag":"meek-out","header":{"X-Meek-Auth":"` + canary + `"}}]},
		"bandit_url_overrides":{"hy2":"https://example.com/cb?token=` + canary + `"},
		"credentials":{"access_token":"` + canary + `"},"port":443,
		"bandit_report_tokens":{"hy2":"` + canary + `"}}`
	out, err := sanitizeJSONAttachment("config.json", []byte(in))
	require.NoError(t, err)
	assert.NotContains(t, string(out), canary)
	for _, kept := range []string{`"tag": "hy2"`, `"https://example.com/cb"`, `"port": 443`} {
		assert.Contains(t, string(out), kept)
	}

	_, err = sanitizeJSONAttachment("config.json", []byte(`{"tag":"hy2"} {"password":"`+canary+`"}`))
	assert.Error(t, err, "trailing JSON values must not be dropped silently")
}

func TestSanitizeJSONAttachmentExtensions(t *testing.T) {
	const helperTag = "helper-0123456789ab"
	in := []byte(`{"password":"` + canary + `","outbounds":[{"type":"samizdat","tag":"` + helperTag + `","server":"203.0.113.7"}]}`)
	for _, tt := range []struct {
		name              string
		redacted, stubbed bool
	}{
		{"config.json", true, true},
		{"CONFIG.JSON", true, true},
		{"notes.txt", false, false},
	} {
		out, err := sanitizeJSONAttachment(tt.name, in)
		require.NoError(t, err, tt.name)
		assert.Equal(t, tt.redacted, !strings.Contains(string(out), canary), tt.name)
		assert.Equal(t, tt.stubbed, !strings.Contains(string(out), helperTag), tt.name)
	}
}

func TestBuildIssueArchiveRedacts(t *testing.T) {
	dir := t.TempDir()
	logLine := `level=INFO msg="Logout request" deviceId=` + canary + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte(logLine), 0644))
	writeGzipFile(t, filepath.Join(dir, "lantern-2026-01-01T00-00-00.000.log.gz"), []byte(logLine))
	config := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(config, []byte(`{"password":"`+canary+`"}`), 0644))
	broken := filepath.Join(dir, "servers.json")
	require.NoError(t, os.WriteFile(broken, []byte(`{"password":"`+canary), 0644))

	result, err := buildIssueArchive(log.NoOpLogger(), dir, []string{config, broken}, 1024*1024)
	require.NoError(t, err)
	entries := readZipEntries(t, result)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.name)
		assert.NotContains(t, e.content, canary, e.name)
	}
	assert.ElementsMatch(t, []string{logArchiveName, "attachments/config.json"}, names)
}

func TestRedactLogUnchangedReturnsInput(t *testing.T) {
	in := []byte("level=INFO msg=\"refreshing auth token\"\nlevel=DEBUG msg=\"tls key loaded\"\n")
	out := redactLog(in)
	require.Equal(t, in, out)
	assert.Same(t, &in[0], &out[0])
}

// Issue reports upload logs, the crash log, config.json, servers.json and
// debug-box-options.json, all of which can name helper- outbounds.
func TestIssueArchiveRedactsHelperTags(t *testing.T) {
	const tag = "helper-0123456789ab"
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("selected "+tag+"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern-crash.log"), []byte("panic in outbound/unbounded["+tag+"]\n"), 0644))
	servers := filepath.Join(dir, "servers.json")
	require.NoError(t, os.WriteFile(servers, []byte(`{"outbounds":[{"tag":"`+tag+`","type":"unbounded"}]}`), 0644))

	result, err := buildIssueArchive(log.NoOpLogger(), dir, []string{servers}, 1024*1024)
	require.NoError(t, err)
	entries := readZipEntries(t, result)
	require.Len(t, entries, 3)
	for _, e := range entries {
		assert.NotContains(t, e.content, tag, e.name)
		assert.Contains(t, e.content, "helper", e.name)
	}
}

// A plan-2 direct-mode helper outbound names the volunteer's address, port
// and keys; the diagnostic copies keep only its type and a redacted tag.
func TestIssueArchiveStubsHelperOutbounds(t *testing.T) {
	const tag = "helper-0123456789ab"
	dir := t.TempDir()
	servers := filepath.Join(dir, "servers.json")
	require.NoError(t, os.WriteFile(servers, []byte(`[
 {"tag":"`+tag+`","type":"samizdat","isLantern":true,"outbound":{"type":"samizdat","tag":"`+tag+`","server":"203.0.113.77","server_port":48213,"public_key":"c2VjcmV0LWtleS1ieXRlcw"}},
 {"tag":"lantern-1","type":"samizdat","isLantern":true,"outbound":{"type":"samizdat","tag":"lantern-1","server":"198.51.100.9","server_port":443}}
]`), 0644))
	config := filepath.Join(dir, "debug-box-options.json")
	require.NoError(t, os.WriteFile(config, []byte(`{"outbounds":[
 {"type":"samizdat","tag":"`+tag+`","server":"203.0.113.77","server_port":48213,"public_key":"c2VjcmV0LWtleS1ieXRlcw"},
 {"type":"selector","tag":"manual","outbounds":["lantern-1","`+tag+`"]}],
 "endpoints":[{"type":"wireguard","tag":"`+tag+`","address":["203.0.113.77/32"]}],
 "bandit_url_overrides":{"`+tag+`":{"server":"203.0.113.77"}}}`), 0644))
	broken := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(broken, []byte(`{"outbounds":[{"tag":"`+tag+`","server":"203.0.113.77"`), 0644))

	result, err := buildIssueArchive(log.NoOpLogger(), dir, []string{servers, config, broken}, 1024*1024)
	require.NoError(t, err)
	entries := readZipEntries(t, result)
	names := map[string]string{}
	for _, e := range entries {
		names[e.name] = e.content
		for _, secret := range []string{"203.0.113.77", "48213", "c2VjcmV0LWtleS1ieXRlcw", tag} {
			assert.NotContains(t, e.content, secret, e.name)
		}
	}
	assert.NotContains(t, names, "attachments/config.json", "an unparseable config is dropped, never uploaded raw")
	require.Contains(t, names, "attachments/servers.json")
	assert.Contains(t, names["attachments/servers.json"], "198.51.100.9", "other servers are kept")
	assert.Contains(t, names["attachments/servers.json"], `"tag": "helper"`)
	assert.Contains(t, names["attachments/debug-box-options.json"], `"type": "samizdat"`)
}

// A tail read that starts mid-line, here 30 bytes before the end of the first
// line, drops that line rather than upload a fragment whose helper outbound
// was cut off and whose address was not.
func TestLogTailsDropTheLineTheyCut(t *testing.T) {
	const line = "outbound/samizdat[helper-0123456789ab]: dial tcp 203.0.113.7:443\n"

	dir := t.TempDir()
	logPath := filepath.Join(dir, "lantern-crash.log")
	require.NoError(t, os.WriteFile(logPath, []byte(line+line), 0644))
	data, err := snapshotLogFile(logPath, int64(len(line)+30)/maxLogReadFactor+1)
	require.NoError(t, err)
	assert.Equal(t, line, string(data))

	gzPath := filepath.Join(dir, "lantern.log.1.gz")
	writeGzipFile(t, gzPath, []byte(line+line))
	data, err = readGzipTail(gzPath, int64(len(line)+30))
	require.NoError(t, err)
	assert.Equal(t, line, string(data))
}

// The group's tag marks a device as having personal proxies, so issue reports
// treat it like a helper- tag: in logs, in debug-box-options.json and in the
// persisted selection.
func TestIssueArchiveRedactsThePersonalProxiesTag(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"),
		[]byte("outbound/mutableurltest[personal-proxies]: dial tcp 203.0.113.7:443\n"), 0644))
	opts := filepath.Join(dir, "debug-box-options.json")
	require.NoError(t, os.WriteFile(opts, []byte(`{"outbounds":[
 {"type":"mutableurltest","tag":"personal-proxies","outbounds":["helper-0123456789ab"]},
 {"type":"mutableselector","tag":"manual","outbounds":["lantern-1","personal-proxies"]}]}`), 0644))
	settingsFile := filepath.Join(dir, "settings.json")
	require.NoError(t, os.WriteFile(settingsFile,
		[]byte(`{"selected_server":{"tag":"personal-proxies","type":"mutableurltest","isLantern":false}}`), 0644))

	result, err := buildIssueArchive(log.NoOpLogger(), dir, []string{opts, settingsFile}, 1024*1024)
	require.NoError(t, err)
	entries := readZipEntries(t, result)
	require.Len(t, entries, 3)
	for _, e := range entries {
		assert.NotContains(t, e.content, "personal-proxies", e.name)
		assert.NotContains(t, e.content, "helper-0123456789ab", e.name)
		assert.NotContains(t, e.content, "203.0.113.7", e.name)
	}
}

func TestIssueArchiveRedactsAPersonalProxySelection(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"),
		[]byte("outbound/mutableurltest[personal-proxy]: dial tcp 203.0.113.7:443\n"), 0644))
	settingsFile := filepath.Join(dir, "settings.json")
	require.NoError(t, os.WriteFile(settingsFile,
		[]byte(`{"selected_server":{"tag":"personal-proxy:helper-0123456789ab","type":"mutableurltest","isLantern":false}}`), 0644))

	result, err := buildIssueArchive(log.NoOpLogger(), dir, []string{settingsFile}, 1024*1024)
	require.NoError(t, err)
	for _, e := range readZipEntries(t, result) {
		assert.NotContains(t, e.content, "personal-proxy", e.name)
		assert.NotContains(t, e.content, "helper-0123456789ab", e.name)
		assert.NotContains(t, e.content, "203.0.113.7", e.name)
	}
}

// debug-box-options.json carries the inviter's reverse outbounds and the
// portal that serves them. Their tags name pairings and the portal's
// masquerade domain is what a censor would match its listener against.
func TestIssueArchiveStubsReverseOutboundsAndThePortal(t *testing.T) {
	const reverse = "helper-0123456789ab-r"
	const domain = "cover.example.com"
	dir := t.TempDir()
	opts := filepath.Join(dir, "debug-box-options.json")
	require.NoError(t, os.WriteFile(opts, []byte(`{
 "inbounds":[{"type":"samizdat-portal","tag":"samizdat-portal","masquerade_domain":"`+domain+`"}],
 "outbounds":[
 {"type":"samizdat-reverse","tag":"`+reverse+`","portal":"samizdat-portal"},
 {"type":"mutableselector","tag":"manual","outbounds":["lantern-1","`+reverse+`"]}]}`), 0644))

	result, err := buildIssueArchive(log.NoOpLogger(), dir, []string{opts}, 1024*1024)
	require.NoError(t, err)
	entries := readZipEntries(t, result)
	require.Len(t, entries, 1)
	content := entries[0].content
	for _, secret := range []string{domain, "0123456789ab", "-r\""} {
		assert.NotContains(t, content, secret)
	}
	assert.Contains(t, content, `"type": "samizdat-reverse"`)
	assert.Contains(t, content, `"type": "samizdat-portal"`)
	assert.Contains(t, content, `"lantern-1"`)
}
