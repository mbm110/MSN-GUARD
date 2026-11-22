package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"testing"

	lblog "github.com/getlantern/lantern-box/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
)

const canary = "canary-7f3a"

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(newHandler(buf, LevelTrace))
}

type outbound struct {
	Tag      string
	Password string
}

type outboundValuer struct{ outbound }

func (o outboundValuer) LogValue() slog.Value { return slog.AnyValue(o.outbound) }

type credentialValuer struct{}

func (credentialValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("tag", "hy2"), slog.String("password", canary))
}

func TestRedactAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	logger.Info("secret keys", "password", canary, "deviceId", canary, slog.Group("user", "user_id", canary))
	logger.Info("secret group", slog.Group("credentials", "value", canary))
	logger.With("token", canary).Info("with attrs")
	logger.WithGroup("credentials").Info("with group", "value", canary)
	logger.Info("structs",
		"server", outbound{Tag: "hy2", Password: canary},
		"pointer", &outbound{Password: canary},
		"map", map[string]any{"password": canary},
		"bytes", []byte(canary),
		"valuer", outboundValuer{outbound{Password: canary}},
		"group_valuer", credentialValuer{},
		"settings", settings.Settings{settings.TokenKey: canary, settings.UserDataKey: map[string]any{"x": canary}},
		"headers", map[string]string{"Accept": "json", "Authorization": canary},
		"current", settings.Settings{"user_data.legacyToken": canary, "user_data.id": canary, "locale": "en-US"},
	)
	assert.NotContains(t, buf.String(), canary)
	assert.Contains(t, buf.String(), "server=\"[REDACTED log.outbound]\"")
	assert.Contains(t, buf.String(), "group_valuer.tag=hy2")
	assert.Contains(t, buf.String(), `headers="map[Accept:json Authorization:[REDACTED]]"`)

	buf.Reset()
	type tag string
	logger.Info("kept",
		"error", errors.New("dial failed"),
		"count", 3,
		"tags", []string{"a", "b"},
		"features", map[string]bool{"x": true},
		"named", tag("hy2"),
		"nil", nil,
		"settings", settings.Settings{settings.LocaleKey: "en-US"},
	)
	for _, want := range []string{`error="dial failed"`, "count=3", "tags=\"[a b]\"", "features=map[x:true]", "named=hy2", "nil=<nil>", "settings.locale=en-US"} {
		assert.Contains(t, buf.String(), want)
	}
}

type formattedError string

func (e formattedError) Error() string { return string(e) }

func (formattedError) Format(f fmt.State, _ rune) { io.WriteString(f, "custom format") }

func TestRedactErrorsKeepTheirFormatting(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Info("errors", "plain", errors.New("dial failed"), "formatted", formattedError("plain"))
	assert.Contains(t, buf.String(), `plain="dial failed" formatted="custom format"`)

	buf.Reset()
	logger.Info("errors", "formatted", formattedError(`body {"token":"`+canary+`"}`))
	assert.NotContains(t, buf.String(), canary, "a secret in Error() outranks the error's own formatting")
	assert.Contains(t, buf.String(), `formatted="body {\"token\":[REDACTED]}"`)
}

type pointerError struct{ msg string }

func (e *pointerError) Error() string { return e.msg }

func TestRedactNilPointerError(t *testing.T) {
	var buf bytes.Buffer
	var err *pointerError
	newTestLogger(&buf).Info("errors", "error", err)
	assert.Contains(t, buf.String(), "error=<nil>")
}

func TestRedactSettings(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf).Info("settings", "settings", settings.Settings{
		settings.TokenKey:    canary,
		settings.LogLevelKey: "debug",
	})
	assert.NotContains(t, buf.String(), canary)
	assert.Contains(t, buf.String(), "settings.log_level=debug settings.token=[REDACTED]")
}

func TestRedactConnectionInfo(t *testing.T) {
	var buf bytes.Buffer
	factory := lblog.NewFactory(RedactConnectionInfo(newTestLogger(&buf).Handler()))
	logger := factory.NewLogger("dns")

	for _, msg := range []string{
		"exchange " + canary + ".example. IN A",
		"sniffed protocol: tls, domain: www." + canary + ".example",
		"outbound connection to " + canary + ".example:443",
		"inbound connection to 203.0.113.7:443",
		"dial tcp [2001:db8::7]:443: i/o timeout",
		"lookup 2001:db8::7 failed",
		"dial tcp [2001:db8::]:443: i/o timeout",
		"lookup fe80:: failed",
		"read tcp 198.51.100.2:5555->203.0.113.7:443: connection reset",
		"exchange _8443._https." + canary + ".example. IN HTTPS",
		"exchanged A " + canary + ".example. 600 IN A 203.0.113.8",
		"found process path: /home/" + canary + "/bin/app, user: " + canary,
		"found package name: org." + canary + ".app",
		"match[3] process_path=/Users/" + canary + "/private-app => route(direct)",
		"router: pre-match[1] process_path=[/Applications/" + canary + " App.app/x /bin/y] network=tcp => route(direct)",
		`match[2] !(process_path=C:\Program Files (x86)\` + canary + `\app.exe) => reject`,
		"match[4] package_name=org." + canary + ".app && user_id=1000 || user=" + canary + " => route(direct)",
		"match[5] process_name=" + canary + " process_path_regex=^/opt/" + canary + "/ => route(direct)",
		"router: match[3] rule_set=[geosite-cn] => route(direct)",
		"outbound/hysteria2[hy2-out]: dial failed: context deadline exceeded",
		"sing-box started (1.13.20) in 0.123s at 12:34:56",
	} {
		logger.InfoContext(t.Context(), msg)
	}
	out := buf.String()
	require.NotEmpty(t, out)
	for _, leaked := range []string{canary, "203.0.113.", "198.51.100.2", "2001:db8::", "fe80::", "user_id=1000"} {
		assert.NotContains(t, out, leaked)
	}
	for _, want := range []string{
		"outbound connection to [domain]:443",
		"inbound connection to [ipv4]:443",
		"dial tcp [[ipv6]]:443: i/o timeout",
		"read tcp [ipv4]:5555->[ipv4]:443",
		"exchanged A [domain]. 600 IN A [ipv4]",
		"lookup [ipv6] failed",
		"router: match[3] rule_set=[geosite-cn] => route(direct)",
		"outbound/hysteria2[hy2-out]: dial failed: context deadline exceeded",
		"sing-box started (1.13.20) in 0.123s at 12:34:56",
	} {
		assert.Contains(t, out, want)
	}
	assert.Contains(t, out, "match[3] process_path=[REDACTED] => route(direct)")
	assert.Contains(t, out, "pre-match[1] process_path=[REDACTED] network=tcp => route(direct)")
	assert.Contains(t, out, "match[2] !(process_path=[REDACTED]) => reject")
	assert.Contains(t, out, "match[4] package_name=[REDACTED] && user_id=[REDACTED] || user=[REDACTED] => route(direct)")
	assert.Contains(t, out, "match[5] process_name=[REDACTED] process_path_regex=[REDACTED] => route(direct)")
	assert.Contains(t, out, "tag=dns")
}

func TestDestinationPlaceholder(t *testing.T) {
	for host, want := range map[string]string{
		"iantem.io":                "",
		"api.iantem.io":            "",
		"Backoffice.LANTR.net":     "",
		"notiantem.io":             "[domain]",
		"www.example.com.:443":     "[domain]",
		"iantem.io.example.com":    "[domain]",
		"127.0.0.1":                "",
		"10.0.0.1":                 "",
		"::ffff:10.0.0.1":          "",
		"::ffff:203.0.113.7":       "[ipv4]",
		"203.0.113.7":              "[ipv4]",
		"198.18.0.5":               "",
		"198.20.0.1":               "[ipv4]",
		"2001:db8::1":              "[ipv6]",
		"fe80::1%eth0":             "[ipv6]",
		"fe80::21a:2bff:fe3c:4d5e": "[ipv6]",
		"fd00::1":                  "[ipv6]",
		"169.254.1.1":              "",
		"ff02::fb":                 "",
		"::":                       "",
	} {
		h, addr, ok := tokenHost(host)
		require.True(t, ok, host)
		assert.Equal(t, want, destinationPlaceholder(h, addr), host)
	}
}

func TestRedactJSONInStrings(t *testing.T) {
	server := `{"tag":"hy2","options":{"password":"` + canary + `","tls":{"insecure":true,"key":["` + canary + `"]}}}`
	nested, err := json.Marshal(map[string]string{"server": server})
	require.NoError(t, err)
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Debug("Auto location server:", "server", server)
	logger.Debug("Auto location server: " + server)
	logger.Debug("event", "data", string(nested))
	logger.Debug("request failed", "error", errors.New(`unexpected status 400 body {"token":"`+canary+`"}`))
	logger.Debug("servers", "list", []string{server}, "by_tag", map[string]string{"hy2": server})
	out := buf.String()
	assert.NotContains(t, out, canary)
	assert.Contains(t, out, `server="{\"tag\":\"hy2\",\"options\":{\"password\":[REDACTED],\"tls\":{\"insecure\":true,\"key\":[REDACTED]}}}"`)

	buf.Reset()
	logger.Debug("kept", "data", `{"tag":"hy2","status":"connected"}`, "monkey", `{"monkey":"x"}`)
	assert.Contains(t, buf.String(), `data="{\"tag\":\"hy2\",\"status\":\"connected\"}"`)
	assert.Contains(t, buf.String(), `monkey="{\"monkey\":\"x\"}"`)
}

func TestRedactLongJSONWhole(t *testing.T) {
	long := `{"password":"` + canary + `","pad":"` + strings.Repeat("x", maxJSONRedactionLen) + `"}`
	plain := `{"pad":"` + strings.Repeat("x", maxJSONRedactionLen) + `"}`
	assert.Equal(t, fmt.Sprintf("[REDACTED %d bytes]", len(long)), redactString(long))
	assert.Equal(t, plain, redactString(plain), "text with no secret word is kept at any length")
}

func TestLogOutputCanaries(t *testing.T) {
	var buf bytes.Buffer
	h := newHandler(newRedactingWriter(&buf), LevelTrace)
	logger := slog.New(h)
	logger.Info("attrs", "password", canary, "deviceId", canary, "email", canary+"@example.com",
		"server", outbound{Tag: "hy2", Password: canary}, "headers", map[string]string{"Authorization": canary},
		"url", "https://api.iantem.io/v1/config?token="+canary)
	logger.Info("Auto location server:", "server", `{"tag":"hy2","password":"`+canary+`"}`)
	logger.Info(`config {"user_id":"` + canary + `"}`)
	logger.Error("request failed", "error", errors.New(`body {"pro_token":"`+canary+`"}`))
	indented, err := json.MarshalIndent(map[string]any{"tls": map[string][]string{"key": {canary}}}, "", "  ")
	require.NoError(t, err)
	logger.Info("config", "options", string(indented), "settings", `{"settings.token":"`+canary+`"}`)
	sb := lblog.NewFactory(RedactConnectionInfo(h)).NewLogger("dns")
	sb.InfoContext(t.Context(), "exchange "+canary+".example. IN A")
	sb.InfoContext(t.Context(), "outbound connection to 203.0.113.9:443")
	sb.InfoContext(t.Context(), "found process path: /Users/"+canary+"/app")

	out := buf.String()
	require.NotEmpty(t, out)
	assert.NotContains(t, out, canary)
	assert.NotContains(t, out, "203.0.113.9")
}

func TestRedactLoggableAnyKeepsUnchangedMaps(t *testing.T) {
	m := map[string]string{"url": "https://a.example/x", "config": `{"tag":"hy2"}`}
	r, changed := redactLoggableAny(m)
	assert.False(t, changed)
	assert.Equal(t, reflect.ValueOf(m).Pointer(), reflect.ValueOf(r).Pointer())
}

func TestRedactStripsURLQueries(t *testing.T) {
	u := "https://192.0.2.1:8080/api/v1/connect-config?token=" + canary
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Debug("performing request", "url", u)
	logger.Debug("retrying request", "request", "GET "+u+" (status: 500)")
	logger.Debug("request failed", "error", &url.Error{Op: "Get", URL: u, Err: errors.New("connection refused")})
	logger.Debug("fetching " + u)
	logger.Debug("mirrors", "urls", []string{u}, "by_region", map[int]string{1: u}, "failures", map[string]int{u: 2})
	type endpoint string
	logger.Debug("named", "endpoint", endpoint(u))
	assert.NotContains(t, buf.String(), canary)
	assert.Equal(t, 8, strings.Count(buf.String(), "connect-config"))
}

const helperTag = "helper-0123456789ab"

// Clients must not export helper- outbound tags, and logs are uploaded with
// issue reports and streamed to the UI.
func TestLogOutputRedactsHelperTags(t *testing.T) {
	var buf bytes.Buffer
	w := newRedactingWriter(&buf)
	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{ReplaceAttr: replaceLogAttr}))
	logger.Info("selected "+helperTag, "tag", helperTag,
		"error", errors.New("outbound/unbounded["+helperTag+"]: dial failed"))
	out := buf.String()
	assert.NotContains(t, out, helperTag)
	assert.Contains(t, out, "outbound/unbounded[helper]: dial failed")
}

func TestRedactingWriterReportsTheCallersLength(t *testing.T) {
	var buf bytes.Buffer
	w := newRedactingWriter(&buf)
	in := []byte("x " + helperTag + " y\n")
	n, err := w.Write(in)
	require.NoError(t, err)
	assert.Equal(t, len(in), n, "io.Writer contract: n counts the input")
	assert.Equal(t, "x helper y\n", buf.String())

	buf.Reset()
	plain := []byte("no tags here\n")
	n, err = w.Write(plain)
	require.NoError(t, err)
	assert.Equal(t, len(plain), n)
	assert.Equal(t, "no tags here\n", buf.String())
}

// Ruling R3: a sing-box dial error names the volunteer's address next to the
// helper outbound.
func TestLogOutputRedactsVolunteerAddressesOnHelperLines(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(newRedactingWriter(&buf), &slog.HandlerOptions{ReplaceAttr: replaceLogAttr}))
	logger.Warn("dial failed", "error", errors.New("outbound/samizdat["+helperTag+"]: dial tcp 203.0.113.7:443"))
	logger.Warn("dial failed", "error", errors.New("outbound/samizdat["+helperTag+"]: dial tcp [2001:db8::7]:443"))
	logger.Warn("dial failed", "error", errors.New("outbound/samizdat[lantern-1]: dial tcp 198.51.100.9:443"))
	out := buf.String()
	assert.NotContains(t, out, "203.0.113.7")
	assert.NotContains(t, out, "2001:db8::7")
	assert.Contains(t, out, "198.51.100.9:443", "lines without a helper outbound keep their addresses")
}

// The tunnel names live-added outbounds' loggers "outbound/<tag>[<type>]", and
// lantern-box's factory redacts the tag in that name before the line reaches
// the writer, so the line names its helper outbound only as
// "outbound/helper[<type>]".
func TestLogOutputRedactsAddressesUnderTunnelHelperLoggers(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(newRedactingWriter(&buf), &slog.HandlerOptions{ReplaceAttr: replaceLogAttr})
	f := lblog.NewFactory(h)
	f.NewLogger("outbound/" + helperTag + "[samizdat]").Error("dial tcp 203.0.113.7:443: connection refused")
	f.NewLogger("endpoint/" + helperTag + "[wireguard]").Error("handshake with [2001:db8::7]:51820 failed")
	f.NewLogger("outbound/lantern-1[samizdat]").Error("dial tcp 198.51.100.9:443: connection refused")
	out := buf.String()
	assert.NotContains(t, out, helperTag)
	assert.NotContains(t, out, "203.0.113.7")
	assert.NotContains(t, out, "2001:db8::7")
	assert.Contains(t, out, "198.51.100.9:443", "lines without a helper outbound keep their addresses")
}

// MutableURLTest's group logger is not a helper logger, but lantern-box has
// already turned the tried outbound's tag into "helper" in the message.
func TestLogOutputRedactsAddressesUnderRedactedOutboundFields(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(newRedactingWriter(&buf), &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: replaceLogAttr})
	l := lblog.NewFactory(h).NewLogger("urltest")
	l.Debug("outbound attempt failed", "outbound", helperTag, "attempt", 1, "error", errors.New("dial tcp 203.0.113.7:443: refused"))
	l.Debug("outbound unavailable", "tag", helperTag, "error", errors.New("dial tcp [2001:db8::7]:443: refused"))
	l.Debug("outbound unavailable", "tag", "lantern-1", "error", errors.New("dial tcp 198.51.100.9:443: refused"))
	out := buf.String()
	assert.NotContains(t, out, helperTag)
	assert.NotContains(t, out, "203.0.113.7")
	assert.NotContains(t, out, "2001:db8::7")
	assert.Contains(t, out, "198.51.100.9:443")
}

func TestRedactingWriterRedactsThePersonalProxiesTag(t *testing.T) {
	var buf bytes.Buffer
	w := newRedactingWriter(&buf)
	in := []byte("outbound/mutableurltest[personal-proxies]: dial tcp 203.0.113.7:443\n")
	n, err := w.Write(in)
	require.NoError(t, err)
	assert.Equal(t, len(in), n)
	assert.Equal(t, "outbound/mutableurltest[helper]: dial tcp [REDACTED]\n", buf.String())
}

func TestRedactingWriterRedactsThePersonalProxyTag(t *testing.T) {
	var buf bytes.Buffer
	w := newRedactingWriter(&buf)
	in := []byte("outbound/mutableurltest[personal-proxy]: dial tcp 203.0.113.7:443\n")
	_, err := w.Write(in)
	require.NoError(t, err)
	assert.Equal(t, "outbound/mutableurltest[helper]: dial tcp [REDACTED]\n", buf.String())
}
