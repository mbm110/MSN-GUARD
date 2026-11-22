package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/getlantern/radiance/common/settings"
	"secretvars"
)

type config struct {
	Password string
	Token    string
	Host     string
}

func direct(c config, m map[string]string, logger *slog.Logger, ctx context.Context) {
	slog.Info(c.Password)                                                            // want `slog.Info logs sensitive data from field Password`
	slog.Debug("connect", "credential", c.Token)                                     // want `slog.Debug logs sensitive data from field Token`
	logger.WarnContext(ctx, "connect", "value", m["access_token"])                   // want `slog.WarnContext logs sensitive data from map key access_token`
	slog.Log(ctx, slog.LevelInfo, c.Password)                                        // want `slog.Log logs sensitive data from field Password`
	slog.LogAttrs(ctx, slog.LevelError, "connect", slog.String("value", c.Password)) // want `slog.LogAttrs logs sensitive data from field Password`
	slog.With("value", c.Password)                                                   // want `slog.With logs sensitive data from field Password`
	logger.With("value", c.Token)                                                    // want `slog.With logs sensitive data from field Token`
	// Secret keys and groups don't stop a report, whatever a handler redacts.
	slog.Info("connect", "PASSWORD", c.Password)                         // want `slog.Info logs sensitive data from field Password`
	slog.Info("connect", slog.String("password", c.Password))            // want `slog.Info logs sensitive data from field Password`
	slog.Info("connect", slog.Group("credentials", "value", c.Password)) // want `slog.Info logs sensitive data from field Password`
	slog.Info("connect", "host", c.Host)
	slog.Info("connect", "length", len(c.Password))
	slog.Info("connect", "present", c.Password != "")
	slog.Info(fmt.Sprintf("%T", c.Password))
	slog.Info("connect", slog.String("value", "literal"))
	slog.Info("connect", slog.Group("details", slog.String("value", c.Password)))           // want `slog.Info logs sensitive data from field Password`
	slog.Info("connect", slog.Any("value", slog.GroupValue(slog.String("value", c.Token)))) // want `slog.Info logs sensitive data from field Token`
	slog.Info("connect", slog.Any("value", slog.StringValue(c.Token)))                      // want `slog.Info logs sensitive data from field Token`
	(*slog.Logger).Error(logger, c.Password)                                                // want `slog.Error logs sensitive data from field Password`
	_ = c
	slog.Info("connect", c.Password)                                                                // want `slog.Info logs sensitive data from field Password`
	slog.Info("connect", c.Password, "value")                                                       // want `slog.Info logs sensitive data from field Password`
	slog.Info("connect", []any{"value", c.Password}...)                                             // want `slog.Info logs sensitive data from field Password`
	slog.LogAttrs(ctx, slog.LevelInfo, "connect", []slog.Attr{slog.String("value", c.Password)}...) // want `slog.LogAttrs logs sensitive data from field Password`
	slog.Info("connect", slog.Attr{Key: "value", Value: slog.StringValue(c.Token)})                 // want `slog.Info logs sensitive data from field Token`
	slog.Info("connect", slog.String(c.Password, "value"))                                          // want `slog.Info logs sensitive data from field Password`
}

func transformations(c config) {
	credential := c.Password
	alias := credential
	message := "connecting with " + alias
	formatted := fmt.Sprintf("%s", message)
	bytes := []byte(formatted)
	slog.Info(string(bytes))          // want `slog.Info logs sensitive data from field Password`
	slog.Info(strings.ToUpper(alias)) // want `slog.Info logs sensitive data from field Password`
	var declared = c.Token
	slog.Info(declared) // want `slog.Info logs sensitive data from field Token`
	clean := "safe"
	clean += c.Password
	slog.Info(clean) // want `slog.Info logs sensitive data from field Password`
	credential = "safe"
	slog.Info(credential)
	slog.Info(alias) // want `slog.Info logs sensitive data from field Password`
	alias, clean = "safe", alias
	slog.Info(alias)
	slog.Info(clean) // want `slog.Info logs sensitive data from field Password`
	attr := slog.String("value", c.Password)
	slog.Info("connect", attr) // want `slog.Info logs sensitive data from field Password`
	args := []any{"value", c.Token}
	slog.Info("connect", args...)     // want `slog.Info logs sensitive data from field Token`
	slog.Info("connect", args[1:]...) // want `slog.Info logs sensitive data from field Token`
}

func branches(c config, condition bool) {
	value := "safe"
	if condition {
		value = c.Password
	} else {
		value = "safe"
	}
	slog.Info(value) // want `slog.Info logs sensitive data from field Password`
	value = "safe"
	slog.Info(value)
	for condition {
		slog.Info(value) // want `slog.Info logs sensitive data from field Token`
		value = c.Token
	}
	slog.Info(value) // want `slog.Info logs sensitive data from field Token`
	{
		value := "safe"
		slog.Info(value)
	}
}

func settingsValues() {
	value := settings.GetString(settings.TokenKey)
	slog.Info(value)                                                   // want `slog.Info logs sensitive data from settings key token`
	slog.Info("settings", "value", settings.Get(settings.DeviceIDKey)) // want `slog.Info logs sensitive data from settings key device_id`
	slog.Info(settings.GetString(settings.HostKey))
}

func groups(c config, logger *slog.Logger) {
	logger.WithGroup(c.Password)                                         // want `slog.WithGroup logs sensitive data from field Password`
	logger.WithGroup("credentials").Info("connect", "value", c.Password) // want `slog.Info logs sensitive data from field Password`
}

func suppression(c config) {
	slog.Info(c.Password) //logleak:ok deliberate test
	//logleak:ok deliberate test
	slog.Info(c.Password)
	slog.Info(c.Password) // want `slog.Info logs sensitive data from field Password`
}

func appends(c config, ctx context.Context) {
	args := []any{"host", c.Host}
	args = append(args, "value", c.Token)
	slog.Info("connect", args...) // want `slog.Info logs sensitive data from field Token`
	copied := append([]any{}, args...)
	slog.Info("connect", copied...) // want `slog.Info logs sensitive data from field Token`
	attrs := append([]slog.Attr{}, slog.String("value", c.Password))
	slog.LogAttrs(ctx, slog.LevelInfo, "connect", attrs...) // want `slog.LogAttrs logs sensitive data from field Password`
}

func assertions() {
	got, _ := settings.Get(settings.TokenKey).(string)
	slog.Info("settings", "value", got) // want `slog.Info logs sensitive data from settings key token`
}

func ranges(c config) {
	list := []string{c.Token}
	for i, item := range list {
		slog.Info("connect", "index", i)
		slog.Info("connect", "value", item) // want `slog.Info logs sensitive data from field Token`
	}
	byKey := map[string]int{c.Password: 1}
	for key := range byKey {
		slog.Info(key) // want `slog.Info logs sensitive data from field Password`
	}
}

func passThrough(c config) {
	err := errors.New("bad " + c.Token)
	slog.Error("connect", "error", err)  // want `slog.Error logs sensitive data from field Token`
	slog.Error(err.Error())              // want `slog.Error logs sensitive data from field Token`
	slog.Info(strconv.Quote(c.Password)) // want `slog.Info logs sensitive data from field Password`
	slog.Info(url.QueryEscape(c.Token))  // want `slog.Info logs sensitive data from field Token`
	slog.Info(strconv.Itoa(len(c.Password)))
}

func names(accessToken, host string) {
	slog.Info("connect", "value", accessToken) // want `slog.Info logs sensitive data from variable accessToken`
	slog.Info("connect", "value", host)
	deviceID := host
	slog.Info(deviceID) // want `slog.Info logs sensitive data from variable deviceID`
}

func rangeKinds(password chan string, token func(func(string) bool), n int) {
	for v := range password {
		slog.Info(v) // want `slog.Info logs sensitive data from variable password`
	}
	for v := range token {
		slog.Info(v) // want `slog.Info logs sensitive data from variable token`
	}
	for i := range n {
		slog.Info("connect", "index", i)
	}
}

func headers(req *http.Request, bearer string) {
	slog.Info("Authorization: " + req.Header.Get("Authorization")) // want `slog.Info logs sensitive data from header Authorization`
	slog.Info("cookies", "values", req.Header.Values("Cookie"))    // want `slog.Info logs sensitive data from header Cookie`
	slog.Info("accept", "value", req.Header.Get("Accept"))
	slog.Info("auth", "value", http.Header.Get(req.Header, "Authorization")) // want `slog.Info logs sensitive data from header Authorization`
	slog.Info("cookies", "values", http.Header.Values(req.Header, "Cookie")) // want `slog.Info logs sensitive data from header Cookie`
	slog.Info(fmt.Sprintf("Bearer %s", bearer))                              // want `slog.Info logs sensitive data from variable bearer`
	dump, _ := httputil.DumpRequest(req, false)
	slog.Info("request", "dump", string(dump)) // want `slog.Info logs sensitive data from httputil.DumpRequest`
}

type spreadConfig struct{ Token []any }

func spreads(s spreadConfig, token []any, m map[string][]any, c config) {
	slog.Info("connect", s.Token...)    // want `slog.Info logs sensitive data from field Token`
	slog.Info("connect", token...)      // want `slog.Info logs sensitive data from variable token`
	slog.Info("connect", m["token"]...) // want `slog.Info logs sensitive data from map key token`
	sets := [][]any{{"value", c.Password}}
	for _, args := range sets {
		slog.Info("connect", args...) // want `slog.Info logs sensitive data from field Password`
	}
	slog.Info("connect", sets[0]...) // want `slog.Info logs sensitive data from field Password`
}

func fmtOperands(c config) {
	slog.Info(string(fmt.Appendf([]byte(c.Token), "x"))) // want `slog.Info logs sensitive data from field Token`
	slog.Info(fmt.Sprintf(c.Password))                   // want `slog.Info logs sensitive data from field Password`
	slog.Info(string(fmt.Append([]byte(c.Token))))       // want `slog.Info logs sensitive data from field Token`
	slog.Info(fmt.Errorf(c.Password).Error())            // want `slog.Info logs sensitive data from field Password`
	args := []any{1, c.Password}
	slog.Info(fmt.Sprintf("%T %s", args...)) // want `slog.Info logs sensitive data from field Password`
}

func packageVars() {
	slog.Info("connect", "value", secretvars.AccessToken) // want `slog.Info logs sensitive data from variable AccessToken`
}

func typeSwitches(c config) {
	var x any = c.Password
	switch v := x.(type) {
	case string:
		slog.Info(v) // want `slog.Info logs sensitive data from field Password`
	default:
		slog.Info("connect", "value", v) // want `slog.Info logs sensitive data from field Password`
	}
	switch x.(type) {
	case string:
		slog.Info("connect")
	}
}

func tupleResults(c config) {
	_, rest, found := strings.Cut(c.Password, ":")
	slog.Info(rest) // want `slog.Info logs sensitive data from field Password`
	slog.Info("cut", "found", found)
	unquoted, err := strconv.Unquote(c.Token)
	slog.Info(unquoted) // want `slog.Info logs sensitive data from field Token`
	slog.Info("unquote", "error", err)
}

func textSlices(c config) {
	parts := strings.Split(c.Password, ":")
	slog.Info(parts[0]) // want `slog.Info logs sensitive data from field Password`
}

type account struct{ token, host string }

func (a *account) GetToken() string                 { return a.token }
func (a *account) Password() (string, bool)         { return a.token, true }
func (a *account) GetHost() string                  { return a.host }
func (a *account) Token(ctx context.Context) string { return a.token }

type cookieList []*http.Cookie

func sources(req *http.Request, u *url.URL, a *account, password string, ctx context.Context) {
	slog.Info("account", "value", a.GetToken()) // want `slog.Info logs sensitive data from method GetToken`
	pw, _ := a.Password()
	slog.Info("account", "value", pw) // want `slog.Info logs sensitive data from method Password`
	slog.Info("account", "value", a.GetHost())
	slog.Info("account", "value", a.Token(ctx))
	userinfo, _ := u.User.Password()
	slog.Info("url", "value", userinfo) // want `slog.Info logs sensitive data from method Password`
	user, pass, ok := req.BasicAuth()
	slog.Info("auth", "value", pass) // want `slog.Info logs sensitive data from http.Request.BasicAuth`
	slog.Info("auth", "value", user) // want `slog.Info logs sensitive data from http.Request.BasicAuth`
	slog.Info("auth", "ok", ok)
	c, _ := req.Cookie("session")
	slog.Info("cookie", "value", c.Value)                               // want `slog.Info logs sensitive data from cookie`
	slog.Info("cookie", "value", c.String())                            // want `slog.Info logs sensitive data from cookie`
	slog.Info("cookie", "value", fmt.Sprint(req.Cookies()))             // want `slog.Info logs sensitive data from cookie`
	slog.Info("cookie", "value", fmt.Sprint(cookieList(req.Cookies()))) // want `slog.Info logs sensitive data from cookie`
	slog.Info("cookie", "name", c.Name)
	dump, _ := httputil.DumpRequest(req, false)
	slog.Info("request", "dump", string(bytes.TrimSpace(dump)))      // want `slog.Info logs sensitive data from httputil.DumpRequest`
	slog.Info("request", "error", errors.Join(errors.New(password))) // want `slog.Info logs sensitive data from variable password`
}

func received(c config, token chan string, req *http.Request) {
	slog.Info(<-token) // want `slog.Info logs sensitive data from variable token`
	select {
	case v := <-token:
		slog.Info(v) // want `slog.Info logs sensitive data from variable token`
	}
	v, ok := <-token
	slog.Info("received", "value", v, "ok", ok)             // want `slog.Info logs sensitive data from variable token`
	slog.Info("config", "value", &config{Host: c.Password}) // want `slog.Info logs sensitive data from field Password`
	p := &c.Password
	slog.Info("config", "value", *p) // want `slog.Info logs sensitive data from field Password`
}

func parseErrors(c config, req *http.Request) {
	n, err := strconv.Atoi(c.Password)
	slog.Error("parse", "error", err) // want `slog.Error logs sensitive data from field Password`
	slog.Info("parse", "n", n)        // want `slog.Info logs sensitive data from field Password`
	_, err = url.Parse(c.Token)
	slog.Error("parse", "error", err) // want `slog.Error logs sensitive data from field Token`
	port, err := strconv.Atoi(c.Host)
	slog.Error("parse", "error", err, "port", port)
	_, err = url.QueryUnescape(c.Token)
	slog.Error("unescape", "error", err) // want `slog.Error logs sensitive data from field Token`
	_, err = url.PathUnescape(c.Token)
	slog.Error("unescape", "error", err) // want `slog.Error logs sensitive data from field Token`
	dump, err := httputil.DumpRequest(req, false)
	slog.Error("dump", "error", err)
	_ = dump
}

func compound(c config) {
	n, _ := strconv.Atoi(c.Password)
	n *= 2
	slog.Info("compound", "n", n) // want `slog.Info logs sensitive data from field Password`
	s := "prefix"
	s += c.Token
	slog.Info(s) // want `slog.Info logs sensitive data from field Token`
	value := n*1 | 0
	slog.Info("arithmetic", "value", value) // want `slog.Info logs sensitive data from field Password`
	slog.Info("compare", "ok", n > 0 && s != "")
	slog.Info("unary", "n", -n, "m", ^n) // want `slog.Info logs sensitive data from field Password`
	slog.Info("not", "ok", !(n > 0))
}

func methodExpressions(c config, a *account) {
	err := errors.New(c.Password)
	slog.Info(error.Error(err))                         // want `slog.Info logs sensitive data from field Password`
	slog.Info("token", "value", (*account).GetToken(a)) // want `slog.Info logs sensitive data from method GetToken`
	slog.Info("host", "value", (*account).GetHost(a))
}

type selfSlice []selfSlice

type genSelfSlice[T any] []genSelfSlice[T]

func selfSlices() (string, selfSlice, genSelfSlice[int]) { return "", nil, nil }

func nestedSlices(c config) {
	a, b, g := selfSlices()
	slog.Info("self", "a", a, "b", b, "g", g, "s", fmt.Sprint(b, g))

	parts := bytes.Split([]byte(c.Password), []byte(","))
	slog.Info("split", "part", string(parts[0])) // want `slog.Info logs sensitive data from field Password`
	fields := bytes.Fields([]byte(c.Host))
	slog.Info("fields", "field", string(fields[0]))
}

func mapLiterals(password string) {
	m := map[string]string{"password": password}
	slog.Info("map", "value", m)             // want `slog.Info logs sensitive data from variable password`
	slog.Info("map", "value", fmt.Sprint(m)) // want `slog.Info logs sensitive data from variable password` `fmt.Sprint formats map\[string\]string`
	slog.Info("map", "value", m["password"]) // want `slog.Info logs sensitive data from map key password`
}

func attrs(ctx context.Context, password string) {
	a := slog.String("password", password)
	slog.Info("attr", a)                          // want `slog.Info logs sensitive data from variable password`
	slog.Info(a.String())                         // want `slog.Info logs sensitive data from variable password`
	slog.Info("attr", "value", a.Value.Any())     // want `slog.Info logs sensitive data from variable password`
	slog.Info("attr", "value", a.Value.Resolve()) // want `slog.Info logs sensitive data from variable password`
	slog.Info("attr", "equal", a.Equal(a))
	slog.Info(slog.Group("g", "value", password).String()) // want `slog.Info logs sensitive data from variable password`
	attrs := []slog.Attr{a}
	slog.LogAttrs(ctx, slog.LevelInfo, "attrs", attrs...)  // want `slog.LogAttrs logs sensitive data from variable password`
	slog.Info("group", "value", slog.GroupValue(attrs...)) // want `slog.Info logs sensitive data from variable password`
}
