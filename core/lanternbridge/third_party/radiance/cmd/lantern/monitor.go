package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/ipc"
	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn"
)

const (
	ansiCursorHome = "\033[H"
	ansiClearToEOL = "\033[K"
	ansiClearBelow = "\033[J"
	ansiHideCursor = "\033[?25l"
	ansiShowCursor = "\033[?25h"
	ansiAltScreen  = "\033[?1049h"
	ansiMainScreen = "\033[?1049l"
	eol            = ansiClearToEOL + "\r\n"
)

type MonitorCmd struct {
	Interval         time.Duration `arg:"-i,--interval" default:"1s" help:"refresh interval"`
	Pool             int           `arg:"--pool" default:"5" help:"number of pool servers to list (tested first, by ascending latency); 0 to omit pool summary"`
	History          int           `arg:"--history" default:"3" help:"number of recent sessions to include; 0 to omit"`
	Logs             int           `arg:"--logs" default:"5" help:"number of recent warn/error log entries to display (totals always shown); 0 hides entries"`
	JSON             bool          `arg:"--json" help:"emit one JSON snapshot per refresh"`
	ReconnectTimeout time.Duration `arg:"--reconnect-timeout" default:"60s" help:"retry the daemon for this long after it goes away (0 disables retry)"`
}

type monitorSnapshot struct {
	Version          string                 `json:"version"`
	DeviceID         string                 `json:"device_id,omitempty"`
	UserID           string                 `json:"user_id,omitempty"`
	Pro              bool                   `json:"pro"`
	Status           statusSnapshot         `json:"status"`
	Mode             string                 `json:"mode"`
	Throughput       vpn.ThroughputSnapshot `json:"throughput"`
	DataCap          *account.DataCapInfo   `json:"data_cap,omitempty"`
	DataCapStreaming bool                   `json:"data_cap_streaming"`
	DataCapAgeMs     int64                  `json:"data_cap_age_ms,omitempty"`
	Settings         map[string]any         `json:"settings"`
	History          []vpn.Session          `json:"history,omitempty"`
	ServerPool       *poolSummary           `json:"server_pool,omitempty"`
	RecentLogs       []logEvent             `json:"recent_logs"`
	LogCounts        logCounts              `json:"log_counts"`
}

type logCounts struct {
	Warn  int `json:"warn"`
	Error int `json:"error"`
}

type poolSummary struct {
	Total   int             `json:"total"`
	Tested  int             `json:"tested"`
	Servers []serverLatency `json:"servers,omitempty"`
}

type serverLatency struct {
	Tag      string                    `json:"tag"`
	Type     string                    `json:"type,omitempty"`
	Location string                    `json:"location,omitempty"`
	DelayMs  uint32                    `json:"delay_ms"`
	TestedAt time.Time                 `json:"tested_at"`
	History  *servers.SelectionHistory `json:"history,omitempty"`
}

type logEvent struct {
	Level string    `json:"level"`
	Pkg   string    `json:"pkg,omitempty"`
	Src   string    `json:"src,omitempty"`
	Msg   string    `json:"msg"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Count int       `json:"count"`
}

func runMonitor(ctx context.Context, c *ipc.Client, cmd *MonitorCmd) error {
	interval := cmd.Interval
	if interval <= 0 {
		interval = time.Second
	}

	ctx, cleanup := quitOnKey(ctx)
	defer cleanup()

	tty := !cmd.JSON && stdoutIsTTY()
	if tty {
		// Use the alternate screen buffer so we don't mess with the user's scrollback, and hide the
		// cursor since it would be distracting when refreshing the screen.
		fmt.Print(ansiAltScreen + ansiHideCursor)
		defer fmt.Print(ansiShowCursor + ansiMainScreen)
	}

	state := newMonitorState(cmd.Logs)
	go state.streamDataCap(ctx, c)
	go state.tailLogs(ctx, c)

	st := newReconnect(cmd.ReconnectTimeout)
	refresh := func() error {
		var snap monitorSnapshot
		err := callWithReconnect(ctx, st, func() error {
			return fetchMonitor(ctx, c, cmd, &snap)
		})
		if err != nil {
			return err
		}
		state.fillSnapshot(&snap, cmd.Logs)
		if cmd.JSON {
			return printJSON(snap)
		}
		width, height := 0, 0
		if tty {
			if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
				width, height = w, h
			}
		}
		var b strings.Builder
		b.WriteString(ansiCursorHome)
		renderMonitor(&b, &snap, width)
		b.WriteString(ansiClearBelow)
		out := b.String()
		if height > 0 {
			out = clipToHeight(out, height, width)
		}
		_, _ = io.WriteString(os.Stdout, out)
		return nil
	}

	if err := refresh(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if err := refresh(); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func fetchMonitor(ctx context.Context, c *ipc.Client, cmd *MonitorCmd, snap *monitorSnapshot) error {
	snap.Version = common.Version

	s, err := fetchStatus(ctx, c)
	if err != nil {
		return err
	}
	snap.Status = s

	tp, err := c.VPNThroughput(ctx)
	if err != nil {
		return err
	}
	snap.Throughput = tp

	cfg, err := c.Settings(ctx)
	if err != nil {
		return err
	}
	snap.Settings = make(map[string]any, len(settingNames))
	for _, name := range settingNames {
		if v, ok := settingValue(name, cfg); ok {
			snap.Settings[name] = v
		}
	}
	if uid := cfg[settings.UserIDKey]; uid != nil {
		if v, ok := uid.(float64); ok {
			snap.UserID = strconv.FormatInt(int64(v), 10)
		} else {
			snap.UserID = fmt.Sprintf("%v", uid)
		}
	}
	if did := cfg[settings.DeviceIDKey]; did != nil {
		snap.DeviceID = fmt.Sprintf("%v", did)
	}
	snap.Pro = strings.EqualFold(fmt.Sprintf("%v", cfg[settings.UserLevelKey]), "pro")
	snap.Mode = selectionMode(cfg)

	if cmd.History > 0 {
		h, err := c.VPNSessions(ctx, cmd.History)
		if err != nil {
			return err
		}
		snap.History = h
	}
	if cmd.Pool > 0 {
		srvs, err := c.Servers(ctx)
		if err != nil {
			return err
		}
		snap.ServerPool = summarizePool(srvs, cmd.Pool)
	}
	return nil
}

func summarizePool(srvs []*servers.Server, top int) *poolSummary {
	out := &poolSummary{Total: len(srvs)}
	entries := make([]serverLatency, 0, len(srvs))
	for _, s := range srvs {
		if s == nil {
			continue
		}
		e := serverLatency{
			Tag:      s.Tag,
			Type:     s.Type,
			Location: joinNonEmpty(", ", s.Location.City, s.Location.Country),
		}
		if s.SelectionHistory != nil {
			out.Tested++
			e.DelayMs = s.SelectionHistory.LatestSuccessDelay()
			e.TestedAt = s.SelectionHistory.LatestSuccessTime()
			e.History = s.SelectionHistory
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		ti, tj := entries[i].History != nil, entries[j].History != nil
		if ti != tj {
			return ti
		}
		if ti {
			return entries[i].DelayMs < entries[j].DelayMs
		}
		return entries[i].Tag < entries[j].Tag
	})
	if top > len(entries) {
		top = len(entries)
	}
	out.Servers = entries[:top]
	return out
}

func renderMonitor(w io.Writer, snap *monitorSnapshot, width int) {
	tier := "free"
	if snap.Pro {
		tier = "pro"
	}
	user := "—"
	if snap.UserID != "" {
		user = snap.UserID
	}
	fmt.Fprintf(w, "Lantern v%s — user %s (%s)%s", snap.Version, user, tier, eol)
	if snap.DeviceID != "" {
		fmt.Fprintf(w, "Device: %s%s", snap.DeviceID, eol)
	}
	io.WriteString(w, eol)

	status := string(snap.Status.Status)
	if status != "" {
		status = strings.ToUpper(status[:1]) + status[1:]
	}
	fmt.Fprintf(w, "Status: %s%s", status, eol)
	if snap.Mode != "" {
		fmt.Fprintf(w, "  Mode: %s%s", snap.Mode, eol)
	}
	if snap.Status.Server != "" {
		line := "  Server: " + formatTag(snap.Status.Server)
		if snap.Status.Location != "" {
			line += " (" + snap.Status.Location + ")"
		}
		if snap.Status.LatencyMs > 0 {
			line += fmt.Sprintf(" — %dms", snap.Status.LatencyMs)
		}
		fmt.Fprintf(w, "%s%s", line, eol)
	}
	if snap.Status.IP != "" {
		fmt.Fprintf(w, "  IP: %s%s", snap.Status.IP, eol)
	}
	if cur := currentSession(snap); cur != nil {
		fmt.Fprintf(w, "  Session: ↓ %s   ↑ %s   (%s)%s",
			formatBytes(cur.BytesDown), formatBytes(cur.BytesUp),
			cur.Duration().Truncate(time.Second), eol)
	}
	io.WriteString(w, eol)

	renderDataCap(w, snap)

	fmt.Fprintf(w, "Throughput:%s", eol)
	fmt.Fprintf(w, "  Global  ↓ %s   ↑ %s   (%d active)%s",
		formatBitsPerSec(snap.Throughput.Global.Down),
		formatBitsPerSec(snap.Throughput.Global.Up),
		snap.Throughput.ActiveConnections, eol)
	tags := outboundTags(snap.Throughput)
	for _, tag := range tags {
		sp := snap.Throughput.PerOutbound[tag]
		name := formatTag(tag)
		if name == "" {
			name = "(unrouted)"
		}
		fmt.Fprintf(w, "    %-30s ↓ %s   ↑ %s   (%d active)%s",
			name, formatBitsPerSec(sp.Down), formatBitsPerSec(sp.Up),
			snap.Throughput.ActivePerOutbound[tag], eol)
	}
	io.WriteString(w, eol)

	renderSettings(w, snap.Settings, width)

	renderServerPool(w, snap.ServerPool)

	if len(snap.History) > 0 {
		fmt.Fprintf(w, "Recent sessions:%s", eol)
		for _, s := range snap.History {
			fmt.Fprintf(w, "  %s%s", formatSessionLine(s), eol)
			if s.Error != "" {
				fmt.Fprintf(w, "    error: %s%s", s.Error, eol)
			}
		}
		io.WriteString(w, eol)
	}

	renderRecentLogs(w, snap.RecentLogs, snap.LogCounts)

	fmt.Fprintf(w, "(press q to quit)%s", eol)
}

func renderDataCap(w io.Writer, snap *monitorSnapshot) {
	dc := snap.DataCap
	if dc != nil && dc.Enabled && dc.Usage != nil {
		used, _ := strconv.ParseInt(dc.Usage.BytesUsed, 10, 64)
		allotted, _ := strconv.ParseInt(dc.Usage.BytesAllotted, 10, 64)
		line := fmt.Sprintf("Data cap: %s / %s used", formatBytes(used), formatBytes(allotted))
		if snap.DataCapStreaming {
			age := time.Duration(snap.DataCapAgeMs) * time.Millisecond
			if age > 30*time.Second {
				line += fmt.Sprintf(" (last update %s ago)", age.Truncate(time.Second))
			}
		}
		fmt.Fprintf(w, "%s%s", line, eol)
		if t, err := time.Parse(time.RFC3339, dc.Usage.AllotmentEndTime); err == nil {
			fmt.Fprintf(w, "  resets %s%s", t.Local().Format("2006-01-02 15:04"), eol)
		}
	} else {
		fmt.Fprintf(w, "Data cap: no samples yet%s", eol)
	}
	io.WriteString(w, eol)
}

func renderSettings(w io.Writer, s map[string]any, width int) {
	if len(s) == 0 {
		return
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([]string, len(keys))
	maxLen := 0
	for i, k := range keys {
		items[i] = fmt.Sprintf("%s: %v", k, s[k])
		if l := len(items[i]); l > maxLen {
			maxLen = l
		}
	}
	const indent, gap = "  ", "  "
	cellWidth := maxLen + len(gap)
	cols := 1
	if avail := width - len(indent); avail > cellWidth {
		cols = avail / cellWidth
	}

	fmt.Fprintf(w, "Settings:%s", eol)
	for i, item := range items {
		if i%cols == 0 {
			io.WriteString(w, indent)
		}
		endOfRow := (i+1)%cols == 0 || i == len(items)-1
		if endOfRow {
			io.WriteString(w, item)
			io.WriteString(w, eol)
		} else {
			fmt.Fprintf(w, "%-*s", cellWidth, item)
		}
	}
	io.WriteString(w, eol)
}

func renderServerPool(w io.Writer, p *poolSummary) {
	if p == nil || p.Total == 0 {
		return
	}
	fmt.Fprintf(w, "Server pool: %d total, %d with recent test%s", p.Total, p.Tested, eol)
	now := time.Now()
	for _, s := range p.Servers {
		name := formatTag(s.Tag)
		if s.Location != "" {
			name = fmt.Sprintf("%s [%s]", name, s.Location)
		}
		delay := "    n/a"
		age := "untested"
		if s.History != nil {
			delay = fmt.Sprintf("%5dms", s.DelayMs)
			age = "tested "
			if s.TestedAt.IsZero() {
				age += "—"
			} else {
				age += now.Sub(s.TestedAt).Truncate(time.Second).String() + " ago"
			}
		}
		fmt.Fprintf(w, "  %s  %s  (%s)%s", delay, name, age, eol)
		if line := historyLine(s.History); line != "" {
			fmt.Fprintf(w, "         %s%s", line, eol)
		}
	}
	io.WriteString(w, eol)
}

func historyLine(h *servers.SelectionHistory) string {
	if h == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	if h.LastSuccessDelayMs > 0 {
		parts = append(parts, fmt.Sprintf("last: %dms", h.LastSuccessDelayMs))
	}
	if h.ConsecutiveFailures > 0 {
		parts = append(parts, fmt.Sprintf("consec: %d", h.ConsecutiveFailures))
	}
	if n := len(h.UserFailures); n > 0 {
		parts = append(parts, fmt.Sprintf("user fail: %d", n))
	}
	return strings.Join(parts, "  ·  ")
}

func renderRecentLogs(w io.Writer, logs []logEvent, counts logCounts) {
	fmt.Fprintf(w, "Recent warn/error logs: %d warn, %d error%s", counts.Warn, counts.Error, eol)
	if len(logs) == 0 {
		fmt.Fprintf(w, "  (none)%s", eol)
		io.WriteString(w, eol)
		return
	}
	for _, e := range logs {
		when := e.Last.Local().Format("15:04:05")
		count := ""
		if e.Count > 1 {
			count = fmt.Sprintf(" (×%d)", e.Count)
		}
		src := e.Pkg
		if e.Src != "" {
			if src != "" {
				src += " " + e.Src
			} else {
				src = e.Src
			}
		}
		if src != "" {
			src = " [" + src + "]"
		}
		fmt.Fprintf(w, "  %s %-5s%s %s%s%s", when, e.Level, src, e.Msg, count, eol)
	}
	io.WriteString(w, eol)
}

func formatSessionLine(s vpn.Session) string {
	when := s.ConnectedAt.Local().Format("15:04:05")
	dur := s.Duration().Truncate(time.Second)
	status := "ended"
	if s.DisconnectedAt.IsZero() {
		status = "active"
	}
	srv := formatTag(s.Server.Tag)
	if srv == "" {
		srv = "(auto)"
	}
	if loc := joinNonEmpty(", ", s.Server.City, s.Server.Country); loc != "" {
		srv = fmt.Sprintf("%s [%s]", srv, loc)
	}
	return fmt.Sprintf("%s  %-9s  %-6s  ↓ %s   ↑ %s   %s",
		when, dur, status, formatBytes(s.BytesDown), formatBytes(s.BytesUp), srv)
}

func currentSession(snap *monitorSnapshot) *vpn.Session {
	if snap.Status.Status != vpn.Connected || len(snap.History) == 0 {
		return nil
	}
	first := snap.History[0]
	if !first.DisconnectedAt.IsZero() {
		return nil
	}
	return &first
}

// clipToHeight trims the rendered frame to at most h visual rows so the cursor
// stays within the viewport. The alt screen has no scrollback, so any line that
// would push the cursor past the bottom permanently drops the topmost row.
//
// Lines wider than width wrap and consume multiple visual rows, so naive newline
// counting under-counts when wrapping is on (the case here, which we keep so log
// messages stay readable).
func clipToHeight(s string, h, width int) string {
	if h <= 0 {
		return s
	}
	suffix := ""
	if strings.HasSuffix(s, ansiClearBelow) {
		s = s[:len(s)-len(ansiClearBelow)]
		suffix = ansiClearBelow
	}
	dropFromLine := func(lineStart int) string {
		if lineStart == 0 {
			return suffix
		}
		// Drop the \n preceding this line so the cursor lands at the end of the
		// previous line rather than at the start of an empty next row.
		return s[:lineStart-1] + suffix
	}
	visual := 0
	lineStart := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' {
			continue
		}
		rows := visualRows(s[lineStart:i], width)
		// Including the trailing \n moves the cursor down one extra row, so the
		// budget for "line + \n" is h-1 rows total (cursor lands at row h).
		if visual+rows > h-1 {
			// If the line content fits without its trailing \n (cursor stops at
			// end of last wrap row), keep it as the final visible line.
			if visual+rows <= h {
				return s[:i] + suffix
			}
			return dropFromLine(lineStart)
		}
		visual += rows
		lineStart = i + 1
	}
	if lineStart < len(s) {
		rows := visualRows(s[lineStart:], width)
		if visual+rows > h {
			return dropFromLine(lineStart)
		}
	}
	return s + suffix
}

// visualRows returns the number of terminal rows a line occupies after wrapping
// at width. width <= 0 disables wrap accounting (one row per line).
func visualRows(line string, width int) int {
	if width <= 0 {
		return 1
	}
	n := visualWidth(line)
	if n == 0 {
		return 1
	}
	return (n + width - 1) / width
}

// visualWidth returns the rendered column count of line. Each rune counts as
// one column — close enough for the ASCII + light-Unicode (↓ ↑ — ×) content
// this dashboard renders; full wcwidth would be overkill.
func visualWidth(line string) int {
	n := 0
	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == 0x1b && i+1 < len(line) && line[i+1] == '[':
			i += 2
			for i < len(line) {
				t := line[i]
				i++
				if t >= 0x40 && t <= 0x7e {
					break
				}
			}
		case c == '\r':
			i++
		case c < 0x80:
			n++
			i++
		default:
			_, size := utf8.DecodeRuneInString(line[i:])
			if size <= 0 {
				size = 1
			}
			n++
			i += size
		}
	}
	return n
}

var tagUUID = regexp.MustCompile(`([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-([0-9a-f]{12})`)

func formatTag(tag string) string {
	if i := strings.Index(tag, "-out-"); i > 0 {
		proto := tag[:i]
		if rest := tag[i+len("-out-"):]; strings.HasPrefix(rest, proto+"-") {
			tag = rest
		}
	}
	return tagUUID.ReplaceAllString(tag, "$1-...-$2")
}

func outboundTags(s vpn.ThroughputSnapshot) []string {
	set := make(map[string]struct{}, len(s.PerOutbound)+len(s.ActivePerOutbound))
	for tag := range s.PerOutbound {
		set[tag] = struct{}{}
	}
	for tag := range s.ActivePerOutbound {
		set[tag] = struct{}{}
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		if isGroupTag(tag) {
			continue
		}
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

// isGroupTag reports whether tag names a selector/auto-select group rather
// than a leaf outbound. sing-box's clash tracker can attribute a connection
// to the group tag in addition to the leaf, so groups must be filtered out
// of per-outbound throughput tags to avoid phantom entries.
func isGroupTag(tag string) bool {
	return tag == vpn.AutoSelectTag || tag == vpn.ManualSelectTag || tag == vpn.PersonalProxiesTag ||
		tag == vpn.PersonalProxyTag
}

type monitorState struct {
	mu          sync.Mutex
	dataCap     atomic.Pointer[account.DataCapInfo]
	dataCapAt   atomic.Int64 // unix nanoseconds of last update; 0 if never
	logCapacity int
	logs        []logEvent
	warnTotal   atomic.Int64
	errorTotal  atomic.Int64
}

func newMonitorState(logCapacity int) *monitorState {
	return &monitorState{logCapacity: logCapacity}
}

func (s *monitorState) setDataCap(info account.DataCapInfo) {
	cp := info
	s.dataCap.Store(&cp)
	s.dataCapAt.Store(time.Now().UnixNano())
}

func (s *monitorState) fillSnapshot(snap *monitorSnapshot, logLimit int) {
	snap.DataCap = s.dataCap.Load()
	if at := s.dataCapAt.Load(); at != 0 {
		snap.DataCapStreaming = true
		snap.DataCapAgeMs = time.Since(time.Unix(0, at)).Milliseconds()
	}
	snap.LogCounts = logCounts{
		Warn:  int(s.warnTotal.Load()),
		Error: int(s.errorTotal.Load()),
	}
	if logLimit <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.logs) == 0 {
		return
	}
	out := make([]logEvent, len(s.logs))
	copy(out, s.logs)
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	if logLimit < len(out) {
		out = out[:logLimit]
	}
	snap.RecentLogs = out
}

func (s *monitorState) streamDataCap(ctx context.Context, c *ipc.Client) {
	for ctx.Err() == nil {
		_ = c.DataCapStream(ctx, s.setDataCap)
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (s *monitorState) tailLogs(ctx context.Context, c *ipc.Client) {
	for ctx.Err() == nil {
		_ = c.TailLogs(ctx, func(entry rlog.LogEntry) {
			if evt, ok := parseLogEvent(entry); ok {
				s.recordLog(evt)
			}
		})
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (s *monitorState) recordLog(evt logEvent) {
	switch evt.Level {
	case "WARN":
		s.warnTotal.Add(1)
	case "ERROR":
		s.errorTotal.Add(1)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.logs {
		e := &s.logs[i]
		if e.Level == evt.Level && e.Pkg == evt.Pkg && e.Msg == evt.Msg {
			e.Last = evt.Last
			e.Count++
			return
		}
	}
	if s.logCapacity > 0 && len(s.logs) >= s.logCapacity*4 {
		// Cap distinct entries at 4× display so a flood of unique messages
		// can't grow the slice unbounded.
		oldestIdx := 0
		for i := range s.logs {
			if s.logs[i].Last.Before(s.logs[oldestIdx].Last) {
				oldestIdx = i
			}
		}
		s.logs = append(s.logs[:oldestIdx], s.logs[oldestIdx+1:]...)
	}
	s.logs = append(s.logs, evt)
}

var (
	logKeyTimeQuoted = regexp.MustCompile(`time="([^"]+)"`)
	logKeyTimeBare   = regexp.MustCompile(`(?:^|\s)time=(\S+)`)
	logKeyLevel      = regexp.MustCompile(`level=(\w+)`)
	logKeyPkg        = regexp.MustCompile(`pkg=(\S+)`)
	logKeySrcFile    = regexp.MustCompile(`source\.file=(\S+)`)
	logKeyMsgQuoted  = regexp.MustCompile(`msg="((?:[^"\\]|\\.)*)"`)
	logKeyMsgBare    = regexp.MustCompile(`msg=(\S+)`)
)

func parseLogEvent(line string) (logEvent, bool) {
	m := logKeyLevel.FindStringSubmatch(line)
	if m == nil {
		return logEvent{}, false
	}
	level := strings.ToUpper(m[1])
	if level != "WARN" && level != "WARNING" && level != "ERROR" {
		return logEvent{}, false
	}
	if level == "WARNING" {
		level = "WARN"
	}
	evt := logEvent{Level: level, Count: 1}
	if m = logKeyMsgQuoted.FindStringSubmatch(line); m != nil {
		evt.Msg = unescapeQuoted(m[1])
	} else if m = logKeyMsgBare.FindStringSubmatch(line); m != nil {
		evt.Msg = m[1]
	}
	if m = logKeyPkg.FindStringSubmatch(line); m != nil {
		evt.Pkg = m[1]
	}
	if m = logKeySrcFile.FindStringSubmatch(line); m != nil {
		evt.Src = m[1]
	}
	ts := time.Now()
	if m = logKeyTimeQuoted.FindStringSubmatch(line); m != nil {
		if t, ok := parseLogTime(m[1]); ok {
			ts = t
		}
	} else if m = logKeyTimeBare.FindStringSubmatch(line); m != nil {
		if t, ok := parseLogTime(m[1]); ok {
			ts = t
		}
	}
	evt.First = ts
	evt.Last = ts
	return evt, true
}

func parseLogTime(s string) (time.Time, bool) {
	for _, layout := range []string{
		"2006-01-02 15:04:05.000 MST",
		"2006-01-02T15:04:05.000Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func unescapeQuoted(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
