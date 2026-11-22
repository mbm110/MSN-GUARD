package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"context"

	"github.com/alexflint/go-arg"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/ipc"
	"github.com/getlantern/radiance/issue"
	rlog "github.com/getlantern/radiance/log"
)

type args struct {
	Connect          *ConnectCmd          `arg:"subcommand:connect" help:"connect to VPN"`
	Disconnect       *DisconnectCmd       `arg:"subcommand:disconnect" help:"disconnect VPN"`
	ClearTunnelCache *ClearTunnelCacheCmd `arg:"subcommand:clear-cache" help:"clear the tunnel cache"`
	Status           *StatusCmd           `arg:"subcommand:status" help:"show VPN status"`
	Servers          *ServersCmd          `arg:"subcommand:servers" help:"manage servers"`
	Set              *SetCmd              `arg:"subcommand:set" help:"update one or more settings"`
	Get              *GetCmd              `arg:"subcommand:get" help:"show one or all settings"`
	SplitTunnel      *SplitTunnelCmd      `arg:"subcommand:split-tunnel" help:"split-tunnel filter management"`
	Features         *FeaturesCmd         `arg:"subcommand:features" help:"list available features and their status"`
	Account          *AccountCmd          `arg:"subcommand:account" help:"login, signup, user data, devices, recovery"`
	Subscription     *SubscriptionCmd     `arg:"subcommand:subscription" help:"plans, payments, and billing"`
	ReportIssue      *ReportIssueCmd      `arg:"subcommand:report-issue" help:"report an issue"`
	Throughput       *ThroughputCmd       `arg:"subcommand:throughput" help:"show throughput, globally and per outbound"`
	Monitor          *MonitorCmd          `arg:"subcommand:monitor" help:"watch status, throughput, settings, recent history and errors; press q or Ctrl-C to quit"`
	Logs             *LogsCmd             `arg:"subcommand:logs" help:"tail daemon logs; press q or Ctrl-C to quit"`
	UpdateConfig     *UpdateConfigCmd     `arg:"subcommand:update-config" help:"force an immediate config fetch"`
	IP               *IPCmd               `arg:"subcommand:ip" help:"show public IP address"`
	Version          *VersionCmd          `arg:"subcommand:version" help:"print version"`
}

func (args) Description() string {
	return "Lantern CLI — command-line interface for the Lantern VPN daemon"
}

type ReportIssueCmd struct {
	Type        int    `arg:"-t,--type,required" help:"0=purchase 1=signin 2=spinner 3=blocked-sites 4=slow 5=link-device 6=crash 9=other 10=update"`
	Description string `arg:"-d,--desc,required" help:"issue description"`
	Email       string `arg:"-e,--email" help:"email address"`
}

func runReportIssue(ctx context.Context, c *ipc.Client, cmd *ReportIssueCmd) error {
	return c.ReportIssue(ctx, issue.IssueType(cmd.Type), cmd.Description, cmd.Email, nil, nil)
}

type LogsCmd struct {
	Level            string        `arg:"--level" help:"only show entries at this level or higher (trace|debug|info|warn|error|fatal|panic)"`
	Grep             string        `arg:"--grep" help:"regex; only show entries that match"`
	ReconnectTimeout time.Duration `arg:"--reconnect-timeout" default:"60s" help:"retry the daemon for this long after it goes away (0 disables retry)"`
}

// tailLogs streams log entries from the daemon, with optional filtering and reconnect logic.
func tailLogs(ctx context.Context, c *ipc.Client, cmd *LogsCmd) error {
	ctx, cleanup := quitOnKey(ctx)
	defer cleanup()

	var levelMin slog.Level
	levelSet := false
	if cmd.Level != "" {
		lvl, err := rlog.ParseLogLevel(cmd.Level)
		if err != nil {
			return err
		}
		levelMin = lvl
		levelSet = true
	}
	var grepRE *regexp.Regexp
	if cmd.Grep != "" {
		re, err := regexp.Compile(cmd.Grep)
		if err != nil {
			return fmt.Errorf("invalid --grep regex: %w", err)
		}
		grepRE = re
	}

	st := newReconnect(cmd.ReconnectTimeout)
	handler := func(entry rlog.LogEntry) {
		st.onSuccess()
		if levelSet && !logEntryMeetsLevel(entry, levelMin) {
			return
		}
		if grepRE != nil && !grepRE.MatchString(entry) {
			return
		}
		fmt.Printf("%s\r\n", entry)
	}

	for {
		err := c.TailLogs(ctx, handler)
		if ctx.Err() != nil {
			st.abandon()
			fmt.Fprint(os.Stderr, "\r\nStopped tailing logs.\r\n")
			return nil
		}
		if err == nil {
			// We connected even if no entries arrived, so the reconnect window has to reset
			// before we map nil → ErrIPCNotRunning to drive the next retry.
			st.onSuccess()
			err = ipc.ErrIPCNotRunning
		}
		if !errors.Is(err, ipc.ErrIPCNotRunning) {
			st.abandon()
			return err
		}
		wait := st.onError()
		if wait <= 0 {
			st.abandon()
			return fmt.Errorf("daemon unreachable: %w", err)
		}
		if err := st.waitForRetry(ctx, wait); err != nil {
			st.abandon()
			fmt.Fprint(os.Stderr, "\r\nStopped tailing logs.\r\n")
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

// logEntryMeetsLevel checks whether the log entry has a level at least as high as the specified
// minimum. Lines without a parseable level=... attr are passed through, not filtered out. Callers
// should not assume `false` means "below min".
func logEntryMeetsLevel(entry string, min slog.Level) bool {
	_, rest, fnd := strings.Cut(entry, "level=")
	if !fnd {
		return true
	}
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		end = len(rest)
	}
	lvlStr := rest[:end]
	lvl, err := rlog.ParseLogLevel(lvlStr)
	return err != nil || lvl >= min
}

type VersionCmd struct{}

func main() {
	// Watch-mode TUI frames are corrupted by stray library slog output on stderr.
	slog.SetDefault(slog.New(slog.DiscardHandler))

	var a args
	p := arg.MustParse(&a)
	if p.Subcommand() == nil {
		p.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client := ipc.NewClient()
	defer client.Close()

	if err := run(ctx, client, &a); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		p.WriteHelpForSubcommand(os.Stdout, p.SubcommandNames()...)
		os.Exit(1)
	}
}

func run(ctx context.Context, c *ipc.Client, a *args) error {
	switch {
	case a.Connect != nil:
		return vpnConnect(ctx, c, a.Connect.Name, a.Connect.Wait)
	case a.Disconnect != nil:
		return c.DisconnectVPN(ctx)
	case a.ClearTunnelCache != nil:
		return runClearTunnelCache(ctx, c)
	case a.Status != nil:
		return vpnStatus(ctx, c, a.Status)
	case a.Throughput != nil:
		return vpnThroughput(ctx, c, a.Throughput)
	case a.Servers != nil:
		return runServers(ctx, c, a.Servers)
	case a.Features != nil:
		return runFeatures(ctx, c)
	case a.Set != nil:
		return runSet(ctx, c, a.Set)
	case a.Get != nil:
		return runGet(ctx, c, a.Get)
	case a.UpdateConfig != nil:
		return runUpdateConfig(ctx, c)
	case a.SplitTunnel != nil:
		return runSplitTunnel(ctx, c, a.SplitTunnel)
	case a.Account != nil:
		return runAccount(ctx, c, a.Account)
	case a.Subscription != nil:
		return runSubscription(ctx, c, a.Subscription)
	case a.ReportIssue != nil:
		return runReportIssue(ctx, c, a.ReportIssue)
	case a.Monitor != nil:
		return runMonitor(ctx, c, a.Monitor)
	case a.Logs != nil:
		return tailLogs(ctx, c, a.Logs)
	case a.IP != nil:
		return runIP(ctx, a.IP)
	case a.Version != nil:
		fmt.Println(common.Version)
		return nil
	default:
		return fmt.Errorf("no subcommand specified")
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
