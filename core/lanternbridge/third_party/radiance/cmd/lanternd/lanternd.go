package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
	wire "github.com/getlantern/common/usermessage"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/common"
	commonenv "github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/serviceowner"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/internal/dirsecurity"
	"github.com/getlantern/radiance/ipc"
	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/vpn"
)

type runCmd struct {
	DataPath    string            `arg:"--data-path" help:"path to store data"`
	LogPath     string            `arg:"--log-path" help:"path to store logs"`
	LogLevel    string            `arg:"--log-level" default:"info" help:"logging level (trace, debug, info, warn, error)"`
	Environment daemonEnvironment `arg:"--environment" default:"prod" help:"backend environment (prod or staging)"`
}

type installCmd struct {
	DataPath    string            `arg:"--data-path" help:"path to store data"`
	LogPath     string            `arg:"--log-path" help:"path to store logs"`
	LogLevel    string            `arg:"--log-level" default:"info" help:"logging level (trace, debug, info, warn, error)"`
	Environment daemonEnvironment `arg:"--environment" default:"prod" help:"backend environment (prod or staging)"`
}

type daemonEnvironment string

const (
	daemonEnvironmentProd    daemonEnvironment = "prod"
	daemonEnvironmentStaging daemonEnvironment = "staging"
)

// UnmarshalText rejects unsupported daemon environments during CLI decoding.
func (e *daemonEnvironment) UnmarshalText(text []byte) error {
	parsed, err := parseDaemonEnvironment(string(text))
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

func parseDaemonEnvironment(value string) (daemonEnvironment, error) {
	environment := daemonEnvironment(value)
	switch environment {
	case daemonEnvironmentProd, daemonEnvironmentStaging:
		return environment, nil
	default:
		return "", fmt.Errorf("unsupported environment %q (must be prod or staging)", value)
	}
}

const (
	// gracefulShutdownTimeout is the maximum time the supervisor waits for a child
	// to exit after requesting a graceful shutdown.
	gracefulShutdownTimeout = 15 * time.Second

	// childForceExitTimeout gives the child time to log a forced-exit reason before
	// the supervisor's shutdown deadline expires.
	childForceExitTimeout = gracefulShutdownTimeout - 3*time.Second

	// childWaitDelay bounds how long Wait may block on inherited stdout/stderr
	// pipes after the child exits.
	childWaitDelay = 5 * time.Second

	// childEnvMarker marks a supervised child process so main runs the daemon
	// directly instead of starting another supervisor.
	childEnvMarker = "_LANTERND_CHILD"

	babysitBackoffBase = time.Second

	// daemonRestartBackoffMax keeps repeated crashes from delaying recovery by more than a minute.
	daemonRestartBackoffMax = 60 * time.Second

	// daemonRestartBackoffResetAfter marks a child as stable so a later failure restarts promptly.
	daemonRestartBackoffResetAfter = 2 * time.Minute
)

type serviceRunConfig struct {
	dataPath    string
	logPath     string
	logLevel    string
	environment daemonEnvironment
}

func (c runCmd) serviceConfig() serviceRunConfig {
	return serviceRunConfig{
		dataPath:    os.ExpandEnv(withDefault(c.DataPath, internal.DefaultDataPath())),
		logPath:     os.ExpandEnv(withDefault(c.LogPath, internal.DefaultLogPath())),
		logLevel:    c.LogLevel,
		environment: c.Environment,
	}
}

func (c serviceRunConfig) args() []string {
	return []string{
		"run",
		"--data-path", c.dataPath,
		"--log-path", c.logPath,
		"--log-level", c.logLevel,
		"--environment", string(c.environment),
	}
}

func parseServiceRunArgs(args []string) (serviceRunConfig, error) {
	var parsed daemonArgs
	parser, err := arg.NewParser(arg.Config{}, &parsed)
	if err != nil {
		return serviceRunConfig{}, fmt.Errorf("create service argument parser: %w", err)
	}
	if err := parser.Parse(args); err != nil {
		return serviceRunConfig{}, fmt.Errorf("parse service arguments: %w", err)
	}
	if parsed.Run == nil {
		return serviceRunConfig{}, errors.New("service command must run the daemon")
	}
	return parsed.Run.serviceConfig(), nil
}

type uninstallCmd struct{}

type versionCmd struct{}

type daemonArgs struct {
	Run       *runCmd       `arg:"subcommand:run" help:"run the daemon"`
	Install   *installCmd   `arg:"subcommand:install" help:"install as system service"`
	Uninstall *uninstallCmd `arg:"subcommand:uninstall" help:"uninstall system service"`
	Version   *versionCmd   `arg:"subcommand:version" help:"print version"`
	Migrate   *migrateCmd   `arg:"subcommand:migrate" help:"import a legacy Windows user"`
}

func (daemonArgs) Description() string {
	return "lanternd — Lantern VPN daemon"
}

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

func main() {
	if maybePlatformService() {
		return
	}

	var a daemonArgs
	p := arg.MustParse(&a)
	if p.Subcommand() == nil {
		p.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	defaultDataPath := internal.DefaultDataPath()
	defaultLogPath := internal.DefaultLogPath()
	var err error
	switch {
	case a.Run != nil:
		config := a.Run.serviceConfig()
		if os.Getenv(childEnvMarker) != "1" {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			logger := newDaemonLogger(config.logPath, config.logLevel)
			err = babysit(ctx, os.Args[1:], logger)
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				os.Exit(exitErr.ExitCode())
			}
			break
		}
		ctx, cancel := context.WithCancel(context.Background())
		// Shut down on stdin closure (babysit parent signals us) or OS signal.
		go func() {
			io.Copy(io.Discard, os.Stdin)
			cancel()
		}()
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
			// Restore default signal behavior so a second signal terminates immediately.
			signal.Reset(syscall.SIGINT, syscall.SIGTERM)
		}()
		err = runDaemon(ctx, config.dataPath, config.logPath, config.logLevel, config.environment)
	case a.Install != nil:
		err = install(
			os.ExpandEnv(withDefault(a.Install.DataPath, defaultDataPath)),
			os.ExpandEnv(withDefault(a.Install.LogPath, defaultLogPath)),
			a.Install.LogLevel,
			a.Install.Environment,
		)
	case a.Uninstall != nil:
		err = uninstall()
	case a.Version != nil:
		fmt.Println(common.Version)
	case a.Migrate != nil:
		err = migrateLegacy(a.Migrate)
	}
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

func withDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

// copyBin copies the current executable to binPath, creating parent directories
// as needed. It returns the destination path.
func copyBin() (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return "", fmt.Errorf("failed to resolve executable path: %w", err)
	}

	dst := binPath
	if src == dst {
		return dst, nil
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("failed to create directory for %s: %w", dst, err)
	}

	sf, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("failed to open source binary: %w", err)
	}
	defer sf.Close()

	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", fmt.Errorf("failed to create %s: %w", dst, err)
	}
	defer df.Close()

	if _, err := io.Copy(df, sf); err != nil {
		return "", fmt.Errorf("failed to copy binary to %s: %w", dst, err)
	}

	slog.Info("Copied binary", "src", src, "dst", dst)
	return dst, nil
}

// newDaemonLogger returns the supervisor logger for the daemon log file.
func newDaemonLogger(logPath, logLevel string) *slog.Logger {
	output := filepath.Join(logPath, internal.LogFileName)
	// The child enforces the directory check by refusing to start; the supervisor
	// only avoids writing into a rejected directory.
	if err := dirsecurity.Prepare(logPath); err != nil {
		slog.Warn("Failed to prepare log directory; logging to stdout", "error", err, "path", logPath)
		output = rlog.StdoutPath
	}
	return rlog.NewLogger(rlog.Config{
		LogPath:          output,
		Level:            logLevel,
		Prod:             true,
		DisablePublisher: true,
	})
}

type childProcess struct {
	cmd    *exec.Cmd
	stdin  io.Closer
	done   chan error
	logger *slog.Logger
}

func childEnv() []string {
	return append(os.Environ(), childEnvMarker+"=1", commonenv.LogToStdout.String()+"=true")
}

// spawnChild starts the daemon as a supervised child process.
// Child stdout and stderr are written directly to the supervisor's log writer.
func spawnChild(args []string, logger *slog.Logger) (*childProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command(exe, args...)
	cmd.Env = childEnv()
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	// The child writes preformatted log lines to stdout. Write them directly to
	// the supervisor's output sink to avoid double formatting.
	var w io.Writer = os.Stdout
	if h, ok := logger.Handler().(*rlog.Handler); ok {
		w = h.Writer()
	}
	// Same writer value for both streams so exec shares one pipe and one
	// copying goroutine between them, and output stays serialized through one
	// sink. lineWriter hands the sink whole lines, so the sink's helper-tag
	// redaction never sees a tag split across two pipe reads.
	out := &lineWriter{w: &bestEffortWriter{w: w}}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = childWaitDelay

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start daemon process: %w", err)
	}
	logger.Info("Started daemon process", "pid", cmd.Process.Pid)

	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		// Wait returns after exec's copying goroutine, so nothing else writes.
		out.Flush()
		done <- err
	}()

	return &childProcess{
		cmd:    cmd,
		stdin:  stdinPipe,
		done:   done,
		logger: logger,
	}, nil
}

// RequestShutdown signals the child to shut down gracefully by closing its stdin pipe.
func (c *childProcess) RequestShutdown() {
	c.logger.Info("Requesting child process shutdown")
	c.stdin.Close()
}

// Done returns a channel that receives the child's exit error (nil on clean exit).
func (c *childProcess) Done() <-chan error {
	return c.done
}

// WaitOrKill waits for the child to exit, killing it if it doesn't exit within the timeout.
func (c *childProcess) WaitOrKill(timeout time.Duration) error {
	select {
	case err := <-c.done:
		return err
	case <-time.After(timeout):
		c.logger.Warn("Child did not exit in time, killing")
		c.cmd.Process.Kill()
		return <-c.done
	}
}

// childExitError treats ErrWaitDelay as non-fatal after process exit.
func childExitError(err error) error {
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	return err
}

// bestEffortWriter drops output rather than reporting a write error. [exec.Cmd] closes the child's
// output pipe when its copy fails, and a Go program whose stdout or stderr pipe breaks exits on
// SIGPIPE, so surfacing a log-sink failure here would crash-loop the daemon over unwritable logs.
type bestEffortWriter struct {
	w      io.Writer
	failed atomic.Bool
}

func (b *bestEffortWriter) Write(p []byte) (int, error) {
	if _, err := b.w.Write(p); err != nil && !b.failed.Swap(true) {
		// Reported on stderr because the sink that just failed cannot report its own failure.
		fmt.Fprintf(os.Stderr, "lanternd: dropping daemon output, log writer failed: %v\n", err)
	}
	return len(p), nil
}

// maxChildLine bounds how much of an unended line lineWriter holds.
const maxChildLine = 64 << 10

// droppedLineNotice replaces a line lineWriter drops for being too long.
const droppedLineNotice = "lanternd: dropped a daemon output line longer than 64 KiB\n"

// lineWriter passes w only whole lines, holding a trailing partial line until
// the rest arrives, so a filter on w sees each line in one Write. A line that
// outgrows maxChildLine before it ends is dropped through its newline, with a
// notice in its place: passing it on in pieces could split a helper tag, or
// separate an address from the tag that marks its line for redaction. Not
// safe for concurrent use; exec gives it one goroutine.
type lineWriter struct {
	w        io.Writer
	buf      []byte
	dropping bool // discarding the rest of an over-long line
}

func (l *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	if l.dropping {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			return n, nil
		}
		l.dropping = false
		p = p[i+1:]
	}
	if last := bytes.LastIndexByte(p, '\n'); last >= 0 {
		if len(l.buf) > 0 {
			l.buf = append(l.buf, p[:last+1]...)
			_, _ = l.w.Write(l.buf)
			l.buf = l.buf[:0]
		} else {
			_, _ = l.w.Write(p[:last+1])
		}
		p = p[last+1:]
	}
	l.buf = append(l.buf, p...)
	if len(l.buf) >= maxChildLine {
		_, _ = io.WriteString(l.w, droppedLineNotice)
		l.buf = l.buf[:0]
		l.dropping = true
	}
	return n, nil
}

// Flush passes on a held partial line.
func (l *lineWriter) Flush() {
	if len(l.buf) > 0 {
		_, _ = l.w.Write(l.buf)
		l.buf = l.buf[:0]
	}
}

// HandleCrash cleans up stale VPN network state left by a crashed child.
func (c *childProcess) HandleCrash(err error) {
	c.logger.Warn("Daemon process exited unexpectedly, cleaning up network state", "error", err)
	vpn.AttemptFixNetState()
}

// babysit runs the daemon as a child process until ctx is canceled.
// Unexpected exits trigger cleanup and restart with backoff.
//
// Graceful shutdown is requested by closing the child's stdin, which works even
// in service environments without console signal delivery.
//
// The returned error is nil, a spawn failure, or the last child exit error.
func babysit(ctx context.Context, args []string, logger *slog.Logger) error {
	bo := common.NewBackoff(babysitBackoffBase, daemonRestartBackoffMax)

	for ctx.Err() == nil {
		child, err := spawnChild(args, logger)
		if err != nil {
			return err
		}
		logger.Info("Monitoring daemon process")
		startedAt := time.Now()

		select {
		case <-ctx.Done():
			logger.Info("Shutdown requested, stopping daemon process")
			child.RequestShutdown()
			return childExitError(child.WaitOrKill(gracefulShutdownTimeout))
		case err = <-child.Done():
			err = childExitError(err)
		}

		if err != nil && ctx.Err() == nil {
			child.HandleCrash(err)
		}

		if time.Since(startedAt) > daemonRestartBackoffResetAfter {
			bo.Reset()
		}

		logger.Info("Restarting child process")
		bo.Wait(ctx)
	}
	return nil
}

func configureDaemonEnvironment(environment daemonEnvironment) error {
	if environment == daemonEnvironmentStaging {
		return os.Setenv(commonenv.ENV.String(), string(environment))
	}
	return nil
}

func daemonBackendOptions(dataPath, logPath, logLevel string) backend.Options {
	return backend.Options{
		DataDir:                  dataPath,
		LogDir:                   logPath,
		LogLevel:                 logLevel,
		PreserveTelemetryConsent: true,
		UserMessageCapabilities:  userMessageCapabilities(),
	}
}

func userMessageCapabilities() wire.ClientCapabilities {
	return wire.ClientCapabilities{
		Version:  wire.CapabilityUserMessagesV1,
		Surfaces: []wire.Surface{wire.SurfaceSnackbar},
		Actions: []wire.ActionType{
			wire.ActionTypeOpenHTTPSURL,
			wire.ActionTypeOpenPlans,
		},
	}
}

func daemonBackendURLs(environment daemonEnvironment) (authURL, proServerURL string) {
	if environment == daemonEnvironmentStaging {
		return common.StageBaseURL, common.StageProServerURL
	}
	return common.BaseURL, common.ProServerURL
}

func runDaemon(ctx context.Context, dataPath, logPath, logLevel string, environment daemonEnvironment) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := configureDaemonEnvironment(environment); err != nil {
		return fmt.Errorf("configure daemon environment: %w", err)
	}
	dataPath = withDefault(commonenv.GetString(commonenv.DataPath), dataPath)
	logPath = withDefault(commonenv.GetString(commonenv.LogPath), logPath)
	for _, path := range []string{dataPath, logPath} {
		if err := dirsecurity.Prepare(path); err != nil {
			return fmt.Errorf("prepare %s: %w", path, err)
		}
	}
	if err := initializeDaemonDiagnostics(dataPath, logPath, logLevel); err != nil {
		slog.Warn("Daemon diagnostics initialization failed", "error", err)
	}
	authURL, proServerURL := daemonBackendURLs(environment)
	slog.Info("Starting lanternd", "version", common.Version, "dataPath", dataPath, "environment", environment, "authURL", authURL, "proServerURL", proServerURL)
	ownerSID, err := serviceowner.Load()
	if err != nil {
		return fmt.Errorf("load service owner: %w", err)
	}
	if err := serviceowner.GrantProcessQuery(); err != nil {
		slog.Warn("Service process queries are unavailable", "error", err)
	}
	server := ipc.NewServer(nil, !common.IsMobile())
	server.SetOwnerSID(ownerSID)
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start IPC server: %w", err)
	}
	defer server.Close()
	be, err := backend.NewLocalBackend(ctx, daemonBackendOptions(dataPath, logPath, logLevel))
	if err != nil {
		slog.Error("Failed to create backend", "error", err)
		<-ctx.Done()
		return nil
	}
	defer be.Close()
	user, err := be.UserData()
	if err != nil {
		return fmt.Errorf("failed to get current data: %w", err)
	}
	if user == nil {
		if _, err := be.NewUser(ctx); err != nil {
			return fmt.Errorf("failed to create new user: %w", err)
		}
	}

	be.Start()
	server.SetBackend(be)

	<-ctx.Done()

	slog.Info("Shutting down...")

	time.AfterFunc(childForceExitTimeout, func() {
		slog.Error("Failed to shut down in time, forcing exit")
		os.Exit(1)
	})

	be.Close()
	if err := server.Close(); err != nil {
		slog.Error("Error closing IPC server", "error", err)
	}
	slog.Info("Shutdown complete")
	return nil
}
