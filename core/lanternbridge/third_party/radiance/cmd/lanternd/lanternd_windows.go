package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"math/rand/v2"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/serviceowner"
	"github.com/getlantern/radiance/internal/dirsecurity"
)

const (
	serviceName = "LanternSvc"
	binPath     = "C:\\Program Files\\Lantern\\" + serviceName + ".exe"

	windowsServiceChildShutdownTimeout = 15 * time.Second
	// windowsServiceStopWaitHint leaves SCM time for forced termination after graceful shutdown times out.
	windowsServiceStopWaitHint = 20 * time.Second

	// windowsServiceRecoveryMaxDelay caps how long SCM waits before retrying a failed service host.
	windowsServiceRecoveryMaxDelay = 64 * time.Second
	// windowsServiceRecoveryResetPeriod keeps the failure count through the longest delay so SCM advances to the next recovery action.
	windowsServiceRecoveryResetPeriod = 2 * windowsServiceRecoveryMaxDelay

	// windowsServiceRestartBackoffInitial allows quick recovery from an isolated child failure.
	windowsServiceRestartBackoffInitial = time.Second
	// windowsServiceRestartBackoffJitter spreads restart attempts after failures that affect many clients.
	windowsServiceRestartBackoffJitter = 0.2
)

var isWindowsService bool

func init() {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if running as Windows service: %v\n", err)
	}
	isWindowsService = isSvc
}

func install(dataPath, logPath, logLevel string, environment daemonEnvironment) error {
	dataPath = os.ExpandEnv(dataPath)
	logPath = os.ExpandEnv(logPath)

	slog.Info("Installing Windows service..", "version", common.Version)

	// Remove any existing service so we can recreate it cleanly.
	// Errors are expected on first install when no service exists yet.
	if err := uninstall(); err != nil {
		slog.Debug("No existing service to remove (expected on first install)", "error", err)
	}

	for _, path := range []string{dataPath, logPath} {
		if err := dirsecurity.Secure(path); err != nil {
			return fmt.Errorf("secure %s: %w", path, err)
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows service manager: %w", err)
	}
	defer m.Disconnect()

	exe, err := copyBin()
	if err != nil {
		return err
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  serviceName,
		Description:  "Lantern Daemon Service",
	}

	args := (serviceRunConfig{
		dataPath:    dataPath,
		logPath:     logPath,
		logLevel:    logLevel,
		environment: environment,
	}).args()

	slog.Info("Creating Windows service", "exe", exe, "args", args)
	service, err := m.CreateService(serviceName, exe, config, args...)
	if err != nil {
		return fmt.Errorf("failed to create %q service: %w", serviceName, err)
	}
	defer service.Close()

	if err := configureWindowsServiceRecovery(service); err != nil {
		return err
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	slog.Info("Windows service installed successfully")
	return nil
}

// windowsServiceRecoveryConfigurer lets recovery setup be tested without connecting to SCM.
type windowsServiceRecoveryConfigurer interface {
	SetRecoveryActions([]mgr.RecoveryAction, uint32) error
	SetRecoveryActionsOnNonCrashFailures(bool) error
}

// configureWindowsServiceRecovery keeps SCM restart as a fallback if the service host fails.
// Non-crash failures are included because Execute reports an exit code instead of crashing.
func configureWindowsServiceRecovery(service windowsServiceRecoveryConfigurer) error {
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 1 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 4 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 8 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 16 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 32 * time.Second},
		{Type: mgr.ServiceRestart, Delay: windowsServiceRecoveryMaxDelay},
	}, uint32(windowsServiceRecoveryResetPeriod/time.Second)); err != nil {
		return fmt.Errorf("failed to set service recovery actions: %w", err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("failed to enable recovery actions for non-crash failures: %w", err)
	}
	return nil
}

func uninstall() error {
	slog.Info("Uninstalling Windows service..")
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("failed to open %q service: %w", serviceName, err)
	}

	status, err := service.Query()
	if err != nil {
		service.Close()
		return fmt.Errorf("failed to query service state: %w", err)
	}
	if status.State != svc.Stopped {
		service.Control(svc.Stop)
	}
	err = service.Delete()
	service.Close()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	slog.Info("Waiting for service to be removed...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for service to be removed")
		case <-time.After(100 * time.Millisecond):
			if service, err = m.OpenService(serviceName); err != nil {
				slog.Info("Windows service uninstalled successfully")
				if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("failed to remove binary: %w", err)
				}
				return nil
			}
			service.Close()
		}
	}
}

func maybePlatformService() bool {
	if !isWindowsService {
		return false
	}
	if err := startWindowsService(); err != nil {
		log.Fatalf("Failed to start Windows service: %v\n", err)
	}
	return true
}

// windowsServiceChild isolates supervision from OS process details so restart and shutdown paths can be tested without launching a daemon.
type windowsServiceChild interface {
	Done() <-chan error
	RequestShutdown()
	WaitOrKill(time.Duration) error
	HandleCrash(error)
}

// windowsServiceBackoff lets a service stop cancel a pending restart delay.
type windowsServiceBackoff interface {
	Wait(context.Context)
	Reset()
}

// windowsServiceExponentialBackoff slows crash loops and spreads restart attempts across clients.
type windowsServiceExponentialBackoff struct {
	next time.Duration
}

func newWindowsServiceExponentialBackoff() *windowsServiceExponentialBackoff {
	return &windowsServiceExponentialBackoff{next: windowsServiceRestartBackoffInitial}
}

func (b *windowsServiceExponentialBackoff) nextDelay() time.Duration {
	delay := b.next
	b.next = min(2*b.next, daemonRestartBackoffMax)
	return delay
}

func jitterWindowsServiceRestartDelay(delay time.Duration, random float64) time.Duration {
	factor := 1 - windowsServiceRestartBackoffJitter + 2*windowsServiceRestartBackoffJitter*random
	return min(time.Duration(float64(delay)*factor), daemonRestartBackoffMax)
}

func (b *windowsServiceExponentialBackoff) Wait(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	timer := time.NewTimer(jitterWindowsServiceRestartDelay(b.nextDelay(), rand.Float64()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (b *windowsServiceExponentialBackoff) Reset() {
	b.next = windowsServiceRestartBackoffInitial
}

// service runs the Windows SCM handler and supervises its daemon child. Dependencies are injected to keep restart and shutdown tests isolated.
type service struct {
	logger        *slog.Logger
	loggerFactory func(string, string) *slog.Logger
	spawnChild    func([]string, *slog.Logger) (windowsServiceChild, error)
	newBackoff    func() windowsServiceBackoff
}

func newWindowsService() *service {
	return &service{
		logger:        slog.Default(),
		loggerFactory: newDaemonLogger,
		spawnChild: func(args []string, logger *slog.Logger) (windowsServiceChild, error) {
			child, err := spawnChild(args, logger)
			if err != nil {
				return nil, err
			}
			return child, nil
		},
		newBackoff: func() windowsServiceBackoff {
			return newWindowsServiceExponentialBackoff()
		},
	}
}

func startWindowsService() error {
	return svc.Run(serviceName, newWindowsService())
}

func (s *service) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	// The Execute args from the SCM dispatcher only contain runtime start parameters
	// (typically just [serviceName]). The actual configured arguments are baked into
	// os.Args via the service ImagePath. Parse from os.Args to get the real values,
	// falling back to defaults if not present.
	config, err := parseServiceRunArgs(os.Args[1:])
	if err != nil {
		s.logger.Error("Failed to parse service arguments", "error", err)
		return true, 1
	}
	if err := serviceowner.GrantProcessQuery(); err != nil {
		s.logger.Warn("Service process queries are unavailable", "error", err)
	}
	return s.run(config, r, status)
}

// run supervises the daemon child so crash cleanup and restart do not depend on SCM recovery.
func (s *service) run(config serviceRunConfig, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	childArgs := config.args()
	logger := s.logger
	if s.loggerFactory != nil {
		logger = s.loggerFactory(config.logPath, config.logLevel)
	}
	child, err := s.spawnChild(childArgs, logger)
	if err != nil {
		logger.Error("Failed to start daemon", "error", err)
		return true, 1
	}

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	logger.Info("Running as Windows service")

	backoff := s.newBackoff()
	startedAt := time.Now()
	childDone := child.Done()
	var restartReady <-chan struct{}
	serviceContext, cancelService := context.WithCancel(context.Background())
	defer cancelService()

	for {
		select {
		case err := <-childDone:
			if err != nil {
				child.HandleCrash(err)
			}
			if time.Since(startedAt) > daemonRestartBackoffResetAfter {
				backoff.Reset()
			}
			logger.Info("Restarting daemon process")
			child = nil
			childDone = nil

			restartDone := make(chan struct{})
			restartReady = restartDone
			go func() {
				backoff.Wait(serviceContext)
				close(restartDone)
			}()
		case <-restartReady:
			restartReady = nil

			child, err = s.spawnChild(childArgs, logger)
			if err != nil {
				logger.Error("Failed to restart daemon", "error", err)
				return true, 1
			}
			startedAt = time.Now()
			childDone = child.Done()
			logger.Info("Running as Windows service")
		case change := <-r:
			switch change.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{
					State:      svc.StopPending,
					CheckPoint: 1,
					WaitHint:   uint32(windowsServiceStopWaitHint / time.Millisecond),
				}
				cancelService()
				if restartReady != nil {
					<-restartReady
				}
				if child != nil {
					logger.Info("Service stop requested")
					child.RequestShutdown()
					if err := child.WaitOrKill(windowsServiceChildShutdownTimeout); err != nil {
						logger.Warn("Daemon process did not stop cleanly", "error", err)
					}
				}
				return false, windows.NO_ERROR
			case svc.Interrogate:
				status <- change.CurrentStatus
			case svc.SessionChange:
				status <- change.CurrentStatus
			}
		}
	}
}
