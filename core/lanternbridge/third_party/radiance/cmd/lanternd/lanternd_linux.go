package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/internal/dirsecurity"
)

const (
	serviceName     = "lanternd"
	binPath         = "/usr/bin/" + serviceName
	systemdUnitPath = "/usr/lib/systemd/system/" + serviceName + ".service"
)

func maybePlatformService() bool {
	return false
}

var systemdUnitTmpl = template.Must(template.New("unit").Funcs(template.FuncMap{
	"arg": systemdQuote,
}).Parse(`[Unit]
Description=Lantern VPN Daemon
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={{.ExePath}} run --data-path {{arg .DataPath}} --log-path {{arg .LogPath}} --log-level {{arg .LogLevel}} --environment {{arg .Environment}}
Restart=on-failure
RestartSec=5s

RuntimeDirectory=lantern
RuntimeDirectoryMode=0755
StateDirectory=lantern
CacheDirectory=lantern
LogsDirectory=lantern

[Install]
WantedBy=multi-user.target
`))

var systemdArgEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	`%`, `%%`,
	`$`, `$$`,
)

// systemdQuote renders s as a single systemd command-line argument. systemd splits a command line
// on unquoted whitespace, and inside double quotes it still applies C-style escapes, % specifier
// expansion and $ variable expansion, so each of those is escaped rather than left to expand.
func systemdQuote(s string) string {
	return `"` + systemdArgEscaper.Replace(s) + `"`
}

func install(dataPath, logPath, logLevel string, environment daemonEnvironment) error {
	slog.Info("Installing systemd service..", "version", common.Version)

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

	exe, err := copyBin()
	if err != nil {
		return err
	}

	f, err := os.Create(systemdUnitPath)
	if err != nil {
		return fmt.Errorf("failed to create unit file %s: %w", systemdUnitPath, err)
	}
	defer f.Close()

	err = systemdUnitTmpl.Execute(f, struct {
		ExePath, DataPath, LogPath, LogLevel, Environment string
	}{exe, dataPath, logPath, logLevel, string(environment)})
	if err != nil {
		return fmt.Errorf("failed to write unit file: %w", err)
	}

	slog.Info("Installing systemd service", "unit", systemdUnitPath)
	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", serviceName},
		{"systemctl", "start", serviceName},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %w\n%s", args, err, out)
		}
	}

	slog.Info("Systemd service installed and started")
	return nil
}

func uninstall() error {
	slog.Info("Uninstalling systemd service")
	for _, args := range [][]string{
		{"systemctl", "stop", serviceName},
		{"systemctl", "disable", serviceName},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			slog.Warn("Command failed", "cmd", args, "error", err, "output", string(out))
		}
	}

	if err := os.Remove(systemdUnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove unit file: %w", err)
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w\n%s", err, out)
	}

	slog.Info("Systemd service uninstalled")
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove binary: %w", err)
	}
	return nil
}
