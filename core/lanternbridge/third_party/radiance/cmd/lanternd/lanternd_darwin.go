//go:build darwin && !ios

package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"text/template"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/internal/dirsecurity"
)

const (
	serviceName = "com.lantern.lanternd"
	binPath     = "/usr/local/bin/" + serviceName
)

func maybePlatformService() bool {
	return false
}

// launchdPlistTmpl discards stdout because the supervisor already captures the
// daemon log stream. Stderr is kept for panics and fatal output that bypass slog.
var launchdPlistTmpl = template.Must(template.New("plist").Funcs(template.FuncMap{
	"str": plistString,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{str .ServiceName}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{str .ExePath}}</string>
		<string>run</string>
		<string>--data-path</string>
		<string>{{str .DataPath}}</string>
		<string>--log-path</string>
		<string>{{str .LogPath}}</string>
		<string>--log-level</string>
		<string>{{str .LogLevel}}</string>
		<string>--environment</string>
		<string>{{str .Environment}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/dev/null</string>
	<key>StandardErrorPath</key>
	<string>{{str .LogPath}}/lanternd.stderr.log</string>
</dict>
</plist>
`))

func plistPath() string {
	return fmt.Sprintf("/Library/LaunchDaemons/%s.plist", serviceName)
}

// plistString renders s as character data for a plist <string> element. An unescaped & or < in a
// path yields XML that launchctl refuses to load.
func plistString(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func install(dataPath, logPath, logLevel string, environment daemonEnvironment) error {
	slog.Info("Installing launchd service..", "version", common.Version)

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

	plist := plistPath()
	f, err := os.Create(plist)
	if err != nil {
		return fmt.Errorf("failed to create plist %s: %w", plist, err)
	}
	defer f.Close()

	err = launchdPlistTmpl.Execute(f, struct {
		ServiceName, ExePath, DataPath, LogPath, LogLevel, Environment string
	}{serviceName, exe, dataPath, logPath, logLevel, string(environment)})
	if err != nil {
		return fmt.Errorf("failed to write plist: %w", err)
	}

	slog.Info("Installing launchd service", "plist", plist)
	if out, err := exec.Command("launchctl", "load", "-w", plist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load: %w\n%s", err, out)
	}

	slog.Info("Launchd service installed and started")
	return nil
}

func uninstall() error {
	slog.Info("Uninstalling launchd service")
	plist := plistPath()

	if out, err := exec.Command("launchctl", "unload", "-w", plist).CombinedOutput(); err != nil {
		slog.Warn("Failed to unload service", "error", err, "output", string(out))
	}

	if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove plist: %w", err)
	}

	slog.Info("Launchd service uninstalled")
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove binary: %w", err)
	}
	return nil
}
