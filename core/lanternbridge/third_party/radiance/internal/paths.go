package internal

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	DebugBoxOptionsFileName    = "debug-box-options.json"
	ConfigFileName             = "config.json"
	ConfigInvalidFileName      = "config.invalid.json"
	ServersFileName            = "servers.json"
	ServersInvalidFileName     = "servers.invalid.json"
	SplitTunnelFileName        = "split-tunnel.json"
	SplitTunnelInvalidFileName = "split-tunnel.invalid.json"
	LogFileName                = "lantern.log"
	CrashLogFileName           = "lantern-crash.log"
	MemoryDumpFileName         = "lantern-memdump.txt"
)

func DefaultDataPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Lantern")
	case "darwin":
		return "/Library/Application Support/Lantern"
	case "linux":
		return "/var/lib/lantern"
	default:
		return ""
	}
}

func DefaultLogPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Lantern")
	case "darwin":
		return "/Library/Logs/Lantern"
	case "linux":
		return "/var/log/lantern"
	default:
		return ""
	}
}
