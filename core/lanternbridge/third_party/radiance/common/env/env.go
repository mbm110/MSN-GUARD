// Package env is responsible for loading radiance configuration based on a order of precedence
// (environment variables > configurations set at .env file).
package env

import (
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type _key string

var (
	LogLevel         _key = "RADIANCE_LOG_LEVEL"
	LogPath          _key = "RADIANCE_LOG_PATH"
	DataPath         _key = "RADIANCE_DATA_PATH"
	DisableFetch     _key = "RADIANCE_DISABLE_FETCH_CONFIG"
	PrintCurl        _key = "RADIANCE_PRINT_CURL"
	DisableStdout    _key = "RADIANCE_DISABLE_STDOUT_LOG"
	ENV              _key = "RADIANCE_ENV"
	SocksAddress     _key = "RADIANCE_SOCKS_ADDRESS"
	Country          _key = "RADIANCE_COUNTRY"
	FeatureOverrides _key = "RADIANCE_FEATURE_OVERRIDES"
	AppVersion       _key = "RADIANCE_VERSION"
	BufPoolBudgetMB  _key = "RADIANCE_BUF_POOL_BUDGET_MB"
	MemoryLimitMB    _key = "RADIANCE_MEM_LIMIT_MB"

	// PeerExternalPort is a manually-forwarded router port (1..65535) for the
	// peer inbound; empty/0 means unset.
	PeerExternalPort _key = "RADIANCE_PEER_EXTERNAL_PORT"

	// LogToStdout makes common.Init configure logging to stdout instead of a file.
	// The log directory is still needed for crash dumps and support archives.
	LogToStdout _key = "RADIANCE_LOG_TO_STDOUT"

	Testing _key = "RADIANCE_TESTING"

	mu     sync.RWMutex
	dotenv = map[string]string{}
)

func (k _key) String() string { return string(k) }

func init() {
	buf, err := os.ReadFile(".env")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error(".env file found, but failed to read", slog.Any("error", err))
	} else if err == nil {
		lines := strings.SplitSeq(string(buf), "\n")
		for line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue // Skip empty lines and comments
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				dotenv[key] = value
			}
		}
	}
	if testing.Testing() {
		dotenv[Testing.String()] = "true"
		dotenv[LogLevel.String()] = "disable"
	}
}

// Get returns the value for key. OS env takes precedence over .env / runtime
// Set values (matching the package docstring); dotenv is the fallback.
func Get(key _key) (string, bool) {
	if value, exists := os.LookupEnv(key.String()); exists {
		return value, true
	}
	mu.RLock()
	value, exists := dotenv[key.String()]
	mu.RUnlock()
	if exists {
		return value, true
	}
	return "", false
}

// Set writes a key to the in-memory dotenv map. If the same key is set in
// the OS env, Get still returns the OS value — shell env wins.
func Set(key string, value string) {
	mu.Lock()
	dotenv[key] = value
	mu.Unlock()
}

// GetAll returns a copy of the in-memory dotenv map.
func GetAll() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	m := make(map[string]string, len(dotenv))
	maps.Copy(m, dotenv)
	return m
}

func GetString(key _key) string {
	value, _ := Get(key)
	return value
}

func GetBool(key _key) bool {
	value, exists := Get(key)
	if !exists {
		return false
	}
	v, _ := strconv.ParseBool(value)
	return v
}

func GetInt(key _key) int {
	value, exists := Get(key)
	if !exists {
		return 0
	}
	v, _ := strconv.Atoi(value)
	return v
}

func SetStagingEnv() {
	slog.Info("setting environment to staging for testing")
	Set(ENV.String(), "staging")
	Set(PrintCurl.String(), "true")
}
