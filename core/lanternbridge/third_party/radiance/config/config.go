/*
Package config provides a handler for fetching and storing proxy configurations.
*/
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	C "github.com/getlantern/common"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	box "github.com/getlantern/lantern-box"
	lbO "github.com/getlantern/lantern-box/option"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/internal"
)

const (
	maxRetryDelay       = 2 * time.Minute
	defaultPollInterval = 10 * time.Minute
)

var (
	// ErrFetchingConfig is returned by [ConfigHandler.GetConfig] when if there was an error
	// fetching the configuration.
	ErrFetchingConfig = errors.New("failed to fetch config")

	// ErrConfigFetchDisabled is returned by [ConfigHandler.Update] when config fetching
	// is disabled via settings.
	ErrConfigFetchDisabled = errors.New("config fetching is disabled")
)

// Config includes all configuration data from the Lantern API
type Config = C.ConfigResponse

type Options struct {
	PollInterval  time.Duration
	DataPath      string
	Locale        string
	AccountClient *account.Client
	Logger        *slog.Logger
	HTTPClient    *http.Client
}

// ConfigHandler handles fetching the proxy configuration from the proxy server. It provides access
// to the most recent configuration.
type ConfigHandler struct {
	// config holds a configResult.
	config  atomic.Pointer[Config]
	ftr     Fetcher
	logger  *slog.Logger
	options Options

	ctx    context.Context
	cancel context.CancelFunc

	started atomic.Bool

	// fetchMu guards fetching/pending. A caller arriving while a fetch is
	// in flight sets pending; the in-flight fetch re-runs once to pick up
	// state that changed mid-fetch (e.g. a user identity refreshed by an
	// email login that completed after the request was already on the wire).
	fetchMu  sync.Mutex
	fetching bool
	pending  bool

	pollInterval time.Duration
	configPath   string
	wgKeyPath    string
	startOnce    sync.Once
}

// NewConfigHandler creates a new ConfigHandler that fetches the proxy configuration every pollInterval.
func NewConfigHandler(ctx context.Context, options Options) *ConfigHandler {
	ctx, cancel := context.WithCancel(ctx)
	pollInterval := options.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	dir := options.DataPath
	ch := &ConfigHandler{
		ctx:          ctx,
		cancel:       cancel,
		pollInterval: pollInterval,
		configPath:   filepath.Join(dir, internal.ConfigFileName),
		wgKeyPath:    filepath.Join(dir, "wg.key"),
		logger:       logger,
		options:      options,
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		ch.logger.Error("creating config directory", "error", err)
	}
	if err := ch.loadConfig(); err != nil {
		ch.logger.Error("failed to load config", "error", err)
	}
	return ch
}

func (ch *ConfigHandler) Start() {
	ch.startOnce.Do(func() {
		ch.ftr = newFetcher(ch.options.Locale, ch.options.AccountClient, ch.options.HTTPClient)
		ch.started.Store(true)
		go ch.fetchLoop(ch.pollInterval)
		events.SubscribeContext(ch.ctx, ch.onUserChange)
	})
}

func (ch *ConfigHandler) onUserChange(account.UserChangeEvent) {
	// Clearing an account must not trigger ensureUser during logout.
	if settings.GetInt64(settings.UserIDKey) == 0 || settings.GetString(settings.TokenKey) == "" {
		return
	}
	if err := ch.fetchConfig(); err != nil {
		ch.logger.Error("Failed to fetch config after account change", "error", err)
	}
}

var ErrNoWGKey = errors.New("no wg key")

func (ch *ConfigHandler) loadWGKey() (wgtypes.Key, error) {
	buf, err := atomicfile.ReadFile(ch.wgKeyPath)
	if os.IsNotExist(err) {
		return wgtypes.Key{}, ErrNoWGKey
	}
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("reading wg key file: %w", err)
	}
	key, err := wgtypes.ParseKey(string(buf))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("parsing wg key: %w", err)
	}
	return key, nil
}

func (ch *ConfigHandler) fetchConfig() error {
	if settings.GetBool(settings.ConfigFetchDisabledKey) {
		ch.logger.Info("config fetch disabled, skipping")
		return nil
	}
	if ch.isClosed() {
		return fmt.Errorf("config handler is closed")
	}

	ch.fetchMu.Lock()
	if ch.fetching {
		ch.pending = true
		ch.fetchMu.Unlock()
		ch.logger.Info("config fetch already in flight, scheduling another after it completes")
		return nil
	}
	ch.fetching = true
	ch.fetchMu.Unlock()

	var lastErr error
	for {
		lastErr = ch.doFetchConfig()
		ch.fetchMu.Lock()
		if !ch.pending {
			ch.fetching = false
			ch.fetchMu.Unlock()
			return lastErr
		}
		ch.pending = false
		ch.fetchMu.Unlock()
	}
}

func (ch *ConfigHandler) doFetchConfig() error {
	privateKey, err := ch.loadWGKey()
	if err != nil && !errors.Is(err, ErrNoWGKey) {
		return fmt.Errorf("loading wg key: %w", err)
	}

	if errors.Is(err, ErrNoWGKey) {
		var keyErr error
		if privateKey, keyErr = wgtypes.GeneratePrivateKey(); keyErr != nil {
			return fmt.Errorf("failed to generate wg keys: %w", keyErr)
		}

		if writeErr := atomicfile.WriteFile(ch.wgKeyPath, []byte(privateKey.String()), fileperm.File); writeErr != nil {
			return fmt.Errorf("writing wg key file: %w", writeErr)
		}
	}

	ch.logger.Info("Fetching config")
	preferred := common.PreferredLocation{}
	if err := settings.GetStruct(settings.PreferredLocationKey, &preferred); err != nil {
		ch.logger.Error("failed to get preferred location from settings", "error", err)
	}

	resp, err := ch.ftr.fetchConfig(ch.ctx, preferred, privateKey.PublicKey().String())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFetchingConfig, err)
	}
	if resp == nil {
		ch.logger.Info("no new config available")
		return nil
	}
	ch.logger.Info("Config fetched from server")

	// Save the raw config for debugging
	if writeErr := atomicfile.WriteFile(strings.TrimSuffix(ch.configPath, ".json")+"_raw.json", resp, fileperm.File); writeErr != nil {
		ch.logger.Error("writing raw config file", "error", writeErr)
	}

	// On fetch/parse error, retain the last-good config since the failure is often transient.
	confResp, err := singjson.UnmarshalExtendedContext[C.ConfigResponse](box.BaseContext(), resp)
	if err != nil {
		ch.logger.Error("failed to parse config", "error", err)
		return fmt.Errorf("parsing config: %w", err)
	}
	cleanTags(&confResp)

	setWireGuardKeyInOptions(confResp.Options.Endpoints, privateKey)
	if err := ch.setConfig(&confResp); err != nil {
		ch.logger.Error("failed to set config", "error", err)
		return fmt.Errorf("setting config: %w", err)
	}
	ch.logger.Info("Config fetched")
	return nil
}

func cleanTags(cfg *C.ConfigResponse) {
	opts := cfg.Options
	locs := cfg.OutboundLocations
	nlocs := make(map[string]*C.ServerLocation, len(locs))
	for i := 0; i < len(opts.Outbounds); i++ {
		tag := opts.Outbounds[i].Tag
		loc := locs[tag]
		opts.Outbounds[i].Tag = strings.TrimPrefix(tag, "singbox")
		nlocs[opts.Outbounds[i].Tag] = loc
	}
	for i := 0; i < len(opts.Endpoints); i++ {
		tag := opts.Endpoints[i].Tag
		loc := locs[tag]
		opts.Endpoints[i].Tag = strings.TrimPrefix(tag, "singbox")
		nlocs[opts.Endpoints[i].Tag] = loc
	}
	cfg.OutboundLocations = nlocs
}

func setWireGuardKeyInOptions(endpoints []option.Endpoint, privateKey wgtypes.Key) {
	// Requires privilege and cannot conflict with existing system interfaces
	// System tries to use system env; for mobile we need to tun device
	system := !(common.IsAndroid() || common.IsIOS() || common.IsMacOS())
	for _, endpoint := range endpoints {
		switch opts := endpoint.Options.(type) {
		case *option.WireGuardEndpointOptions:
			opts.PrivateKey = privateKey.String()
			opts.System = opts.System && system
		case *lbO.AmneziaEndpointOptions:
			opts.PrivateKey = privateKey.String()
			opts.System = opts.System && system
		default:
		}
	}
}

// fetchLoop fetches the configuration periodically. It uses the server's
// recommended poll interval (PollIntervalSeconds) when available, falling
// back to the default pollInterval. This allows the bandit to control how
// often the client re-fetches based on learning confidence.
func (ch *ConfigHandler) fetchLoop(defaultPollInterval time.Duration) {
	backoff := common.NewBackoff(0, maxRetryDelay)
	for {
		if err := ch.fetchConfig(); err != nil {
			ch.logger.Error("Failed to fetch config. Retrying", "error", err)
			backoff.Wait(ch.ctx)
			if ch.ctx.Err() != nil {
				return
			}
			continue
		}
		backoff.Reset()

		// Use server-recommended poll interval if available, clamped to a
		// minimum of 10s to prevent excessive polling.
		interval := defaultPollInterval
		if cfg := ch.config.Load(); cfg != nil && cfg.PollIntervalSeconds > 0 {
			serverInterval := time.Duration(cfg.PollIntervalSeconds) * time.Second
			if serverInterval < 10*time.Second {
				serverInterval = 10 * time.Second
			}
			interval = serverInterval
			ch.logger.Debug("Using server-recommended poll interval",
				"interval", interval,
				"default", defaultPollInterval,
			)
		}

		select {
		case <-ch.ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// Fetch immediately fetches the latest config. It returns [ErrConfigFetchDisabled]
// if config fetching is disabled in settings.
func (ch *ConfigHandler) Fetch() error {
	if settings.GetBool(settings.ConfigFetchDisabledKey) {
		return ErrConfigFetchDisabled
	}
	if !ch.started.Load() {
		return fmt.Errorf("config handler not started")
	}
	return ch.fetchConfig()
}

// Stop stops the ConfigHandler from fetching new configurations.
func (ch *ConfigHandler) Stop() {
	ch.cancel()
}

func (ch *ConfigHandler) isClosed() bool {
	select {
	case <-ch.ctx.Done():
		return true
	default:
		return false
	}
}

// loadConfig loads the config file from the disk. If the config file is not found, it returns
// nil.
func (ch *ConfigHandler) loadConfig() error {
	ch.logger.Debug("reading config file")
	cfg, err := load(ch.configPath)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	if cfg != nil {
		ch.config.Store(cfg)
	}
	return nil
}

func load(path string) (*Config, error) {
	rawConfig, err := atomicfile.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // No config file yet
	}
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	ctx := box.Context(context.Background())
	cfg, err := singjson.UnmarshalExtendedContext[*Config](ctx, rawConfig)
	if err == nil {
		if cfg != nil && cfg.IP != "" {
			if err := saveConfig(cfg, path); err != nil {
				slog.Warn("Failed to remove client IP from saved config", "path", path, "error", err)
			}
		}
		return cfg, nil
	}

	// try to migrate from old format if parsing fails
	// TODO: remove this migration once the old config format no longer appears
	// on disk in the field.
	if migrated, mErr := migrateToNewFmt(rawConfig); mErr == nil {
		if err := saveConfig(migrated, path); err != nil {
			return nil, fmt.Errorf("saving migrated config: %w", err)
		}
		return migrated, nil
	}

	// The config is unparseable — most likely a downgrade where this build's
	// sing-box can't decode a newer on-disk config. Quarantine it so it stops
	// re-failing on every start and is preserved for diagnostics, then start
	// with no config; the next successful fetch repopulates config.json.
	slog.Warn("config file is invalid; quarantining and starting without a config",
		"path", path, "error", err)
	quarantineInvalidConfig(path, rawConfig)
	return nil, nil
}

// quarantineInvalidConfig moves an unparseable config aside to
// config.invalid.json so it no longer blocks loading on subsequent starts while
// remaining available for diagnostics.
func quarantineInvalidConfig(path string, buf []byte) {
	invalidPath := filepath.Join(filepath.Dir(path), internal.ConfigInvalidFileName)
	if err := atomicfile.WriteFile(invalidPath, buf, fileperm.File); err != nil {
		// Keep the original in place when the copy fails so the unparseable
		// config isn't lost entirely; the next fetch overwrites it regardless.
		slog.Error("writing invalid config copy; leaving original in place", "path", invalidPath, "error", err)
		return
	}
	slog.Warn("quarantined unparseable config for diagnostics", "path", invalidPath)
	if err := os.Remove(path); err != nil {
		slog.Error("removing unparseable config file", "path", path, "error", err)
	}
}

func migrateToNewFmt(data []byte) (*Config, error) {
	type T struct {
		ConfigResponse    json.RawMessage
		PreferredLocation C.ServerLocation
	}
	var tmp T
	if err := json.Unmarshal(data, &tmp); err != nil {
		return nil, err
	}
	opts, err := singjson.UnmarshalExtendedContext[C.ConfigResponse](box.BaseContext(), tmp.ConfigResponse)
	if err != nil {
		return nil, err
	}
	settings.Set(settings.PreferredLocationKey, &tmp.PreferredLocation)
	return &opts, nil
}

// saveConfig omits the client IP so issue-report attachments do not expose it.
func saveConfig(cfg *Config, path string) error {
	persisted := *cfg
	persisted.IP = ""
	buf, err := singjson.Marshal(&persisted)
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}
	return atomicfile.WriteFile(path, buf, fileperm.File)
}

// GetConfig returns the current configuration. It returns an error if the config is not yet available.
func (ch *ConfigHandler) GetConfig() (*Config, error) {
	cfg := ch.config.Load()
	if cfg == nil {
		return nil, fmt.Errorf("no config yet -- first run?")
	}
	return cfg, nil
}

func (ch *ConfigHandler) setConfig(cfg *Config) error {
	ch.logger.Info("Setting config")
	if cfg == nil {
		ch.logger.Warn("Config is nil, not setting")
		return nil
	}
	oldConfig, _ := ch.GetConfig()
	ch.config.Store(cfg)
	ch.logger.Debug("Saving config", "path", ch.configPath)
	saveErr := saveConfig(cfg, ch.configPath)
	if saveErr != nil {
		ch.logger.Error("saving config", "error", saveErr)
	} else {
		ch.logger.Info("saved new config")
	}
	// The config is live once stored, so subscribers hear of it even when
	// saving fails. A retry of the same config would emit nothing, since it
	// equals the stored one.
	if !ch.isClosed() {
		emit(oldConfig, cfg)
	}
	if saveErr != nil {
		return fmt.Errorf("saving config: %w", saveErr)
	}
	ch.logger.Info("Config set")
	return nil
}

// NewConfigEvent is emitted when the configuration changes.
type NewConfigEvent struct {
	events.Event
	Old *Config
	New *Config
}

func emit(old, new *Config) {
	if !reflect.DeepEqual(old, new) {
		events.Emit(NewConfigEvent{Old: old, New: new})
	}
}
