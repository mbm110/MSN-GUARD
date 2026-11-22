package config

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/getlantern/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/log"
)

func TestSaveConfig(t *testing.T) {
	// Setup temporary directory for testing
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, internal.ConfigFileName)

	// Create a sample config to save
	expectedConfig := Config{
		// Populate with sample data
		Servers: []C.ServerLocation{
			{Country: "US", City: "New York"},
			{Country: "UK", City: "London"},
		},
	}
	// Save the config
	withIP := expectedConfig
	withIP.IP = "203.0.113.7"
	err := saveConfig(&withIP, configPath)
	require.NoError(t, err, "Should not return an error when saving config")
	assert.Equal(t, "203.0.113.7", withIP.IP, "saving must not modify the in-memory config")

	// Read the file content
	data, err := os.ReadFile(configPath)
	require.NoError(t, err, "Should be able to read the config file")

	var actualConfig Config
	err = json.Unmarshal(data, &actualConfig)
	require.NoError(t, err, "Should be able to parse the config file")

	// Verify the content matches the expected config
	assert.Equal(t, expectedConfig, actualConfig, "Saved config should match the expected config")
}

func TestLoad_DropsClientIP(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), internal.ConfigFileName)
	require.NoError(t, os.WriteFile(configPath, []byte(`{"country":"US","ip":"203.0.113.7"}`), 0o600))

	cfg, err := load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "US", cfg.Country)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "203.0.113.7")
	reloaded, err := load(configPath)
	require.NoError(t, err)
	assert.Equal(t, "US", reloaded.Country)
	assert.Empty(t, reloaded.IP)
}

func TestLoadQuarantinesUnparseableConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, internal.ConfigFileName)
	// An outbound type this build's sing-box can't decode — the shape a
	// downgrade leaves behind.
	require.NoError(t, os.WriteFile(configPath,
		[]byte(`{"options":{"outbounds":[{"tag":"x","type":"future-proto"}]}}`), 0o600))

	cfg, err := load(configPath)
	require.NoError(t, err, "unparseable config must not be a fatal error")
	assert.Nil(t, cfg, "no config should be returned for an unparseable file")

	assert.NoFileExists(t, configPath, "unparseable config.json should be moved aside")
	invalidPath := filepath.Join(tempDir, internal.ConfigInvalidFileName)
	assert.FileExists(t, invalidPath, "unparseable config should be quarantined for diagnostics")
}

func TestGetConfig(t *testing.T) {
	// Setup temporary directory for testing
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, internal.ConfigFileName)

	// Create a ConfigHandler with the mock parser
	ch := &ConfigHandler{
		configPath: configPath,
	}

	// Test case: No config set
	t.Run("NoConfigSet", func(t *testing.T) {
		_, err := ch.GetConfig()
		require.Error(t, err, "Expected error when no config is set")
		assert.Contains(t, err.Error(), "no config", "Error message should indicate nil config")
	})

	// Test case: Valid config set
	t.Run("ValidConfigSet", func(t *testing.T) {
		expectedConfig := &Config{
			Servers: []C.ServerLocation{
				{Country: "US", City: "New York"},
				{Country: "UK", City: "London"},
			},
		}

		ch.config.Store(expectedConfig)

		// Retrieve the config
		actualConfig, err := ch.GetConfig()
		require.NoError(t, err, "Should not return an error when config is set")
		assert.Equal(t, expectedConfig, actualConfig, "Retrieved config should match the expected config")
	})
}

func TestHandlerFetchConfig(t *testing.T) {
	// Setup temporary directory for testing
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, internal.ConfigFileName)

	// Mock fetcher
	mockFetcher := &MockFetcher{}

	// Create a ConfigHandler with the mock parser and fetcher
	ctx, cancel := context.WithCancel(context.Background())
	ch := &ConfigHandler{
		configPath: configPath,
		ftr:        mockFetcher,
		wgKeyPath:  filepath.Join(tempDir, "wg.key"),
		ctx:        ctx,
		cancel:     cancel,
		logger:     log.NoOpLogger(),
	}

	// Test case: No server location set
	t.Run("NoServerLocationSet", func(t *testing.T) {
		mockFetcher.response = []byte(`{
				"Servers": [
					{"Country": "US", "City": "New York"},
					{"Country": "UK", "City": "London"}
				]
		}`)

		err := ch.fetchConfig()
		require.NoError(t, err, "Should not return an error when no server location is set")
		actualConfig, err := ch.GetConfig()
		require.NoError(t, err, "Should not return an error when getting config")
		assert.Equal(t, "US", actualConfig.Servers[0].Country, "First server country should match")
		assert.Equal(t, "New York", actualConfig.Servers[0].City, "First server city should match")
	})

	// Test case: No stored config, fetch succeeds
	t.Run("NoStoredConfigFetchSuccess", func(t *testing.T) {
		mockFetcher.response = []byte(`{
				"Servers": [
					{"Country": "US", "City": "New York"},
					{"Country": "UK", "City": "London"}
				]
		}`)
		mockFetcher.err = nil

		err := ch.fetchConfig()
		require.NoError(t, err, "Should not return an error when fetch succeeds")

		actualConfig, err := ch.GetConfig()
		require.NoError(t, err, "Should not return an error when getting config")
		assert.Equal(t, "US", actualConfig.Servers[0].Country, "First server country should match")
		assert.Equal(t, "New York", actualConfig.Servers[0].City, "First server city should match")
	})

	// Test case: Fetch fails
	t.Run("FetchFails", func(t *testing.T) {
		mockFetcher.response = nil
		mockFetcher.err = errors.New("fetch error")

		err := ch.fetchConfig()
		require.Error(t, err, "Should return an error when fetch fails")
		assert.Contains(t, err.Error(), "fetch error", "Error message should contain fetch error")
	})

	// Test case: Fetch returns nil response
	t.Run("FetchReturnsNilResponse", func(t *testing.T) {
		mockFetcher.response = nil
		mockFetcher.err = nil

		err := ch.fetchConfig()
		require.NoError(t, err, "Should not return an error when fetch returns nil response")
	})

	// Test case: Config parsing fails
	t.Run("ConfigParsingFails", func(t *testing.T) {
		mockFetcher.response = []byte(`invalid json`)
		mockFetcher.err = nil

		err := ch.fetchConfig()
		require.Error(t, err, "Should return an error when config parsing fails")
		assert.Contains(t, err.Error(), "parsing config", "Error message should indicate parsing error")
	})
}

// TestFetchConfigCoalescesConcurrentRequest verifies that a fetchConfig call
// arriving while another fetch is in flight returns immediately and causes
// the in-flight fetch to re-run exactly once after it completes.
func TestFetchConfigCoalescesConcurrentRequest(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, internal.ConfigFileName)

	release := make(chan struct{})
	bf := &BlockingFetcher{
		response: []byte(`{"Servers":[{"Country":"US","City":"New York"}]}`),
		entered:  make(chan struct{}, 2),
		release:  release,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := &ConfigHandler{
		configPath: configPath,
		ftr:        bf,
		wgKeyPath:  filepath.Join(tempDir, "wg.key"),
		ctx:        ctx,
		cancel:     cancel,
		logger:     log.NoOpLogger(),
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- ch.fetchConfig() }()

	select {
	case <-bf.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first fetch never started")
	}

	require.NoError(t, ch.fetchConfig(), "concurrent call should return nil while a fetch is in flight")

	close(release)
	require.NoError(t, <-firstDone, "first fetch should complete cleanly")

	select {
	case <-bf.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("coalesced follow-up fetch never started")
	}

	assert.Equal(t, int32(2), bf.calls.Load(), "expected exactly two fetches: original + coalesced follow-up")
}

// Make sure MockFetcher implements the Fetcher interface
var _ Fetcher = (*MockFetcher)(nil)

// MockFetcher is a mock implementation of the fetcher used for testing
type MockFetcher struct {
	response []byte
	err      error
}

func (mf *MockFetcher) fetchConfig(ctx context.Context, preferred C.ServerLocation, wgPublicKey string) ([]byte, error) {
	return mf.response, mf.err
}

var _ Fetcher = (*BlockingFetcher)(nil)

// BlockingFetcher is a test Fetcher that signals entry into each fetchConfig
// call and blocks until release is closed.
type BlockingFetcher struct {
	response []byte
	err      error
	entered  chan struct{}
	release  <-chan struct{}
	calls    atomic.Int32
}

func (bf *BlockingFetcher) fetchConfig(ctx context.Context, preferred C.ServerLocation, wgPublicKey string) ([]byte, error) {
	bf.calls.Add(1)
	select {
	case bf.entered <- struct{}{}:
	default:
	}
	<-bf.release
	return bf.response, bf.err
}

func TestUserChangeSkipsConfigFetchWithoutCredentials(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	release := make(chan struct{})
	close(release)
	fetcher := &BlockingFetcher{release: release}
	ch := NewConfigHandler(context.Background(), Options{DataPath: t.TempDir(), Logger: log.NoOpLogger()})
	defer ch.cancel()
	ch.ftr = fetcher

	ch.onUserChange(account.UserChangeEvent{})
	require.Zero(t, fetcher.calls.Load())
	require.NoError(t, settings.Set(settings.UserIDKey, 123))
	ch.onUserChange(account.UserChangeEvent{})
	require.Zero(t, fetcher.calls.Load())
	require.NoError(t, settings.Set(settings.TokenKey, "test-token"))
	ch.onUserChange(account.UserChangeEvent{})
	require.EqualValues(t, 1, fetcher.calls.Load())

	a := &account.Client{}
	a.ClearUser()
	ch.onUserChange(account.UserChangeEvent{})
	require.EqualValues(t, 1, fetcher.calls.Load())
	require.Zero(t, settings.GetInt64(settings.UserIDKey))

	require.NoError(t, settings.Patch(settings.Settings{settings.UserIDKey: 456, settings.TokenKey: "new-token"}))
	ch.onUserChange(account.UserChangeEvent{})
	require.EqualValues(t, 2, fetcher.calls.Load())
}

type accountCreationTransport func(*http.Request) (*http.Response, error)

func (f accountCreationTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestInitialAccountEventDoesNotLoopConfigCreation(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	var created, fetched atomic.Int32
	client := &http.Client{Transport: accountCreationTransport(func(req *http.Request) (*http.Response, error) {
		status, body := http.StatusNoContent, ""
		switch {
		case strings.HasSuffix(req.URL.Path, "/user-create"):
			created.Add(1)
			status, body = http.StatusOK, `{"userId":123,"token":"test-token"}`
		case strings.HasSuffix(req.URL.Path, "/config-new"):
			fetched.Add(1)
		default:
			return nil, errors.New("unexpected test request")
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
	ch := NewConfigHandler(context.Background(), Options{
		DataPath: t.TempDir(), Logger: log.NoOpLogger(), HTTPClient: client,
		AccountClient: account.NewClient(client, t.TempDir(), log.NoOpLogger()),
	})
	defer ch.cancel()
	ch.Start()
	require.Eventually(t, func() bool { return fetched.Load() > 0 }, 3*time.Second, time.Millisecond)
	require.Never(t, func() bool { return created.Load() > 1 || fetched.Load() > 2 }, 100*time.Millisecond, time.Millisecond)
	require.EqualValues(t, 1, created.Load())
}

// TestSetConfig_EmitsWhenSaveFails checks that a config published but not
// saved still reaches subscribers: it is live, and a retry of the same config
// would emit nothing.
func TestSetConfig_EmitsWhenSaveFails(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions don't block writes on Windows or as root")
	}
	dataDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := NewConfigHandler(ctx, Options{DataPath: dataDir, Logger: log.NoOpLogger()})
	got := make(chan *Config, 1)
	sub := events.Subscribe(func(evt NewConfigEvent) { got <- evt.New })
	t.Cleanup(sub.Unsubscribe)

	require.NoError(t, os.Chmod(dataDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })
	cfg := &Config{Country: "IR"}
	require.Error(t, ch.setConfig(cfg), "the save fails")
	live, err := ch.GetConfig()
	require.NoError(t, err)
	assert.Same(t, cfg, live)
	select {
	case evt := <-got:
		assert.Same(t, cfg, evt)
	case <-time.After(5 * time.Second):
		t.Fatal("no NewConfigEvent for a config published but not saved")
	}
}
