package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchMetadataAndHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/downgrade" {
			http.Redirect(w, r, "http://example.com/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("origin response"))
	}))
	defer srv.Close()
	cert := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	t.Setenv("CURL_CA_BUNDLE", cert)
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("all_proxy", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
	dir := t.TempDir()
	require.NoError(t, fetch(context.Background(), srv.URL, "", dir, time.Second))
	data, err := os.ReadFile(filepath.Join(dir, "fetch.json"))
	require.NoError(t, err)
	var stats struct {
		Status int `json:"http_code"`
		Exit   int `json:"exitcode"`
	}
	require.NoError(t, json.Unmarshal(data, &stats))
	assert.Equal(t, 503, stats.Status)
	assert.Zero(t, stats.Exit)
	assert.Error(t, fetch(context.Background(), srv.URL, "127.0.0.1:1", t.TempDir(), time.Second), "explicit proxy must not be bypassed by NO_PROXY")
	_, err = os.Stat(filepath.Join(dir, "success"))
	require.NoError(t, err)
	dir = t.TempDir()
	require.Error(t, fetch(context.Background(), srv.URL+"/downgrade", "", dir, time.Second))
	_, err = os.Stat(filepath.Join(dir, "success"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Error(t, fetch(context.Background(), "http://example.com", "", t.TempDir(), time.Second))
}

func TestRunRejectsMissingPinnedTarget(t *testing.T) {
	t.Setenv("RADIANCE_DATA_PATH", "")
	t.Setenv("RADIANCE_LOG_PATH", "")
	t.Setenv("RADIANCE_DISABLE_FETCH_CONFIG", "")
	t.Setenv("DATA", t.TempDir())
	t.Setenv("TARGET_URL", "https://example.com")
	t.Setenv("RADIANCE_ENV", "staging")
	t.Setenv("STICKY", "true")
	t.Setenv("TARGET_TAG", "")
	t.Setenv("DIRECT", "false")
	assert.ErrorContains(t, run(t.Context()), "TARGET_TAG")
	t.Setenv("TARGET_TAG", "assigned")
	assert.ErrorContains(t, run(t.Context()), "sticky config")
}

func TestRunIsolatesClientState(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA", dir)
	t.Setenv("TARGET_URL", "https://example.com")
	t.Setenv("DIRECT", "false")
	t.Setenv("RADIANCE_ENV", "staging")
	t.Setenv("USER_ID", "")
	t.Setenv("TARGET_TAG", "assigned")
	t.Setenv("RADIANCE_DATA_PATH", dir)
	t.Setenv("RADIANCE_LOG_PATH", dir)
	t.Setenv("RADIANCE_DISABLE_FETCH_CONFIG", "true")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"pinned":true}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "servers.json"), []byte(`{"stale":true}`), 0o600))
	for _, sticky := range []string{"true", "false"} {
		t.Setenv("STICKY", sticky)
		require.ErrorContains(t, run(t.Context()), "USER_ID")
		clientDir := os.Getenv("RADIANCE_DATA_PATH")
		assert.NotEqual(t, dir, clientDir)
		assert.Equal(t, clientDir, os.Getenv("RADIANCE_LOG_PATH"))
		assert.Equal(t, sticky, os.Getenv("RADIANCE_DISABLE_FETCH_CONFIG"))
		_, err := os.Stat(filepath.Join(clientDir, "servers.json"))
		assert.ErrorIs(t, err, os.ErrNotExist)
		config, err := os.ReadFile(filepath.Join(clientDir, "config.json"))
		if sticky == "true" {
			require.NoError(t, err)
			assert.JSONEq(t, `{"pinned":true}`, string(config))
		} else {
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
	}
}

func TestInvalidRunClearsPreviousResult(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA", dir)
	names := []string{"success", "fetch.json", "connection.txt", "output.txt", "timing.txt"}
	for _, target := range []string{"", "https://example.com"} {
		for _, name := range names {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("previous run"), 0o600))
		}
		t.Setenv("TARGET_URL", target)
		t.Setenv("FETCH_TIMEOUT_SECONDS", "invalid")
		require.Error(t, run(t.Context()))
		for _, name := range names {
			_, err := os.Stat(filepath.Join(dir, name))
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
	}
}
