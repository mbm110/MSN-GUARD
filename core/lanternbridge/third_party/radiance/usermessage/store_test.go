package usermessage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	wire "github.com/getlantern/common/usermessage"
)

func TestStorePersistsPendingAndSeenByUser(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	state, err := newStore(dir)
	require.NoError(t, err)
	requireOffer(t, state, "1", testMessage("display-1", now.Add(time.Hour)), now)
	requireOffer(t, state, "2", testMessage("display-2", now.Add(time.Hour)), now)

	reloaded, err := newStore(dir)
	require.NoError(t, err)
	message, err := reloaded.current("1", "en-US", now)
	require.NoError(t, err)
	require.Equal(t, "display-1", message.DisplayID)
	require.NoError(t, reloaded.acknowledge("1", "display-1", now))
	require.NoError(t, reloaded.acknowledge("1", "display-1", now))
	require.Equal(t, []string{"display-1"}, reloaded.seen("1"))
	require.Empty(t, reloaded.seen("2"))

	reloadedAgain, err := newStore(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"display-1"}, reloadedAgain.seen("1"))
	message, err = reloadedAgain.current("1", "en-US", now)
	require.NoError(t, err)
	require.Nil(t, message)
}

func TestStoreBoundsSeenIDsAndExpiresPending(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	state, err := newStore(t.TempDir())
	require.NoError(t, err)
	for i := 0; i < wire.MaxSeenDisplayIDs+3; i++ {
		id := fmt.Sprintf("display-%d", i)
		requireOffer(t, state, "1", testMessage(id, now.Add(time.Hour)), now)
		require.NoError(t, state.acknowledge("1", id, now))
	}
	seen := state.seen("1")
	require.Len(t, seen, wire.MaxSeenDisplayIDs)
	require.Equal(t, "display-3", seen[0])

	requireOffer(t, state, "1", testMessage("expiring", now.Add(time.Minute)), now)
	message, err := state.current("1", "en-US", now.Add(time.Minute))
	require.NoError(t, err)
	require.Nil(t, message)
	require.ErrorIs(t, state.acknowledge("1", "expiring", now.Add(time.Minute)), ErrMessageNotPending)
}

func TestStoreDoesNotReplaceUnacknowledgedMessage(t *testing.T) {
	now := time.Now()
	state, err := newStore(t.TempDir())
	require.NoError(t, err)
	require.True(t, requireOffer(t, state, "1", testMessage("first", now.Add(time.Hour)), now))
	require.False(t, requireOffer(t, state, "1", testMessage("second", now.Add(time.Hour)), now))
	message, err := state.current("1", "en-US", now)
	require.NoError(t, err)
	require.Equal(t, "first", message.DisplayID)
	require.ErrorIs(t, state.acknowledge("1", "second", now), ErrMessageNotPending)
}

func TestStoreReconcilesRequestedLocaleAndPreservesSeenIDs(t *testing.T) {
	now := time.Now()
	state, err := newStore(t.TempDir())
	require.NoError(t, err)
	requireOffer(t, state, "1", testMessage("seen", now.Add(time.Hour)), now)
	require.NoError(t, state.acknowledge("1", "seen", now))
	requireOffer(t, state, "1", testMessage("pending", now.Add(time.Hour)), now)

	reloaded, err := newStore(filepath.Dir(state.path))
	require.NoError(t, err)
	current, err := reloaded.current("1", "fa-IR", now)
	require.NoError(t, err)
	require.Nil(t, current)
	require.Equal(t, []string{"seen"}, reloaded.seen("1"))

	message := testMessage("pending", now.Add(time.Hour))
	message.Locale = "en-US"
	changed, err := reloaded.offer("1", "fa-IR", message, now)
	require.NoError(t, err)
	require.True(t, changed)
	current, err = reloaded.current("1", "fa-IR", now)
	require.NoError(t, err)
	require.NotNil(t, current)
	changed, err = reloaded.offer("1", "de-DE", nil, now)
	require.NoError(t, err)
	require.True(t, changed)
	current, err = reloaded.current("1", "de-DE", now)
	require.NoError(t, err)
	require.Nil(t, current)
}

func TestStoreSanitizesInvalidPersistedSeenIDs(t *testing.T) {
	dir := t.TempDir()
	state, err := newStore(dir)
	require.NoError(t, err)
	state.state.Users["1"] = &userState{Seen: []string{"valid-id", "invalid id", "valid-id"}}
	state.state.Order = []string{"1"}
	require.NoError(t, writeState(state.path, state.state))

	reloaded, err := newStore(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"valid-id"}, reloaded.seen("1"))
}

func TestStoreQuarantinesInvalidPersistedState(t *testing.T) {
	tests := map[string][]byte{
		"invalid JSON":        []byte("not-json"),
		"unsupported version": []byte(`{"version":2,"users":{"1":{"seen":["display-1"]}}}`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "user-messages.json")
			require.NoError(t, os.WriteFile(path, data, 0o600))

			state, err := newStore(dir)
			require.NoError(t, err)
			require.Empty(t, state.state.Users)
			require.NoFileExists(t, path)
			quarantined, err := os.ReadFile(filepath.Join(dir, invalidStateFileName))
			require.NoError(t, err)
			require.Equal(t, data, quarantined)

			now := time.Now()
			requireOffer(t, state, "1", testMessage("display-2", now.Add(time.Hour)), now)
			require.FileExists(t, path)
		})
	}
}

func TestStoreTouchesExistingUserWhenAcceptingMessage(t *testing.T) {
	now := time.Now()
	state, err := newStore(t.TempDir())
	require.NoError(t, err)
	requireOffer(t, state, "1", testMessage("display-1", now.Add(time.Hour)), now)
	require.NoError(t, state.acknowledge("1", "display-1", now))
	requireOffer(t, state, "2", testMessage("display-2", now.Add(time.Hour)), now)
	require.NoError(t, state.acknowledge("2", "display-2", now))
	require.Equal(t, []string{"1", "2"}, state.state.Order)

	requireOffer(t, state, "1", testMessage("display-3", now.Add(time.Hour)), now)
	require.Equal(t, []string{"2", "1"}, state.state.Order)
}

func TestStoreKeepsPendingWhenAcknowledgmentWriteFails(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	state, err := newStore(dir)
	require.NoError(t, err)
	requireOffer(t, state, "1", testMessage("display-1", now.Add(time.Hour)), now)

	validPath := state.path
	state.path = dir
	require.Error(t, state.acknowledge("1", "display-1", now))
	state.path = validPath
	message, err := state.current("1", "en-US", now)
	require.NoError(t, err)
	require.Equal(t, "display-1", message.DisplayID)
	require.Empty(t, state.seen("1"))
}

func requireOffer(t *testing.T, state *store, userID string, message *wire.ResolvedUserMessage, now time.Time) bool {
	t.Helper()
	accepted, err := state.offer(userID, "en-US", message, now)
	require.NoError(t, err)
	return accepted
}
