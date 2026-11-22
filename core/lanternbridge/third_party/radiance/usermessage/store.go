package usermessage

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	wire "github.com/getlantern/common/usermessage"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
)

const (
	stateVersion         = 1
	maxUsers             = 16
	invalidStateFileName = "user-messages.invalid.json"
)

// ErrMessageNotPending indicates that a display ID cannot be acknowledged for the current account.
var ErrMessageNotPending = errors.New("user message is not pending")

type persistedState struct {
	Version int                   `json:"version"`
	Users   map[string]*userState `json:"users,omitempty"`
	Order   []string              `json:"order,omitempty"`
}

type userState struct {
	Seen    []string                  `json:"seen,omitempty"`
	Pending *wire.ResolvedUserMessage `json:"pending,omitempty"`
	Locale  string                    `json:"locale,omitempty"`
}

type store struct {
	mu    sync.Mutex
	path  string
	state persistedState
}

// newStore loads persisted state, falling back to clean state when stored data is unusable.
func newStore(dataDir string) (*store, error) {
	s := &store{
		path:  filepath.Join(dataDir, "user-messages.json"),
		state: newPersistedState(),
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read user-message state: %w", err)
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		s.resetInvalidState(data, "invalid_json")
		return s, nil
	}
	if s.state.Version != stateVersion {
		s.resetInvalidState(data, "unsupported_version")
		return s, nil
	}
	if s.state.Users == nil {
		s.state.Users = make(map[string]*userState)
	}
	s.sanitize()
	return s, nil
}

func newPersistedState() persistedState {
	return persistedState{
		Version: stateVersion,
		Users:   make(map[string]*userState),
	}
}

// resetInvalidState resets memory and attempts to quarantine invalid bytes before removing the active file.
func (s *store) resetInvalidState(data []byte, reason string) {
	s.state = newPersistedState()
	invalidPath := filepath.Join(filepath.Dir(s.path), invalidStateFileName)
	if err := atomicfile.WriteFile(invalidPath, data, fileperm.File); err != nil {
		slog.Warn("Could not quarantine invalid user-message state", "reason", reason, "error", err)
		return
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("Could not remove invalid user-message state", "reason", reason, "error", err)
		return
	}
	slog.Warn("Quarantined invalid user-message state", "reason", reason)
}

// seen returns a copy so callers cannot mutate persisted state without a commit.
func (s *store) seen(userID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Users[userID]
	if state == nil {
		return nil
	}
	return slices.Clone(state.Seen)
}

// current returns a copy of the pending message, clearing expired or differently targeted locale content.
func (s *store) current(userID, locale string, now time.Time) (*wire.ResolvedUserMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Users[userID]
	if state == nil || state.Pending == nil {
		return nil, nil
	}
	if state.Locale != locale || !now.Before(state.Pending.ExpiresAt) {
		next := cloneState(s.state)
		next.Users[userID].Pending = nil
		if err := s.commitLocked(next); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return cloneMessage(state.Pending), nil
}

// offer reports whether pending state changed, preserving valid content for the same requested locale.
func (s *store) offer(userID, locale string, message *wire.ResolvedUserMessage, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	state := next.Users[userID]
	stale := state != nil && state.Pending != nil &&
		(state.Locale != locale || !now.Before(state.Pending.ExpiresAt))
	if stale {
		state.Pending = nil
	}
	if message == nil || !now.Before(message.ExpiresAt) ||
		(state != nil && (slices.Contains(state.Seen, message.DisplayID) || state.Pending != nil)) {
		if stale {
			return true, s.commitLocked(next)
		}
		return false, nil
	}
	if state == nil {
		state = &userState{}
		next.Users[userID] = state
	}
	state.Pending = cloneMessage(message)
	state.Locale = locale
	touch(&next, userID)
	if err := s.commitLocked(next); err != nil {
		return false, err
	}
	return true, nil
}

// acknowledge is idempotent for seen IDs and otherwise accepts only the current unexpired pending ID.
func (s *store) acknowledge(userID, displayID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state.Users[userID]
	if state == nil {
		return ErrMessageNotPending
	}
	if slices.Contains(state.Seen, displayID) {
		return nil
	}
	if state.Pending == nil || state.Pending.DisplayID != displayID || !now.Before(state.Pending.ExpiresAt) {
		if state.Pending != nil && !now.Before(state.Pending.ExpiresAt) {
			next := cloneState(s.state)
			next.Users[userID].Pending = nil
			if err := s.commitLocked(next); err != nil {
				return err
			}
		}
		return ErrMessageNotPending
	}
	next := cloneState(s.state)
	state = next.Users[userID]
	state.Pending = nil
	state.Seen = append(state.Seen, displayID)
	if len(state.Seen) > wire.MaxSeenDisplayIDs {
		state.Seen = slices.Clone(state.Seen[len(state.Seen)-wire.MaxSeenDisplayIDs:])
	}
	touch(&next, userID)
	return s.commitLocked(next)
}

// touch moves a user to the newest position and evicts the oldest retained accounts.
func touch(state *persistedState, userID string) {
	state.Order = slices.DeleteFunc(state.Order, func(id string) bool { return id == userID })
	state.Order = append(state.Order, userID)
	for len(state.Order) > maxUsers {
		delete(state.Users, state.Order[0])
		state.Order = state.Order[1:]
	}
}

// commitLocked publishes next in memory only after its durable write succeeds. The caller holds s.mu.
func (s *store) commitLocked(next persistedState) error {
	if err := writeState(s.path, next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func writeState(path string, state persistedState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode user-message state: %w", err)
	}
	if err := atomicfile.WriteFile(path, data, fileperm.File); err != nil {
		return fmt.Errorf("write user-message state: %w", err)
	}
	return nil
}

func cloneState(state persistedState) persistedState {
	clone := persistedState{
		Version: state.Version,
		Users:   make(map[string]*userState, len(state.Users)),
		Order:   slices.Clone(state.Order),
	}
	for userID, current := range state.Users {
		clone.Users[userID] = &userState{
			Seen:    slices.Clone(current.Seen),
			Pending: cloneMessage(current.Pending),
			Locale:  current.Locale,
		}
	}
	return clone
}

func (s *store) sanitize() {
	validUsers := make(map[string]*userState, len(s.state.Users))
	for userID, state := range s.state.Users {
		if userID == "" || state == nil {
			continue
		}
		seen := make([]string, 0, min(len(state.Seen), wire.MaxSeenDisplayIDs))
		for _, id := range state.Seen {
			if validDisplayID(id) && !slices.Contains(seen, id) {
				seen = append(seen, id)
			}
		}
		if len(seen) > wire.MaxSeenDisplayIDs {
			seen = seen[len(seen)-wire.MaxSeenDisplayIDs:]
		}
		state.Seen = seen
		if state.Pending != nil && (state.Locale == "" || state.Pending.Validate() != nil) {
			state.Pending = nil
		}
		validUsers[userID] = state
	}
	s.state.Users = validUsers
	order := make([]string, 0, min(len(s.state.Order), maxUsers))
	for _, userID := range s.state.Order {
		if _, ok := validUsers[userID]; ok && !slices.Contains(order, userID) {
			order = append(order, userID)
		}
	}
	for userID := range validUsers {
		if !slices.Contains(order, userID) {
			order = append(order, userID)
		}
	}
	if len(order) > maxUsers {
		for _, userID := range order[:len(order)-maxUsers] {
			delete(validUsers, userID)
		}
		order = order[len(order)-maxUsers:]
	}
	s.state.Order = order
}

func validDisplayID(id string) bool {
	if id == "" || len(id) > wire.MaxDisplayIDLength {
		return false
	}
	for _, r := range id {
		if r > 127 || !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}

// cloneMessage gives callers ownership of the message and its optional action.
func cloneMessage(message *wire.ResolvedUserMessage) *wire.ResolvedUserMessage {
	if message == nil {
		return nil
	}
	clone := *message
	if message.Action != nil {
		action := *message.Action
		clone.Action = &action
	}
	return &clone
}
