package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"
	"sync"

	lbA "github.com/getlantern/lantern-box/adapter"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
)

// reverseFriendsFileName is kept out of issue reports: it pairs friends with
// (hashed) pairing IDs.
const reverseFriendsFileName = "reverse-friends.json"

// reverseFriends is the friends the reverse client has published a reverse
// outbound for, kept across VPN sessions and launches until their pairing
// ends, so a selection of one stands while its outbound is down. The zero
// value holds nothing and saves nothing; a nil *reverseFriends holds nothing.
// It is safe for concurrent use.
type reverseFriends struct {
	path string

	mu sync.Mutex
	// byPairing maps a pairing ID's hash to the friend's helper tag. Only the
	// hash is stored, since pairing IDs never leave memory.
	byPairing map[string]string
	// tags is the client's latest pairing ID to helper tag map. Not saved.
	tags map[string]string
}

// loadReverseFriends reads the set saved at path. A missing or unreadable
// file is an empty set.
func loadReverseFriends(path string) *reverseFriends {
	f := &reverseFriends{path: path, byPairing: map[string]string{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("Could not read the reverse friends", "error", err)
		}
		return f
	}
	var saved map[string]string
	if err := json.Unmarshal(data, &saved); err != nil {
		slog.Warn("Could not parse the reverse friends", "error", err)
		return f
	}
	for h, friend := range saved {
		if lbA.IsHelperTag(friend) {
			f.byPairing[h] = friend
		}
	}
	// A file saved before it took fileperm.File may be unreadable to the
	// other process sharing the data dir, such as the app when the root
	// network extension saved it on macOS. Saving it again replaces it with
	// one in the right mode. Only a regular file is replaced: the rename
	// replaces a link itself, but a link's target is left alone.
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() &&
		info.Mode().Perm() != fileperm.File && runtime.GOOS != "windows" {
		f.saveLocked()
	}
	return f
}

func pairingHash(pairingID string) string {
	sum := sha256.Sum256([]byte(pairingID))
	return hex.EncodeToString(sum[:])
}

// setTags takes the reverse client's pairing ID to helper tag map.
func (f *reverseFriends) setTags(tags map[string]string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags = maps.Clone(tags)
}

// record adds the friend of each reverse tag whose pairing the client's tags
// name and pairingIDs() still lists. pairingIDs is read under the lock prune
// takes, so a pairing revoked after its tags were taken is not recorded again.
func (f *reverseFriends) record(reverseTags []string, pairingIDs func() []string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := pairingIDs()
	changed := false
	for id, friend := range f.tags {
		if !slices.Contains(reverseTags, lbA.ReverseHelperTag(friend)) || !slices.Contains(ids, id) {
			continue
		}
		h := pairingHash(id)
		if f.byPairing[h] != friend {
			if f.byPairing == nil {
				f.byPairing = map[string]string{}
			}
			f.byPairing[h] = friend
			changed = true
		}
	}
	if changed {
		f.saveLocked()
	}
}

// prune drops every friend whose pairing is not in pairingIDs() and reports
// whether any was dropped. pairingIDs is read under the lock record takes, so
// a friend recorded for a pairing it does not yet list is never dropped.
func (f *reverseFriends) prune(pairingIDs func() []string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := pairingIDs()
	keep := make(map[string]bool, len(ids))
	for _, id := range ids {
		keep[pairingHash(id)] = true
	}
	n := len(f.byPairing)
	maps.DeleteFunc(f.byPairing, func(h, _ string) bool { return !keep[h] })
	if len(f.byPairing) == n {
		return false
	}
	f.saveLocked()
	return true
}

func (f *reverseFriends) has(friend string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, known := range f.byPairing {
		if known == friend {
			return true
		}
	}
	return false
}

// friends returns the friends held, unsorted and possibly repeated.
func (f *reverseFriends) friends() []string {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Collect(maps.Values(f.byPairing))
}

func (f *reverseFriends) saveLocked() {
	if f.path == "" {
		return
	}
	data, err := json.Marshal(f.byPairing)
	if err == nil {
		// fileperm.File, not Private: on macOS the app and the root network
		// extension both read it from the shared data dir.
		err = atomicfile.WriteFile(f.path, data, fileperm.File)
	}
	if err != nil {
		slog.Warn("Could not save the reverse friends", "error", err)
	}
}
