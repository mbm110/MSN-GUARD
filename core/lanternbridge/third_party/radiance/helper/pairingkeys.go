package helper

import (
	"bytes"
	"maps"
	"slices"
	"sync"

	"github.com/getlantern/broflake/common/helperticket"
	"golang.org/x/crypto/chacha20poly1305"
)

// PairingKey is one helper pairing's K_pair and this device's side of the
// pairing. Key is a secret and must never be logged.
type PairingKey struct {
	Key  []byte `json:"key"`
	Role string `json:"role"`
}

// PairingKeys holds the K_pair of each of this device's helper pairings,
// keyed by pairing ID, in memory only. Pairing IDs must never be logged.
// The zero value is ready to use, methods on a nil PairingKeys do nothing,
// and it is safe for concurrent use.
type PairingKeys struct {
	mu       sync.Mutex
	keys     map[string]PairingKey
	set      bool
	onChange func()
}

// Set replaces every key with keys, dropping entries whose Key is not a
// chacha20poly1305 key or whose Role is neither inviter nor volunteer. It
// copies keys. Only on the first Set, which may be empty, or when the stored
// set changed does it run the change callback, synchronously and without p's
// lock held, before returning.
func (p *PairingKeys) Set(keys map[string]PairingKey) {
	if p == nil {
		return
	}
	next := make(map[string]PairingKey, len(keys))
	for id, k := range keys {
		if len(k.Key) != chacha20poly1305.KeySize || !validPairingRole(k.Role) {
			continue
		}
		next[id] = PairingKey{Key: bytes.Clone(k.Key), Role: k.Role}
	}
	p.mu.Lock()
	if p.set && maps.EqualFunc(p.keys, next, func(a, b PairingKey) bool {
		return a.Role == b.Role && bytes.Equal(a.Key, b.Key)
	}) {
		p.mu.Unlock()
		return
	}
	p.keys, p.set = next, true
	onChange := p.onChange
	p.mu.Unlock()
	if onChange != nil {
		onChange()
	}
}

func validPairingRole(role string) bool {
	return role == string(helperticket.RoleInviter) || role == string(helperticket.RoleVolunteer)
}

// Get returns a copy of the key for pairingID.
func (p *PairingKeys) Get(pairingID string) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.keys[pairingID]
	if !ok {
		return nil, false
	}
	return bytes.Clone(k.Key), true
}

// IDs returns the sorted IDs of the pairings held with role.
func (p *PairingKeys) IDs(role string) []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for id, k := range p.keys {
		if k.Role == role {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// SetOnChange sets f to run after the first Set and each Set that changes the
// stored keys. f runs synchronously on Set's goroutine and must not block.
func (p *PairingKeys) SetOnChange(f func()) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onChange = f
}
