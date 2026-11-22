package helper

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pairingKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestPairingKeysGetReturnsACopy(t *testing.T) {
	var p PairingKeys
	in := pairingKey(1)
	p.Set(map[string]PairingKey{"a": {Key: in, Role: "inviter"}})
	in[0] = 9

	got, ok := p.Get("a")
	require.True(t, ok)
	assert.Equal(t, pairingKey(1), got, "Set copies its input")
	got[0] = 9
	again, _ := p.Get("a")
	assert.Equal(t, pairingKey(1), again, "Get returns a copy")

	_, ok = p.Get("missing")
	assert.False(t, ok)
}

func TestPairingKeysIDsFiltersByRole(t *testing.T) {
	var p PairingKeys
	p.Set(map[string]PairingKey{
		"c": {Key: pairingKey(1), Role: "inviter"},
		"a": {Key: pairingKey(2), Role: "inviter"},
		"b": {Key: pairingKey(3), Role: "volunteer"},
	})
	assert.Equal(t, []string{"a", "c"}, p.IDs("inviter"))
	assert.Equal(t, []string{"b"}, p.IDs("volunteer"))
	assert.Empty(t, p.IDs("other"))
}

func TestPairingKeysSetReplacesTheWholeSet(t *testing.T) {
	var p PairingKeys
	p.Set(map[string]PairingKey{"a": {Key: pairingKey(1), Role: "inviter"}})
	p.Set(map[string]PairingKey{"b": {Key: pairingKey(2), Role: "volunteer"}})
	_, ok := p.Get("a")
	assert.False(t, ok)
	_, ok = p.Get("b")
	assert.True(t, ok)
}

func TestPairingKeysSetDropsInvalidEntries(t *testing.T) {
	var p PairingKeys
	p.Set(map[string]PairingKey{
		"short":   {Key: make([]byte, 31), Role: "inviter"},
		"long":    {Key: make([]byte, 33), Role: "inviter"},
		"norole":  {Key: pairingKey(1)},
		"badrole": {Key: pairingKey(1), Role: "admin"},
		"ok":      {Key: pairingKey(1), Role: "volunteer"},
	})
	for _, id := range []string{"short", "long", "norole", "badrole"} {
		_, ok := p.Get(id)
		assert.False(t, ok, id)
	}
	assert.Equal(t, []string{"ok"}, p.IDs("volunteer"))
}

func TestPairingKeysOnChangeFiresOnlyOnAChange(t *testing.T) {
	var p PairingKeys
	calls := 0
	p.SetOnChange(func() { calls++ })

	keys := map[string]PairingKey{"a": {Key: pairingKey(1), Role: "inviter"}}
	p.Set(keys)
	assert.Equal(t, 1, calls)
	p.Set(map[string]PairingKey{"a": {Key: pairingKey(1), Role: "inviter"}})
	assert.Equal(t, 1, calls, "an identical set is not a change")

	p.Set(map[string]PairingKey{"a": {Key: pairingKey(2), Role: "inviter"}})
	assert.Equal(t, 2, calls, "a new key")
	p.Set(map[string]PairingKey{"a": {Key: pairingKey(2), Role: "volunteer"}})
	assert.Equal(t, 3, calls, "a new role")
	p.Set(map[string]PairingKey{
		"a":   {Key: pairingKey(2), Role: "volunteer"},
		"bad": {Key: pairingKey(2)[:5], Role: "volunteer"},
	})
	assert.Equal(t, 3, calls, "dropped entries are not a change")
	p.Set(nil)
	assert.Equal(t, 4, calls, "clearing")
	p.Set(map[string]PairingKey{})
	assert.Equal(t, 4, calls)
}

func TestPairingKeysOnChangeFiresOnTheFirstSetEvenIfEmpty(t *testing.T) {
	var p PairingKeys
	calls := 0
	p.SetOnChange(func() { calls++ })
	p.Set(nil)
	assert.Equal(t, 1, calls, "the first set is authoritative")
	p.Set(map[string]PairingKey{})
	assert.Equal(t, 1, calls)
}

func TestPairingKeysOnChangeRunsWithoutTheLock(t *testing.T) {
	var p PairingKeys
	var ids []string
	p.SetOnChange(func() { ids = p.IDs("inviter") })
	p.Set(map[string]PairingKey{"a": {Key: pairingKey(1), Role: "inviter"}})
	assert.Equal(t, []string{"a"}, ids)
}

func TestPairingKeysNilIsSafe(t *testing.T) {
	var p *PairingKeys
	p.Set(map[string]PairingKey{"a": {Key: pairingKey(1), Role: "inviter"}})
	p.SetOnChange(func() {})
	_, ok := p.Get("a")
	assert.False(t, ok)
	assert.Empty(t, p.IDs("inviter"))
}
