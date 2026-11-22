package unbounded

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConnSources_resolve pins the accept→close source backfill. broflake
// delivers the consumer addr on accept but a nil (empty) addr on close, so
// resolve must restore the accept's addr onto the close — otherwise the close
// event carries an empty Source and downstream consumers (the Flutter globe
// arc + the "people helped" counter) can't match it to the accept, so the
// arc orphans and the counter never decrements.
func TestConnSources_resolve(t *testing.T) {
	c := newConnSources()

	// Accept echoes its own addr and remembers it for the slot.
	assert.Equal(t, "1.2.3.4", c.resolve(1, 7, "1.2.3.4"),
		"accept returns its own source")

	// Close arrives with an empty addr (broflake's nil) — restore the
	// accept's addr so the -1 can be matched to its +1.
	assert.Equal(t, "1.2.3.4", c.resolve(-1, 7, ""),
		"close restores the accept's source")

	// The slot was freed; a stale/duplicate close has nothing to restore.
	assert.Equal(t, "", c.resolve(-1, 7, ""),
		"close after the slot is freed restores nothing")

	// Slots are tracked independently.
	c.resolve(1, 8, "5.6.7.8")
	c.resolve(1, 9, "1.1.1.1")
	assert.Equal(t, "5.6.7.8", c.resolve(-1, 8, ""), "slot 8 restores 8's addr")
	assert.Equal(t, "1.1.1.1", c.resolve(-1, 9, ""), "slot 9 unaffected by slot 8")

	// An accept with no addr (broflake couldn't surface the consumer IP)
	// stays empty through close — neither end is counted, which is correct:
	// with no source there's nothing to match or draw.
	assert.Equal(t, "", c.resolve(1, 10, ""), "accept with empty addr stays empty")
	assert.Equal(t, "", c.resolve(-1, 10, ""), "its close stays empty too")

	// A close that already carries a real addr is passed through unchanged
	// (don't clobber a good value) and still frees the slot.
	c.resolve(1, 11, "9.9.9.9")
	assert.Equal(t, "9.9.9.9", c.resolve(-1, 11, "9.9.9.9"),
		"close with a real addr is passed through")
	assert.Equal(t, "", c.resolve(-1, 11, ""), "slot 11 freed after its close")

	// Slot reuse: broflake recycles a workerIdx; a fresh accept overwrites
	// the prior addr even without an intervening close.
	c.resolve(1, 12, "2.2.2.2")
	c.resolve(1, 12, "3.3.3.3")
	assert.Equal(t, "3.3.3.3", c.resolve(-1, 12, ""),
		"reused slot restores the latest accept's addr")
}
