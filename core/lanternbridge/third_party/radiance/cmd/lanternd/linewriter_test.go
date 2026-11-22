package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type recordingSink struct{ writes []string }

func (r *recordingSink) Write(p []byte) (int, error) {
	r.writes = append(r.writes, string(p))
	return len(p), nil
}

// A pipe read can split a line, and with it a helper tag, which the
// redacting writer downstream must see whole.
func TestLineWriterPassesWholeLines(t *testing.T) {
	sink := &recordingSink{}
	lw := &lineWriter{w: sink}
	n, err := lw.Write([]byte("first line\nsecond: outbound/unbounded[helper-0123"))
	assert.NoError(t, err)
	assert.Equal(t, 49, n)
	lw.Write([]byte("456789ab]: x\nthird"))
	assert.Equal(t, []string{"first line\n", "second: outbound/unbounded[helper-0123456789ab]: x\n"}, sink.writes)
	lw.Flush()
	assert.Equal(t, "third", sink.writes[2])
	lw.Flush()
	assert.Len(t, sink.writes, 3)
}

// A line past the bound is dropped through its newline rather than passed on
// in pieces, which could split a helper tag across two writes.
func TestLineWriterDropsAnOverlongLine(t *testing.T) {
	sink := &recordingSink{}
	lw := &lineWriter{w: sink}
	long := make([]byte, maxChildLine-4)
	for i := range long {
		long[i] = 'a'
	}
	lw.Write(append([]byte("ok\n"), long...))
	lw.Write([]byte("helper-0123"))
	assert.Equal(t, []string{"ok\n", droppedLineNotice}, sink.writes)
	lw.Write([]byte("456789ab 203.0.113.7:443"))
	lw.Write([]byte(" more\nnext line\n"))
	assert.Equal(t, []string{"ok\n", droppedLineNotice, "next line\n"}, sink.writes)
	lw.Flush()
	assert.Len(t, sink.writes, 3)
}
