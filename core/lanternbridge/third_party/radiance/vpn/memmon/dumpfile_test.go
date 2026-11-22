package memmon

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAppendDumpText(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	a := Decision{
		Reason: reasonHardPredicted,
		Snapshot: &Snapshot{
			Samples: []Sample{{
				Footprint: 46 << 20,
				Cap:       48 << 20,
				GoBytes:   30 << 20,
				Available: 2 << 20,
				GoStats:   GoStats{TotalSys: 30 << 20, HeapObjects: 20 << 20, Goroutines: 42, NumGC: 7},
				Timestamp: at,
			}},
			Levels: []LevelChange{{Timestamp: at.Add(-time.Second), From: LevelSoft, To: LevelHard, Reason: reasonHardEnter}},
		},
	}

	got := string(buildDump(nil, a, 12, 15, at, "ios", "1.2.3"))
	for _, want := range []string{
		`platform="ios"`,
		`version="1.2.3"`,
		`reason="hard_predicted"`,
		"pressure=0.9583333333333334",
		"footprint_bytes=48234496",
		"non_go_bytes=16777216",
		"routed_conns=12 dialed_conns=15",
		"samples:\n  at=1970-01-01T00:01:40Z",
		`levels:` + "\n" + `  at=1970-01-01T00:01:39Z from="soft" to="hard" reason="hard_enter"`,
	} {
		assert.Truef(t, strings.Contains(got, want), "dump missing %q:\n%s", want, got)
	}
}

func TestAppendDumpAllocFree(t *testing.T) {
	a := Decision{
		Reason: reasonHardEnter,
		Snapshot: &Snapshot{
			Samples: []Sample{{Timestamp: time.Unix(1, 0)}, {Timestamp: time.Unix(2, 0)}},
			Levels:  []LevelChange{{Timestamp: time.Unix(1, 0), Reason: reasonSoftEnter}},
		},
	}
	buf := make([]byte, 0, 4096)
	buf = buildDump(buf[:0], a, 1, 2, time.Unix(2, 0), "ios", "1.2.3")
	allocs := testing.AllocsPerRun(100, func() {
		buf = buildDump(buf[:0], a, 1, 2, time.Unix(2, 0), "ios", "1.2.3")
	})
	assert.Zero(t, allocs, "appendDump must be alloc-free after warmup")
}
