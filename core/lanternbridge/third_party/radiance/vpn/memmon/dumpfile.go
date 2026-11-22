package memmon

import (
	"path/filepath"
	"strconv"
	"time"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/internal"
)

// dumpWriter assembles and writes the single-slot dump. The buffer is reused across writes so the
// encode step allocates nothing after warmup.
type dumpWriter struct {
	path     string
	platform string
	version  string
	buf      []byte
}

func newDumpWriter(dir, platform, version string) *dumpWriter {
	return &dumpWriter{
		path:     filepath.Join(dir, internal.MemoryDumpFileName),
		platform: platform,
		version:  version,
		buf:      make([]byte, 0, 4096),
	}
}

// write assembles the dump from the Decision's Snapshot plus the connection counts and writes it
// atomically. The caller guarantees a.Snapshot is non-nil.
func (d *dumpWriter) write(a Decision, routed, dialed int, now time.Time) error {
	d.buf = buildDump(d.buf[:0], a, routed, dialed, now, d.platform, d.version)
	return atomicfile.WriteFile(d.path, d.buf, fileperm.File)
}

func buildDump(buf []byte, a Decision, routed, dialed int, now time.Time, platform, version string) []byte {
	last := lastSample(a.Snapshot)
	var samples []Sample
	var levels []LevelChange
	if a.Snapshot != nil {
		samples = a.Snapshot.Samples
		levels = a.Snapshot.Levels
	}
	nonGo := uint64(0)
	if last.Footprint > last.GoBytes {
		nonGo = last.Footprint - last.GoBytes
	}

	b := append(buf, "ts="...)
	b = now.AppendFormat(b, time.RFC3339Nano)
	b = appendKVStr(b, " platform", platform)
	b = appendKVStr(b, " version", version)
	b = appendKVStr(b, " reason", a.Reason)
	b = append(b, '\n')

	b = appendKVFloat(b, "pressure", last.PressureRatio())
	b = appendKVU64(b, " footprint_bytes", last.Footprint)
	b = appendKVU64(b, " avail_bytes", last.Available)
	b = appendKVU64(b, " go_bytes", last.GoBytes)
	b = appendKVU64(b, " non_go_bytes", nonGo)
	b = appendKVBool(b, " has_native_footprint", last.HasNativeFootprint)
	b = append(b, '\n')

	b = append(b, "go"...)
	b = appendKVU64(b, ".total_sys", last.GoStats.TotalSys)
	b = appendKVU64(b, " heap_objects", last.GoStats.HeapObjects)
	b = appendKVU64(b, " heap_released", last.GoStats.HeapReleased)
	b = appendKVU64(b, " stacks", last.GoStats.Stacks)
	b = appendKVU64(b, " goroutines", last.GoStats.Goroutines)
	b = appendKVU64(b, " num_gc", last.GoStats.NumGC)
	b = appendKVInt(b, " routed_conns", routed)
	b = appendKVInt(b, " dialed_conns", dialed)
	b = append(b, '\n')

	b = append(b, "samples:\n"...)
	for _, s := range samples {
		b = append(b, "  at="...)
		b = s.Timestamp.AppendFormat(b, time.RFC3339Nano)
		b = appendKVFloat(b, " pressure", s.PressureRatio())
		b = appendKVU64(b, " footprint", s.Footprint)
		b = appendKVU64(b, " cap", s.Cap)
		b = appendKVU64(b, " go_bytes", s.GoBytes)
		b = appendKVU64(b, " avail", s.Available)
		b = append(b, '\n')
	}

	b = append(b, "levels:\n"...)
	for _, l := range levels {
		b = append(b, "  at="...)
		b = l.Timestamp.AppendFormat(b, time.RFC3339Nano)
		b = appendKVStr(b, " from", l.From.String())
		b = appendKVStr(b, " to", l.To.String())
		b = appendKVStr(b, " reason", l.Reason)
		b = append(b, '\n')
	}
	return b
}

func lastSample(s *Snapshot) Sample {
	if s == nil || len(s.Samples) == 0 {
		return Sample{}
	}
	return s.Samples[len(s.Samples)-1]
}

func appendKVStr(b []byte, k, v string) []byte {
	b = append(b, k...)
	b = append(b, '=')
	return strconv.AppendQuote(b, v)
}

func appendKVU64(b []byte, k string, v uint64) []byte {
	b = append(b, k...)
	b = append(b, '=')
	return strconv.AppendUint(b, v, 10)
}

func appendKVInt(b []byte, k string, v int) []byte {
	b = append(b, k...)
	b = append(b, '=')
	return strconv.AppendInt(b, int64(v), 10)
}

func appendKVFloat(b []byte, k string, v float64) []byte {
	b = append(b, k...)
	b = append(b, '=')
	return strconv.AppendFloat(b, v, 'g', -1, 64)
}

func appendKVBool(b []byte, k string, v bool) []byte {
	b = append(b, k...)
	b = append(b, '=')
	return strconv.AppendBool(b, v)
}
