//go:build android

package memmon

import (
	"bytes"
	"os"
)

var vmRSSPrefix = []byte("VmRSS:")

// readNative reads the process RSS from /proc/self/status (VmRSS). Android has no
// headroom API, so availableSupported is false and the Cap comes from the static budget.
// A read/parse failure returns footprint=0 so the Sensor falls back to goBytes.
func readNative() (footprint, available uint64, availableSupported bool) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, 0, false
	}
	rss, parsed := parseStatusVmRSS(data)
	if !parsed {
		return 0, 0, false
	}
	return rss, 0, false
}

// parseStatusVmRSS extracts the resident set size in bytes from the contents of
// /proc/self/status. It reads the VmRSS line, whose value the kernel always
// reports in kibibytes, and returns value × 1024. ok is false if no VmRSS line
// is present or its value is non-numeric.
func parseStatusVmRSS(data []byte) (uint64, bool) {
	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		if !bytes.HasPrefix(line, vmRSSPrefix) {
			continue
		}
		rest := line[len(vmRSSPrefix):]
		j := 0
		for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
			j++
		}
		start := j
		var kb uint64
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			kb = kb*10 + uint64(rest[j]-'0')
			j++
		}
		if j == start {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}
