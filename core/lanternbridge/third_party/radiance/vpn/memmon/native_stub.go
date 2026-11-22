//go:build !(ios && cgo) && !android

package memmon

// readNative reports that no native footprint source is available on this
// platform. The sampler then falls back to Go runtime memory.
func readNative() (footprint, available uint64, availableSupported bool) { return 0, 0, false }
