//go:build android

package vpn

import "syscall"

// kernelVersion returns the Linux kernel version string (e.g. "5.15.0-android13").
// This is used on Android to decide which TUN stack to use: kernels below 5.10
// are not reliable with the system stack and fall back to gvisor instead.
// We read it directly via syscall.Uname.
func kernelVersion() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return ""
	}
	b := make([]byte, 0, len(uts.Release))
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
