package lanternbridge

import (
	"fmt"
	"sync/atomic"
	"syscall"
)

// The TUN fd handoff (3.4.0) — the official-app data path for MSN's Lantern.
//
// The app process owns the Android VpnService and its Builder; the sidecar
// owns the tunnel. The app hands the established TUN's file descriptor to the
// sidecar over a private Unix socket with SCM_RIGHTS (cmd/lanternsidecar's
// handoff listener). androidPlatform.OpenTun then returns a fresh dup of the
// master for every tunnel (re)start — the same role the official app's
// gomobile OpenTun plays with VpnService.establish().
//
// Why a master + dup: sing-tun closes the descriptor it returned when a tunnel
// stops, and a tunnel restart calls OpenTun AGAIN. Handing back the raw fd of
// a previous tunnel would return a closed number; the master outlives every
// restart and each OpenTun gets its own dup.
var tunMasterFd atomic.Int64

// SetTunFd stores the app's TUN fd as the handoff master, closing any
// previous master (a new VPN session replaces the old TUN device).
func SetTunFd(fd int) {
	if old := tunMasterFd.Swap(int64(fd)); old >= 0 {
		closeFd(int(old))
	}
}

// CloseTunFd drops the master (sidecar shutdown).
func CloseTunFd() {
	if old := tunMasterFd.Swap(-1); old >= 0 {
		closeFd(int(old))
	}
}

// openTunFd returns a fresh dup of the master for one tunnel lifetime.
func openTunFd() (int, error) {
	master := int(tunMasterFd.Load())
	if master < 0 {
		return -1, fmt.Errorf("the app has not handed off the Android TUN fd yet")
	}
	dup, err := dupFd(master)
	if err != nil {
		return -1, fmt.Errorf("dup handed-off TUN fd: %w", err)
	}
	return dup, nil
}

func dupFd(fd int) (int, error) { return syscall.Dup(fd) }

func closeFd(fd int) { _ = syscall.Close(fd) }
