package ipc

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func getUid(rConn syscall.RawConn) (uid uint32, err error) {
	var cred *unix.Ucred
	cerr := rConn.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cerr != nil {
		return 0, fmt.Errorf("control: %w", cerr)
	}
	if err != nil {
		return 0, fmt.Errorf("getsockopt ucred: %w", err)
	}
	return cred.Uid, nil
}
