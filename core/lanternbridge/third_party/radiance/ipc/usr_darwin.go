package ipc

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func getUid(rConn syscall.RawConn) (uid uint32, err error) {
	var cred *unix.Xucred
	cerr := rConn.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			err = fmt.Errorf("getsockopt xucred: %w", err)
		}
	})
	if cerr != nil {
		return 0, fmt.Errorf("control: %w", cerr)
	}
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
