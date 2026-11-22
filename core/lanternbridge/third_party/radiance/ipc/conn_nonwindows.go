//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
)

const apiURL = "http://lantern"

func dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath())
}

type sockListener struct {
	net.Listener
	path string
}

func listen() (net.Listener, error) {
	path := socketPath()
	os.Remove(path)

	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: path,
		Net:  "unix",
	})
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	if err := setPermissions(); err != nil {
		listener.Close()
		return nil, fmt.Errorf("update socket permissions: %w", err)
	}
	socket := &sockListener{
		Listener: listener,
		path:     path,
	}
	// ensure listener is closed
	runtime.AddCleanup(socket, func(ll *net.UnixListener) {
		ll.Close()
	}, listener)
	return socket, nil
}

func (l *sockListener) Close() error {
	err := l.Listener.Close()
	os.Remove(l.path)
	return err
}

func getConnPeer(conn net.Conn) (p usr, err error) {
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return p, fmt.Errorf("not a unix domain socket connection")
	}
	rawConn, err := uconn.SyscallConn()
	if err != nil {
		return p, fmt.Errorf("syscall conn: %w", err)
	}

	uid, err := getUid(rawConn)
	if err != nil {
		return p, fmt.Errorf("get uid: %w", err)
	}
	if uid == 0 {
		return usr{
			uid:     "0",
			uname:   "root",
			isAdmin: true,
		}, nil
	}

	uidStr := strconv.FormatUint(uint64(uid), 10)
	u, err := user.LookupId(uidStr)
	if err != nil {
		return p, fmt.Errorf("lookup user id %v: %w", uid, err)
	}
	return usr{
		uid:     uidStr,
		uname:   u.Username,
		isAdmin: canSudo(u.Username),
	}, nil
}
