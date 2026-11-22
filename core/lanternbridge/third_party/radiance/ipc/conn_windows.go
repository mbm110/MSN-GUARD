package ipc

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go conn_windows.go

//sys impersonateNamedPipeClient(h windows.Handle) (err error) [int32(failretval)==0] = advapi32.ImpersonateNamedPipeClient

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const (
	pipePath = `\\.\pipe\Lantern\lantern`

	apiURL         = "http://pipe"
	connectTimeout = 10 * time.Second

	// The interactive-user ACE excludes pipe-instance creation rights.
	sddl             = `D:P(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;0x12019b;;;IU)`
	pipeClientAccess = 0x12019b
)

func dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	return winio.DialPipeAccessImpLevel(ctx, pipePath, pipeClientAccess, winio.PipeImpLevelIdentification)
}

func listen() (net.Listener, error) {
	ln, err := winio.ListenPipe(
		pipePath,
		&winio.PipeConfig{
			SecurityDescriptor: sddl,
			InputBufferSize:    256 * 1024,
			OutputBufferSize:   256 * 1024,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create named pipe listener: %w", err)
	}
	return &winioListener{ln}, nil
}

type winioConn interface {
	net.Conn
	Fd() uintptr
}

type winioListener struct {
	net.Listener
}

type winconn struct {
	winioConn
	once  sync.Once
	peer  usr
	err   error
	ready chan struct{}
}

func (c *winconn) Read(buffer []byte) (int, error) {
	n, err := c.winioConn.Read(buffer)
	if n > 0 {
		c.once.Do(func() {
			defer close(c.ready)
			token, err := getPipeClientToken(c.winioConn)
			if err != nil {
				c.err = err
				return
			}
			defer token.Close()
			c.peer, c.err = usrFromToken(token)
		})
		if c.err != nil {
			c.Close()
			return 0, c.err
		}
	}
	return n, err
}

// Accept defers client authentication until the connection has read request data.
func (l *winioListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wc, ok := c.(winioConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("expected winio.Conn, got %T", c)
	}
	return &winconn{
		winioConn: wc,
		ready:     make(chan struct{}),
	}, nil
}

func getPipeClientToken(conn winioConn) (windows.Token, error) {
	ph := windows.Handle(conn.Fd())
	if ph == 0 {
		return 0, fmt.Errorf("invalid pipe handle")
	}

	type tokenResult struct {
		token windows.Token
		err   error
	}
	results := make(chan tokenResult, 1)
	go func() {
		runtime.LockOSThread()
		if err := impersonateNamedPipeClient(ph); err != nil {
			runtime.UnlockOSThread()
			results <- tokenResult{err: fmt.Errorf("failed to impersonate client: %w", err)}
			return
		}
		var token windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			if token != 0 {
				token.Close()
			}
			results <- tokenResult{err: fmt.Errorf("failed to revert client impersonation: %w", revertErr)}
			// Exiting while locked prevents Go from reusing an impersonating OS thread.
			return
		}
		runtime.UnlockOSThread()
		results <- tokenResult{token: token, err: err}
	}()
	result := <-results
	return result.token, result.err
}

func getConnPeer(conn net.Conn) (p usr, err error) {
	wc, ok := conn.(*winconn)
	if !ok {
		return p, fmt.Errorf("expected *winconn, got %T", conn)
	}
	select {
	case <-wc.ready:
		return wc.peer, wc.err
	default:
		return p, fmt.Errorf("pipe client identity is unavailable before a request read")
	}
}

// setSocketPathForTesting is a no-op because Windows uses a fixed pipe path.
func setSocketPathForTesting(path string) {}
