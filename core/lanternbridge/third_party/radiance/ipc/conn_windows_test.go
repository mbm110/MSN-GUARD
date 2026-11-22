package ipc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestWindowsPipeInteractiveAccess(t *testing.T) {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil {
		t.Fatalf("pipe DACL = %v, %v", acl, err)
	}
	for index := uint16(0); index < acl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.IsWellKnown(windows.WinInteractiveSid) {
			continue
		}
		if ace.Mask != pipeClientAccess {
			t.Fatalf("interactive access = %#x, client requests %#x", ace.Mask, pipeClientAccess)
		}
		// FILE_APPEND_DATA and FILE_CREATE_PIPE_INSTANCE share the same access bit.
		if ace.Mask&windows.FILE_APPEND_DATA != 0 {
			t.Fatal("interactive users can create pipe instances")
		}
		if ace.Mask&(windows.FILE_READ_DATA|windows.FILE_WRITE_DATA) != windows.FILE_READ_DATA|windows.FILE_WRITE_DATA {
			t.Fatal("interactive users cannot read and write pipe data")
		}
		return
	}
	t.Fatal("pipe DACL has no interactive-user access entry")
}

func TestWindowsPipeHTTPAuthenticatesAfterReadingAndSurvivesAnonymousClient(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	path := fmt.Sprintf(`\\.\pipe\Lantern-IPC-Test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	raw, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: `D:P(A;;GA;;;` + sid + `)`})
	if err != nil {
		t.Fatal(err)
	}
	listener := &winioListener{Listener: raw}
	type connectionKey struct{}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if _, err := getConnPeer(conn); err == nil {
				t.Error("authenticated peer before reading client data")
			}
			return context.WithValue(ctx, connectionKey{}, conn)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, err := getConnPeer(r.Context().Value(connectionKey{}).(net.Conn))
			if err != nil || peer.uid != sid {
				http.Error(w, "wrong peer", http.StatusForbidden)
				return
			}
			_, _ = io.WriteString(w, peer.uid)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { server.Close(); <-done })
	for _, level := range []winio.PipeImpLevel{winio.PipeImpLevelAnonymous, winio.PipeImpLevelIdentification} {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return winio.DialPipeAccessImpLevel(ctx, path, pipeClientAccess, level)
		}}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("http://pipe/peer")
		if level == winio.PipeImpLevelAnonymous {
			if err == nil {
				response.Body.Close()
				t.Fatal("anonymous HTTP client received a response")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || string(body) != sid {
				t.Fatalf("HTTP peer response = %d %q, %v", response.StatusCode, body, err)
			}
		}
		transport.CloseIdleConnections()
	}
}
