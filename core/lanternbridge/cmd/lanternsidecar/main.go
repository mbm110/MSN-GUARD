package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mbm110/msn-guard/lanternbridge"
)

type controlRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Token  string          `json:"token"`
	Body   json.RawMessage `json:"body,omitempty"`
}

type controlResponse struct {
	OK     bool   `json:"ok"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	Tx     int64  `json:"tx,omitempty"`
	Rx     int64  `json:"rx,omitempty"`
	// Data carries endpoint-specific payloads (e.g. the server list) as JSON.
	Data json.RawMessage `json:"data,omitempty"`
}

func main() {
	if err := run(); err != nil {
		log.Printf("lantern sidecar stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	dataDir := flag.String("data-dir", "", "private Radiance data directory")
	logDir := flag.String("log-dir", "", "private Radiance log directory")
	socksAddress := flag.String("socks-address", "127.0.0.1:1831", "loopback mixed SOCKS/HTTP listener")
	controlSocket := flag.String("control-socket", "127.0.0.1:1832", "app-private loopback control endpoint")
	controlToken := flag.String("control-token", "", "random per-process bearer token")
	// The device locale, forwarded by the service. Empty falls back to
	// Radiance's own detection exactly like the reference app.
	locale := flag.String("locale", "", "device locale, e.g. fa-IR; drives Radiance's DNS choice")
	flag.Parse()

	if *dataDir == "" || *logDir == "" || *controlSocket == "" || *controlToken == "" {
		return errors.New("data-dir, log-dir, control-socket and control-token are required")
	}
	if !isLoopbackAddress(*socksAddress) {
		return errors.New("Lantern SOCKS listener must bind to loopback only")
	}
	controlNetwork := "unix"
	controlAddress := *controlSocket
	abstract := strings.HasPrefix(controlAddress, "@")
	if abstract {
		controlAddress = "\x00" + strings.TrimPrefix(controlAddress, "@")
	} else if strings.Contains(controlAddress, ":") {
		if !isLoopbackAddress(controlAddress) {
			return errors.New("Lantern control listener must bind to loopback only")
		}
		controlNetwork = "tcp"
	}
	if controlNetwork == "unix" && !abstract && len(controlAddress) > 100 {
		return errors.New("control socket path is too long for Android Unix sockets")
	}
	if controlNetwork == "tcp" {
		abstract = false
	}
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	// Publish the private control socket before Radiance initialization. NewLocalBackend
	// may load settings and start its first network prewarm; Android must still be
	// able to query /health and receive the real initialization error.
	if controlNetwork == "unix" && !abstract {
		if err := os.MkdirAll(filepath.Dir(*controlSocket), 0700); err != nil {
			return fmt.Errorf("create control socket directory: %w", err)
		}
		_ = os.Remove(*controlSocket)
	}
	listener, err := net.Listen(controlNetwork, controlAddress)
	if err != nil {
		return fmt.Errorf("listen on control socket: %w", err)
	}
	if controlNetwork == "unix" && !abstract {
		if err := os.Chmod(*controlSocket, 0600); err != nil {
			_ = listener.Close()
			_ = os.Remove(*controlSocket)
			return fmt.Errorf("secure control socket: %w", err)
		}
	}
	if controlNetwork == "tcp" {
		// The loopback listener is private to the app UID on Android. The
		// bearer token remains mandatory, and the actual selected port is
		// reported so Java can follow an ephemeral port without collisions.
		if addr, ok := listener.Addr().(*net.TCPAddr); ok {
			// Machine-readable marker consumed by LanternEngine before the
			// first health request. The port is otherwise unknowable when :0
			// is used and the old client repeatedly connected to port 0.
			log.Printf("LANTERN_CONTROL_PORT=%d", addr.Port)
		}
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveControl(listener, *controlToken)
	}()
	log.Printf("Lantern sidecar control socket ready; SOCKS=%s control-socket=%s", *socksAddress, listener.Addr().String())

	// TUN fd handoff (3.4.0): the app owns the VpnService and hands the
	// established TUN fd to this process over a private Unix socket with
	// SCM_RIGHTS — the split-process twin of the official app's gomobile
	// OpenTun. LanternEngine connects and sends the fd BEFORE /connect; the
	// box's OpenTun then serves a fresh dup of the master per tunnel.
	handoffPath := filepath.Join(*dataDir, "tun-handoff.sock")
	handoffErr := make(chan error, 1)
	go func() {
		handoffErr <- serveTunHandoff(handoffPath)
	}()

	if err := lanternbridge.Init(*dataDir, *logDir, *socksAddress, *locale); err != nil {
		_ = listener.Close()
		_ = os.Remove(*controlSocket)
		return fmt.Errorf("initialize Radiance: %w", err)
	}
	if signalCtx.Err() != nil {
		lanternbridge.Shutdown()
		_ = listener.Close()
		_ = os.Remove(*controlSocket)
		return nil
	}

	select {
	case <-signalCtx.Done():
		log.Printf("shutdown signal received")
	case err := <-serverErr:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			lanternbridge.CancelConnect()
			_ = listener.Close()
			_ = os.Remove(*controlSocket)
			lanternbridge.Shutdown()
			return fmt.Errorf("control socket: %w", err)
		}
	}

	lanternbridge.CancelConnect()
	_ = listener.Close()
	_ = os.Remove(*controlSocket)
	lanternbridge.Shutdown()
	return nil
}

func serveControl(listener net.Listener, token string) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleControl(conn, token)
	}
}

// serveTunHandoff relays engine→app TUN requests — the reference openTun
// semantics across the process boundary (3.4.4). The socket lives in the
// sidecar's private data dir (0600, app UID), so only the app itself can
// reach it. The app connects once per sidecar lifetime and waits; when the
// engine starts (or restarts) a tunnel, OpenTun serializes its own TunOptions
// into an OPEN line, the relay forwards it to the app, the app mirrors the
// reference's createVPNBuilder(tunOptions), establish()es and returns the fd
// via SCM_RIGHTS; the relay passes it back to the blocked OpenTun call.
func serveTunHandoff(path string) error {
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on tun handoff socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("secure tun handoff socket: %w", err)
	}
	log.Printf("LANTERN_TUN_HANDOFF=%s", path)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		relayTunHandoff(conn)
	}
}

// relayTunHandoff serves one app connection for its whole lifetime: each
// engine OPEN request becomes one OPEN line out and one reply (fd or error)
// in. A dead app connection fails only the request in flight; the accept loop
// takes the app's next connection (it reconnects on its next connect cycle).
func relayTunHandoff(conn net.Conn) {
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	for {
		req, ok := lanternbridge.PullTunRequest(24 * time.Hour)
		if !ok {
			continue // nothing to serve yet; keep waiting
		}
		fd, err := relayOneTunRequest(unixConn, req.Payload)
		req.Reply(fd, err)
		if err != nil {
			log.Printf("tun handoff relay: connection failed: %v", err)
			return
		}
		log.Printf("tun handoff relay: app returned fd=%d", fd)
	}
}

// relayOneTunRequest sends one OPEN line and reads the app's reply. The app's
// reply line and its SCM_RIGHTS descriptor arrive in ONE unix message, so the
// reply is read raw with ReadMsgUnix — a bufio.Reader would swallow the
// control data (the 3.4.4 note: never buffer a message that carries an fd).
func relayOneTunRequest(unixConn *net.UnixConn, payload []byte) (int, error) {
	_ = unixConn.SetDeadline(time.Now().Add(120 * time.Second))
	if _, err := fmt.Fprintf(unixConn, "OPEN %s\n", payload); err != nil {
		return -1, fmt.Errorf("send OPEN to the app: %w", err)
	}
	buf := make([]byte, 256)
	oob := make([]byte, 128)
	n, oobn, _, _, err := unixConn.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, fmt.Errorf("read the app's reply: %w", err)
	}
	text := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(text, "OK ") {
		return -1, fmt.Errorf("app rejected the TUN request: %s", strings.TrimPrefix(text, "ERR "))
	}
	if oobn == 0 {
		return -1, fmt.Errorf("the app's reply carried no descriptor")
	}
	messages, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse the app's control message: %w", err)
	}
	var fds []int
	for _, msg := range messages {
		if msg.Header.Level == syscall.SOL_SOCKET && msg.Header.Type == syscall.SCM_RIGHTS {
			// An SCM_RIGHTS payload is a packed array of native-endian int32
			// descriptors; Android ABIs are little-endian. Stdlib syscall has
			// ParseSocketControlMessage but not ParseRights (that one lives
			// in x/sys), so unpack the rights directly.
			for off := 0; off+4 <= len(msg.Data); off += 4 {
				fds = append(fds, int(binary.LittleEndian.Uint32(msg.Data[off:])))
			}
		}
	}
	if len(fds) == 0 {
		return -1, fmt.Errorf("the app's reply carried no SCM_RIGHTS descriptor")
	}
	fd := fds[0]
	for _, extra := range fds[1:] {
		_ = syscall.Close(extra)
	}
	return fd, nil
}

func handleControl(conn net.Conn, token string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(310 * time.Second))

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		_ = writeControl(conn, controlResponse{OK: false, Error: "invalid request"})
		return
	}
	var request controlRequest
	if err := json.Unmarshal(line, &request); err != nil {
		_ = writeControl(conn, controlResponse{OK: false, Error: "invalid JSON"})
		return
	}
	if request.Token == "" || subtle.ConstantTimeCompare([]byte(request.Token), []byte(token)) != 1 {
		_ = writeControl(conn, controlResponse{OK: false, Error: "unauthorized"})
		return
	}

	switch {
	case request.Method == "GET" && request.Path == "/health":
		// Control readiness is deliberately independent from Lantern's network
		// prewarm/config fetch. MLM's proven wrapper starts the core, publishes
		// its local listeners, then tests the data path separately. Returning
		// false here while Radiance is fetching config made Android abort at the
		// 10-second control deadline and never reach /connect.
		_ = writeControl(conn, controlResponse{OK: true, Status: "ready"})

	case request.Method == "POST" && request.Path == "/connect":
		timeoutSeconds := int64(180)
		var body struct {
			TimeoutSeconds int64 `json:"timeout_seconds"`
		}
		if len(request.Body) > 0 {
			_ = json.Unmarshal(request.Body, &body)
		}
		if body.TimeoutSeconds > 0 {
			timeoutSeconds = body.TimeoutSeconds
		}
		if err := lanternbridge.Connect(timeoutSeconds); err != nil {
			_ = writeControl(conn, controlResponse{
				OK: false, Status: lanternbridge.Status(), Error: err.Error(),
			})
			return
		}
		_ = writeControl(conn, controlResponse{OK: true, Status: lanternbridge.Status()})

	case request.Method == "POST" && request.Path == "/cancel":
		lanternbridge.CancelConnect()
		_ = writeControl(conn, controlResponse{OK: true, Status: lanternbridge.Status()})

	case request.Method == "POST" && request.Path == "/disconnect":
		if err := lanternbridge.Disconnect(); err != nil {
			_ = writeControl(conn, controlResponse{
				OK: false, Status: lanternbridge.Status(), Error: err.Error(),
			})
			return
		}
		_ = writeControl(conn, controlResponse{OK: true, Status: lanternbridge.Status()})

	case request.Method == "GET" && request.Path == "/status":
		status := lanternbridge.Status()
		_ = writeControl(conn, controlResponse{
			OK: status == "connected", Status: status, Error: lanternbridge.LastError(),
		})

	case request.Method == "GET" && request.Path == "/traffic":
		var totals struct {
			Tx int64 `json:"tx"`
			Rx int64 `json:"rx"`
		}
		_ = json.Unmarshal([]byte(lanternbridge.TrafficJSON()), &totals)
		_ = writeControl(conn, controlResponse{OK: true, Tx: totals.Tx, Rx: totals.Rx})

	case request.Method == "GET" && request.Path == "/servers":
		_ = writeControl(conn, controlResponse{
			OK:     true,
			Status: lanternbridge.Status(),
			Data:   json.RawMessage(lanternbridge.ServersJSON()),
		})

	case request.Method == "POST" && request.Path == "/select":
		var body struct {
			Tag string `json:"tag"`
		}
		if len(request.Body) > 0 {
			_ = json.Unmarshal(request.Body, &body)
		}
		if err := lanternbridge.SelectServer(body.Tag); err != nil {
			_ = writeControl(conn, controlResponse{
				OK: false, Status: lanternbridge.Status(), Error: err.Error(),
			})
			return
		}
		_ = writeControl(conn, controlResponse{
			OK:     true,
			Status: lanternbridge.Status(),
			Data:   json.RawMessage(lanternbridge.ServersJSON()),
		})

	case request.Method == "POST" && request.Path == "/ping":
		// Blocking probe of every server (up to ~60s); the connection deadline
		// above already covers it.
		if err := lanternbridge.PingServers(); err != nil {
			_ = writeControl(conn, controlResponse{
				OK: false, Status: lanternbridge.Status(), Error: err.Error(),
			})
			return
		}
		_ = writeControl(conn, controlResponse{
			OK:     true,
			Status: lanternbridge.Status(),
			Data:   json.RawMessage(lanternbridge.ServersJSON()),
		})

	default:
		_ = writeControl(conn, controlResponse{OK: false, Error: "unknown control request"})
	}
}

func writeControl(conn net.Conn, response controlResponse) error {
	encoder := json.NewEncoder(conn)
	return encoder.Encode(response)
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
