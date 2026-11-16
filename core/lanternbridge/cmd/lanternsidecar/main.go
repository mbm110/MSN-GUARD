package main

import (
	"bufio"
	"context"
	"crypto/subtle"
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
	controlSocket := flag.String("control-socket", "127.0.0.1:0", "app-private loopback control endpoint")
	controlToken := flag.String("control-token", "", "random per-process bearer token")
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

	if err := lanternbridge.Init(*dataDir, *logDir, *socksAddress); err != nil {
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
