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
	controlSocket := flag.String("control-socket", "", "app-private Unix control socket")
	controlToken := flag.String("control-token", "", "random per-process bearer token")
	flag.Parse()

	if *dataDir == "" || *logDir == "" || *controlSocket == "" || *controlToken == "" {
		return errors.New("data-dir, log-dir, control-socket and control-token are required")
	}
	if !isLoopbackAddress(*socksAddress) {
		return errors.New("Lantern SOCKS listener must bind to loopback only")
	}
	if len(*controlSocket) > 100 {
		return errors.New("control socket path is too long for Android Unix sockets")
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if err := lanternbridge.Init(*dataDir, *logDir, *socksAddress); err != nil {
		return fmt.Errorf("initialize Radiance: %w", err)
	}
	if signalCtx.Err() != nil {
		lanternbridge.Shutdown()
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(*controlSocket), 0700); err != nil {
		lanternbridge.Shutdown()
		return fmt.Errorf("create control socket directory: %w", err)
	}
	_ = os.Remove(*controlSocket)
	listener, err := net.Listen("unix", *controlSocket)
	if err != nil {
		lanternbridge.Shutdown()
		return fmt.Errorf("listen on control socket: %w", err)
	}
	if err := os.Chmod(*controlSocket, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(*controlSocket)
		lanternbridge.Shutdown()
		return fmt.Errorf("secure control socket: %w", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveControl(listener, *controlToken)
	}()

	log.Printf("Lantern sidecar ready; SOCKS=%s control-socket=%s", *socksAddress, *controlSocket)

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
