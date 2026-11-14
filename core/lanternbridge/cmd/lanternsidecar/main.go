package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mbm110/msn-guard/lanternbridge"
)

type apiResponse struct {
	OK     bool   `json:"ok"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
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
	controlAddress := flag.String("control-address", "127.0.0.1:1832", "loopback control API")
	controlToken := flag.String("control-token", "", "random per-process bearer token")
	flag.Parse()

	if *dataDir == "" || *logDir == "" || *controlToken == "" {
		return errors.New("data-dir, log-dir and control-token are required")
	}
	if !isLoopbackAddress(*controlAddress) || !isLoopbackAddress(*socksAddress) {
		return errors.New("Lantern SOCKS and control listeners must bind to loopback only")
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

	mux := http.NewServeMux()
	authorized := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(*controlToken)) != 1 {
				writeJSON(w, http.StatusUnauthorized, apiResponse{OK: false, Error: "unauthorized"})
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/health", authorized(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Status: "ready"})
	}))

	mux.HandleFunc("/connect", authorized(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: "method not allowed"})
			return
		}
		timeoutSeconds := int64(180)
		var body struct {
			TimeoutSeconds int64 `json:"timeout_seconds"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		if body.TimeoutSeconds > 0 {
			timeoutSeconds = body.TimeoutSeconds
		}
		if err := lanternbridge.Connect(timeoutSeconds); err != nil {
			writeJSON(w, http.StatusBadGateway, apiResponse{
				OK: false, Status: lanternbridge.Status(), Error: err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Status: lanternbridge.Status()})
	}))

	mux.HandleFunc("/cancel", authorized(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: "method not allowed"})
			return
		}
		lanternbridge.CancelConnect()
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Status: lanternbridge.Status()})
	}))

	mux.HandleFunc("/disconnect", authorized(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: "method not allowed"})
			return
		}
		if err := lanternbridge.Disconnect(); err != nil {
			writeJSON(w, http.StatusBadGateway, apiResponse{OK: false, Status: lanternbridge.Status(), Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Status: lanternbridge.Status()})
	}))

	mux.HandleFunc("/status", authorized(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: "method not allowed"})
			return
		}
		status := lanternbridge.Status()
		writeJSON(w, http.StatusOK, apiResponse{
			OK: status == "connected", Status: status, Error: lanternbridge.LastError(),
		})
	}))

	mux.HandleFunc("/traffic", authorized(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{OK: false, Error: "method not allowed"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(lanternbridge.TrafficJSON()))
	}))

	server := &http.Server{
		Addr:              *controlAddress,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      310 * time.Second,
		IdleTimeout:       15 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	log.Printf("Lantern sidecar ready; SOCKS=%s control=%s", *socksAddress, *controlAddress)

	select {
	case <-signalCtx.Done():
		log.Printf("shutdown signal received")
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			lanternbridge.CancelConnect()
			lanternbridge.Shutdown()
			return fmt.Errorf("control server: %w", err)
		}
	}

	lanternbridge.CancelConnect()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	lanternbridge.Shutdown()
	return nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, status int, value apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

