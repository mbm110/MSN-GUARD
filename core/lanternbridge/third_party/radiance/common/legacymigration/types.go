// Package legacymigration imports a verified legacy Windows account snapshot.
package legacymigration

import (
	"context"
	"encoding/json"
	"errors"
)

// Request carries the original user's live identity and supported preferences.
type Request struct {
	Version         int    `json:"version"`
	MigrationID     string `json:"migration_id"`
	SourceDirectory string `json:"source_directory"`
	UserID          int64  `json:"user_id"`
	Token           string `json:"token"`
	DeviceID        string `json:"device_id"`
	Locale          string `json:"locale"`
	AutoReport      bool   `json:"auto_report"`
	ProxyAll        bool   `json:"proxy_all"`
	AutoLaunch      bool   `json:"auto_launch"`
}

// Verify authenticates the snapshot without changing the running account.
type Verify func(context.Context, Request) (json.RawMessage, string, error)

// ErrConflict means existing destination state is incompatible with import.
var ErrConflict = errors.New("legacy migration conflicts with existing state")

// ErrUnauthorized means the caller or input lacks the required Windows permissions.
var ErrUnauthorized = errors.New("legacy migration is not authorized")
