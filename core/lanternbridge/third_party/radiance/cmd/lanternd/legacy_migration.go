package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/getlantern/radiance/common"
	commonenv "github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/internal"
	rlog "github.com/getlantern/radiance/log"
)

type migrateCmd struct {
	SID         string            `arg:"--sid,required"`
	Source      string            `arg:"--source,required"`
	MigrationID string            `arg:"--migration-id,required"`
	Request     string            `arg:"--request,required"`
	Environment daemonEnvironment `arg:"--environment" default:"prod" help:"backend environment (prod or staging)"`
}

func initializeDaemonDiagnostics(dataPath, logPath, logLevel string) error {
	dataPath = withDefault(commonenv.GetString(commonenv.DataPath), dataPath)
	logPath = withDefault(commonenv.GetString(commonenv.LogPath), logPath)
	if err := settings.SetRuntimePaths(dataPath, logPath); err != nil {
		return err
	}
	if err := os.MkdirAll(logPath, 0755); err != nil {
		return err
	}
	output := filepath.Join(logPath, internal.LogFileName)
	if commonenv.GetBool(commonenv.LogToStdout) {
		output = rlog.StdoutPath
	}
	slog.SetDefault(rlog.NewLogger(rlog.Config{LogPath: output, Level: logLevel, Prod: common.Prod()}))
	return nil
}
