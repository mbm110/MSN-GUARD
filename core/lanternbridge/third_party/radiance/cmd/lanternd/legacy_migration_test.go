package main

import (
	"testing"

	"github.com/alexflint/go-arg"
	"github.com/stretchr/testify/require"
)

func TestMigrateRequiresBoundSnapshot(t *testing.T) {
	for _, missing := range []string{"--sid", "--source", "--migration-id", "--request"} {
		values := []string{"migrate"}
		for _, pair := range [][2]string{{"--sid", "S-1-5-21-123"}, {"--source", `C:\Users\Original\Lantern`}, {"--migration-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, {"--request", `C:\Users\Original\snapshot.json`}} {
			if pair[0] != missing {
				values = append(values, pair[0], pair[1])
			}
		}
		var args daemonArgs
		parser, err := arg.NewParser(arg.Config{}, &args)
		require.NoError(t, err)
		require.Error(t, parser.Parse(values))
	}
	var args daemonArgs
	parser, err := arg.NewParser(arg.Config{}, &args)
	require.NoError(t, err)
	require.NoError(t, parser.Parse([]string{"migrate", "--sid", "S-1-5-21-123", "--source", `C:\Users\Original\Lantern`, "--migration-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--request", `C:\Users\Original\snapshot.json`, "--environment", "staging"}))
	require.Equal(t, daemonEnvironmentStaging, args.Migrate.Environment)
}

func TestDaemonPreservesTelemetryConsent(t *testing.T) {
	require.True(t, daemonBackendOptions("data", "logs", "info").PreserveTelemetryConsent)
}
