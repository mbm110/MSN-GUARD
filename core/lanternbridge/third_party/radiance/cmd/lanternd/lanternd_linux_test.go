package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemdUnitQuotesAwkwardPaths(t *testing.T) {
	var out strings.Builder
	err := systemdUnitTmpl.Execute(&out, struct {
		ExePath, DataPath, LogPath, LogLevel, Environment string
	}{"/usr/bin/lanternd", "/home/a b/data", "/home/a&b/logs", "info", "prod"})
	require.NoError(t, err)

	var execStart string
	for line := range strings.SplitSeq(out.String(), "\n") {
		if after, ok := strings.CutPrefix(line, "ExecStart="); ok {
			execStart = after
		}
	}
	require.NotEmpty(t, execStart, "unit file has no ExecStart line")
	require.Equal(t,
		`/usr/bin/lanternd run --data-path "/home/a b/data" --log-path "/home/a&b/logs" --log-level "info" --environment "prod"`,
		execStart)
}

func TestSystemdQuoteEscapesExpansions(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain path", `/var/lib/lantern`, `"/var/lib/lantern"`},
		{"space", `/home/a b/Lantern`, `"/home/a b/Lantern"`},
		{"ampersand", `/tmp/a&b`, `"/tmp/a&b"`},
		{"double quote", `/tmp/a"b`, `"/tmp/a\"b"`},
		{"backslash", `/tmp/a\b`, `"/tmp/a\\b"`},
		{"percent specifier", `/tmp/50%off`, `"/tmp/50%%off"`},
		{"dollar variable", `/tmp/$HOME`, `"/tmp/$$HOME"`},
		{"empty", ``, `""`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, systemdQuote(test.in))
		})
	}
}
