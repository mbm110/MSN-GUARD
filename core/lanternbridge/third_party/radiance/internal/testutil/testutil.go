package testutil

import (
	"testing"

	"github.com/getlantern/radiance/common/settings"
)

func SetPathsForTesting(t *testing.T) {
	if !testing.Testing() {
		panic("SetPathsForTesting should only be called in tests")
	}
	t.Helper()
	tmp := t.TempDir()
	settings.Set(settings.DataPathKey, tmp)
	settings.Set(settings.LogPathKey, tmp)
}
