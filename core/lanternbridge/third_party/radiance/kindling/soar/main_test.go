package soar

import (
	"os"
	"testing"

	"github.com/getlantern/radiance/internal/testutil"
)

// Tests here send through the bypass proxy port, which other packages' tests bind.
func TestMain(m *testing.M) {
	unlock := testutil.LockBypassPort()
	code := m.Run()
	unlock()
	os.Exit(code)
}
