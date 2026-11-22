package kindling

import (
	"os"
	"testing"

	"github.com/getlantern/radiance/internal/testutil"
)

// Tests here dial through the bypass proxy port, which other packages' tests bind.
func TestMain(m *testing.M) {
	unlock := testutil.LockBypassPort()
	code := m.Run()
	unlock()
	os.Exit(code)
}
