package bypass

import (
	"os"
	"testing"

	"github.com/getlantern/radiance/internal/testutil"
)

func TestMain(m *testing.M) {
	unlock := testutil.LockBypassPort()
	code := m.Run()
	unlock()
	os.Exit(code)
}
