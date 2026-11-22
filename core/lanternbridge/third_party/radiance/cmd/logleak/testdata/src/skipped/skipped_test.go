package skipped

import (
	"fmt"
	"log/slog"
)

func helper(c cfg) {
	_ = fmt.Sprint(c)
	slog.Info(c.Password)
}
