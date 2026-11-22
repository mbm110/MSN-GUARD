package ipc

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/getlantern/radiance/vpn"
)

func TestSplitTunnelStatus(t *testing.T) {
	assert.Equal(t, http.StatusBadRequest, splitTunnelStatus(fmt.Errorf("add: %w", vpn.ErrInvalidSplitTunnelFilter)))
	assert.Equal(t, http.StatusInternalServerError, splitTunnelStatus(errors.New("disk full")))
}
