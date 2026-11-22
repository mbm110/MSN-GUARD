package ipc

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/getlantern/radiance/internal/hostaccess"
)

func TestAddServersStatus(t *testing.T) {
	assert.Equal(t, http.StatusBadRequest, addServersStatus(fmt.Errorf("add: %w", hostaccess.ErrDenied)))
	assert.Equal(t, http.StatusInternalServerError, addServersStatus(errors.New("disk full")))
}
