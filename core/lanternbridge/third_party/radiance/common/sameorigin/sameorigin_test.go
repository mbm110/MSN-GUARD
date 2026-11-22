package sameorigin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRedirect(t *testing.T) {
	check := CheckRedirect("test")
	req := httptest.NewRequest(http.MethodPost, "https://api.example/v1/x", nil)
	via := make([]*http.Request, MaxRedirects)
	for i := range via {
		via[i] = req
	}
	assert.EqualError(t, check(req, via), "test: stopped after 10 redirects")
	assert.NoError(t, check(req, via[:MaxRedirects-1]))
	other := httptest.NewRequest(http.MethodPost, "https://api.example:8443/v1/x", nil)
	assert.EqualError(t, check(other, via[:1]), "test: refusing a redirect to another origin")
	plain := httptest.NewRequest(http.MethodPost, "http://api.example/v1/x", nil)
	assert.Error(t, check(plain, via[:1]), "a downgrade to http is another origin")
	explicit := httptest.NewRequest(http.MethodPost, "https://API.example:443/y", nil)
	assert.NoError(t, check(explicit, via[:1]))
}

func TestClientCopies(t *testing.T) {
	in := &http.Client{Transport: http.DefaultTransport, Timeout: 7 * time.Second}
	out := Client(in, "test")
	require.NotSame(t, in, out)
	assert.Nil(t, in.CheckRedirect, "the caller's client is not changed")
	assert.NotNil(t, out.CheckRedirect)
	assert.Equal(t, in.Transport, out.Transport)
	assert.Equal(t, in.Timeout, out.Timeout)
	assert.NotNil(t, Client(nil, "test").CheckRedirect)
}
