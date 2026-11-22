package unbounded

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/sameorigin"
)

// widgetSignalingClient starts a widget and returns the HTTP client the
// manager handed broflake for signaling.
func widgetSignalingClient(t *testing.T) *http.Client {
	t.Helper()
	count, opts, _ := recordingWidgets(t)
	primeManager(t, nil)
	manager.start()
	waitForCount(t, count, 1, 2*time.Second)
	require.NotNil(t, opts(0).HTTPClient)
	return opts(0).HTTPClient
}

// A genesis POST carries the widget's room tickets in its form. A redirect to
// another origin must not replay it there.
func TestWidgetSignalingRefusesCrossOriginRedirects(t *testing.T) {
	client := widgetSignalingClient(t)
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var other atomic.Int32
			elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				other.Add(1)
			}))
			defer elsewhere.Close()
			freddie := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, elsewhere.URL+"/v1/signal", code)
			}))
			defer freddie.Close()

			resp, err := client.PostForm(freddie.URL+"/v1/signal", url.Values{"room-ticket": {"eyJ2IjoxfQ.c2ln"}})
			if resp != nil {
				resp.Body.Close()
			}
			require.Error(t, err)
			assert.Zero(t, other.Load(), "the other origin never receives the form")
		})
	}
}

func TestWidgetSignalingFollowsSameOriginRedirects(t *testing.T) {
	client := widgetSignalingClient(t)
	var form url.Values
	freddie := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/v1/signal", http.StatusTemporaryRedirect)
			return
		}
		require.NoError(t, r.ParseForm())
		form = r.PostForm
	}))
	defer freddie.Close()

	resp, err := client.PostForm(freddie.URL+"/old", url.Values{"room-ticket": {"t"}})
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "t", form.Get("room-ticket"))
}

func TestSignalingRedirectLimit(t *testing.T) {
	checkSignalingRedirect := widgetSignalingClient(t).CheckRedirect
	maxSignalingRedirects := sameorigin.MaxRedirects
	req := httptest.NewRequest(http.MethodPost, "https://freddie.example/v1/signal", nil)
	via := make([]*http.Request, maxSignalingRedirects)
	for i := range via {
		via[i] = req
	}
	assert.Error(t, checkSignalingRedirect(req, via))
	assert.NoError(t, checkSignalingRedirect(req, via[:maxSignalingRedirects-1]))
	other := httptest.NewRequest(http.MethodPost, "https://freddie.example:8443/v1/signal", nil)
	assert.Error(t, checkSignalingRedirect(other, via[:1]), "another port is another origin")
	plain := httptest.NewRequest(http.MethodPost, "http://freddie.example/v1/signal", nil)
	assert.Error(t, checkSignalingRedirect(plain, via[:1]), "a downgrade to http is another origin")
	explicit := httptest.NewRequest(http.MethodPost, "https://FREDDIE.example:443/x", nil)
	assert.NoError(t, checkSignalingRedirect(explicit, via[:1]))
}
