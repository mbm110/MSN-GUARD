package fronted

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/getlantern/domainfront"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common"
)

// TestEmbeddedConfigValid guards the offline-boot guarantee: NewFronted seeds
// domainfront with the embedded config, so a fresh install with configURL
// blocked still boots — which requires the embedded copy to parse and carry
// providers. (Persistence and bootstrap-preference are tested in domainfront.)
func TestEmbeddedConfigValid(t *testing.T) {
	cfg, err := domainfront.ParseConfigFromReader(bytes.NewReader(embeddedConfig))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.Providers, "embedded fronted config must contain providers")
	require.NotEmpty(t, cfg.TrustedCAs)
	_, err = cfg.CertPool()
	require.NoError(t, err)
	// These limits mirror lantern-cloud publishedconfig/compact.go so an
	// oversized artifact fails the daily refresh before it can ship.
	for name, provider := range cfg.Providers {
		assert.NotEmpty(t, provider.Masquerades, name)
		assert.LessOrEqual(t, len(provider.Masquerades), 200, name)
		for country, config := range provider.FrontingSNIs {
			assert.LessOrEqual(t, len(config.ArbitrarySNIs), 256, name+"/"+country)
		}
	}
}

// TestRetryableResponse pins the origin-vs-edge distinction: an origin-issued
// rejection is a real answer and must reach the caller; the same status from an
// edge means "wrong front, try another".
func TestRetryableResponse(t *testing.T) {
	// Header sets observed on the wire. Only common.OriginHeader may sway the
	// verdict — CloudFront stamps x-cache/via onto proxied origin 4xx too.
	origin := http.Header{
		common.OriginHeader: []string{"1"},
		"Content-Type":      []string{"application/x-protobuf"},
	}
	originViaCloudFront := http.Header{
		common.OriginHeader: []string{"1"},
		"Content-Type":      []string{"application/x-protobuf"},
		"X-Cache":           []string{"Error from cloudfront"},
		"Via":               []string{"1.1 google, 1.1 abc.cloudfront.net (CloudFront)"},
	}
	cloudFrontEdge := http.Header{
		"Content-Type": []string{"text/html"},
		"Server":       []string{"CloudFront"},
		"X-Cache":      []string{"Error from cloudfront"},
	}
	akamaiEdge := http.Header{
		"Content-Type": []string{"text/html"},
		"Server":       []string{"AkamaiGHost"},
	}

	for _, tc := range []struct {
		name   string
		status int
		header http.Header
		want   bool
	}{
		{"origin 403 is a real answer", 403, origin, false},
		{"origin 403 relayed by cloudfront", 403, originViaCloudFront, false},
		{"origin 500 is the origin's own failure", 500, origin, false},
		{"origin 503", 503, origin, false},
		{"cloudfront edge 403", 403, cloudFrontEdge, true},
		{"akamai edge 403", 403, akamaiEdge, true},
		{"edge 502 with no marker", 502, http.Header{}, true},
		// Third-party fronted origins can't set the marker, so they keep the
		// default behavior rather than gaining a pass-through.
		{"third-party origin 403", 403, http.Header{"Server": []string{"GitHub.com"}}, true},
		// Non-rejection statuses are never a front failure, marker or not.
		{"origin 200", 200, origin, false},
		{"edge 200", 200, cloudFrontEdge, false},
		{"404 is a real answer even unmarked", 404, http.Header{}, false},
		{"301 is not a front failure", 301, http.Header{}, false},
		// Outside 5xx, so not a rejection status even though it exceeds 500.
		{"malformed 600 is not a front failure", 600, http.Header{}, false},
		// An empty marker is unusable, so it falls back to the default behavior
		// rather than being honored as proof of origin.
		{"empty marker is not proof of origin", 403, http.Header{common.OriginHeader: []string{""}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := retryableResponse(&http.Response{StatusCode: tc.status, Header: tc.header})
			assert.Equal(t, tc.want, got)
		})
	}
}
