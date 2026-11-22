package common

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"net/http"
	"sync/atomic"

	"github.com/getlantern/radiance/common/settings"
)

// publicIP holds the most recently detected public IP address and the
// network it was looked up on, read and written together.
var publicIP atomic.Pointer[publicIPSnapshot]

type publicIPSnapshot struct {
	ip      string
	network uint64
}

func init() {
	publicIP.Store(&publicIPSnapshot{})
}

// publicIPNetwork counts network changes.
var publicIPNetwork atomic.Uint64

// SetPublicIP stores the detected public IP for inclusion in API requests.
func SetPublicIP(ip string) { SetPublicIPFrom(ip, PublicIPNetwork()) }

// PublicIPNetwork returns a value that changes with each MarkPublicIPStale.
func PublicIPNetwork() uint64 { return publicIPNetwork.Load() }

// SetPublicIPFrom is SetPublicIP for an IP looked up while PublicIPNetwork
// returned network: if the network changed since, the IP is stored stale.
func SetPublicIPFrom(ip string, network uint64) {
	publicIP.Store(&publicIPSnapshot{ip: ip, network: network})
}

// MarkPublicIPStale records that the network changed since the public IP was
// looked up, until an IP looked up after this call is set.
func MarkPublicIPStale() { publicIPNetwork.Add(1) }

// PublicIPStale reports whether the network changed since the public IP was
// looked up.
func PublicIPStale() bool { return publicIP.Load().network != publicIPNetwork.Load() }

// FreshPublicIP returns the public IP if it was looked up on the current
// network, or "".
func FreshPublicIP() string {
	snap := publicIP.Load()
	if snap.network != publicIPNetwork.Load() {
		return ""
	}
	return snap.ip
}

const (
	// Common Lantern headers. All are request headers sent to the proxy server
	// except OriginHeader, which the server sets on responses.
	AppVersionHeader        = "X-Lantern-App-Version"
	VersionHeader           = "X-Lantern-Version"
	PlatformHeader          = "X-Lantern-Platform"
	AppNameHeader           = "X-Lantern-App"
	DeviceIDHeader          = "X-Lantern-Device-Id"
	UserIDHeader            = "X-Lantern-User-Id"
	SupportedDataCapsHeader = "X-Lantern-Supported-Data-Caps"
	TimeZoneHeader          = "X-Lantern-Time-Zone"
	RandomNoiseHeader       = "X-Lantern-Rand"
	ProTokenHeader          = "X-Lantern-Pro-Token"
	RefererHeader           = "referer"
	ClientCountryHeader     = "X-Lantern-Client-Country"
	ClientIPHeader          = "X-Lantern-Config-Client-IP"
	ContentTypeHeader       = "content-type"
	AcceptHeader            = "accept"

	// OriginHeader is set by Lantern origins on every response. Fronted requests
	// read it to tell an origin-issued status from a CDN edge's, which is
	// otherwise impossible: a CDN relays the origin's response verbatim.
	OriginHeader = "X-Lantern-Origin"
)

// NewRequestWithHeaders creates a new [http.Request] with the required headers.
func NewRequestWithHeaders(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	// We include a random length string here to make it harder for censors to identify lantern
	// based on consistent packet lengths.
	req.Header.Add(RandomNoiseHeader, randomizedString())

	req.Header.Set(AppVersionHeader, GetVersion())
	req.Header.Set(VersionHeader, GetVersion())
	req.Header.Set(UserIDHeader, settings.GetString(settings.UserIDKey))
	req.Header.Set(PlatformHeader, Platform)
	req.Header.Set(AppNameHeader, Name)
	req.Header.Set(DeviceIDHeader, settings.GetString(settings.DeviceIDKey))
	if tz := LocalTimeZone(); tz != "" {
		req.Header.Set(TimeZoneHeader, tz)
	}
	if ip := publicIP.Load().ip; ip != "" {
		req.Header.Set(ClientIPHeader, ip)
	}
	return req, nil
}

// randomizedString returns a random string to avoid consistent packet lengths censors
// may use to detect Lantern.
func randomizedString() string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	size, err := rand.Int(rand.Reader, big.NewInt(300))
	if err != nil {
		return ""
	}

	bytes := make([]byte, size.Int64())
	for i := range bytes {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return ""
		}
		bytes[i] = charset[index.Int64()]
	}
	return string(bytes)
}
