// Package soar builds the Soar DNS-tunnel transport for kindling: the last-resort path that
// still works when only recursive DNS does.
package soar

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/getlantern/soar"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/common/settings"
)

// Zone and PublicKey identify the Soar server. They're set at build time
// (-ldflags "-X github.com/getlantern/radiance/kindling/soar.Zone=... -X ...PublicKey=...")
// rather than committed: a public repo naming the zone hands a censor the string to block, and
// the tunnel is a bootstrap path, so it can't wait for fetched config.
var (
	Zone      string
	PublicKey string
)

// Configured reports whether this build carries a Soar server.
func Configured() bool { return Zone != "" && PublicKey != "" }

// New returns a Soar client: resolvers come from discovery (the bundled per-country lists for
// the user's country, the device's own resolvers, and a per-device cache of ones that worked),
// and both UDP and TCP/53 go through radiance's bypass so they never loop through the VPN.
func New(dataDir string) (*soar.Client, error) {
	if !Configured() {
		return nil, errors.New("soar: no server configured in this build")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(PublicKey))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("soar: bad public key")
	}
	cc := country(common.LocalTimeZone())
	return soar.NewClient(soar.Config{
		Zone:         Zone,
		ServerKey:    ed25519.PublicKey(key),
		ListenPacket: bypass.ListenPacket,
		DialTCP:      bypass.DialContext,
		Discovery: soar.Discovery{
			Enabled: true,
			Country: cc,
			Cache:   &fileCache{path: filepath.Join(dataDir, "soar_resolvers.json"), country: cc},
		},
		Logger: slog.Default().With("component", "soar"),
	})
}

// country picks the bundled resolver list to vet. A fresh install doesn't know its country
// until config arrives, which may need this tunnel, and phones expose no system resolvers to
// fall back on, so the time zone stands in for the countries Soar bundles lists for. A wrong
// guess only adds candidates.
func country(zone string) string {
	if cc := settings.GetString(settings.CountryCodeKey); cc != "" {
		return cc
	}
	return zoneCountry[zone]
}

var zoneCountry = map[string]string{
	"Asia/Tehran": "IR", "Iran": "IR",

	"Asia/Shanghai": "CN", "Asia/Urumqi": "CN", "Asia/Chongqing": "CN", "Asia/Chungking": "CN",
	"Asia/Harbin": "CN", "Asia/Kashgar": "CN", "PRC": "CN",

	"Europe/Moscow": "RU", "W-SU": "RU", "Europe/Kaliningrad": "RU", "Europe/Samara": "RU",
	"Europe/Volgograd": "RU", "Europe/Saratov": "RU", "Europe/Ulyanovsk": "RU",
	"Europe/Astrakhan": "RU", "Europe/Kirov": "RU", "Asia/Yekaterinburg": "RU", "Asia/Omsk": "RU",
	"Asia/Novosibirsk": "RU", "Asia/Barnaul": "RU", "Asia/Tomsk": "RU", "Asia/Novokuznetsk": "RU",
	"Asia/Krasnoyarsk": "RU", "Asia/Irkutsk": "RU", "Asia/Chita": "RU", "Asia/Yakutsk": "RU",
	"Asia/Khandyga": "RU", "Asia/Vladivostok": "RU", "Asia/Ust-Nera": "RU", "Asia/Sakhalin": "RU",
	"Asia/Magadan": "RU", "Asia/Srednekolymsk": "RU", "Asia/Kamchatka": "RU", "Asia/Anadyr": "RU",
}

// maxCachedResolvers bounds what Load returns. Soar wants the cache keyed by network, but
// nothing identifies the network before the tunnel on every platform (with the VPN up, local
// addresses are the TUN's). After a network change, stale entries then hold a few of
// discovery's probe slots rather than all of them, and the next store drops them.
const maxCachedResolvers = 4

// fileCache persists resolvers that carried the tunnel, keyed by country, so the next start
// vets them first instead of rediscovering.
type fileCache struct {
	mu   sync.Mutex
	path string
	// country is the one discovery used, so resolvers verified on a fresh install (country
	// guessed from the time zone) land where the next start, with config's country, looks.
	country string
}

func (f *fileCache) key() string {
	if f.country != "" {
		return strings.ToUpper(f.country)
	}
	return "_"
}

func (f *fileCache) load() map[string][]string {
	var m map[string][]string
	if b, err := os.ReadFile(f.path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m == nil { // missing, malformed, or a JSON null
		m = map[string][]string{}
	}
	return m
}

func (f *fileCache) Load() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	cached := f.load()[f.key()]
	return cached[:min(len(cached), maxCachedResolvers)]
}

func (f *fileCache) Store(resolvers []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.load()
	m[f.key()] = resolvers
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	if err := atomicfile.WriteFile(f.path, b, fileperm.Private); err != nil {
		slog.Debug("soar: storing resolver cache", "error", err)
	}
}
