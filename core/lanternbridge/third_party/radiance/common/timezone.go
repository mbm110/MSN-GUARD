package common

import (
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/tkuchiki/go-timezone"

	"github.com/getlantern/radiance/common/settings"
)

// LocalTimeZone returns the device's IANA time zone name (e.g. "Asia/Tehran"), or "" when it
// can't be determined without guessing.
//
// The API treats this value as stronger evidence of the user's country than their IP address, so
// a wrong zone is worse than none.
func LocalTimeZone() string {
	env, envSet := os.LookupEnv("TZ")
	return tzSources{
		host:      settings.GetString(settings.TimeZoneKey),
		env:       env,
		envSet:    envSet,
		goLocal:   time.Local.String(),
		localtime: func() (string, error) { return os.Readlink("/etc/localtime") },
		now:       time.Now(),
	}.resolve()
}

type tzSources struct {
	host      string
	env       string
	envSet    bool
	goLocal   string
	localtime func() (string, error)
	now       time.Time
}

// ianaName matches zone names such as "UTC", "Iran", "Asia/Tehran" and
// "America/Argentina/Buenos_Aires".
var ianaName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*$`)

func (s tzSources) resolve() string {
	// Mobile Go runtimes may lack tzdata, so the host app's zone is trusted without loading it.
	if s.host != "Local" && ianaName.MatchString(s.host) {
		return s.host
	}
	if s.envSet {
		name := strings.TrimPrefix(s.env, ":")
		if loadable(name) {
			return name
		}
		if name := zoneFromPath(name); loadable(name) {
			return name
		}
		// TZ overrides /etc/localtime, so only the configured zone's abbreviation is left.
		return uniqueZoneForAbbreviation(s.now, time.LoadLocation)
	}
	// Go reports "UTC" for time.Local when it couldn't find the zone, as on Android.
	if strings.Contains(s.goLocal, "/") && loadable(s.goLocal) {
		return s.goLocal
	}
	if s.localtime != nil {
		if target, err := s.localtime(); err == nil {
			if name := zoneFromPath(target); loadable(name) {
				return name
			}
		}
	}
	return uniqueZoneForAbbreviation(s.now, time.LoadLocation)
}

func loadable(name string) bool {
	if name == "" || name == "Local" {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

// zoneFromPath extracts the zone name from a zoneinfo path such as
// /usr/share/zoneinfo/Asia/Tehran or /var/db/timezone/zoneinfo/Asia/Tehran.
func zoneFromPath(path string) string {
	_, name, ok := strings.Cut(path, "zoneinfo/")
	if !ok {
		return ""
	}
	name = strings.TrimPrefix(name, "posix/")
	return strings.TrimPrefix(name, "right/")
}

// uniqueZoneForAbbreviation returns the only zone using now's abbreviation and offset, or "" if
// there is none or several (e.g. CST at +08:00 is used by Shanghai, Macau and Taipei). It also
// returns "" if any candidate can't be loaded, since that candidate might be the device's zone.
func uniqueZoneForAbbreviation(now time.Time, load func(string) (*time.Location, error)) string {
	abbr, offset := now.Zone()
	candidates, err := timezone.New().GetTimezones(abbr)
	if err != nil {
		return ""
	}
	match := ""
	for _, name := range candidates {
		loc, err := load(name)
		if err != nil {
			return ""
		}
		if a, o := now.In(loc).Zone(); a != abbr || o != offset {
			continue
		}
		if match != "" {
			return ""
		}
		match = name
	}
	return match
}
