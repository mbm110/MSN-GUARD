package common

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
)

var testZones = []string{
	"Asia/Tehran",
	"Asia/Yangon",
	"Asia/Dubai",
	"Asia/Shanghai",
	"UTC",
	"Europe/London",
	"America/New_York",
}

// Winter and summer, so zones with DST are checked under both abbreviations.
var testDates = []time.Time{
	time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC),
	time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC),
}

func noLink() (string, error) { return "", errors.New("no /etc/localtime") }

func TestResolveTimeZone_HostZoneWins(t *testing.T) {
	for _, zone := range append(testZones, "Iran", "Japan", "Singapore", "America/Argentina/Buenos_Aires", "Etc/GMT+3") {
		got := tzSources{host: zone, env: "Europe/Paris", envSet: true, goLocal: "Asia/Tokyo", localtime: noLink, now: testDates[0]}.resolve()
		assert.Equal(t, zone, got)
	}
}

func TestResolveTimeZone_NamedSources(t *testing.T) {
	for _, zone := range testZones {
		now := testDates[0]
		assert.Equal(t, zone, tzSources{env: zone, envSet: true, goLocal: "Local", localtime: noLink, now: now}.resolve(), "TZ=%s", zone)
		assert.Equal(t, zone, tzSources{env: ":" + zone, envSet: true, goLocal: "Local", localtime: noLink, now: now}.resolve(), "TZ=:%s", zone)
		assert.Equal(t, zone, tzSources{env: "/usr/share/zoneinfo/" + zone, envSet: true, goLocal: "Local", localtime: noLink, now: now}.resolve(), "TZ=path %s", zone)

		link := func() (string, error) { return "/usr/share/zoneinfo/" + zone, nil }
		assert.Equal(t, zone, tzSources{goLocal: "Local", localtime: link, now: now}.resolve(), "linux link %s", zone)
		macLink := func() (string, error) { return "/var/db/timezone/zoneinfo/" + zone, nil }
		assert.Equal(t, zone, tzSources{goLocal: "Local", localtime: macLink, now: now}.resolve(), "macOS link %s", zone)
	}
	assert.Equal(t, "Asia/Tehran", tzSources{goLocal: "Asia/Tehran", localtime: noLink, now: testDates[0]}.resolve())
}

// TestResolveTimeZone_NeverWrong covers a device whose only signal is the zone abbreviation and
// offset, which is what the removed reverse-mapping used: the result must be the true zone or "".
func TestResolveTimeZone_NeverWrong(t *testing.T) {
	for _, zone := range testZones {
		loc, err := time.LoadLocation(zone)
		require.NoError(t, err)
		for _, date := range testDates {
			got := tzSources{goLocal: "Local", localtime: noLink, now: date.In(loc)}.resolve()
			if got != "" {
				assert.Equal(t, zone, got, "abbreviation fallback for %s on %s", zone, date.Format("Jan"))
			}
		}
	}
}

func TestResolveTimeZone_AbbreviationFallback(t *testing.T) {
	for zone, want := range map[string]string{
		// Numeric abbreviations (+0330, +0630, +04) have no named zone to look up.
		"Asia/Tehran": "",
		"Asia/Yangon": "",
		"Asia/Dubai":  "",
		// CST at +08:00 is shared with Macau and Taipei; the old lookup sent Asia/Macau.
		"Asia/Shanghai": "",
	} {
		loc, err := time.LoadLocation(zone)
		require.NoError(t, err)
		got := tzSources{goLocal: "Local", localtime: noLink, now: testDates[0].In(loc)}.resolve()
		assert.Equal(t, want, got, zone)
	}
}

func TestResolveTimeZone_IgnoresUnreliableSources(t *testing.T) {
	now := testDates[0]
	for _, s := range []tzSources{
		{host: "Local", goLocal: "Local", localtime: noLink, now: now},
		{host: "not a zone", goLocal: "Local", localtime: noLink, now: now},
		{env: "Mars/Olympus_Mons", envSet: true, goLocal: "Local", localtime: noLink, now: now},
		// Go reports UTC for time.Local when it can't find the device's zone.
		{goLocal: "UTC", localtime: noLink, now: now},
		{goLocal: "Local", localtime: func() (string, error) { return "/etc/zoneinfo-missing", nil }, now: now},
	} {
		assert.Empty(t, s.resolve(), "%+v", s)
	}
}

func TestZoneFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/usr/share/zoneinfo/Asia/Tehran":               "Asia/Tehran",
		"../usr/share/zoneinfo/America/Argentina/Salta": "America/Argentina/Salta",
		"/usr/share/zoneinfo/posix/Asia/Yangon":         "Asia/Yangon",
		"/var/db/timezone/zoneinfo/Europe/London":       "Europe/London",
		"/etc/localtime":                                "",
	} {
		assert.Equal(t, want, zoneFromPath(path), path)
	}
}

func TestNewRequestWithHeaders_TimeZone(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.Set(settings.TimeZoneKey, "Asia/Tehran"))

	req, err := NewRequestWithHeaders(context.Background(), http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	assert.Equal(t, "Asia/Tehran", req.Header.Get(TimeZoneHeader))
}

func TestUniqueZoneForAbbreviation_IncompleteTzdata(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	require.NoError(t, err)
	now := testDates[0].In(berlin) // CET, shared by many zones
	onlyParis := func(name string) (*time.Location, error) {
		if name == "Europe/Paris" {
			return time.LoadLocation(name)
		}
		return nil, errors.New("not installed")
	}
	assert.Empty(t, uniqueZoneForAbbreviation(now, onlyParis))
	assert.Empty(t, uniqueZoneForAbbreviation(now, time.LoadLocation), "CET is shared, so never unique")
}

func TestResolveTimeZone_ExplicitTZBeatsLocaltimeLink(t *testing.T) {
	tehranLink := func() (string, error) { return "/usr/share/zoneinfo/Asia/Tehran", nil }
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	require.NoError(t, err)
	now := testDates[0].In(shanghai)

	// An explicit TZ the resolver can't name must not fall back to /etc/localtime.
	assert.Empty(t, tzSources{env: "CST-8", envSet: true, goLocal: "Local", localtime: tehranLink, now: now}.resolve())
	assert.Empty(t, tzSources{env: "", envSet: true, goLocal: "UTC", localtime: tehranLink, now: testDates[0]}.resolve())
	assert.Equal(t, "Asia/Tehran", tzSources{goLocal: "Local", localtime: tehranLink, now: now}.resolve(), "unset TZ uses the link")
}
