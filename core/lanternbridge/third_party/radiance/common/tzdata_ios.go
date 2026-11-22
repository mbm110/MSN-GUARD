//go:build ios

package common

// iOS has no zone database Go can read, so time.LoadLocation would fail for
// the zone LocalTimeZone reports. Embed one.
import _ "time/tzdata"
