//go:build probe

// MSN 3.4.12: probe-only staging for the Server Pool switch contract test
// (core/lanternbridge/poolswitch_test.go). NEVER compiled into the APK or the
// sidecar — the probe build tag exists only for diagnostics probes.
package backend

import (
	"github.com/getlantern/radiance/servers"
)

// ProbeStageLanternServers seeds the manager exactly the way a server config
// draw does (updateServers with IsLantern servers), without any network. The
// public Add* paths deliberately set IsLantern=false (user-supplied servers
// are never pool members), so the switch test cannot stage Lantern members
// through them — this is the same path a real config fetch takes, minus the
// fetch. Helpers and user servers are unaffected.
func (r *LocalBackend) ProbeStageLanternServers(list servers.ServerList) error {
	return r.updateServers(list, false)
}
