package servers

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/option"

	"github.com/getlantern/radiance/internal/redact"
)

// ErrReservedTag is returned for a user server whose tag the tunnel uses for
// its own outbounds and groups.
var ErrReservedTag = errors.New("tag is reserved")

// reservedTags are the tags the tunnel reserves: its selection groups, the
// personal proxy groups and the built-in outbounds. vpn.ReservedTags must
// match it.
var reservedTags = []string{"auto", "manual", redact.PersonalProxiesTag, redact.PersonalProxyTag, "direct", "block", "proxyless-hedge"}

// reservedPrefix starts the tags that select one friend's personal proxy
// (vpn.PersonalProxySelection), which a user server's tag would shadow.
const reservedPrefix = redact.PersonalProxyTag + ":"

// ReservedTags returns the tags no user server may use.
func ReservedTags() []string {
	return slices.Clone(reservedTags)
}

// normalizeUserTag sets the tag of the outbound or endpoint a user
// (non-Lantern) server carries to the server's own tag, in place. The tunnel
// creates the outbound under the embedded tag, so the server's tag, which is
// what the reserved-tag check and the server list see, must be the effective
// one. Callers such as a rename change only the server's tag. Lantern config
// servers are left alone: the config sets both tags together.
func normalizeUserTag(srv *Server) {
	if srv.IsLantern {
		return
	}
	switch o := srv.Options.(type) {
	case option.Outbound:
		o.Tag = srv.Tag
		srv.Options = o
	case *option.Outbound:
		if o != nil {
			cp := *o
			cp.Tag = srv.Tag
			srv.Options = &cp
		}
	case option.Endpoint:
		o.Tag = srv.Tag
		srv.Options = o
	case *option.Endpoint:
		if o != nil {
			cp := *o
			cp.Tag = srv.Tag
			srv.Options = &cp
		}
	}
}

// checkUserTag refuses a user (non-Lantern) server whose tag is reserved.
// After normalizeUserTag that is also the tag the tunnel uses. Lantern config
// servers are exempt: a config may carry the built-in outbounds, which the
// tunnel merges but never offers.
func checkUserTag(srv *Server) error {
	if !srv.IsLantern && (slices.Contains(reservedTags, srv.Tag) || strings.HasPrefix(srv.Tag, reservedPrefix)) {
		return fmt.Errorf("server %q: %w", srv.Tag, ErrReservedTag)
	}
	return nil
}
