package vpn

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/http2"

	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/getlantern/lantern-box/protocol/samizdatreverse"

	"github.com/getlantern/radiance/internal/redact"
	"github.com/getlantern/radiance/servers"
)

// reversePortalTag is the portal inbound's tag, which every reverse outbound
// names to find its sessions.
const reversePortalTag = redact.ReversePortalTag

type reversePortal interface {
	Configure(samizdatreverse.PortalConfig) error
	Rebind() error
	Addr() net.Addr
	Session(reverseTag string) (*http2.ClientConn, bool)
}

// setReversePortal configures the portal, first creating it for
// masqueradeDomain if it is missing or was created for another, or with a nil
// cfg removes it and every reverse outbound.
func (t *tunnel) setReversePortal(cfg *samizdatreverse.PortalConfig, masqueradeDomain string) error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if cfg == nil {
		err := t.setReverseOutboundsLocked(nil)
		if errors.Is(err, errLibboxClosed) {
			return err
		}
		return errors.Join(err, t.removeReversePortalLocked())
	}
	portal, err := t.reversePortalLocked(masqueradeDomain)
	if err != nil {
		return err
	}
	return portal.Configure(*cfg)
}

// reversePortalLocked returns the tunnel's portal for masqueradeDomain,
// creating it, or replacing one created for another domain, since the
// masquerade is fixed at creation. The caller must hold t.outboundMu.
func (t *tunnel) reversePortalLocked(masqueradeDomain string) (reversePortal, error) {
	inbounds := service.FromContext[adapter.InboundManager](t.ctx)
	if inbounds == nil {
		return nil, errors.New("inbound manager not found")
	}
	if _, ok := inbounds.Get(reversePortalTag); !ok || t.portalMasquerade != masqueradeDomain {
		router := service.FromContext[adapter.Router](t.ctx)
		logger := t.logFactory.NewLogger("inbound/" + reversePortalTag + "[" + lbC.TypeSamizdatPortal + "]")
		in := reversePortalInbound(masqueradeDomain)
		// Create closes a portal already under the tag.
		if err := inbounds.Create(t.ctx, router, logger, in.Tag, in.Type, in.Options); err != nil {
			return nil, fmt.Errorf("create reverse portal: %w", err)
		}
		t.portalMasquerade = masqueradeDomain
	}
	in, _ := inbounds.Get(reversePortalTag)
	portal, ok := in.(reversePortal)
	if !ok {
		return nil, errors.New("reverse portal cannot be configured")
	}
	return portal, nil
}

// removeReversePortalLocked closes and removes the portal, if any. The caller
// must hold t.outboundMu.
func (t *tunnel) removeReversePortalLocked() error {
	inbounds := service.FromContext[adapter.InboundManager](t.ctx)
	if inbounds == nil {
		return nil
	}
	if _, ok := inbounds.Get(reversePortalTag); !ok {
		return nil
	}
	if err := inbounds.Remove(reversePortalTag); err != nil {
		return fmt.Errorf("remove reverse portal: %w", err)
	}
	return nil
}

func (t *tunnel) rebindReversePortal() error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	inbounds := service.FromContext[adapter.InboundManager](t.ctx)
	if inbounds == nil {
		return nil
	}
	in, ok := inbounds.Get(reversePortalTag)
	if !ok {
		return nil
	}
	portal, ok := in.(reversePortal)
	if !ok {
		return errors.New("reverse portal cannot be rebound")
	}
	return portal.Rebind()
}

func (t *tunnel) reversePortalListening() bool {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	inbounds := service.FromContext[adapter.InboundManager](t.ctx)
	if inbounds == nil {
		return false
	}
	in, ok := inbounds.Get(reversePortalTag)
	if !ok {
		return false
	}
	portal, ok := in.(reversePortal)
	return ok && portal.Addr() != nil
}

// reverseSessionLive reports whether the portal holds a session for
// reverseTag that can take a new stream. The portal is looked up under
// t.outboundMu but asked outside it, since the check calls into the session's
// HTTP/2 client.
func (t *tunnel) reverseSessionLive(reverseTag string) bool {
	t.outboundMu.Lock()
	inbounds := service.FromContext[adapter.InboundManager](t.ctx)
	var in adapter.Inbound
	if inbounds != nil {
		in, _ = inbounds.Get(reversePortalTag)
	}
	t.outboundMu.Unlock()
	portal, ok := in.(reversePortal)
	if !ok {
		return false
	}
	_, live := portal.Session(reverseTag)
	return live
}

func (t *tunnel) setReverseOutbounds(tags []string) error {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	return t.setReverseOutboundsLocked(tags)
}

// setReverseOutboundsLocked makes the selection groups' reverse outbounds
// exactly tags, which must all be reverse tags, and resyncs the personal proxy
// groups. The caller must hold t.outboundMu.
func (t *tunnel) setReverseOutboundsLocked(tags []string) error {
	if t.mutGrpMgr == nil {
		return nil
	}
	selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	if !ok {
		return errors.New("manual select group not found")
	}
	var stale []string
	for _, tag := range selector.All() {
		if lbA.IsReverseHelperTag(tag) && !slices.Contains(tags, tag) {
			stale = append(stale, tag)
		}
	}
	list := servers.ServerList{Servers: make([]*servers.Server, 0, len(tags))}
	for _, tag := range tags {
		list.Servers = append(list.Servers, reverseServer(tag))
	}
	err := t.loadOutboundsLocked(list, false)
	if errors.Is(err, errLibboxClosed) {
		return err
	}
	errs := []error{err}
	if len(stale) > 0 {
		err := t.removeOutboundsLocked(stale)
		if errors.Is(err, errLibboxClosed) {
			return err
		}
		errs = append(errs, err)
	}
	errs = append(errs, t.syncPersonalProxiesLocked())
	return errors.Join(errs...)
}

// reversePortalInbound is the portal inbound, forwarding probes that fail
// authentication to masqueradeDomain.
func reversePortalInbound(masqueradeDomain string) O.Inbound {
	return O.Inbound{
		Type:    lbC.TypeSamizdatPortal,
		Tag:     reversePortalTag,
		Options: &lbO.SamizdatPortalInboundOptions{MasqueradeDomain: masqueradeDomain},
	}
}

// loggableTag is tag, or "reverse" for a reverse tag: a reverse tag in a log
// line would show that the pairing has a reverse route.
func loggableTag(tag string) string {
	if lbA.IsReverseHelperTag(tag) {
		return "reverse"
	}
	return tag
}

// loggableTags is tags with each reverse tag replaced as loggableTag does.
func loggableTags(tags []string) []string {
	out := make([]string, len(tags))
	for i, tag := range tags {
		out[i] = loggableTag(tag)
	}
	return out
}

// loggableError is err for logging under tag: for a reverse tag, its text with
// helper and reverse tags redacted, since sing-box errors name the outbound.
func loggableError(tag string, err error) any {
	if err == nil || !lbA.IsReverseHelperTag(tag) {
		return err
	}
	return lbA.RedactHelperTags(err.Error())
}

// reverseServer is the reverse outbound for tag. It is not a Lantern server:
// the helper's bridge at the far end does not read client info.
func reverseServer(tag string) *servers.Server {
	return &servers.Server{
		Tag:  tag,
		Type: lbC.TypeSamizdatReverse,
		Options: O.Outbound{
			Tag:     tag,
			Type:    lbC.TypeSamizdatReverse,
			Options: &lbO.SamizdatReverseOutboundOptions{Portal: reversePortalTag},
		},
	}
}
