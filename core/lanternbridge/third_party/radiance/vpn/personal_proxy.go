package vpn

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"

	"github.com/getlantern/radiance/internal/redact"
	"github.com/getlantern/radiance/servers"
)

// PersonalProxyTag is the tag of the url-test group over the selected
// friend's outbounds. The group exists only while a friend is selected and
// has a member, and is never a managed server.
const PersonalProxyTag = redact.PersonalProxyTag

// ErrPersonalProxyUnavailable is returned for a selection of PersonalProxyTag
// itself or of a friend with no member.
var ErrPersonalProxyUnavailable = errors.New("personal proxy unavailable")

// roomsConsumerType is the type of the helper outbound that reaches friends
// through their rooms on freddie. A variable so tests can stand one in.
var roomsConsumerType = lbC.TypeUnbounded

// PersonalProxySelection returns the tag that selects the personal proxy of
// the friend whose direct outbound tag (lbA.IsHelperTag) is friend.
func PersonalProxySelection(friend string) string {
	return PersonalProxyTag + ":" + friend
}

// ParsePersonalProxySelection returns the friend tag that tag selects, and
// whether tag is a PersonalProxySelection of a helper tag.
func ParsePersonalProxySelection(tag string) (friend string, ok bool) {
	friend, ok = strings.CutPrefix(tag, PersonalProxyTag+":")
	if !ok || !lbA.IsHelperTag(friend) {
		return "", false
	}
	return friend, true
}

// personalProxyOutbound is the url-test group over members, which must not be
// empty.
func personalProxyOutbound(members []string) O.Outbound {
	return O.Outbound{
		Type: lbC.TypeMutableURLTest,
		Tag:  PersonalProxyTag,
		Options: &lbO.MutableURLTestOutboundOptions{
			Outbounds:   members,
			URL:         personalProxiesProbeURL,
			Interval:    badoption.Duration(personalProxiesProbeInterval),
			IdleTimeout: badoption.Duration(urlTestIdleTimeout),
		},
	}
}

// personalProxyStartMembers returns the members of friend's group in a tunnel
// built with outbounds, whose helper tags are helpers.
func personalProxyStartMembers(friend string, helpers []string, outbounds []O.Outbound, rooms bool) []string {
	reverse := lbA.ReverseHelperTag(friend)
	var members []string
	for _, out := range outbounds {
		if !slices.Contains(helpers, out.Tag) || slices.Contains(members, out.Tag) {
			continue
		}
		consumer := out.Type == roomsConsumerType
		if (consumer && rooms) || (!consumer && (out.Tag == friend || out.Tag == reverse)) {
			members = append(members, out.Tag)
		}
	}
	return members
}

// roomsReachable reports whether a rooms consumer may reach friend: src holds
// an inviter ticket for its pairing, or has not yet been answered, when one may
// still come.
func roomsReachable(src InviterTickets, friend string) bool {
	if src == nil {
		return false
	}
	tickets, answered := src.InviterFor(friend)
	return len(tickets) > 0 || !answered
}

// selectedFriend returns the friend the tunnel's rooms tickets are narrowed
// to, or "".
func (t *tunnel) selectedFriend() string {
	if f := t.personalProxy.Load(); f != nil {
		return *f
	}
	return ""
}

// roomTickets is the rooms consumer's ticket source: every inviter ticket, or
// only the selected friend's while one is.
func (t *tunnel) roomTickets() []string {
	if friend := t.selectedFriend(); friend != "" {
		tickets, _ := t.inviterTickets.InviterFor(friend)
		return tickets
	}
	return t.inviterTickets.Inviter()
}

// personalProxyGroup returns the personal proxy group, or nil while it does
// not exist.
func (t *tunnel) personalProxyGroup() lbA.MutableOutboundGroup {
	g, _ := t.liveOutbound(PersonalProxyTag).(lbA.MutableOutboundGroup)
	return g
}

// roomsConsumersLocked returns the selector's helper outbounds that are rooms
// consumers. The caller must hold t.outboundMu.
func (t *tunnel) roomsConsumersLocked(selector lbA.MutableOutboundGroup) []string {
	var consumers []string
	for _, tag := range helperTags(selector.All()) {
		if out := t.liveOutbound(tag); out != nil && out.Type() == roomsConsumerType {
			consumers = append(consumers, tag)
		}
	}
	return consumers
}

// personalProxyMembersLocked returns what friend's group holds now: its direct
// and reverse outbounds if the selector offers them, and the rooms consumers if
// they may reach it. The caller must hold t.outboundMu.
func (t *tunnel) personalProxyMembersLocked(selector lbA.MutableOutboundGroup, friend string) []string {
	var members []string
	if slices.Contains(selector.All(), friend) {
		if out := t.liveOutbound(friend); out != nil && out.Type() != roomsConsumerType {
			members = append(members, friend)
		}
	}
	if reverse := lbA.ReverseHelperTag(friend); reverse != "" && slices.Contains(selector.All(), reverse) &&
		t.liveOutbound(reverse) != nil {
		members = append(members, reverse)
	}
	if roomsReachable(t.inviterTickets, friend) {
		members = append(members, t.roomsConsumersLocked(selector)...)
	}
	return members
}

// selectPersonalProxyLocked narrows the rooms tickets to friend, gives the
// tunnel friend's group and selects it. A change of friend restarts the rooms
// consumers, whose slots to other friends would otherwise outlive the
// narrowing, and closes every connection through the previous friend's group.
// On any failure but errLibboxClosed the selection is refused and the previous
// one restored. The caller must hold t.outboundMu.
func (t *tunnel) selectPersonalProxyLocked(friend string) error {
	if t.mutGrpMgr == nil || t.outboundMgr == nil || t.clashModeManager == nil {
		return errors.New("tunnel not running")
	}
	selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	if !ok {
		return errors.New("manual select group not found")
	}
	// Checked before anything changes, so a refused selection changes nothing.
	members := t.personalProxyMembersLocked(selector, friend)
	if len(members) == 0 {
		return ErrPersonalProxyUnavailable
	}
	prev, prevMode, prevSelected := t.personalProxy.Load(), t.clashModeManager.selectedMode(), selector.Now()
	changed := t.selectedFriend() != friend
	if changed {
		t.personalProxy.Store(&friend)
		if err := t.restartRoomsConsumersLocked(selector); err != nil {
			if errors.Is(err, errLibboxClosed) {
				return err
			}
			// Consumers restarted under the new narrowing go back to the old.
			t.personalProxy.Store(prev)
			return errors.Join(err, t.restartRoomsConsumersLocked(selector))
		}
	}
	if err := t.installPersonalProxyLocked(selector, members); err != nil {
		if errors.Is(err, errLibboxClosed) {
			return err
		}
		return errors.Join(err, t.restorePersonalProxyLocked(selector, changed, prev, prevMode, prevSelected))
	}
	// The selector keeps the same tag across friends, so it does not close the
	// previous friend's connections itself. A connection is recorded under the
	// member selected before it dialed, not the one that carried it, so none
	// is kept.
	if changed {
		t.connTracker.closeThrough(PersonalProxyTag)
	}
	return nil
}

// installPersonalProxyLocked offers a fresh group over members in place of any
// previous one, and selects it in manual mode. The caller must hold
// t.outboundMu.
func (t *tunnel) installPersonalProxyLocked(selector lbA.MutableOutboundGroup, members []string) error {
	if err := t.offerPersonalProxyLocked(selector, members, t.personalProxyFault); err != nil {
		return err
	}
	if err := faultAt(t.personalProxyFault, "select"); err != nil {
		return err
	}
	if !selector.(Selector).SelectOutbound(PersonalProxyTag) {
		return ErrPersonalProxyUnavailable
	}
	if err := faultAt(t.personalProxyFault, "mode"); err != nil {
		return err
	}
	// Last: leaving a mode closes the flows matched to it, which a restore
	// cannot reopen.
	return t.selectMode(ManualSelectTag)
}

func faultAt(fault func(step string) error, step string) error {
	if fault == nil {
		return nil
	}
	return fault(step)
}

// offerPersonalProxyLocked creates the group over members, which must not be
// empty, and has the selector offer it; a group already offered is replaced
// in place, so a selection of it never lapses. fault, if set, can fail it
// before a named step. The caller must hold t.outboundMu.
func (t *tunnel) offerPersonalProxyLocked(selector lbA.MutableOutboundGroup, members []string, fault func(step string) error) error {
	if err := faultAt(fault, "create"); err != nil {
		return err
	}
	if err := t.createPersonalProxyLocked(members); err != nil {
		return err
	}
	if err := faultAt(fault, "offer"); err != nil {
		return err
	}
	if slices.Contains(selector.All(), PersonalProxyTag) {
		replacer, ok := selector.(lbA.MemberReplacer)
		if !ok {
			return errors.New("manual selector cannot replace members")
		}
		if _, err := replacer.Replace(PersonalProxyTag); err != nil {
			return fmt.Errorf("offer personal proxy group: %w", err)
		}
	} else if _, err := selector.Add(PersonalProxyTag); err != nil {
		return fmt.Errorf("offer personal proxy group: %w", err)
	}
	return nil
}

// restorePersonalProxyLocked puts the narrowing, manual choice and mode back
// to prev, prevSelected and prevMode after a failed selectPersonalProxyLocked,
// and the group back to prev's or away if prev has no member, best effort.
// The caller must hold t.outboundMu.
func (t *tunnel) restorePersonalProxyLocked(selector lbA.MutableOutboundGroup, changed bool, prev *string,
	prevMode, prevSelected string) error {
	var errs []error
	if changed {
		t.personalProxy.Store(prev)
		errs = append(errs, t.restartRoomsConsumersLocked(selector))
	}
	var members []string
	if friend := t.selectedFriend(); friend != "" {
		members = t.personalProxyMembersLocked(selector, friend)
	}
	if len(members) > 0 {
		errs = append(errs, t.offerPersonalProxyLocked(selector, members, nil))
	} else {
		errs = append(errs, t.removePersonalProxyGroupLocked(selector))
	}
	if prevSelected != "" && selector.Now() != prevSelected && !selector.(Selector).SelectOutbound(prevSelected) {
		errs = append(errs, fmt.Errorf("restore the manual selection"))
	}
	errs = append(errs, t.selectMode(prevMode))
	return errors.Join(errs...)
}

// removePersonalProxyGroupLocked takes the group out of the selector and then
// the outbound manager, so the selector never holds a closed group. The
// caller must hold t.outboundMu.
func (t *tunnel) removePersonalProxyGroupLocked(selector lbA.MutableOutboundGroup) error {
	if slices.Contains(selector.All(), PersonalProxyTag) {
		err := faultAt(t.personalProxyFault, "remove")
		if err == nil {
			_, err = selector.Remove(PersonalProxyTag)
		}
		if err != nil {
			return err
		}
	}
	if t.personalProxyGroup() != nil {
		if err := t.outboundMgr.Remove(PersonalProxyTag); err != nil {
			return fmt.Errorf("remove personal proxy group: %w", err)
		}
	}
	return nil
}

// createPersonalProxyLocked creates the group over members, which must not be
// empty, replacing any group under its tag. The caller must hold
// t.outboundMu.
func (t *tunnel) createPersonalProxyLocked(members []string) error {
	out := personalProxyOutbound(members)
	router := service.FromContext[adapter.Router](t.ctx)
	logger := t.logFactory.NewLogger("outbound/" + out.Tag + "[" + out.Type + "]")
	if err := t.outboundMgr.Create(t.ctx, router, logger, out.Tag, out.Type, out.Options); err != nil {
		return fmt.Errorf("create personal proxy group: %w", err)
	}
	return nil
}

// syncPersonalProxyLocked makes the selected friend's group hold exactly its
// members as the outbound manager now holds them, pointing those in replaced
// at their new outbounds. When the last goes it withdraws the group (see
// withdrawPersonalProxyLocked). The caller must hold t.outboundMu.
func (t *tunnel) syncPersonalProxyLocked(replaced map[string]struct{}) error {
	friend := t.selectedFriend()
	if friend == "" || t.mutGrpMgr == nil || t.outboundMgr == nil {
		return nil
	}
	selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	if !ok {
		return errors.New("manual select group not found")
	}
	members := t.personalProxyMembersLocked(selector, friend)
	group := t.personalProxyGroup()
	switch {
	case len(members) == 0:
		return t.withdrawPersonalProxyLocked(selector)
	case group == nil:
		if err := t.createPersonalProxyLocked(members); err != nil {
			return err
		}
		if !slices.Contains(selector.All(), PersonalProxyTag) {
			if _, err := selector.Add(PersonalProxyTag); err != nil {
				return fmt.Errorf("offer personal proxy group: %w", err)
			}
		}
		return nil
	}
	// Added before the stale members go, so the group is never empty.
	if _, err := group.Add(members...); err != nil {
		return fmt.Errorf("update personal proxy group: %w", err)
	}
	var stale, swap []string
	for _, tag := range group.All() {
		if !slices.Contains(members, tag) {
			stale = append(stale, tag)
		} else if _, ok := replaced[tag]; ok {
			swap = append(swap, tag)
		}
	}
	if len(stale) > 0 {
		if _, err := group.Remove(stale...); err != nil {
			return fmt.Errorf("update personal proxy group: %w", err)
		}
	}
	return swapPersonalProxiesLocked(group, swap)
}

// deselectPersonalProxyLocked withdraws the selected friend's group, if any,
// after the selection has moved off it. The caller must hold t.outboundMu.
func (t *tunnel) deselectPersonalProxyLocked() error {
	if t.selectedFriend() == "" && t.personalProxyGroup() == nil {
		return nil
	}
	if t.mutGrpMgr == nil {
		return nil
	}
	selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	if !ok {
		return errors.New("manual select group not found")
	}
	return t.withdrawPersonalProxyLocked(selector)
}

// withdrawPersonalProxyLocked removes the friend's group and ends the
// narrowing, restarting the rooms consumers. A selection of the group falls
// back to PersonalProxiesTag if the selector offers it, else to auto-select,
// as the backend's fallbackFor does. The caller must hold t.outboundMu.
func (t *tunnel) withdrawPersonalProxyLocked(selector lbA.MutableOutboundGroup) error {
	var errs []error
	if selector.Now() == PersonalProxyTag && t.boxInstance != nil {
		fellBack := slices.Contains(selector.All(), PersonalProxiesTag) && selector.(Selector).SelectOutbound(PersonalProxiesTag)
		if !fellBack {
			if err := t.selectMode(AutoSelectTag); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if t.selectedFriend() != "" {
		t.personalProxy.Store(nil)
		if err := t.restartRoomsConsumersLocked(selector); errors.Is(err, errLibboxClosed) {
			return err
		} else if err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, t.removePersonalProxyGroupLocked(selector))
	return errors.Join(errs...)
}

// restartRoomsConsumersLocked recreates each rooms consumer under its tag from
// the options it was loaded with, so it reconnects with the tickets the
// narrowing now allows, and swaps the new one into every group holding the
// old. The caller must hold t.outboundMu.
func (t *tunnel) restartRoomsConsumersLocked(selector lbA.MutableOutboundGroup) error {
	var errs []error
	for _, tag := range t.roomsConsumersLocked(selector) {
		raw, ok := t.optsMap.Load(tag)
		if !ok {
			errs = append(errs, errors.New("restart rooms consumer: options unknown"))
			continue
		}
		var out O.Outbound
		if err := json.UnmarshalContext(t.ctx, raw, &out); err != nil {
			errs = append(errs, fmt.Errorf("restart rooms consumer: %w", err))
			continue
		}
		// Forgotten so the load does not skip identical options.
		t.optsMap.Delete(tag)
		err := t.loadOutboundsLocked(servers.ServerList{Servers: []*servers.Server{{
			Tag: tag, Type: out.Type, IsLantern: true, Options: out,
		}}}, false)
		if errors.Is(err, errLibboxClosed) {
			return err
		}
		if _, stored := t.optsMap.Load(tag); !stored {
			t.optsMap.Store(tag, raw)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("restart rooms consumer: %w", err))
			continue
		}
		delete(t.replacedHelpers, tag)
		for _, group := range []lbA.MutableOutboundGroup{t.personalProxiesGroup(), t.personalProxyGroup()} {
			if group != nil && slices.Contains(group.All(), tag) {
				errs = append(errs, swapPersonalProxiesLocked(group, []string{tag}))
			}
		}
	}
	return errors.Join(errs...)
}

// PersonalProxyStatus is what this device can reach of one friend it invited,
// identified by the friend's direct outbound tag.
type PersonalProxyStatus struct {
	Tag string `json:"tag"`
	// Direct reports whether the config carries the friend's direct outbound,
	// which it does while the friend has a live route.
	Direct bool `json:"direct"`
	// Reverse reports whether the VPN client keeps the friend's reverse tag
	// and the running tunnel's portal holds a live session the friend dialed
	// in, so the reverse outbound can carry traffic now. It is false with no
	// tunnel running, before the friend's bridge connects and once its
	// session ends.
	Reverse bool `json:"reverse"`
	// Rooms reports whether this device has a rooms consumer and an inviter
	// ticket for the friend's pairing.
	Rooms bool `json:"rooms"`
	// DirectDelayMs is the direct outbound's last URL-test delay in the
	// running tunnel, or 0 if it has none.
	DirectDelayMs uint16 `json:"direct_delay_ms,omitempty"`
	// RoomsPath is the WebRTC path of the running tunnel's rooms consumer to
	// the friend, one of the RoomsPath constants, whenever Rooms is true. It
	// is RoomsPathUnknown when the path can't be measured: no tunnel is
	// running, or another friend is selected and the consumers are narrowed
	// to that friend. It is empty only when Rooms is false, or from a radiance
	// that predates it. Rooms only says a consumer and a ticket exist: a
	// consumer whose path is RoomsPathUnavailable carries nothing, and one
	// whose path is RoomsPathUnknown may carry nothing. While no friend is
	// selected one consumer serves every friend, and a path to any of them
	// counts.
	RoomsPath string `json:"rooms_path,omitempty"`
	// RoomsPathSince is when RoomsPath's connection last changed, in Unix
	// seconds: the path connecting or dropping or, while no path has
	// connected since the consumer started, the consumer starting. Selecting
	// a friend restarts the consumers, so the clock starts over then. It is
	// omitted while RoomsPath is RoomsPathUnknown.
	RoomsPathSince int64 `json:"rooms_path_since,omitempty"`
}

// PersonalProxyStatus.RoomsPath values.
const (
	// RoomsPathConnected: a WebRTC data channel to a helper is open. The
	// egress behind it may still fail.
	RoomsPathConnected = "connected"
	// RoomsPathConnecting: no data channel has opened since the consumer
	// started, less than lbA.HelperPathGrace ago. Nothing is carried yet.
	RoomsPathConnecting = "connecting"
	// RoomsPathReconnecting: the last data channel closed less than
	// lbA.HelperPathGrace ago, which a channel that reopens at once does.
	RoomsPathReconnecting = "reconnecting"
	// RoomsPathUnavailable: the path has been down for lbA.HelperPathGrace,
	// or none has connected that long since the consumer started (the
	// friend's helper is offline or unreachable), and the consumer fails its
	// flows and dials until one connects.
	RoomsPathUnavailable = "unavailable"
	// RoomsPathUnknown: the friend has a rooms route, but its path can't be
	// measured now, because no tunnel is running or the rooms consumers are
	// narrowed to another, selected friend. The path may be down.
	RoomsPathUnknown = "unknown"
)

// roomsPathState returns s's PersonalProxyStatus.RoomsPath.
func roomsPathState(s lbA.HelperPathStatus) string {
	switch {
	case s.Connected:
		return RoomsPathConnected
	case s.Connecting:
		return RoomsPathConnecting
	case s.Available:
		return RoomsPathReconnecting
	default:
		return RoomsPathUnavailable
	}
}

// roomsPathRank orders paths from the least to the most usable.
func roomsPathRank(s lbA.HelperPathStatus) int {
	switch {
	case s.Connected:
		return 3
	case s.Available && !s.Connecting:
		return 2
	case s.Connecting:
		return 1
	default:
		return 0
	}
}

// PersonalProxyMember is what a running tunnel holds for one friend.
type PersonalProxyMember struct {
	// Direct reports whether the tunnel holds the friend's direct outbound.
	Direct bool
	// DirectDelay is the direct outbound's last URL-test delay in
	// milliseconds, or 0 if it has none.
	DirectDelay uint16
	// Rooms reports whether the tunnel holds a rooms consumer that may reach
	// the friend now and reports its path, which is then RoomsPath.
	Rooms     bool
	RoomsPath lbA.HelperPathStatus
}

// helperPathOf reads out's path to its helper (lbA.HelperPathReporter). A
// variable so tests can stand one in for consumers that are not Unbounded.
var helperPathOf = func(out adapter.Outbound) (lbA.HelperPathStatus, bool) {
	r, ok := out.(lbA.HelperPathReporter)
	if !ok {
		return lbA.HelperPathStatus{}, false
	}
	return r.HelperPath()
}

func (t *tunnel) personalProxyMember(friend string) PersonalProxyMember {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	var m PersonalProxyMember
	if t.mutGrpMgr == nil {
		return m
	}
	selector, ok := t.mutGrpMgr.OutboundGroup(ManualSelectTag)
	if !ok {
		return m
	}
	m.RoomsPath, m.Rooms = t.roomsPathLocked(selector, friend)
	if !slices.Contains(selector.All(), friend) {
		return m
	}
	out := t.liveOutbound(friend)
	if out == nil || out.Type() == roomsConsumerType {
		return m
	}
	m.Direct = true
	if t.ctx != nil {
		if h := service.PtrFromContext[urltest.HistoryStorage](t.ctx); h != nil {
			if rec := h.LoadURLTestHistory(friend); rec != nil {
				m.DirectDelay = rec.Delay
			}
		}
	}
	return m
}

// roomsPathLocked returns the most usable path of the rooms consumers that
// may reach friend now, and false if none reports one. While another friend
// is selected the consumers are narrowed to that friend's tickets, so none
// may. The caller must hold t.outboundMu.
func (t *tunnel) roomsPathLocked(selector lbA.MutableOutboundGroup, friend string) (lbA.HelperPathStatus, bool) {
	if selected := t.selectedFriend(); selected != "" && selected != friend {
		return lbA.HelperPathStatus{}, false
	}
	if !roomsReachable(t.inviterTickets, friend) {
		return lbA.HelperPathStatus{}, false
	}
	var best lbA.HelperPathStatus
	found := false
	for _, tag := range t.roomsConsumersLocked(selector) {
		out := t.liveOutbound(tag)
		if out == nil {
			continue
		}
		s, ok := helperPathOf(out)
		if ok && (!found || roomsPathRank(s) > roomsPathRank(best)) {
			best, found = s, true
		}
	}
	return best, found
}

// unixOrZero returns ts in Unix seconds, or 0 for the zero time.
func unixOrZero(ts time.Time) int64 {
	if ts.IsZero() {
		return 0
	}
	return ts.Unix()
}

// SetRoomsPath sets s's RoomsPath and RoomsPathSince from path.
func (s *PersonalProxyStatus) SetRoomsPath(path lbA.HelperPathStatus) {
	s.RoomsPath = roomsPathState(path)
	s.RoomsPathSince = unixOrZero(path.Since)
}
