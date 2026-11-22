package backend

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/broflake/common/helperticket"
	lbA "github.com/getlantern/lantern-box/adapter"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn"
)

const (
	ppFriendA  = "helper-aaaaaaaaaaaa"
	ppFriendB  = "helper-bbbbbbbbbbbb"
	ppConsumer = "helper-0000000000ff"
	ppPairingA = "6f1c2b0e-8a7d-4c1e-9f00-0123456789aa"
	ppPairingB = "6f1c2b0e-8a7d-4c1e-9f00-0123456789bb"
)

func consumerServers() servers.ServerList {
	return servers.ServerList{Servers: []*servers.Server{{
		Tag: ppConsumer, Type: "unbounded", IsLantern: true,
		Options: option.Outbound{Tag: ppConsumer, Type: "unbounded", Options: &lbO.UnboundedOutboundOptions{}},
	}}}
}

// fakeTickets is the ticket service's answer, which a test changes.
type fakeTickets struct {
	mu         sync.Mutex
	tickets    helper.Tickets
	reconciled chan struct{}
}

func (f *fakeTickets) fetch(context.Context) (helper.Tickets, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tickets, nil
}

// issue sets the answer to one inviter ticket per pairing, keyed by tag.
func (f *fakeTickets) issue(t *testing.T, pairings map[string]string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	tk := helper.Tickets{Lifetime: 15 * time.Minute}
	if len(pairings) > 0 {
		tk.InviterPairings = pairings
	}
	for _, pairing := range pairings {
		s, err := helperticket.Sign(priv, helperticket.Ticket{PairingID: pairing, Role: helperticket.RoleInviter, Expires: time.Now().Add(15 * time.Minute)})
		require.NoError(t, err)
		tk.Inviter = append(tk.Inviter, s)
	}
	f.mu.Lock()
	f.tickets = tk
	f.mu.Unlock()
}

// withTickets gives r a ticket source answering from the returned fake, as
// NewLocalBackend wires it, and waits for the reconcile its first answer runs.
func withTickets(t *testing.T, r *LocalBackend, pairings map[string]string) *fakeTickets {
	t.Helper()
	f := &fakeTickets{reconciled: make(chan struct{}, 16)}
	f.issue(t, pairings)
	r.helperTickets = helper.NewSource(r.ctx, f.fetch)
	// A reconcile still running after the test would race the next test's
	// setup (both reach sing-box's registry), so cleanup waits for it.
	var (
		mu      sync.Mutex
		stopped bool
		running sync.WaitGroup
	)
	r.helperTickets.SetOnInviterChange(func() {
		mu.Lock()
		if stopped {
			mu.Unlock()
			return
		}
		running.Add(1)
		mu.Unlock()
		defer running.Done()
		r.reconcilePersonalProxy()
		f.reconciled <- struct{}{}
	})
	t.Cleanup(func() {
		mu.Lock()
		stopped = true
		mu.Unlock()
		running.Wait()
	})
	r.helperTickets.Inviter()
	f.awaitReconcile(t)
	return f
}

// reissue changes the tickets and waits for the reconcile the change runs,
// which reads settings through sing-box's registry and so must not overlap
// the test's own reads.
func (f *fakeTickets) reissue(t *testing.T, r *LocalBackend, pairings map[string]string) {
	t.Helper()
	f.issue(t, pairings)
	r.helperTickets.Invalidate()
	r.helperTickets.Inviter()
	f.awaitReconcile(t)
}

func (f *fakeTickets) awaitReconcile(t *testing.T) {
	t.Helper()
	select {
	case <-f.reconciled:
	case <-time.After(2 * time.Second):
		t.Fatal("no reconcile after the tickets changed")
	}
}

func fallbackEvents(t *testing.T) <-chan vpn.PersonalProxyFallbackEvent {
	ch := make(chan vpn.PersonalProxyFallbackEvent, 8)
	sub := events.Subscribe(func(evt vpn.PersonalProxyFallbackEvent) { ch <- evt })
	t.Cleanup(sub.Unsubscribe)
	return ch
}

func requireFallbackEvent(t *testing.T, ch <-chan vpn.PersonalProxyFallbackEvent, want vpn.PersonalProxyFallbackEvent) {
	t.Helper()
	select {
	case got := <-ch:
		assert.Equal(t, want.Tag, got.Tag)
		assert.Equal(t, want.Fallback, got.Fallback)
	case <-time.After(2 * time.Second):
		t.Fatal("no fallback event")
	}
}

func selectedTag(t *testing.T) string {
	t.Helper()
	if settings.GetBool(settings.AutoConnectKey) {
		return vpn.AutoSelectTag
	}
	var sel servers.Server
	require.NoError(t, settings.GetStruct(settings.SelectedServerKey, &sel))
	return sel.Tag
}

// A friend's selection is persisted as its selection tag and type alone, and
// read back as long as the friend has a member.
func TestPersonalProxySelectionPersistsTheTagOnly(t *testing.T) {
	dataDir := t.TempDir()
	r := newPersonalProxiesBackendIn(t, dataDir)
	withTickets(t, r, map[string]string{ppFriendA: ppPairingA})
	require.NoError(t, r.srvManager.AddServers(directServers(ppFriendA), false))
	sel := vpn.PersonalProxySelection(ppFriendA)
	r.persistSelection(sel)

	assert.Equal(t, sel, selectedTag(t))
	raw, err := json.Marshal(settings.Get(settings.SelectedServerKey))
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, json.Unmarshal(raw, &stored))
	assert.Equal(t, sel, stored["tag"])
	assert.Equal(t, "mutableurltest", stored["type"])
	for k, v := range stored {
		if k != "tag" && k != "type" {
			assert.Empty(t, v, "only the tag and type are persisted: %s", k)
		}
	}
	file, err := os.ReadFile(filepath.Join(dataDir, "settings.json"))
	require.NoError(t, err)
	assert.Contains(t, string(file), sel)
	assert.NotContains(t, string(file), ppPairingA, "never a pairing ID")

	got, exists, err := r.SelectedServer()
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, sel, got.Tag)
	for _, s := range r.AllServers() {
		assert.NotEqual(t, sel, s.Tag, "never listed among servers")
	}
}

// Selecting a friend needs a live member: its direct outbound, or a rooms
// consumer with a ticket for its pairing.
func TestPersonalProxySelectionNeedsALiveMember(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	withTickets(t, r, map[string]string{ppFriendB: ppPairingB})
	require.NoError(t, r.srvManager.AddServers(directServers(ppFriendA), false))

	assert.True(t, r.friendReach(ppFriendA).selectable(), "direct")
	assert.False(t, r.friendReach(ppFriendB).selectable(), "a ticket without a consumer")
	require.ErrorIs(t, r.SelectServer(vpn.PersonalProxySelection(ppFriendB)), vpn.ErrPersonalProxyUnavailable)
	require.ErrorIs(t, r.SelectServer(vpn.PersonalProxySelection("helper-cccccccccccc")), vpn.ErrPersonalProxyUnavailable)
	require.Error(t, r.SelectServer(vpn.PersonalProxyTag), "the group itself is not selectable by its tag")

	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	assert.True(t, r.friendReach(ppFriendB).selectable(), "rooms only")
}

// Before the ticket source first answers, a persisted rooms-only selection
// stands, but a new one is refused.
func TestPersonalProxySelectionSurvivesUnknownTickets(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	r.helperTickets = helper.NewSource(r.ctx, func(ctx context.Context) (helper.Tickets, error) {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return helper.Tickets{}, ctx.Err()
	})
	f := r.friendReach(ppFriendA)
	assert.True(t, f.live())
	assert.False(t, f.selectable())
}

// A friend whose direct outbound goes keeps the selection while a rooms
// ticket remains; when the last member goes the selection falls back to the
// personal proxies group, and then, with no helpers left, to auto-select.
func TestPersonalProxySelectionFallsBackWhenItsLastMemberGoes(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up()
	tickets := withTickets(t, r, map[string]string{ppFriendA: ppPairingA, ppFriendB: ppPairingB})
	evts := fallbackEvents(t)
	all := directServers(ppFriendA, ppFriendB)
	all.Servers = append(all.Servers, consumerServers().Servers...)
	require.NoError(t, r.updateServers(all, true))
	sel := vpn.PersonalProxySelection(ppFriendA)
	r.persistSelection(sel)

	// Friend A goes offline: its direct route goes, its ticket stays.
	rest := directServers(ppFriendB)
	rest.Servers = append(rest.Servers, consumerServers().Servers...)
	require.NoError(t, r.updateServers(rest, true))
	assert.Equal(t, sel, selectedTag(t), "the group shrinks; the selection stays")
	assert.Empty(t, evts)

	// Its pairing ends: the ticket goes too.
	tickets.reissue(t, r, map[string]string{ppFriendB: ppPairingB})
	requireFallbackEvent(t, evts, vpn.PersonalProxyFallbackEvent{Tag: ppFriendA, Fallback: vpn.PersonalProxiesTag})
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
	assert.Contains(t, tun.callLog(), "select:"+vpn.PersonalProxiesTag)

	// With no helper left, a friend's selection falls back to auto-select.
	require.NoError(t, r.updateServers(directServers(ppFriendB), true))
	r.persistSelection(vpn.PersonalProxySelection(ppFriendB))
	require.NoError(t, r.updateServers(directServers("lantern-1"), true))
	requireFallbackEvent(t, evts, vpn.PersonalProxyFallbackEvent{Tag: ppFriendB, Fallback: vpn.AutoSelectTag})
	assert.Equal(t, vpn.AutoSelectTag, selectedTag(t))
}

// A ticket-key rotation changes every tag at once: the selected tag vanishes
// from the config and the tickets, and the selection falls back.
func TestPersonalProxySelectionFallsBackWhenItsTagIsRotated(t *testing.T) {
	const rotatedA, rotatedB = "helper-abababababab", "helper-bcbcbcbcbcbc"
	r := newPersonalProxiesBackend(t)
	tickets := withTickets(t, r, map[string]string{ppFriendA: ppPairingA, ppFriendB: ppPairingB})
	evts := fallbackEvents(t)
	before := directServers(ppFriendA, ppFriendB)
	before.Servers = append(before.Servers, consumerServers().Servers...)
	require.NoError(t, r.updateServers(before, true))
	r.persistSelection(vpn.PersonalProxySelection(ppFriendA))

	tickets.reissue(t, r, map[string]string{rotatedA: ppPairingA, rotatedB: ppPairingB})
	after := directServers(rotatedA, rotatedB)
	after.Servers = append(after.Servers, consumerServers().Servers...)
	require.NoError(t, r.updateServers(after, true))
	requireFallbackEvent(t, evts, vpn.PersonalProxyFallbackEvent{Tag: ppFriendA, Fallback: vpn.PersonalProxiesTag})
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
}

// Other selections still fall back straight to auto-select, without an event.
func TestServerSelectionStillFallsBackToAuto(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	evts := fallbackEvents(t)
	require.NoError(t, r.updateServers(directServers("lantern-1", ppFriendA), true))
	r.persistSelection("lantern-1")
	_, err := r.srvManager.RemoveServers([]string{"lantern-1"})
	require.NoError(t, err)
	r.clearSelectedIfMissing()
	assert.Equal(t, vpn.AutoSelectTag, selectedTag(t))
	assert.Empty(t, evts)
}

func TestPersonalProxyStatus(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	assert.Empty(t, r.PersonalProxyStatus())
	withTickets(t, r, map[string]string{ppFriendA: ppPairingA, ppFriendB: ppPairingB})
	require.NoError(t, r.srvManager.AddServers(directServers(ppFriendA, "lantern-1"), false))
	assert.Equal(t, []vpn.PersonalProxyStatus{
		{Tag: ppFriendA, Direct: true},
		{Tag: ppFriendB},
	}, r.PersonalProxyStatus(), "no consumer, no rooms")

	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	assert.Equal(t, []vpn.PersonalProxyStatus{
		{Tag: ppFriendA, Direct: true, Rooms: true, RoomsPath: vpn.RoomsPathUnknown},
		{Tag: ppFriendB, Rooms: true, RoomsPath: vpn.RoomsPathUnknown},
	}, r.PersonalProxyStatus(), "with no tunnel running the rooms path can't be measured")
}

// A friend's reverse outbound is part of that friend, never a friend of its
// own, and alone makes the friend selectable. The status reports it only with
// a live session, which no tunnel means there is not.
func TestPersonalProxyStatusFoldsReverseOutboundsIntoTheirFriend(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(directServers(ppFriendA, "lantern-1"), false))
	require.NoError(t, r.vpnClient.SetReverseOutbounds([]string{
		lbA.ReverseHelperTag(ppFriendA), lbA.ReverseHelperTag(ppFriendB),
	}))
	assert.Equal(t, []vpn.PersonalProxyStatus{
		{Tag: ppFriendA, Direct: true},
		{Tag: ppFriendB},
	}, r.PersonalProxyStatus(), "configured, but no session")
	_, found := r.GetServerByTag(vpn.PersonalProxySelection(ppFriendB))
	assert.True(t, found)
	assert.NoError(t, r.checkConnectSelection(t.Context(), vpn.PersonalProxySelection(ppFriendB)))
}

// A connect may restore the persisted friend before its tickets are known,
// but a friend it newly chooses must be selectable, as SelectServer requires.
func TestConnectRefusesANewFriendWithoutAMember(t *testing.T) {
	shortenConnectTicketWait(t, 50*time.Millisecond)
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	r.helperTickets = helper.NewSource(r.ctx, func(ctx context.Context) (helper.Tickets, error) {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return helper.Tickets{}, ctx.Err()
	})
	persisted, fresh := vpn.PersonalProxySelection(ppFriendA), vpn.PersonalProxySelection(ppFriendB)
	r.persistSelection(persisted)
	require.Equal(t, persisted, selectedTag(t))

	require.ErrorIs(t, r.ConnectVPN(t.Context(), fresh), vpn.ErrPersonalProxyUnavailable)
	assert.NoError(t, r.checkConnectSelection(t.Context(), persisted), "the persisted friend is restored")
}

// selectionSaves records, for each SelectionSavedEvent, the selection a
// settings read saw when the event was handled.
func selectionSaves(t *testing.T) <-chan string {
	ch := make(chan string, 16)
	sub := events.Subscribe(func(vpn.SelectionSavedEvent) {
		if settings.GetBool(settings.AutoConnectKey) {
			ch <- vpn.AutoSelectTag
			return
		}
		var sel servers.Server
		_ = settings.GetStruct(settings.SelectedServerKey, &sel)
		ch <- sel.Tag
	})
	t.Cleanup(sub.Unsubscribe)
	return ch
}

func requireSaved(t *testing.T, saves <-chan string, want string) {
	t.Helper()
	select {
	case got := <-saves:
		assert.Equal(t, want, got, "the event follows the save")
	case <-time.After(2 * time.Second):
		t.Fatal("no selection saved event")
	}
}

func requireNoSave(t *testing.T, saves <-chan string) {
	t.Helper()
	select {
	case got := <-saves:
		t.Fatalf("selection saved event for %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// Every path that saves the selection announces it once the save is
// readable: a select, a connect, a fallback and a settings patch.
func TestSelectionSavedEvents(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up()
	require.NoError(t, r.updateServers(directServers("lantern-1", "lantern-2", ppFriendA), true))
	saves := selectionSaves(t)

	require.NoError(t, r.SelectServer("lantern-1"))
	requireSaved(t, saves, "lantern-1")

	r.persistConnectedSelection("lantern-2")
	requireSaved(t, saves, "lantern-2")

	r.persistSelection(vpn.PersonalProxySelection(ppFriendA))
	requireSaved(t, saves, vpn.PersonalProxySelection(ppFriendA))
	require.NoError(t, r.updateServers(directServers("lantern-1", "lantern-2"), true))
	requireSaved(t, saves, vpn.AutoSelectTag)

	require.NoError(t, r.SelectServer("lantern-1"))
	requireSaved(t, saves, "lantern-1")
	require.NoError(t, r.PatchSettings(settings.Settings{settings.AutoConnectKey: true}))
	requireSaved(t, saves, vpn.AutoSelectTag)
}

// A selection that is refused, or whose save fails, announces nothing.
func TestSelectionSavedEventsOnlyAfterASave(t *testing.T) {
	dataDir := t.TempDir()
	r := newPersonalProxiesBackendIn(t, dataDir)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up()
	require.NoError(t, r.updateServers(directServers("lantern-1"), true))
	saves := selectionSaves(t)

	require.Error(t, r.SelectServer("lantern-unknown"))
	requireNoSave(t, saves)

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions don't block writes on Windows or as root")
	}
	require.NoError(t, os.Chmod(dataDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })
	r.persistSelection("lantern-1")
	requireNoSave(t, saves)
}

// closableBackend is a personal proxies backend that Close can tear down.
func closableBackend(t *testing.T) *LocalBackend {
	t.Helper()
	r := newPersonalProxiesBackend(t)
	ctx, cancel := context.WithCancel(r.ctx)
	r.ctx, r.cancel = ctx, cancel
	return r
}

// A ticket-change reconcile delayed until after Close must not touch the
// saved selection: on mobile a replacement backend may own it by then.
func TestTicketReconcileStopsAtClose(t *testing.T) {
	t.Run("after close", func(t *testing.T) {
		r := closableBackend(t)
		sel := vpn.PersonalProxySelection(ppFriendA)
		require.NoError(t, r.srvManager.AddServers(directServers(ppFriendA), false))
		r.persistSelection(sel)
		_, err := r.srvManager.RemoveServers([]string{ppFriendA})
		require.NoError(t, err)
		r.Close()
		r.reconcilePersonalProxy()
		assert.Equal(t, sel, selectedTag(t), "a closed backend fell back")
	})
	t.Run("in flight", func(t *testing.T) {
		r := closableBackend(t)
		r.selectionMu.Lock() // a reconcile in flight
		closed := make(chan struct{})
		go func() { r.Close(); close(closed) }()
		select {
		case <-closed:
			r.selectionMu.Unlock()
			t.Fatal("Close returned while a reconcile held the selection")
		case <-time.After(200 * time.Millisecond):
		}
		r.selectionMu.Unlock()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Close never returned")
		}
	})
}

// A rooms-only friend whose last ticket goes while the tunnel switches to it
// is still saved as the selection the tunnel made.
func TestSelectServerSavesTheFriendItSwitchedTo(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up()
	list := directServers("lantern-1")
	list.Servers = append(list.Servers, consumerServers().Servers...)
	require.NoError(t, r.updateServers(list, true))
	require.NoError(t, r.SelectServer("lantern-1"))
	f := &fakeTickets{}
	f.issue(t, map[string]string{ppFriendA: ppPairingA})
	r.helperTickets = helper.NewSource(r.ctx, f.fetch)
	require.Eventually(t, func() bool { tk, _ := r.helperTickets.InviterFor(ppFriendA); return len(tk) > 0 },
		2*time.Second, 5*time.Millisecond)

	tun.onSelect = func() {
		tun.onSelect = nil
		f.issue(t, nil)
		r.helperTickets.Invalidate()
		require.Eventually(t, func() bool { tk, _ := r.helperTickets.InviterFor(ppFriendA); return len(tk) == 0 },
			2*time.Second, 5*time.Millisecond)
	}
	sel := vpn.PersonalProxySelection(ppFriendA)
	require.NoError(t, r.SelectServer(sel))
	assert.Equal(t, sel, selectedTag(t), "the switch was made but not saved")
}

// A restart rebuilds the tunnel on the saved selection, a friend's included,
// rather than in auto-select; a saved server the manager no longer holds
// restarts in auto-select.
func TestRestartKeepsTheSavedSelection(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(directServers("lantern-1", ppFriendA), false))
	sel := vpn.PersonalProxySelection(ppFriendA)
	for _, tag := range []string{"lantern-1", sel} {
		r.persistSelection(tag)
		assert.Equal(t, tag, r.restartBoxOptions().InitialServer)
	}
	r.persistSelection(vpn.AutoSelectTag)
	assert.Equal(t, vpn.AutoSelectTag, r.restartBoxOptions().InitialServer)

	r.persistSelection("lantern-1")
	_, err := r.srvManager.RemoveServers([]string{"lantern-1"})
	require.NoError(t, err)
	assert.Equal(t, vpn.AutoSelectTag, r.restartBoxOptions().InitialServer)
}

// A platform restart reconnects through ConnectVPN on auto. The saved manual
// selection must survive it, both saved and on the rebuilt tunnel.
func TestPlatformRestartKeepsTheManualSelection(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(directServers("lantern-1"), false))
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.ConnectVPN(ctx, "lantern-1"))

	tun.platformRestart = func() {
		require.NoError(t, r.ConnectVPN(ctx, vpn.AutoSelectTag))
	}
	require.NoError(t, r.RestartVPN())
	assert.Equal(t, "lantern-1", selectedTag(t))
	assert.Equal(t, "lantern-1", tun.current())
}

// Outside a restart, an auto connect is how a manual selection is replaced
// with auto, so it must not be redirected to the saved selection.
func TestAutoConnectReplacesTheManualSelection(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(directServers("lantern-1"), false))
	r.persistSelection("lantern-1")
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.ConnectVPN(ctx, vpn.AutoSelectTag))
	assert.Equal(t, vpn.AutoSelectTag, selectedTag(t))
	assert.Equal(t, vpn.AutoSelectTag, tun.current())
}

// A server added and selected while a restart captures its options must not
// become the initial selection of options that lack it.
func TestRestartOptionsPairTheSelectionWithItsOutbounds(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up()
	require.NoError(t, r.updateServers(directServers("lantern-1"), true))
	require.NoError(t, r.SelectServer("lantern-1"))
	done := make(chan error, 1)
	r.beforeRestartSelection = func() {
		r.beforeRestartSelection = nil
		go func() {
			if err := r.updateServers(directServers("lantern-1", "lantern-2"), true); err != nil {
				done <- err
				return
			}
			done <- r.SelectServer("lantern-2")
		}()
		select {
		case err := <-done:
			done <- err
		case <-time.After(200 * time.Millisecond):
		}
	}
	bOptions := r.restartBoxOptions()
	tags := make([]string, 0, len(bOptions.Options.Outbounds))
	for _, out := range bOptions.Options.Outbounds {
		tags = append(tags, out.Tag)
	}
	assert.Contains(t, tags, bOptions.InitialServer)
	require.NoError(t, <-done)
	assert.Equal(t, "lantern-2", selectedTag(t))
}

// A selection saved after a restart captured the previous one, but before it
// rebuilt the tunnel, must still be the one the rebuilt tunnel carries.
func TestRestartAppliesASelectionSavedDuringIt(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up()
	require.NoError(t, r.updateServers(directServers("lantern-1", "lantern-2"), true))
	require.NoError(t, r.SelectServer("lantern-1"))
	tun.onRestart = func() {
		tun.onRestart = nil
		done := make(chan error, 1)
		go func() { done <- r.SelectServer("lantern-2") }()
		require.NoError(t, <-done)
	}
	require.NoError(t, r.RestartVPN())
	assert.Equal(t, "lantern-2", selectedTag(t))
	assert.Equal(t, "lantern-2", tun.current(), "the rebuilt tunnel carries the stale selection")
}

// A personal proxies group saved during a restart while it has no member is
// applied as auto-select, which the rebuilt tunnel can carry, and stays saved.
func TestRestartAppliesAnEmptyGroupSavedDuringItAsAuto(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	r.reverseFriends = &reverseFriends{byPairing: map[string]string{pairingHash(reversePairing): ppFriendB}}
	tun := &fakeHelperTunnel{refuseGroup: true}
	tun.attach(r)
	tun.up()
	require.NoError(t, r.updateServers(directServers("lantern-1"), true))
	require.NoError(t, r.SelectServer("lantern-1"))
	tun.onRestart = func() {
		tun.onRestart = nil
		r.persistSelection(vpn.PersonalProxiesTag)
	}
	require.NoError(t, r.RestartVPN())
	assert.Equal(t, vpn.AutoSelectTag, tun.current())
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
}

// A tunnel built while the selected friend had no member starts on the
// personal proxies group. If the friend is reachable once the tunnel is up,
// the connect or restart switches to it; if not, it commits the fallback, so
// the saved selection never names a friend the tunnel is not on.
func TestStartOffTheSelectedFriendSettles(t *testing.T) {
	sel := vpn.PersonalProxySelection(ppFriendA)
	starts := map[string]func(t *testing.T, r *LocalBackend, tun *fakeHelperTunnel) error{
		"connect": func(t *testing.T, r *LocalBackend, _ *fakeHelperTunnel) error {
			return r.ConnectVPN(t.Context(), sel)
		},
		"restart": func(_ *testing.T, r *LocalBackend, tun *fakeHelperTunnel) error {
			tun.up()
			return r.RestartVPN()
		},
	}
	setup := func(t *testing.T) (*LocalBackend, *fakeHelperTunnel) {
		r := newPersonalProxiesBackend(t)
		tun := &fakeHelperTunnel{friendless: true}
		tun.attach(r)
		require.NoError(t, r.srvManager.AddServers(directServers("lantern-1", ppFriendA), false))
		r.persistSelection(sel)
		return r, tun
	}
	for name, start := range starts {
		t.Run(name+" reachable", func(t *testing.T) {
			r, tun := setup(t)
			evts := fallbackEvents(t)
			require.NoError(t, start(t, r, tun))
			assert.Equal(t, sel, selectedTag(t))
			assert.Equal(t, sel, tun.current(), "the tunnel stayed on the personal proxies group")
			assert.Equal(t, ppFriendA, tun.SelectedPersonalProxy())
			assert.Empty(t, evts)
		})
		t.Run(name+" unreachable", func(t *testing.T) {
			r, tun := setup(t)
			tun.refuseFriend = true
			evts := fallbackEvents(t)
			require.NoError(t, start(t, r, tun))
			assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t), "the saved selection names a friend the tunnel is not on")
			assert.Equal(t, vpn.PersonalProxiesTag, tun.current())
			requireFallbackEvent(t, evts, vpn.PersonalProxyFallbackEvent{Tag: ppFriendA, Fallback: vpn.PersonalProxiesTag})
		})
	}
}

// A friend added and selected after a restart captured its options is
// missing from the rebuilt tunnel until its helpers are reconciled, which
// must happen before the restart takes the friend up rather than fall back.
func TestRestartTakesUpAFriendAddedDuringIt(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{rebuild: true}
	tun.attach(r)
	tun.up()
	require.NoError(t, r.updateServers(directServers("lantern-1", ppFriendA), true))
	require.NoError(t, r.SelectServer("lantern-1"))
	sel := vpn.PersonalProxySelection(ppFriendB)
	tun.onRestart = func() {
		tun.onRestart = nil
		require.NoError(t, r.updateServers(directServers("lantern-1", ppFriendA, ppFriendB), true))
		require.NoError(t, r.SelectServer(sel))
	}
	evts := fallbackEvents(t)
	require.NoError(t, r.RestartVPN())
	assert.Equal(t, sel, selectedTag(t), "the friend's selection fell back")
	assert.Equal(t, sel, tun.current())
	assert.Equal(t, ppFriendB, tun.SelectedPersonalProxy())
	assert.Empty(t, evts)
}

func shortenConnectTicketWait(t *testing.T, d time.Duration) {
	t.Helper()
	prev := connectTicketWait
	connectTicketWait = d
	t.Cleanup(func() { connectTicketWait = prev })
}

// delayedTickets gives r a ticket source whose first fetch answers with
// pairings only once release is closed.
func delayedTickets(t *testing.T, r *LocalBackend, pairings map[string]string) (release chan struct{}) {
	t.Helper()
	f := &fakeTickets{}
	f.issue(t, pairings)
	release = make(chan struct{})
	r.helperTickets = helper.NewSource(r.ctx, func(ctx context.Context) (helper.Tickets, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return helper.Tickets{}, ctx.Err()
		}
		return f.fetch(ctx)
	})
	return release
}

// On macOS and iOS the backend starts with the tunnel, a moment before the
// connect is checked, and holds no tickets yet. With auto-connect on, no
// selection is exempt, so a friend reachable only through rooms is accepted
// once the first fetch brings its ticket.
func TestConnectWaitsForTheFirstTicketFetch(t *testing.T) {
	shortenConnectTicketWait(t, 5*time.Second)
	r := newPersonalProxiesBackend(t)
	require.NoError(t, settings.Set(settings.AutoConnectKey, true))
	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	release := delayedTickets(t, r, map[string]string{ppFriendB: ppPairingB})
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(release)
	}()

	assert.NoError(t, r.checkConnectSelection(t.Context(), vpn.PersonalProxySelection(ppFriendB)))
}

// Once lantern-cloud has answered, a friend whose ticket it didn't send is
// refused at once rather than after the whole wait.
func TestConnectRefusesOnceTicketsAnswerWithoutTheFriend(t *testing.T) {
	shortenConnectTicketWait(t, 5*time.Second)
	r := newPersonalProxiesBackend(t)
	require.NoError(t, settings.Set(settings.AutoConnectKey, true))
	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	close(delayedTickets(t, r, map[string]string{ppFriendA: ppPairingA}))

	start := time.Now()
	err := r.checkConnectSelection(t.Context(), vpn.PersonalProxySelection(ppFriendB))
	assert.ErrorIs(t, err, vpn.ErrPersonalProxyUnavailable)
	assert.Less(t, time.Since(start), time.Second)
}

// Without a rooms consumer, tickets can't make the friend selectable, so the
// connect is refused without waiting for them.
func TestConnectDoesNotWaitForTicketsWithoutAConsumer(t *testing.T) {
	shortenConnectTicketWait(t, 5*time.Second)
	r := newPersonalProxiesBackend(t)
	require.NoError(t, settings.Set(settings.AutoConnectKey, true))
	delayedTickets(t, r, map[string]string{ppFriendB: ppPairingB})

	start := time.Now()
	err := r.checkConnectSelection(t.Context(), vpn.PersonalProxySelection(ppFriendB))
	assert.ErrorIs(t, err, vpn.ErrPersonalProxyUnavailable)
	assert.Less(t, time.Since(start), time.Second)
}

// A disconnect while a connect waits for tickets stops it from starting the
// tunnel once they arrive: Disconnect found no tunnel to stop.
func TestDisconnectCancelsAConnectWaitingForTickets(t *testing.T) {
	shortenConnectTicketWait(t, 5*time.Second)
	r := newPersonalProxiesBackend(t)
	require.NoError(t, settings.Set(settings.AutoConnectKey, true))
	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	release := delayedTickets(t, r, map[string]string{ppFriendB: ppPairingB})

	done := make(chan error, 1)
	go func() { done <- r.ConnectVPN(t.Context(), vpn.PersonalProxySelection(ppFriendB)) }()
	require.Eventually(t, func() bool {
		r.pendingConnectMu.Lock()
		defer r.pendingConnectMu.Unlock()
		return r.pendingConnect != nil
	}, 2*time.Second, 5*time.Millisecond, "the connect is waiting")
	time.Sleep(50 * time.Millisecond)
	_ = r.DisconnectVPN()
	close(release)

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("the connect didn't return after the disconnect")
	}
	assert.NotEqual(t, vpn.Connected, r.liveTunnel().Status())
}
