package vpn

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
)

func TestWithHelperRoomTicketsGivesTheConsumerInviterTickets(t *testing.T) {
	src := helper.NewSource(context.Background(), func(context.Context) (helper.Tickets, error) {
		return helper.Tickets{Inviter: []string{"i.1"}, Volunteer: []string{"v.1"}, Lifetime: 15 * time.Minute}, nil
	})
	get := lbA.RoomTicketSourceFromContext(withHelperRoomTickets(context.Background(), &tunnel{inviterTickets: src}))
	require.NotNil(t, get)
	require.Eventually(t, func() bool { return slices.Equal(get(), []string{"i.1"}) }, 2*time.Second, 10*time.Millisecond,
		"the consumer gets the inviter tickets, never the volunteer ones")
}

func TestWithHelperRoomTicketsWithoutASourceAddsNothing(t *testing.T) {
	assert.Nil(t, lbA.RoomTicketSourceFromContext(withHelperRoomTickets(context.Background(), &tunnel{})))
}

type countingInviter struct{ n int }

func (c *countingInviter) Inviter() []string { c.n++; return nil }

func (c *countingInviter) InviterFor(string) ([]string, bool) { return nil, false }

// The VPN client hands its ticket source to every tunnel it builds.
func TestVPNClientPassesItsInviterTicketsToTheTunnel(t *testing.T) {
	src := &countingInviter{}
	c := NewVPNClient(t.TempDir(), nil, nil)
	c.SetInviterTickets(src)
	tn := c.newTunnel(BoxOptions{}, AutoSelectTag)
	get := lbA.RoomTicketSourceFromContext(withHelperRoomTickets(context.Background(), tn))
	require.NotNil(t, get)
	get()
	assert.Equal(t, 1, src.n)
}

// Status errors reach the UI, and sing-box names the failing outbound in them.
func TestStatusErrorsRedactHelperTags(t *testing.T) {
	got := make(chan StatusUpdateEvent, 1)
	sub := events.Subscribe(func(evt StatusUpdateEvent) {
		if evt.Status == ErrorStatus {
			got <- evt
		}
	})
	defer sub.Unsubscribe()
	c := NewVPNClient(t.TempDir(), nil, nil)
	c.setStatus(ErrorStatus, errors.New("start service: outbound/unbounded[helper-0123456789ab]: dial failed"))
	select {
	case evt := <-got:
		assert.Equal(t, "start service: outbound/unbounded[helper]: dial failed", evt.Error)
	case <-time.After(2 * time.Second):
		t.Fatal("no status event")
	}
}

// A tunnel starts the inviter ticket fetch as soon as it gets a helper
// Unbounded outbound, so its first subscribe is likely to carry tickets, and
// never for other outbounds.
func TestPrefetchInviterTicketsOnlyForHelperUnbounded(t *testing.T) {
	src := &countingInviter{}
	tn := &tunnel{inviterTickets: src}
	tn.prefetchInviterTickets([]O.Outbound{
		{Type: lbC.TypeUnbounded, Tag: "unbounded-pool"},
		{Type: lbC.TypeSamizdat, Tag: "helper-0123456789ab"},
	})
	assert.Equal(t, 0, src.n)
	tn.prefetchInviterTickets([]O.Outbound{{Type: lbC.TypeUnbounded, Tag: "helper-0123456789ab"}})
	assert.Equal(t, 1, src.n)
	(&tunnel{}).prefetchInviterTickets([]O.Outbound{{Type: lbC.TypeUnbounded, Tag: "helper-0123456789ab"}})
}
