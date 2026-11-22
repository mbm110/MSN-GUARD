package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	C "github.com/getlantern/common"

	"github.com/getlantern/radiance/ipc"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn"
)

type ServersCmd struct {
	List          *ServersListCmd    `arg:"subcommand:list" help:"list servers"`
	Show          *ServersShowCmd    `arg:"subcommand:show" help:"display server by tag"`
	AddJSON       *ServersAddJSONCmd `arg:"subcommand:add-json" help:"add servers from JSON config"`
	AddURL        *ServersAddURLCmd  `arg:"subcommand:add-url" help:"add servers from URLs"`
	Remove        *ServersRemoveCmd  `arg:"subcommand:remove" help:"remove servers by tag"`
	PrivateServer *PrivateServerCmd  `arg:"subcommand:private" help:"private server operations"`
}

type ServersListCmd struct {
	Latency bool `arg:"--latency" help:"include latest latency from selection history"`
	JSON    bool `arg:"--json" help:"output JSON"`
	Limit   int  `arg:"--limit" help:"limit number of servers to list"`
}

type ServersShowCmd struct {
	Tag string `arg:"positional,required" help:"server tag"`
}

type ServersAddJSONCmd struct {
	Config string `arg:"positional,required" help:"JSON config"`
}

type ServersAddURLCmd struct {
	URLs           []string `arg:"positional,required" help:"server URLs"`
	SkipCertVerify bool     `arg:"--skip-cert-verify" help:"deprecated and ignored; TLS server identity is verified"`
}

type ServersRemoveCmd struct {
	Tags []string `arg:"positional,required" help:"server tags to remove"`
}

// ServerListEntry represents a server in the list output.
type ServerListEntry struct {
	Tag              string                    `json:"tag"`
	Type             string                    `json:"type"`
	Location         C.ServerLocation          `json:"location,omitempty"`
	SelectionHistory *servers.SelectionHistory `json:"selection_history,omitempty"`
}

// ServerDetail represents a server in the detail output; it omits the outbound
// options and private-server access token.
type ServerDetail struct {
	ServerListEntry
	IsLantern   bool                     `json:"isLantern"`
	Credentials *ServerDetailCredentials `json:"credentials,omitempty"`
}

// ServerDetailCredentials is [servers.ServerCredentials] without the access token.
type ServerDetailCredentials struct {
	Port     int  `json:"port,omitempty"`
	IsJoined bool `json:"is_joined,omitempty"`
}

func newServerListEntry(s *servers.Server) ServerListEntry {
	return ServerListEntry{
		Tag:              s.Tag,
		Type:             s.Type,
		Location:         s.Location,
		SelectionHistory: s.SelectionHistory,
	}
}

func redactServer(s *servers.Server) ServerDetail {
	if s == nil {
		return ServerDetail{}
	}
	detail := ServerDetail{
		ServerListEntry: newServerListEntry(s),
		IsLantern:       s.IsLantern,
	}
	if c := s.Credentials; c != nil {
		detail.Credentials = &ServerDetailCredentials{Port: c.Port, IsJoined: c.IsJoined}
	}
	return detail
}

type PrivateServerCmd struct {
	Add          *PrivateServerAddCmd          `arg:"subcommand:add" help:"add a private server"`
	Invite       *PrivateServerInviteCmd       `arg:"subcommand:invite" help:"create an invite for a private server"`
	RevokeInvite *PrivateServerRevokeInviteCmd `arg:"subcommand:revoke-invite" help:"revoke a private server invite"`
}

// PrivateServerConn holds connection parameters for a private server.
type PrivateServerConn struct {
	IP    string `arg:"--ip,required" help:"server IP"`
	Port  int    `arg:"--port,required" help:"server port"`
	Token string `arg:"--token,required" help:"access token"`
}

type PrivateServerAddCmd struct {
	Tag string `arg:"positional,required" help:"tag to assign to the server"`
	PrivateServerConn
}

type PrivateServerInviteCmd struct {
	Name string `arg:"positional,required" help:"invitee name"`
	PrivateServerConn
}

type PrivateServerRevokeInviteCmd struct {
	Name string `arg:"positional,required" help:"invitee name to revoke"`
	PrivateServerConn
}

func runServers(ctx context.Context, c *ipc.Client, cmd *ServersCmd) error {
	switch {
	case cmd.Show != nil:
		return serversGet(ctx, c, cmd.Show.Tag)
	case cmd.AddJSON != nil:
		return printAddedServers(c.AddServersByJSON(ctx, cmd.AddJSON.Config))
	case cmd.AddURL != nil:
		return printAddedServers(c.AddServersByURL(ctx, cmd.AddURL.URLs, cmd.AddURL.SkipCertVerify))
	case cmd.Remove != nil:
		return c.RemoveServers(ctx, cmd.Remove.Tags)
	case cmd.PrivateServer != nil:
		return runPrivateServer(ctx, c, cmd.PrivateServer)
	case cmd.List != nil:
		return serversList(ctx, c, cmd.List.Latency, cmd.List.JSON, cmd.List.Limit)
	default:
		return serversList(ctx, c, false, false, 0)
	}
}

func runPrivateServer(ctx context.Context, c *ipc.Client, cmd *PrivateServerCmd) error {
	switch {
	case cmd.Add != nil:
		return c.AddPrivateServer(ctx, cmd.Add.Tag, cmd.Add.IP, cmd.Add.Port, cmd.Add.Token, C.ServerLocation{}, false)
	case cmd.Invite != nil:
		code, err := c.InviteToPrivateServer(ctx, cmd.Invite.IP, cmd.Invite.Port, cmd.Invite.Token, cmd.Invite.Name)
		if err != nil {
			return err
		}
		fmt.Println(code)
		return nil
	case cmd.RevokeInvite != nil:
		return c.RevokePrivateServerInvite(ctx, cmd.RevokeInvite.IP, cmd.RevokeInvite.Port, cmd.RevokeInvite.Token, cmd.RevokeInvite.Name)
	default:
		return fmt.Errorf("must specify one of: add, invite, revoke-invite")
	}
}

func serversList(ctx context.Context, c *ipc.Client, showLatency, asJSON bool, limit int) error {
	srvs, err := c.Servers(ctx)
	if err != nil {
		return err
	}
	total := len(srvs)

	latestDelay := func(s *servers.Server) uint32 {
		if s.SelectionHistory != nil {
			return s.SelectionHistory.LatestSuccessDelay()
		}
		return 0
	}
	slices.SortFunc(srvs, func(a, b *servers.Server) int {
		ad := latestDelay(a)
		bd := latestDelay(b)

		switch {
		case ad == 0 && bd == 0:
			return 0
		case ad == 0:
			return 1
		case bd == 0:
			return -1
		case ad < bd:
			return -1
		case ad > bd:
			return 1
		default:
			return 0
		}
	})
	if limit > 0 && limit < len(srvs) {
		srvs = srvs[:limit]
	}

	if asJSON {
		out := make([]ServerListEntry, 0, len(srvs))
		for _, s := range srvs {
			out = append(out, newServerListEntry(s))
		}
		return printJSON(out)
	}
	if total == 0 {
		fmt.Println("No servers available")
		return nil
	}
	for _, s := range srvs {
		printServerEntry(s, showLatency)
	}
	fmt.Printf("%d total server(s)\n", total)
	return nil
}

func printServerEntry(s *servers.Server, showLatency bool) {
	fmt.Printf("  %s [%s]", s.Tag, s.Type)
	if s.Location != (C.ServerLocation{}) {
		fmt.Printf(" — %s, %s", s.Location.City, s.Location.Country)
	}
	if !showLatency {
		fmt.Println()
		return
	}
	if s.SelectionHistory != nil {
		if d := s.SelectionHistory.LatestSuccessDelay(); d > 0 {
			fmt.Printf(" (%dms)\n", d)
			return
		}
	}
	fmt.Println(" (n/a)")
}

func serversGet(ctx context.Context, c *ipc.Client, tag string) error {
	svr, exists, err := c.GetServerByTag(ctx, tag)
	if err != nil {
		return err
	}
	if !exists {
		fmt.Println("Server not found")
		return nil
	}
	return printJSON(redactServer(svr))
}

func serversSelected(ctx context.Context, c *ipc.Client) error {
	svr, exists, err := c.SelectedServer(ctx)
	if err != nil {
		return err
	}
	if !exists {
		fmt.Println("No server selected")
		return nil
	}
	return printJSON(redactServer(svr))
}

func serversAutoSelections(ctx context.Context, c *ipc.Client, watch bool) error {
	if watch {
		return c.AutoSelectedEvents(ctx, func(ev vpn.AutoSelectedEvent) {
			s := ev.Selected
			fmt.Printf("Selected: %s\n", s)
		})
	}
	sel, err := c.AutoSelected(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Selected: %s\n", sel.Tag)
	return nil
}

func printAddedServers(tags []string, err error) error {
	if err != nil {
		return err
	}
	fmt.Printf("Added %d server(s): %s\n", len(tags), strings.Join(tags, ", "))
	return nil
}
