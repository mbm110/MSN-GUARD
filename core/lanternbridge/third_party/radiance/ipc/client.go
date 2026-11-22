package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"syscall"
	"time"

	C "github.com/getlantern/common"
	box "github.com/getlantern/lantern-box"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/issue"
	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/unbounded"
	"github.com/getlantern/radiance/usermessage"
	"github.com/getlantern/radiance/vpn"

	sjson "github.com/sagernet/sing/common/json"
)

func newClient() *Client {
	return &Client{
		http: &http.Client{
			Transport: &http.Transport{
				DialContext:       dialContext,
				ForceAttemptHTTP2: true,
				Protocols:         &protocols,
			},
		},
	}
}

// marshalBody encodes body as a JSON reader suitable for an HTTP request body.
// Returns nil if body is nil.
func marshalBody(body any) (io.Reader, error) {
	if body == nil {
		return nil, nil
	}
	switch body := body.(type) {
	case []byte:
		return bytes.NewReader(body), nil
	default:
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		return bytes.NewReader(data), nil
	}
}

// doJSON executes an HTTP request and decodes the JSON response into dst.
func (c *Client) doJSON(ctx context.Context, method, endpoint string, body, dst any) error {
	data, err := c.do(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if dst == nil {
		return nil
	}
	return json.Unmarshal(data, dst)
}

// Error is returned by Client methods when the server responds with an error status.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("ipc: status %d: %s", e.Status, e.Message)
}

// IsNotFound reports whether the error is a 404 response.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

///////////////////
//   Peer share  //
///////////////////

// PeerStatus reads the peer client's current lifecycle state.
//
// This seeds consumers that attach to the peer-status *events* stream after
// the client is already running. The SSE handler replays a snapshot on
// connect, so its consumers are covered; the in-process bus used by localOnly
// builds is not — events.SubscribeContext is purely edge-triggered, so an
// in-process subscriber sees nothing until the next transition. That gap is
// routine, not rare: the peer client resumes from persisted settings at
// process start, well before any UI subscribes, and a UI restart leaves
// radiance running. Without reading the current state, such a consumer sits
// on whatever it assumed at startup.
func (c *Client) PeerStatus(ctx context.Context) (peer.Status, error) {
	var status peer.Status
	err := c.doJSON(ctx, http.MethodGet, peerStatusEndpoint, nil, &status)
	return status, err
}

// PeerRelaySnapshot reads the bytes the current or most recent direct-sharing
// session has relayed, in the shape of UnboundedSnapshot.
func (c *Client) PeerRelaySnapshot(ctx context.Context) (peer.Snapshot, error) {
	var s peer.Snapshot
	err := c.doJSON(ctx, http.MethodGet, peerSnapshotEndpoint, nil, &s)
	return s, err
}

/////////////
//   VPN   //
/////////////

func (c *Client) VPNStatus(ctx context.Context) (vpn.VPNStatus, error) {
	var status vpn.VPNStatus
	err := c.doJSON(ctx, http.MethodGet, vpnStatusEndpoint, nil, &status)
	return status, err
}

// ConnectVPN connects the VPN using the given server tag.
func (c *Client) ConnectVPN(ctx context.Context, tag string) error {
	_, err := c.do(ctx, http.MethodPost, vpnConnectEndpoint, TagRequest{Tag: tag})
	return err
}

// DisconnectVPN disconnects the VPN.
func (c *Client) DisconnectVPN(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, vpnDisconnectEndpoint, nil)
	return err
}

// RestartVPN restarts the VPN connection.
func (c *Client) RestartVPN(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, vpnRestartEndpoint, nil)
	return err
}

// ResetNetwork asks the daemon to drop VPN connections and re-seed interface state.
func (c *Client) ResetNetwork(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, vpnResetNetworkEndpoint, nil)
	return err
}

// Pause asks the daemon to pause the VPN for a device sleep.
func (c *Client) Pause(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, vpnPauseEndpoint, nil)
	return err
}

// Wake asks the daemon to wake the VPN after a device sleep.
func (c *Client) Wake(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, vpnWakeEndpoint, nil)
	return err
}

// VPNConnections returns the active VPN connections.
func (c *Client) VPNConnections(ctx context.Context) ([]vpn.Connection, error) {
	var conns []vpn.Connection
	err := c.doJSON(ctx, http.MethodGet, vpnConnectionsEndpoint, nil, &conns)
	return conns, err
}

// VPNSessions returns recorded VPN sessions in descending order. A limit value of 0 returns all
// sessions.
func (c *Client) VPNSessions(ctx context.Context, limit int) ([]vpn.Session, error) {
	endpoint := vpnSessionsEndpoint
	if limit > 0 {
		endpoint = fmt.Sprintf("%s?limit=%d", endpoint, limit)
	}
	var sessions []vpn.Session
	err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &sessions)
	return sessions, err
}

// ClearTunnelCache removes the tunnel cache. If the tunnel is connected, the
// backend restarts it to apply the removal, since the cache cannot be deleted
// while in use.
func (c *Client) ClearTunnelCache(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, vpnClearTunnelCacheEndpoint, nil)
	return err
}

// VPNThroughput returns the most recent global and per-outbound throughput sample.
func (c *Client) VPNThroughput(ctx context.Context) (vpn.ThroughputSnapshot, error) {
	var s vpn.ThroughputSnapshot
	err := c.doJSON(ctx, http.MethodGet, vpnThroughputEndpoint, nil, &s)
	return s, err
}

// RunOfflineURLTests runs URL performance tests when offline (VPN disconnected) and caches the
// results. This enables autoconnect to select the best server for the initial connection.
func (c *Client) RunOfflineURLTests(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, vpnOfflineTestsEndpoint, nil)
	return err
}

///////////////////////
// Server selection  //
///////////////////////

// boxCtx holds the sing-box registries and should not be mutated. It is used
// for JSON marshalling/unmarshalling of server options.
var boxCtx = box.Context(context.Background())

// SelectServer selects the server with the given tag.
func (c *Client) SelectServer(ctx context.Context, tag string) error {
	_, err := c.do(ctx, http.MethodPost, serverSelectedEndpoint, TagRequest{Tag: tag})
	return err
}

// SelectedServer returns the currently selected server and whether it still exists.
func (c *Client) SelectedServer(ctx context.Context) (*servers.Server, bool, error) {
	data, err := c.do(ctx, http.MethodGet, serverSelectedEndpoint, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := sjson.UnmarshalExtendedContext[SelectedServerResponse](boxCtx, data)
	return resp.Server, resp.Exists, err
}

// SelectedServerJSON returns the currently selected server as raw JSON bytes.
func (c *Client) SelectedServerJSON(ctx context.Context) ([]byte, error) {
	return c.do(ctx, http.MethodGet, serverSelectedEndpoint, nil)
}

// AutoSelected returns the server that's currently auto-selected.
func (c *Client) AutoSelected(ctx context.Context) (*servers.Server, error) {
	data, err := c.do(ctx, http.MethodGet, serverAutoSelectedEndpoint, nil)
	if err != nil {
		return nil, err
	}
	return sjson.UnmarshalExtendedContext[*servers.Server](boxCtx, data)
}

////////////
// Config //
////////////

// UpdateConfig forces an immediate config fetch on the daemon. Returns an error
// if config fetching is disabled.
func (c *Client) UpdateConfig(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, configUpdateEndpoint, nil)
	return err
}

// CurrentUserMessage returns the pending message for the current account.
func (c *Client) CurrentUserMessage(ctx context.Context) (*usermessage.Message, error) {
	var response CurrentUserMessageResponse
	if err := c.doJSON(ctx, http.MethodGet, userMessageEndpoint, nil, &response); err != nil {
		return nil, err
	}
	return response.Message, nil
}

// RefreshUserMessages schedules an immediate server eligibility refresh.
func (c *Client) RefreshUserMessages(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, userMessageRefreshEndpoint, nil)
	return err
}

// AcknowledgeUserMessage records that the UI displayed displayID.
func (c *Client) AcknowledgeUserMessage(ctx context.Context, displayID, accountID string) error {
	_, err := c.do(ctx, http.MethodPost, userMessageAcknowledgeEndpoint,
		UserMessageAcknowledgeRequest{DisplayID: displayID, AccountID: accountID})
	return err
}

// SetUserMessageActivity updates the app lifecycle used by polling.
func (c *Client) SetUserMessageActivity(ctx context.Context, active bool) error {
	_, err := c.do(ctx, http.MethodPatch, userMessageActivityEndpoint,
		UserMessageActivityRequest{Active: active})
	return err
}

///////////////////////
// Server management //
///////////////////////

// Servers returns all servers.
func (c *Client) Servers(ctx context.Context) ([]*servers.Server, error) {
	data, err := c.do(ctx, http.MethodGet, serversEndpoint, nil)
	if err != nil {
		return nil, err
	}
	return sjson.UnmarshalExtendedContext[[]*servers.Server](boxCtx, data)
}

// ServersJSON returns all servers as raw JSON bytes.
// This is useful when the caller needs to forward the JSON without re-marshaling,
// since the server options require sing-box's context-aware JSON encoder.
func (c *Client) ServersJSON(ctx context.Context) ([]byte, error) {
	return c.do(ctx, http.MethodGet, serversEndpoint, nil)
}

// GetServerByTag returns the server with the given tag.
func (c *Client) GetServerByTag(ctx context.Context, tag string) (*servers.Server, bool, error) {
	q := url.Values{"tag": {tag}}
	data, err := c.do(ctx, http.MethodGet, serversEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		if IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	server, err := sjson.UnmarshalExtendedContext[*servers.Server](boxCtx, data)
	if err != nil {
		return nil, false, err
	}
	return server, true, nil
}

// GetServerByTagJSON returns the server with the given tag as raw JSON bytes.
func (c *Client) GetServerByTagJSON(ctx context.Context, tag string) ([]byte, bool, error) {
	q := url.Values{"tag": {tag}}
	data, err := c.do(ctx, http.MethodGet, serversEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		if IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

// AddServers adds servers.
func (c *Client) AddServers(ctx context.Context, list servers.ServerList) error {
	req := AddServersRequest{Servers: list}
	body, err := sjson.MarshalContext(boxCtx, req)
	if err != nil {
		return fmt.Errorf("marshal add servers request: %w", err)
	}
	_, err = c.do(ctx, http.MethodPost, serversAddEndpoint, body)
	return err
}

// RemoveServers removes servers by tag from the given group.
func (c *Client) RemoveServers(ctx context.Context, tags []string) error {
	_, err := c.do(ctx, http.MethodPost, serversRemoveEndpoint, RemoveServersRequest{Tags: tags})
	return err
}

// AddServersByJSON adds servers from a JSON configuration string and returns the tags of the added servers.
func (c *Client) AddServersByJSON(ctx context.Context, config string) ([]string, error) {
	data, err := c.do(ctx, http.MethodPost, serversFromJSONEndpoint, JSONConfigRequest{Config: config})
	if err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, err
	}
	return tags, nil
}

// AddServersByURL adds servers from the given URLs and returns the tags of the added servers.
func (c *Client) AddServersByURL(ctx context.Context, urls []string, skipCertVerification bool) ([]string, error) {
	data, err := c.do(ctx, http.MethodPost, serversFromURLsEndpoint, URLsRequest{URLs: urls, SkipCertVerification: skipCertVerification})
	if err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, err
	}
	return tags, nil
}

// AddPrivateServer adds a private server.
func (c *Client) AddPrivateServer(ctx context.Context, tag, ip string, port int, accessToken string, loc C.ServerLocation, joined bool) error {
	_, err := c.do(ctx, http.MethodPost, serversPrivateEndpoint, PrivateServerRequest{Tag: tag, IP: ip, Port: port, AccessToken: accessToken, Location: loc, Joined: joined})
	return err
}

// InviteToPrivateServer creates an invite for a private server and returns the invite code.
func (c *Client) InviteToPrivateServer(ctx context.Context, ip string, port int, accessToken, inviteName string) (string, error) {
	var resp CodeResponse
	err := c.doJSON(ctx, http.MethodPost, serversPrivateInviteEndpoint,
		PrivateServerInviteRequest{IP: ip, Port: port, AccessToken: accessToken, InviteName: inviteName}, &resp)
	return resp.Code, err
}

// RevokePrivateServerInvite revokes an invite for a private server.
func (c *Client) RevokePrivateServerInvite(ctx context.Context, ip string, port int, accessToken, inviteName string) error {
	_, err := c.do(ctx, http.MethodDelete, serversPrivateInviteEndpoint,
		PrivateServerInviteRequest{IP: ip, Port: port, AccessToken: accessToken, InviteName: inviteName})
	return err
}

//////////////
// Settings //
//////////////

func (c *Client) Features(ctx context.Context) (map[string]bool, error) {
	var features map[string]bool
	err := c.doJSON(ctx, http.MethodGet, featuresEndpoint, nil, &features)
	return features, err
}

// Settings returns the current settings as a map of key-value pairs.
func (c *Client) Settings(ctx context.Context) (settings.Settings, error) {
	var s settings.Settings
	err := c.doJSON(ctx, http.MethodGet, settingsEndpoint, nil, &s)
	return s, err
}

// PatchSettings updates settings with the given key-value pairs and returns the full updates settings.
func (c *Client) PatchSettings(ctx context.Context, updates settings.Settings) (settings.Settings, error) {
	var s settings.Settings
	err := c.doJSON(ctx, http.MethodPatch, settingsEndpoint, updates, &s)
	return s, err
}

func (c *Client) EnableTelemetry(ctx context.Context, enable bool) error {
	_, err := c.PatchSettings(ctx, settings.Settings{settings.TelemetryKey: enable})
	return err
}

func (c *Client) EnableSplitTunneling(ctx context.Context, enable bool) error {
	_, err := c.PatchSettings(ctx, settings.Settings{settings.SplitTunnelKey: enable})
	return err
}

// SetSplitTunnelPolicy selects how the split-tunnel filter is interpreted (see
// [vpn.SplitTunnelPolicy]).
func (c *Client) SetSplitTunnelPolicy(ctx context.Context, policy vpn.SplitTunnelPolicy) error {
	if !policy.Valid() {
		return fmt.Errorf("invalid split-tunnel policy: %q", policy)
	}
	_, err := c.PatchSettings(ctx, settings.Settings{settings.SplitTunnelPolicyKey: string(policy)})
	return err
}

func (c *Client) EnableSmartRouting(ctx context.Context, enable bool) error {
	_, err := c.PatchSettings(ctx, settings.Settings{settings.SmartRoutingKey: enable})
	return err
}

func (c *Client) EnableAdBlocking(ctx context.Context, enable bool) error {
	_, err := c.PatchSettings(ctx, settings.Settings{settings.AdBlockKey: enable})
	return err
}

// EnableConfigFetch toggles periodic config fetching.
func (c *Client) EnableConfigFetch(ctx context.Context, enable bool) error {
	_, err := c.PatchSettings(ctx, settings.Settings{settings.ConfigFetchDisabledKey: !enable})
	return err
}

// SetLogLevel sets the daemon's log level. Valid values: trace, debug, info,
// warn, error, fatal, panic, disable.
func (c *Client) SetLogLevel(ctx context.Context, level string) error {
	if _, err := rlog.ParseLogLevel(level); err != nil {
		return err
	}
	_, err := c.PatchSettings(ctx, settings.Settings{settings.LogLevelKey: level})
	return err
}

// SetSendLogsToSigNoz turns uploading the daemon's log to the telemetry
// collector on or off.
func (c *Client) SetSendLogsToSigNoz(ctx context.Context, enable bool) error {
	_, err := c.PatchSettings(ctx, settings.Settings{settings.SendLogsToSigNozKey: enable})
	return err
}

/////////
// Env //
/////////

// PatchEnvVars updates the daemon's in-memory environment variables.
// This is intended for dev/testing use only.
func (c *Client) PatchEnvVars(ctx context.Context, updates map[string]string) (map[string]string, error) {
	var result map[string]string
	err := c.doJSON(ctx, http.MethodPatch, envEndpoint, updates, &result)
	return result, err
}

//////////////////
// Split Tunnel //
/////////////////

// SplitTunnelFilters returns the current split tunnel configuration.
func (c *Client) SplitTunnelFilters(ctx context.Context) (vpn.SplitTunnelFilter, error) {
	var filter vpn.SplitTunnelFilter
	err := c.doJSON(ctx, http.MethodGet, splitTunnelEndpoint, nil, &filter)
	return filter, err
}

// AddSplitTunnelItems adds items to the split tunnel filter.
func (c *Client) AddSplitTunnelItems(ctx context.Context, items vpn.SplitTunnelFilter) error {
	_, err := c.do(ctx, http.MethodPost, splitTunnelEndpoint, items)
	return err
}

// RemoveSplitTunnelItems removes items from the split tunnel filter.
func (c *Client) RemoveSplitTunnelItems(ctx context.Context, items vpn.SplitTunnelFilter) error {
	_, err := c.do(ctx, http.MethodDelete, splitTunnelEndpoint, items)
	return err
}

/////////////
// Account //
/////////////

// NewUser creates a new anonymous user.
func (c *Client) NewUser(ctx context.Context) (*account.UserData, error) {
	var userData account.UserData
	if err := c.doJSON(ctx, http.MethodPost, accountNewUserEndpoint, nil, &userData); err != nil {
		return nil, err
	}
	return &userData, nil
}

// Login authenticates the user with email and password.
func (c *Client) Login(ctx context.Context, email, password string) (*account.UserData, error) {
	var userData account.UserData
	err := c.doJSON(ctx, http.MethodPost, accountLoginEndpoint,
		EmailPasswordRequest{Email: email, Password: password}, &userData)
	if err != nil {
		return nil, err
	}
	return &userData, nil
}

// Logout logs the user out.
func (c *Client) Logout(ctx context.Context, email string) (*account.UserData, error) {
	var userData account.UserData
	if err := c.doJSON(ctx, http.MethodPost, accountLogoutEndpoint, EmailRequest{Email: email}, &userData); err != nil {
		return nil, err
	}
	return &userData, nil
}

// FetchUserData fetches fresh user data from the remote server.
func (c *Client) FetchUserData(ctx context.Context) (*account.UserData, error) {
	return c.userData(ctx, true)
}

// UserData returns locally cached user data.
func (c *Client) UserData(ctx context.Context) (*account.UserData, error) {
	return c.userData(ctx, false)
}

func (c *Client) userData(ctx context.Context, fetch bool) (*account.UserData, error) {
	var userData account.UserData
	url := fmt.Sprintf("%s?fetch=%v", accountUserDataEndpoint, fetch)
	if err := c.doJSON(ctx, http.MethodGet, url, nil, &userData); err != nil {
		return nil, err
	}
	return &userData, nil
}

// UserDevices returns the list of devices linked to the user's account.
func (c *Client) UserDevices(ctx context.Context) ([]settings.Device, error) {
	var devices []settings.Device
	err := c.doJSON(ctx, http.MethodGet, accountDevicesEndpoint, nil, &devices)
	return devices, err
}

// RemoveDevice removes a device from the user's account.
func (c *Client) RemoveDevice(ctx context.Context, deviceID string) (*account.LinkResponse, error) {
	var resp account.LinkResponse
	if err := c.doJSON(ctx, http.MethodDelete, accountDevicesEndpoint+url.PathEscape(deviceID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignUp creates a new account with the given email and password.
func (c *Client) SignUp(ctx context.Context, email, password string) ([]byte, *account.SignupResponse, error) {
	var resp SignupResponse
	err := c.doJSON(
		ctx, http.MethodPost, accountSignupEndpoint,
		EmailPasswordRequest{Email: email, Password: password}, &resp,
	)
	if err != nil {
		return nil, nil, err
	}
	return resp.Salt, resp.Response, nil
}

// SignupEmailConfirmation confirms the signup email with the given code.
func (c *Client) SignupEmailConfirmation(ctx context.Context, email, code string) error {
	_, err := c.do(ctx, http.MethodPost, accountSignupEndpoint+"confirm", EmailCodeRequest{Email: email, Code: code})
	return err
}

// SignupEmailResendCode requests a resend of the signup confirmation email.
func (c *Client) SignupEmailResendCode(ctx context.Context, email string) error {
	_, err := c.do(ctx, http.MethodPost, accountSignupEndpoint+"resend", EmailRequest{Email: email})
	return err
}

// VerifyPassword checks the password for the given email, returning a nil
// error only when the credentials are valid.
func (c *Client) VerifyPassword(ctx context.Context, email, password string) error {
	_, err := c.do(ctx, http.MethodPost, accountVerifyPasswordEndpoint, EmailPasswordRequest{Email: email, Password: password})
	return err
}

// StartChangeEmail initiates an email address change.
func (c *Client) StartChangeEmail(ctx context.Context, newEmail, password string) error {
	_, err := c.do(ctx, http.MethodPost, accountEmailEndpoint+"/start", ChangeEmailStartRequest{NewEmail: newEmail, Password: password})
	return err
}

// CompleteChangeEmail completes an email address change.
func (c *Client) CompleteChangeEmail(ctx context.Context, newEmail, password, code string) error {
	_, err := c.do(ctx, http.MethodPost, accountEmailEndpoint+"/complete",
		ChangeEmailCompleteRequest{NewEmail: newEmail, Password: password, Code: code})
	return err
}

// StartRecoveryByEmail initiates account recovery by email.
func (c *Client) StartRecoveryByEmail(ctx context.Context, email string) error {
	_, err := c.do(ctx, http.MethodPost, accountRecoveryEndpoint+"/start", EmailRequest{Email: email})
	return err
}

// CompleteRecoveryByEmail completes account recovery with a new password and code.
func (c *Client) CompleteRecoveryByEmail(ctx context.Context, email, newPassword, code string) error {
	_, err := c.do(ctx, http.MethodPost, accountRecoveryEndpoint+"/complete",
		RecoveryCompleteRequest{Email: email, NewPassword: newPassword, Code: code})
	return err
}

// ValidateEmailRecoveryCode validates the recovery code without completing the recovery.
func (c *Client) ValidateEmailRecoveryCode(ctx context.Context, email, code string) error {
	_, err := c.do(ctx, http.MethodPost, accountRecoveryEndpoint+"/validate", EmailCodeRequest{Email: email, Code: code})
	return err
}

// DeleteAccount deletes the user's account.
func (c *Client) DeleteAccount(ctx context.Context, email, password string) (*account.UserData, error) {
	var userData account.UserData
	err := c.doJSON(ctx, http.MethodDelete, accountDeleteEndpoint,
		EmailPasswordRequest{Email: email, Password: password}, &userData)
	if err != nil {
		return nil, err
	}
	return &userData, nil
}

// OAuthLoginURL returns the OAuth login URL for the given provider.
func (c *Client) OAuthLoginURL(ctx context.Context, provider string) (string, error) {
	var resp URLResponse
	q := url.Values{"provider": {provider}}
	err := c.doJSON(ctx, http.MethodGet, accountOAuthEndpoint+"?"+q.Encode(), nil, &resp)
	return resp.URL, err
}

// OAuthLoginCallback exchanges an OAuth token for user data.
func (c *Client) OAuthLoginCallback(ctx context.Context, oAuthToken string) (*account.UserData, error) {
	var userData account.UserData
	err := c.doJSON(ctx, http.MethodPost, accountOAuthEndpoint,
		OAuthTokenRequest{OAuthToken: oAuthToken}, &userData)
	if err != nil {
		return nil, err
	}
	return &userData, nil
}

// OAuthDeviceLimitCallback stores the account identity from a device-limit
// OAuth callback token without logging the user in; see account.Client.OAuthDeviceLimitCallback.
func (c *Client) OAuthDeviceLimitCallback(ctx context.Context, oAuthToken string) error {
	_, err := c.do(ctx, http.MethodPost, accountOAuthDeviceLimitEndpoint,
		OAuthTokenRequest{OAuthToken: oAuthToken})
	return err
}

// DataCapInfo returns the current data cap information as a JSON string.
func (c *Client) DataCapInfo(ctx context.Context) (*account.DataCapInfo, error) {
	var resp account.DataCapInfo
	err := c.doJSON(ctx, http.MethodGet, accountDataCapEndpoint, nil, &resp)
	return &resp, err
}

///////////////////
// Subscriptions //
///////////////////

// ActivationCode purchases a subscription using a reseller code.
func (c *Client) ActivationCode(ctx context.Context, email, resellerCode string) (*account.PurchaseResponse, error) {
	var resp account.PurchaseResponse
	err := c.doJSON(ctx, http.MethodPost, subscriptionActivationEndpoint,
		ActivationRequest{Email: email, ResellerCode: resellerCode}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// NewStripeSubscription creates a new Stripe subscription and returns the client secret.
func (c *Client) NewStripeSubscription(ctx context.Context, email, planID, couponCode string) (string, error) {
	var resp ClientSecretResponse
	err := c.doJSON(ctx, http.MethodPost, subscriptionStripeEndpoint,
		StripeSubscriptionRequest{Email: email, PlanID: planID, CouponCode: couponCode}, &resp)
	return resp.ClientSecret, err
}

// ReferralAttach attaches a referral code to the current user. A non-empty
// channel also returns the resulting plans, providers, and discount.
func (c *Client) ReferralAttach(ctx context.Context, code, channel string) (*account.ReferralAttachResponse, error) {
	var resp account.ReferralAttachResponse
	err := c.doJSON(ctx, http.MethodPost, subscriptionReferralEndpoint, CodeRequest{Code: code, Channel: channel}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// StripeBillingPortalURL returns the Stripe billing portal URL.
func (c *Client) StripeBillingPortalURL(ctx context.Context) (string, error) {
	var resp URLResponse
	err := c.doJSON(ctx, http.MethodGet, subscriptionBillingPortalEndpoint, nil, &resp)
	return resp.URL, err
}

// PaymentRedirect returns a payment redirect URL.
func (c *Client) PaymentRedirect(ctx context.Context, data account.PaymentRedirectData) (string, error) {
	var resp URLResponse
	err := c.doJSON(ctx, http.MethodPost, subscriptionPaymentRedirectEndpoint, data, &resp)
	return resp.URL, err
}

// SubscriptionPaymentRedirectURL returns a subscription payment redirect URL.
func (c *Client) SubscriptionPaymentRedirectURL(ctx context.Context, data account.PaymentRedirectData) (string, error) {
	var resp URLResponse
	err := c.doJSON(ctx, http.MethodPost, subscriptionPaymentRedirectURLEndpoint, data, &resp)
	return resp.URL, err
}

// SubscriptionPlans returns available subscription plans for the given channel.
func (c *Client) SubscriptionPlans(ctx context.Context, channel string) (string, error) {
	var resp PlansResponse
	q := url.Values{"channel": {channel}}
	err := c.doJSON(ctx, http.MethodGet, subscriptionPlansEndpoint+"?"+q.Encode(), nil, &resp)
	return resp.Plans, err
}

// VerifySubscription verifies a subscription purchase.
func (c *Client) VerifySubscription(ctx context.Context, service account.SubscriptionService, data map[string]string) (string, error) {
	var resp ResultResponse
	err := c.doJSON(ctx, http.MethodPost, subscriptionVerifyEndpoint,
		VerifySubscriptionRequest{Service: service, Data: data}, &resp)
	return resp.Result, err
}

// RestoreSubscription restores a previously purchased subscription.
// For Apple and Google services, data must contain the appropriate purchase information.
func (c *Client) RestoreSubscription(ctx context.Context, service account.SubscriptionService, data map[string]string) (*account.RestoreSubscriptionResponse, error) {
	var resp account.RestoreSubscriptionResponse
	err := c.doJSON(ctx, http.MethodPost, subscriptionRestoreEndpoint,
		RestoreSubscriptionRequest{Service: service, Data: data}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

///////////
// Issue //
///////////

// ReportIssue submits an issue report. additionalAttachments is a list of file paths for additional
// files to include. Logs, diagnostics, and the config response are included automatically and do
// not need to be specified. attachments contains screenshot files sent as first-class multipart
// attachments; callers may include up to [issue.MaxFirstClassAttachmentCount] files with a
// combined size of [issue.MaxFirstClassAttachmentBytes] bytes.
//
// On mobile the report is assembled in this process to avoid pressuring the tunnel process.
func (c *Client) ReportIssue(ctx context.Context, issueType issue.IssueType, description, email string, additionalAttachments []string, attachments []*issue.Attachment) error {
	return c.reportIssue(ctx, issueType, description, email, additionalAttachments, attachments)
}

/////////////
// streams //
/////////////

// sseStableAfter is how long an accepted stream must stay open before its end resets the retry
// backoff. Resetting on every accepted stream would let a server that accepts and then
// immediately closes drive a tight loop.
const sseStableAfter = time.Second

// sseRetryLoop runs sseStream in a retry loop until ctx is cancelled.
func (c *Client) sseRetryLoop(ctx context.Context, endpoint string, handler func([]byte)) error {
	bo := common.NewBackoff(0, 30*time.Second)
	for ctx.Err() == nil {
		var opened time.Time
		err := c.sseStream(ctx, endpoint, handler, func(at time.Time) { opened = at })
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !opened.IsZero() && time.Since(opened) >= sseStableAfter {
			bo.Reset()
		}
		// silently ignore IPC not running errors, since they are expected when the daemon is not running.
		// prevent spamming the logs with errors until the daemon starts.
		if err != nil && !errors.Is(err, ErrIPCNotRunning) {
			slog.Warn("SSE stream ended, retrying", "endpoint", endpoint, "error", err)
		}
		bo.Wait(ctx)
	}
	return ctx.Err()
}

// dataCapStream runs the data-cap SSE stream only while the VPN is connected. Blocks until ctx
// is cancelled.
func (c *Client) dataCapStream(ctx context.Context, handler func(account.DataCapInfo)) error {
	var (
		mu       sync.Mutex
		cancelFn context.CancelFunc
	)

	decode := func(data []byte) {
		var info account.DataCapInfo
		if err := json.Unmarshal(data, &info); err == nil {
			handler(info)
		}
	}

	start := func() {
		mu.Lock()
		defer mu.Unlock()
		if cancelFn != nil {
			return
		}
		subCtx, cancel := context.WithCancel(ctx)
		cancelFn = cancel
		go c.sseRetryLoop(subCtx, accountDataCapStreamEndpoint, decode)
	}

	stop := func() {
		mu.Lock()
		defer mu.Unlock()
		if cancelFn != nil {
			cancelFn()
			cancelFn = nil
		}
	}
	defer stop()

	// check if VPN is already connected before starting the stream, otherwise we might miss the
	// "connected" event that triggers the stream start
	if status, err := c.VPNStatus(ctx); err == nil && status == vpn.Connected {
		start()
	}

	return c.VPNStatusEvents(ctx, func(evt vpn.StatusUpdateEvent) {
		if evt.Status == vpn.Connected {
			start()
		} else {
			stop()
		}
	})
}

/////////////
// helpers //
/////////////

// isConnectionError reports whether err indicates that the IPC socket is unreachable
// (e.g. connection refused or socket file not found).
func isConnectionError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// connection refused (server not listening)
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return true
		}
		// socket file does not exist (server never started / was cleaned up)
		if errors.Is(opErr.Err, syscall.ENOENT) {
			return true
		}
		// check wrapped syscall errors
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return errors.Is(sysErr.Err, syscall.ECONNREFUSED) || errors.Is(sysErr.Err, syscall.ENOENT)
		}
	}
	// Also check the unwrapped error directly for cases where the wrapping differs by platform
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT)
}

// UnboundedSnapshot reads status and peers from the backend that owns the widget.
func (c *Client) UnboundedSnapshot(ctx context.Context) (unbounded.Snapshot, error) {
	data, err := c.do(ctx, http.MethodGet, unboundedSnapshotEndpoint, nil)
	if err != nil {
		return unbounded.Snapshot{}, err
	}
	var s unbounded.Snapshot
	err = json.Unmarshal(data, &s)
	return s, err
}

////////////////////
// Helper invites //
////////////////////

// HelperRelay relays one helper-invite request to lantern-cloud (see
// helper.Relayer). lantern-cloud's status is in the result; an error means
// the relay itself failed.
func (c *Client) HelperRelay(ctx context.Context, op string, body []byte) (helper.RelayResult, error) {
	if len(body) > 0 && !json.Valid(body) {
		// Fixed text: the encoder's error would quote the body.
		return helper.RelayResult{}, errors.New("helper relay: body is not JSON")
	}
	var res helper.RelayResult
	err := c.doJSON(ctx, http.MethodPost, helperRelayEndpoint, HelperRelayRequest{Op: op, Body: body}, &res)
	return res, err
}

// SetHelperPairingKeys replaces the helper pairing keys radiance holds with
// keys, keyed by pairing ID.
func (c *Client) SetHelperPairingKeys(ctx context.Context, keys map[string]helper.PairingKey) error {
	return c.doJSON(ctx, http.MethodPost, helperPairingKeysEndpoint, HelperPairingKeysRequest{Keys: keys}, nil)
}

// PersonalProxyStatus reads the status of each friend this device invited
// (see vpn.PersonalProxyStatus).
func (c *Client) PersonalProxyStatus(ctx context.Context) ([]vpn.PersonalProxyStatus, error) {
	var statuses []vpn.PersonalProxyStatus
	err := c.doJSON(ctx, http.MethodGet, helperPersonalProxiesEndpoint, nil, &statuses)
	return statuses, err
}

// HelperActivity reads today's sharing totals (see helper.Activity).
func (c *Client) HelperActivity(ctx context.Context) (helper.Activity, error) {
	var a helper.Activity
	err := c.doJSON(ctx, http.MethodGet, helperActivityEndpoint, nil, &a)
	return a, err
}

// HelperLive reads whether each helper pairing's friend is connected to this
// volunteer now (see helper.LiveSnapshot).
func (c *Client) HelperLive(ctx context.Context) (helper.LiveSnapshot, error) {
	var s helper.LiveSnapshot
	err := c.doJSON(ctx, http.MethodGet, helperLiveEndpoint, nil, &s)
	return s, err
}
