package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel"
	"google.golang.org/protobuf/proto"

	"github.com/getlantern/radiance/account/protos"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/traces"
)

const saltFileName = ".salt"

type UserDataResponse struct {
	*protos.BaseResponse
	*protos.LoginResponse_UserData
}

type SignupResponse = protos.SignupResponse
type UserData = protos.LoginResponse

// NewUser creates a new user account
func (a *Client) NewUser(ctx context.Context) (*UserData, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "new_user")
	defer span.End()

	resp, err := a.sendProRequest(ctx, "POST", "/user-create", nil, nil, nil)
	if err != nil {
		a.logger.Error("creating new user", "error", err)
		return nil, traces.RecordError(ctx, err)
	}
	var userResp UserDataResponse
	if err := json.Unmarshal(resp, &userResp); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling new user response: %w", err))
	}
	userData, err := a.storeData(ctx, userResp)
	if err != nil {
		return nil, err
	}
	return userData, nil
}

// FetchUserData fetches user data from the server.
func (a *Client) FetchUserData(ctx context.Context) (*UserData, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "fetch_user_data")
	defer span.End()
	return a.fetchUserData(ctx)
}

// fetchUserData fetches the user's account data and stores it.
func (a *Client) fetchUserData(ctx context.Context) (*UserData, error) {
	resp, err := a.sendProRequest(ctx, "GET", "/user-data", nil, nil, nil)
	if err != nil {
		a.logger.Error("user data", "error", err)
		return nil, traces.RecordError(ctx, fmt.Errorf("getting user data: %w", err))
	}
	var userResp UserDataResponse
	if err := json.Unmarshal(resp, &userResp); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling new user response: %w", err))
	}
	return a.storeData(ctx, userResp)
}

func normalizeLegacyUserLevel(level string) string {
	// The legacy API omits userLevel for free accounts.
	if level == "" {
		return "free"
	}
	return level
}

func (a *Client) storeData(ctx context.Context, resp UserDataResponse) (*UserData, error) {
	if resp.BaseResponse != nil && resp.Error != "" {
		err := fmt.Errorf("received bad response: %s", resp.Error)
		a.logger.Error("user data", "error", err)
		return nil, traces.RecordError(ctx, err)
	}
	if resp.LoginResponse_UserData == nil {
		a.logger.Error("user data", "error", "no user data in response")
		return nil, traces.RecordError(ctx, fmt.Errorf("no user data in response"))
	}
	resp.UserLevel = normalizeLegacyUserLevel(resp.UserLevel)
	resp.DeviceID = settings.GetString(settings.DeviceIDKey)
	a.mu.Lock()
	defer a.mu.Unlock()

	if resp.Token == "" && resp.UserId != 0 && resp.UserId == settings.GetInt64(settings.UserIDKey) {
		resp.Token = settings.GetString(settings.TokenKey)
	}
	login := &UserData{
		LegacyID:       resp.UserId,
		LegacyToken:    resp.Token,
		LegacyUserData: resp.LoginResponse_UserData,
	}
	return a.setDataLocked(login, true), nil
}

type DataCapInfo struct {
	// Whether data cap is enabled for this device/user
	Enabled bool `json:"enabled"`
	// Data cap usage details (only populated if enabled is true)
	Usage *DataCapUsageDetails `json:"usage,omitempty"`
	// Exhausted is set locally when the SSE stream emits cap_exhausted. It is not
	// part of the server JSON payload.
	Exhausted bool `json:"exhausted,omitempty"`
}

type DataCapUsageDetails struct {
	BytesAllotted      string `json:"bytesAllotted"`
	BytesUsed          string `json:"bytesUsed"`
	AllotmentStartTime string `json:"allotmentStartTime"`
	AllotmentEndTime   string `json:"allotmentEndTime"`
}

func (a *Client) DataCapInfo(ctx context.Context) (*DataCapInfo, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "data_cap_info")
	defer span.End()

	getURL := "/datacap/" + settings.GetString(settings.DeviceIDKey)
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	resp, err := a.sendRequest(ctx, "GET", getURL, nil, headers, nil)
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("getting datacap info: %w", err))
	}
	var usage *DataCapInfo
	if err := json.Unmarshal(resp, &usage); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling datacap info response: %w", err))
	}
	return usage, nil
}

// SignUp signs the user up for an account.
func (a *Client) SignUp(ctx context.Context, email, password string) ([]byte, *protos.SignupResponse, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "sign_up")
	defer span.End()

	lowerCaseEmail := strings.ToLower(email)
	salt, err := generateSalt()
	if err != nil {
		return nil, nil, traces.RecordError(ctx, err)
	}
	srpClient, err := newSRPClient(lowerCaseEmail, password, salt)
	if err != nil {
		return nil, nil, traces.RecordError(ctx, err)
	}
	verifierKey, err := srpClient.Verifier()
	if err != nil {
		return nil, nil, traces.RecordError(ctx, err)
	}
	data := &protos.SignupRequest{
		Email:                 lowerCaseEmail,
		Salt:                  salt,
		Verifier:              verifierKey.Bytes(),
		SkipEmailConfirmation: true,
		// Always temporary so a user who hits an error mid-signup can sign up again.
		Temp: true,
	}

	proToken := settings.GetString(settings.TokenKey)
	userID := settings.GetString(settings.UserIDKey)
	if proToken == "" || userID == "" {
		return nil, nil, traces.RecordError(ctx, errors.New("signup requires the pro token and user ID to continue"))
	}
	headers := map[string]string{
		common.DeviceIDHeader: settings.GetString(settings.DeviceIDKey),
		common.ProTokenHeader: proToken,
		common.UserIDHeader:   userID,
	}

	resp, err := a.sendRequest(ctx, "POST", "/users/signup", nil, headers, data)
	if err != nil {
		return nil, nil, traces.RecordError(ctx, err)
	}
	a.setSalt(salt)

	var signupData protos.SignupResponse
	if err := proto.Unmarshal(resp, &signupData); err != nil {
		return nil, nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling sign up response: %w", err))
	}
	if err := a.storeIdentity(signupData.LegacyID, signupData.ProToken); err != nil {
		return nil, nil, traces.RecordError(ctx, fmt.Errorf("saving signup identity: %w", err))
	}
	jwtTokenErr := settings.Set(settings.JwtTokenKey, signupData.Token)
	if jwtTokenErr != nil {
		return nil, nil, traces.RecordError(ctx, fmt.Errorf("could not save JWT token: %w", jwtTokenErr))
	}

	return salt, &signupData, nil
}

var ErrNoSalt = errors.New("no salt available")
var ErrNotLoggedIn = errors.New("not logged in")
var ErrInvalidCode = errors.New("invalid code")

// SignupEmailResendCode requests that the sign-up code be resent via email.
func (a *Client) SignupEmailResendCode(ctx context.Context, email string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "sign_up_email_resend_code")
	defer span.End()

	salt := a.getSaltCached()
	if salt == nil {
		return traces.RecordError(ctx, ErrNoSalt)
	}
	data := &protos.SignupEmailResendRequest{
		Email: email,
		Salt:  salt,
	}
	_, err := a.sendRequest(ctx, "POST", "/users/signup/resend/email", nil, nil, data)
	return traces.RecordError(ctx, err)
}

// SignupEmailConfirmation confirms the new account using the sign-up code received via email.
func (a *Client) SignupEmailConfirmation(ctx context.Context, email, code string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "sign_up_email_confirmation")
	defer span.End()

	data := &protos.ConfirmSignupRequest{
		Email: email,
		Code:  code,
	}
	_, err := a.sendRequest(ctx, "POST", "/users/signup/complete/email", nil, nil, data)
	return traces.RecordError(ctx, err)
}

func writeSalt(salt []byte, path string) error {
	if err := atomicfile.WriteFile(path, salt, fileperm.File); err != nil {
		return fmt.Errorf("writing salt to %s: %w", path, err)
	}
	return nil
}

func readSalt(path string) ([]byte, error) {
	buf, err := atomicfile.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading salt from %s: %w", path, err)
	}
	if len(buf) == 0 {
		return nil, nil
	}
	return buf, nil
}

// Login logs the user in.
func (a *Client) Login(ctx context.Context, email, password string) (*UserData, error) {
	a.setSalt(nil)
	ctx, span := otel.Tracer(tracerName).Start(ctx, "login")
	defer span.End()

	lowerCaseEmail := strings.ToLower(email)
	salt, err := a.getSalt(ctx, lowerCaseEmail)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}

	deviceID := settings.GetString(settings.DeviceIDKey)
	proof, err := a.clientProof(ctx, lowerCaseEmail, password, salt)
	if err != nil {
		return nil, err
	}

	loginData := &protos.LoginRequest{
		Email:    lowerCaseEmail,
		DeviceId: deviceID,
		Proof:    proof,
	}
	resp, err := a.sendRequest(ctx, "POST", "/users/login", nil, nil, loginData)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}

	var loginResp UserData
	if err := proto.Unmarshal(resp, &loginResp); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling login response: %w", err))
	}
	//this can be nil if the user has reached the device limit
	if loginResp.LegacyUserData != nil {
		loginResp.LegacyUserData.DeviceID = deviceID
	}

	// regardless of state we need to save login information
	// We have device flow limit on login
	a.setData(&loginResp)
	a.setSalt(salt)
	if saltErr := writeSalt(salt, a.saltPath); saltErr != nil {
		return nil, traces.RecordError(ctx, saltErr)
	}
	settings.Set(settings.OAuthLoginKey, false)
	settings.Set(settings.OAuthProviderKey, "")
	return &loginResp, nil
}

// Logout logs the user out. No-op if there is no user account logged in.
func (a *Client) Logout(ctx context.Context, email string) (*UserData, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "logout")
	defer span.End()
	logout := &protos.LogoutRequest{
		Email:        email,
		DeviceId:     settings.GetString(settings.DeviceIDKey),
		LegacyUserID: settings.GetInt64(settings.UserIDKey),
		LegacyToken:  settings.GetString(settings.TokenKey),
	}
	// JWT token is only set for OAuth users; omit the field entirely when empty
	jwtToken := settings.GetString(settings.JwtTokenKey)
	if jwtToken != "" {
		logout.Token = jwtToken
	}
	a.logger.Info("Logout request", "JWTTokenSet", jwtToken != "")
	_, err := a.sendRequest(ctx, "POST", "/users/logout", nil, nil, logout)
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("logging out: %w", err))
	}
	a.ClearUser()
	a.setSalt(nil)
	settings.Set(settings.OAuthLoginKey, false)
	settings.Set(settings.OAuthProviderKey, "")
	if err := writeSalt(nil, a.saltPath); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("writing salt after logout: %w", err))
	}
	return a.NewUser(ctx)
}

// StartRecoveryByEmail initializes the account recovery process for the provided email.
func (a *Client) StartRecoveryByEmail(ctx context.Context, email string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "start_recovery_by_email")
	defer span.End()

	data := &protos.StartRecoveryByEmailRequest{Email: email}
	_, err := a.sendRequest(ctx, "POST", "/users/recovery/start/email", nil, nil, data)
	return traces.RecordError(ctx, err)
}

// CompleteRecoveryByEmail completes account recovery using the code received via email.
func (a *Client) CompleteRecoveryByEmail(ctx context.Context, email, newPassword, code string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "complete_recovery_by_email")
	defer span.End()
	lowerCaseEmail := strings.ToLower(email)
	newSalt, err := generateSalt()
	if err != nil {
		return traces.RecordError(ctx, err)
	}
	srpClient, err := newSRPClient(lowerCaseEmail, newPassword, newSalt)
	if err != nil {
		return traces.RecordError(ctx, err)
	}
	verifierKey, err := srpClient.Verifier()
	if err != nil {
		return traces.RecordError(ctx, err)
	}

	data := &protos.CompleteRecoveryByEmailRequest{
		Email:       lowerCaseEmail,
		Code:        code,
		NewSalt:     newSalt,
		NewVerifier: verifierKey.Bytes(),
	}
	_, err = a.sendRequest(ctx, "POST", "/users/recovery/complete/email", nil, nil, data)
	if err != nil {
		return traces.RecordError(ctx, fmt.Errorf("failed to complete recovery by email: %w", err))
	}
	if err = writeSalt(newSalt, a.saltPath); err != nil {
		return traces.RecordError(ctx, fmt.Errorf("failed to write new salt: %w", err))
	}
	return nil
}

// ValidateEmailRecoveryCode validates the recovery code received via email.
func (a *Client) ValidateEmailRecoveryCode(ctx context.Context, email, code string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "validate_email_recovery_code")
	defer span.End()

	data := &protos.ValidateRecoveryCodeRequest{
		Email: email,
		Code:  code,
	}
	resp, err := a.sendRequest(ctx, "POST", "/users/recovery/validate/email", nil, nil, data)
	if err != nil {
		return traces.RecordError(ctx, err)
	}
	var codeResp protos.ValidateRecoveryCodeResponse
	if err := proto.Unmarshal(resp, &codeResp); err != nil {
		return traces.RecordError(ctx, fmt.Errorf("error unmarshalling validate recovery code response: %w", err))
	}
	if !codeResp.Valid {
		return traces.RecordError(ctx, ErrInvalidCode)
	}
	return nil
}

// VerifyPassword confirms the password is correct for the given email by deriving the SRP client proof.
func (a *Client) VerifyPassword(ctx context.Context, email, password string) ([]byte, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "verify_password")
	defer span.End()
	lowerCaseEmail := strings.ToLower(email)
	salt, err := a.getSalt(ctx, lowerCaseEmail)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}
	proof, err := a.clientProof(ctx, lowerCaseEmail, password, salt)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}
	return proof, nil
}

// StartChangeEmail initializes a change of the email address associated with this user account.
func (a *Client) StartChangeEmail(ctx context.Context, newEmail, password string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "start_change_email")
	defer span.End()

	lowerCaseEmail := strings.ToLower(settings.GetString(settings.EmailKey))
	lowerCaseNewEmail := strings.ToLower(newEmail)

	proof, err := a.VerifyPassword(ctx, lowerCaseEmail, password)
	if err != nil {
		return traces.RecordError(ctx, err)
	}

	data := &protos.ChangeEmailRequest{
		OldEmail: lowerCaseEmail,
		NewEmail: lowerCaseNewEmail,
		Proof:    proof,
	}
	_, err = a.sendRequest(ctx, "POST", "/users/change_email", nil, nil, data)
	return traces.RecordError(ctx, err)
}

// CompleteChangeEmail completes a change of the email address associated with this user account,
// using the code received via email.
func (a *Client) CompleteChangeEmail(ctx context.Context, newEmail, password, code string) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "complete_change_email")
	defer span.End()

	newSalt, err := generateSalt()
	if err != nil {
		return traces.RecordError(ctx, err)
	}

	newEmail = strings.ToLower(newEmail)
	srpClient, err := newSRPClient(newEmail, password, newSalt)
	if err != nil {
		return traces.RecordError(ctx, err)
	}
	verifierKey, err := srpClient.Verifier()
	if err != nil {
		return traces.RecordError(ctx, err)
	}

	data := &protos.CompleteChangeEmailRequest{
		OldEmail:    settings.GetString(settings.EmailKey),
		NewEmail:    newEmail,
		Code:        code,
		NewSalt:     newSalt,
		NewVerifier: verifierKey.Bytes(),
	}
	_, err = a.sendRequest(ctx, "POST", "/users/change_email/complete/email", nil, nil, data)
	if err != nil {
		return traces.RecordError(ctx, err)
	}
	if err := writeSalt(newSalt, a.saltPath); err != nil {
		return traces.RecordError(ctx, err)
	}
	if err := settings.Set(settings.EmailKey, newEmail); err != nil {
		return traces.RecordError(ctx, err)
	}

	a.setSalt(newSalt)
	return nil
}

// DeleteAccount deletes this user account.
func (a *Client) DeleteAccount(ctx context.Context, email, password string) (*UserData, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "delete_account")
	defer span.End()

	lowerCaseEmail := strings.ToLower(email)
	data := &protos.DeleteUserRequest{
		Email:     lowerCaseEmail,
		Permanent: true,
		DeviceId:  settings.GetString(settings.DeviceIDKey),
		Token:     settings.GetString(settings.JwtTokenKey),
	}
	if !settings.GetBool(settings.OAuthLoginKey) {
		salt, err := a.getSalt(ctx, lowerCaseEmail)
		if err != nil {
			return nil, traces.RecordError(ctx, err)
		}
		proof, err := a.clientProof(ctx, lowerCaseEmail, password, salt)
		if err != nil {
			return nil, err
		}
		data.Proof = proof
	} else {
		if data.Token == "" {
			return nil, traces.RecordError(ctx, errors.New("jwt token is required for OAuth account deletion"))
		}
	}

	_, err := a.sendRequest(ctx, "POST", "/users/delete", nil, nil, data)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}

	a.ClearUser()
	a.setSalt(nil)
	if err := writeSalt(nil, a.saltPath); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("failed to write salt during account deletion cleanup: %w", err))
	}

	return a.NewUser(ctx)
}

// OAuthLoginURL initiates the OAuth login process for the specified provider.
func (a *Client) OAuthLoginURL(ctx context.Context, provider string) (string, error) {
	authURL := a.authURL
	if authURL == "" {
		authURL = common.GetBaseURL()
	}
	loginURL, err := url.Parse(authURL + "/users/oauth2/" + provider)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}
	query := loginURL.Query()
	query.Set("deviceId", settings.GetString(settings.DeviceIDKey))
	query.Set("userId", settings.GetString(settings.UserIDKey))
	query.Set("proToken", settings.GetString(settings.TokenKey))
	query.Set("returnTo", "lantern://auth")
	loginURL.RawQuery = query.Encode()
	// Persist the provider so it's available after the callback completes.
	if err := settings.Set(settings.OAuthProviderKey, provider); err != nil {
		return "", fmt.Errorf("failed to persist OAuth provider: %w", err)
	}
	return loginURL.String(), nil
}

func (a *Client) OAuthLoginCallback(ctx context.Context, oAuthToken string) (*UserData, error) {
	a.logger.Debug("Getting OAuth login callback")
	jwtUserInfo, err := decodeJWT(oAuthToken)
	if err != nil {
		return nil, fmt.Errorf("error decoding JWT: %w", err)
	}

	// Seed the identity first so the fetchUserData call below can authenticate.
	login := &UserData{
		LegacyID:    jwtUserInfo.LegacyUserID,
		LegacyToken: jwtUserInfo.LegacyToken,
		LegacyUserData: &protos.LoginResponse_UserData{
			UserId:   jwtUserInfo.LegacyUserID,
			Token:    jwtUserInfo.LegacyToken,
			DeviceID: jwtUserInfo.DeviceID,
			Email:    jwtUserInfo.Email,
		},
	}
	a.setData(login)
	user, err := a.fetchUserData(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting user data: %w", err)
	}

	if err := settings.Set(settings.JwtTokenKey, oAuthToken); err != nil {
		a.logger.Error("Failed to persist JWT token", "error", err)
		return nil, fmt.Errorf("failed to persist JWT token: %w", err)
	}
	settings.Set(settings.OAuthLoginKey, true)
	user.Id = jwtUserInfo.Email
	user.EmailConfirmed = true
	a.setData(user)
	return user, nil
}

// OAuthDeviceLimitCallback stores the account identity from a device-limit
// OAuth callback token so the follow-up device removal authenticates as that
// account. It does not log the user in.
func (a *Client) OAuthDeviceLimitCallback(ctx context.Context, oAuthToken string) error {
	jwtUserInfo, err := decodeJWT(oAuthToken)
	if err != nil {
		return fmt.Errorf("%w: error decoding JWT: %w", ErrInvalidToken, err)
	}
	if jwtUserInfo.LegacyUserID == 0 || jwtUserInfo.LegacyToken == "" {
		return fmt.Errorf("%w: device-limit token is missing the account identity", ErrInvalidToken)
	}
	return a.storeIdentity(jwtUserInfo.LegacyUserID, jwtUserInfo.LegacyToken)
}

// ErrInvalidToken distinguishes an unusable OAuth callback token from a
// failure persisting its claims, so transports can map it to a client error.
var ErrInvalidToken = errors.New("invalid OAuth token")

type LinkResponse struct {
	*protos.BaseResponse `json:",inline"`
	UserID               int `json:"userID"`
}

// RemoveDevice removes a device from the user's account.
func (a *Client) RemoveDevice(ctx context.Context, deviceID string) (*LinkResponse, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "remove_device")
	defer span.End()

	data := map[string]string{
		"deviceId": deviceID,
	}
	resp, err := a.sendProRequest(ctx, "POST", "/user-link-remove", nil, nil, data)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}
	var link LinkResponse
	if err := json.Unmarshal(resp, &link); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling remove device response: %w", err))
	}
	if link.BaseResponse != nil && link.BaseResponse.Error != "" {
		return nil, traces.RecordError(ctx, fmt.Errorf("failed to remove device: %s", link.BaseResponse.Error))
	}
	return &link, nil
}

type ReferralAttachResponse struct {
	*protos.BaseResponse `json:",inline"`
	Providers            map[string][]*protos.PaymentMethod `json:"providers"`
	Plans                []*protos.Plan                     `json:"plans"`
	Code                 string                             `json:"code"`
	DiscountPct          int                                `json:"discountPct"`
	Type                 string                             `json:"referralType"`
}

// ReferralAttach attaches a referral code to the current user. A non-empty
// channel uses the v2 API, which also returns the plans, providers, and
// discount for the referral; the legacy v1 API returns only a BaseResponse.
func (a *Client) ReferralAttach(ctx context.Context, code, channel string) (*ReferralAttachResponse, error) {
	if channel == "" {
		return a.referralAttachV1(ctx, code)
	}
	return a.referralAttachV2(ctx, code, channel)
}

func (a *Client) referralAttachV1(ctx context.Context, code string) (*ReferralAttachResponse, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "referral_attach")
	defer span.End()

	data := map[string]string{
		"code": code,
	}
	resp, err := a.sendProRequest(ctx, "POST", "/referral-attach", nil, nil, data)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}
	var baseResp protos.BaseResponse
	if err := proto.Unmarshal(resp, &baseResp); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling referral attach response: %w", err))
	}
	if baseResp.Error != "" {
		return nil, traces.RecordError(ctx, errors.New(baseResp.Error))
	}
	return &ReferralAttachResponse{
		BaseResponse: &baseResp,
	}, nil
}

func (a *Client) referralAttachV2(ctx context.Context, code, channel string) (*ReferralAttachResponse, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "referral_attach_v2")
	defer span.End()

	params := map[string]string{
		"distributionChannel": channel,
	}
	data := map[string]string{
		"code": code,
	}
	resp, err := a.sendProRequest(ctx, "POST", "/referral-attach-v2", params, nil, data)
	if err != nil {
		return nil, traces.RecordError(ctx, err)
	}
	var referral ReferralAttachResponse
	if err := json.Unmarshal(resp, &referral); err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("error unmarshalling referral attach v2 response: %w", err))
	}
	if referral.BaseResponse != nil && referral.Error != "" {
		return nil, traces.RecordError(ctx, errors.New(referral.Error))
	}
	return &referral, nil
}

// UserChangeEvent signals account changes, including initial creation and clearing.
type UserChangeEvent struct {
	events.Event
}

func (a *Client) storeIdentity(id int64, token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	changed, err := a.storeIdentityLocked(id, token)
	if changed {
		events.Emit(UserChangeEvent{})
	}
	return err
}

// storeIdentityLocked requires a.mu to be held.
func (a *Client) storeIdentityLocked(id int64, token string) (bool, error) {
	previousID := settings.GetInt64(settings.UserIDKey)
	previousToken := settings.GetString(settings.TokenKey)
	updates := settings.Settings{}
	// The cached response can lag behind signup or OAuth, so compare the active identity.
	if id != 0 && id != previousID {
		updates[settings.TokenKey] = ""
		updates[settings.JwtTokenKey] = ""
		updates[settings.EmailKey] = ""
		updates[settings.UserLevelKey] = ""
		updates[settings.DevicesKey] = []settings.Device{}
		updates[settings.UserDataKey] = nil
	}
	if id != 0 {
		updates[settings.UserIDKey] = id
	}
	if token != "" {
		updates[settings.TokenKey] = token
	}
	if len(updates) == 0 {
		return false, nil
	}
	err := settings.Patch(updates)
	changed := settings.GetInt64(settings.UserIDKey) != previousID || settings.GetString(settings.TokenKey) != previousToken
	return changed, err
}

func (a *Client) setData(data *UserData) {
	if data == nil {
		a.ClearUser()
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.setDataLocked(data, false)
}

// setDataLocked requires a.mu to be held and data to be non-nil.
func (a *Client) setDataLocked(data *UserData, preserveLoginFields bool) *UserData {
	changed, err := a.storeIdentityLocked(data.LegacyID, data.LegacyToken)
	if err != nil {
		a.logger.Error("failed to store account identity", "error", err)
	}
	defer func() {
		if changed {
			events.Emit(UserChangeEvent{})
		}
	}()
	if data.LegacyUserData == nil {
		a.logger.Info("no user data to set, storing id and token only")
		return data
	}

	if data.LegacyUserData.UserLevel != "" {
		oldUserLevel := settings.GetString(settings.UserLevelKey)
		changed = changed || oldUserLevel != data.LegacyUserData.UserLevel
		if err := settings.Set(settings.UserLevelKey, data.LegacyUserData.UserLevel); err != nil {
			a.logger.Error("failed to set user level in settings", "error", err)
		}
	}
	if data.LegacyUserData.Email != "" {
		oldEmail := settings.GetString(settings.EmailKey)
		changed = changed || oldEmail != data.LegacyUserData.Email
		if err := settings.Set(settings.EmailKey, data.LegacyUserData.Email); err != nil {
			a.logger.Error("failed to set email in settings", "error", err)
		}
	}
	if data.Token != "" {
		oldJwtToken := settings.GetString(settings.JwtTokenKey)
		changed = changed || oldJwtToken != data.Token
		if err := settings.Set(settings.JwtTokenKey, data.Token); err != nil {
			a.logger.Error("failed to set JWT token in settings", "error", err)
		}
	}

	if len(data.Devices) > 0 {
		devices := []settings.Device{}
		for _, d := range data.Devices {
			devices = append(devices, settings.Device{
				Name: d.Name,
				ID:   d.Id,
			})
		}
		if err := settings.Set(settings.DevicesKey, devices); err != nil {
			a.logger.Error("failed to set devices in settings", "error", err)
		}
	}

	if preserveLoginFields {
		// Merge only the cached response so old login fields cannot overwrite newer settings.
		cached := new(UserData)
		if err := settings.GetStruct(settings.UserDataKey, cached); err != nil {
			a.logger.Warn("ignoring invalid cached user data", "error", err)
		} else if data.LegacyID != 0 && cached.LegacyID == data.LegacyID {
			cached.LegacyToken = data.LegacyToken
			cached.LegacyUserData = data.LegacyUserData
			data = cached
		}
	}
	if err := settings.Set(settings.UserDataKey, data); err != nil {
		a.logger.Error("failed to set login response in settings", "error", err)
	}

	return data
}

// ClearUser removes the cached account and its credentials.
func (a *Client) ClearUser() {
	a.mu.Lock()
	defer a.mu.Unlock()
	hadIdentity := settings.GetInt64(settings.UserIDKey) != 0 || settings.GetString(settings.TokenKey) != ""
	err := settings.Clear(
		settings.UserIDKey,
		settings.TokenKey,
		settings.UserLevelKey,
		settings.EmailKey,
		settings.DevicesKey,
		settings.JwtTokenKey,
		settings.UserDataKey,
	)
	if err != nil {
		a.logger.Warn("failed to clear user info", "error", err)
	}
	if hadIdentity {
		events.Emit(UserChangeEvent{})
	}
}
