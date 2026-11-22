package account

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/getlantern/radiance/common"
)

// VerifyLegacyIdentity authenticates supplied credentials without changing persisted account state.
func VerifyLegacyIdentity(ctx context.Context, client *http.Client, proURL string, userID int64, token, deviceID string) (*UserData, error) {
	if userID <= 0 || token == "" || deviceID == "" || !strings.HasPrefix(proURL, "https://") {
		return nil, errors.New("invalid legacy identity")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(proURL, "/")+"/user-data", nil)
	if err != nil {
		return nil, errors.New("invalid account verification endpoint")
	}
	req.Header.Set(common.UserIDHeader, strconv.FormatInt(userID, 10))
	req.Header.Set(common.ProTokenHeader, token)
	req.Header.Set(common.DeviceIDHeader, deviceID)
	req.Header.Set(common.AppNameHeader, common.Name)
	req.Header.Set(common.AppVersionHeader, common.GetVersion())
	req.Header.Set(common.PlatformHeader, common.Platform)
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := requestClient.Do(req)
	if err != nil {
		return nil, errors.New("account verification unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("account verification rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("invalid account verification response")
	}
	var data UserDataResponse
	if json.Unmarshal(raw, &data) != nil || data.LoginResponse_UserData == nil {
		return nil, errors.New("account verification identity mismatch")
	}
	data.UserLevel = normalizeLegacyUserLevel(data.UserLevel)
	if (data.BaseResponse != nil && data.Error != "") || data.UserId != userID ||
		(data.UserLevel != "free" && data.UserLevel != "pro") ||
		(data.DeviceID != "" && data.DeviceID != deviceID) ||
		(data.Token != "" && data.Token != token) {
		return nil, errors.New("account verification identity mismatch")
	}
	data.Token, data.DeviceID = token, deviceID
	return &UserData{LegacyID: userID, LegacyToken: token, LegacyUserData: data.LoginResponse_UserData}, nil
}
