package account

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/getlantern/radiance/account/protos"
	"github.com/getlantern/radiance/common/settings"
)

func TestFetchUserDataPreservesLogin(t *testing.T) {
	ac, server := newTestClientWithSRP(t, "test@example.com", "password")
	require.NoError(t, settings.Set(settings.DeviceIDKey, "deviceId"))
	server.loginResponse = &UserData{
		LegacyID:       123,
		LegacyToken:    "old-token",
		Id:             "account-id",
		EmailConfirmed: true,
		Success:        true,
		Token:          "jwt-token",
		Devices:        []*protos.LoginResponse_Device{{Id: "deviceId", Name: "Laptop"}},
		LegacyUserData: &protos.LoginResponse_UserData{
			UserId:     123,
			Token:      "old-token",
			UserLevel:  "pro",
			Expiration: 123456789,
			Devices:    []*protos.LoginResponse_Device{{Id: "old-device"}},
		},
	}
	ctx := context.Background()
	login, err := ac.Login(ctx, "test@example.com", "password")
	require.NoError(t, err)
	want := proto.Clone(login).(*UserData)
	want.LegacyToken = "test-token"
	want.LegacyUserData = &protos.LoginResponse_UserData{
		UserId:    123,
		Token:     "test-token",
		DeviceID:  "deviceId",
		UserLevel: "free",
	}

	for range 2 {
		got, err := ac.FetchUserData(ctx)
		require.NoError(t, err)
		assert.True(t, proto.Equal(want, got), "want %v, got %v", want, got)
		require.NoError(t, settings.Reload())
		var stored UserData
		require.NoError(t, settings.GetStruct(settings.UserDataKey, &stored))
		assert.True(t, proto.Equal(want, &stored), "want %v, stored %v", want, &stored)
	}

	user, err := ac.Logout(ctx, "test@example.com")
	require.NoError(t, err)
	want = &UserData{
		LegacyID:       123,
		LegacyToken:    "test-token",
		LegacyUserData: want.LegacyUserData,
	}
	assert.True(t, proto.Equal(want, user), "want %v, got %v", want, user)
	var stored UserData
	require.NoError(t, settings.GetStruct(settings.UserDataKey, &stored))
	assert.True(t, proto.Equal(want, &stored), "want %v, stored %v", want, &stored)
	assert.Empty(t, settings.GetString(settings.JwtTokenKey))
}

func TestFetchUserDataWithoutMatchingLogin(t *testing.T) {
	for _, tt := range []struct {
		name     string
		cachedID int64
		cache    bool
	}{
		{name: "no cached login"},
		{name: "different account", cachedID: 456, cache: true},
		{name: "unknown account", cache: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ac, _ := newTestClient(t)
			if tt.cache {
				ac.setData(&UserData{
					LegacyID:       tt.cachedID,
					Id:             "previous-account",
					EmailConfirmed: true,
					Success:        true,
					Token:          "previous-jwt",
					Devices:        []*protos.LoginResponse_Device{{Id: "old-device"}},
					LegacyUserData: &protos.LoginResponse_UserData{
						UserId: tt.cachedID, Email: "old@example.com", UserLevel: "pro",
					},
				})
			}
			got, err := ac.FetchUserData(context.Background())
			require.NoError(t, err)
			want := &UserData{
				LegacyID:       123,
				LegacyToken:    "test-token",
				LegacyUserData: &protos.LoginResponse_UserData{UserId: 123, Token: "test-token", UserLevel: "free"},
			}
			assert.True(t, proto.Equal(want, got), "want %v, got %v", want, got)
			var stored UserData
			require.NoError(t, settings.GetStruct(settings.UserDataKey, &stored))
			assert.True(t, proto.Equal(want, &stored), "want %v, stored %v", want, &stored)
			assert.Empty(t, settings.GetString(settings.JwtTokenKey))
			assert.Empty(t, settings.GetString(settings.EmailKey))
			assert.False(t, settings.IsPro())
			devices, err := settings.Devices()
			require.NoError(t, err)
			assert.Empty(t, devices)
		})
	}
}

func TestFetchUserDataWithoutToken(t *testing.T) {
	for _, id := range []int64{123, 456, 0} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			ac, _ := newTestClient(t)
			ac.setData(&UserData{
				LegacyID: 123, LegacyToken: "cached-token", Id: "account-id",
				LegacyUserData: &protos.LoginResponse_UserData{UserId: 123, Token: "cached-token"},
			})
			require.NoError(t, settings.Set(settings.TokenKey, "current-token"))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, UserDataResponse{
					LoginResponse_UserData: &protos.LoginResponse_UserData{UserId: id, UserLevel: "free"},
				})
			}))
			defer server.Close()
			ac.proURL = server.URL

			got, err := ac.FetchUserData(context.Background())
			require.NoError(t, err)
			wantToken := ""
			if id == 123 {
				wantToken = "current-token"
				assert.Equal(t, "account-id", got.Id)
			}
			assert.Equal(t, wantToken, got.LegacyToken)
			assert.Equal(t, wantToken, got.LegacyUserData.Token)
			require.NoError(t, settings.Reload())
			var stored UserData
			require.NoError(t, settings.GetStruct(settings.UserDataKey, &stored))
			assert.True(t, proto.Equal(got, &stored))
			if id != 0 {
				assert.Equal(t, wantToken, settings.GetString(settings.TokenKey))
			}
		})
	}
}

func TestSignupSwitchesAccountBeforeRefresh(t *testing.T) {
	ac, _ := newTestClient(t)
	ac.setData(&UserData{
		LegacyID: 456, LegacyToken: "old-token", Token: "old-jwt",
		Devices:        []*protos.LoginResponse_Device{{Id: "old-device"}},
		LegacyUserData: &protos.LoginResponse_UserData{UserId: 456},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProtoResponse(w, &protos.SignupResponse{LegacyID: 123, ProToken: "signup-token", Token: "signup-jwt"})
	}))
	defer server.Close()
	ac.authURL = server.URL
	_, _, err := ac.SignUp(context.Background(), "new@example.com", "password")
	require.NoError(t, err)
	_, err = ac.FetchUserData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "signup-jwt", settings.GetString(settings.JwtTokenKey))
	devices, err := settings.Devices()
	require.NoError(t, err)
	assert.Empty(t, devices)
}

func TestLoginReplacesCachedFields(t *testing.T) {
	ac, server := newTestClientWithSRP(t, "test@example.com", "password")
	ac.setData(&UserData{
		LegacyID:       123,
		Id:             "previous-id",
		EmailConfirmed: true,
		Success:        true,
		Token:          "previous-jwt",
		Devices:        []*protos.LoginResponse_Device{{Id: "old-device"}},
		LegacyUserData: &protos.LoginResponse_UserData{UserId: 123},
	})
	server.loginResponse = &UserData{
		LegacyID:       123,
		LegacyUserData: &protos.LoginResponse_UserData{UserId: 123},
	}
	got, err := ac.Login(context.Background(), "test@example.com", "password")
	require.NoError(t, err)
	assert.True(t, proto.Equal(server.loginResponse, got))
	var stored UserData
	require.NoError(t, settings.GetStruct(settings.UserDataKey, &stored))
	assert.True(t, proto.Equal(server.loginResponse, &stored))
}

func TestFetchUserDataReplacesInvalidCache(t *testing.T) {
	for _, tt := range []struct {
		name   string
		cached any
	}{
		{name: "invalid object", cached: "invalid"},
		{name: "partially decoded object", cached: map[string]any{
			"legacyID":       123,
			"id":             "old-id",
			"emailConfirmed": true,
			"Success":        true,
			"legacyUserData": "invalid",
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ac, _ := newTestClient(t)
			require.NoError(t, settings.Set(settings.UserIDKey, int64(123)))
			require.NoError(t, settings.Set(settings.UserDataKey, tt.cached))
			got, err := ac.FetchUserData(context.Background())
			require.NoError(t, err)
			want := &UserData{
				LegacyID:       123,
				LegacyToken:    "test-token",
				LegacyUserData: &protos.LoginResponse_UserData{UserId: 123, Token: "test-token", UserLevel: "free"},
			}
			assert.True(t, proto.Equal(want, got), "want %v, got %v", want, got)
			require.NoError(t, settings.Reload())
			var stored UserData
			require.NoError(t, settings.GetStruct(settings.UserDataKey, &stored))
			assert.True(t, proto.Equal(want, &stored), "want %v, stored %v", want, &stored)
		})
	}
}

func TestSetDataNilClearsCachedUser(t *testing.T) {
	ac, _ := newTestClient(t)
	_, err := ac.NewUser(context.Background())
	require.NoError(t, err)
	ac.setData(nil)
	assert.False(t, settings.Exists(settings.UserDataKey))
	assert.Empty(t, settings.GetString(settings.TokenKey))
}

func TestFetchUserDataDoesNotReplayLoginSettings(t *testing.T) {
	ac, _ := newTestClient(t)
	ac.setData(&UserData{
		LegacyID:       123,
		Token:          "old-jwt",
		Devices:        []*protos.LoginResponse_Device{{Id: "old-device"}},
		LegacyUserData: &protos.LoginResponse_UserData{UserId: 123},
	})
	devices := []settings.Device{{ID: "new-device", Name: "Laptop"}}
	require.NoError(t, settings.Patch(settings.Settings{
		settings.JwtTokenKey: "new-jwt",
		settings.DevicesKey:  devices,
	}))
	_, err := ac.FetchUserData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "new-jwt", settings.GetString(settings.JwtTokenKey))
	storedDevices, err := settings.Devices()
	require.NoError(t, err)
	assert.Equal(t, devices, storedDevices)
	assert.Equal(t, "test-token", settings.GetString(settings.TokenKey))

	require.NoError(t, settings.Set(settings.UserDataKey, &UserData{LegacyID: 456, Token: "old-jwt"}))
	_, err = ac.FetchUserData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "new-jwt", settings.GetString(settings.JwtTokenKey))
	storedDevices, err = settings.Devices()
	require.NoError(t, err)
	assert.Equal(t, devices, storedDevices)
}

func TestFetchUserDataKeepsFreeLevel(t *testing.T) {
	ac, _ := newTestClient(t)
	ac.setData(&UserData{
		LegacyID: 123, LegacyToken: "test-token",
		LegacyUserData: &protos.LoginResponse_UserData{UserId: 123, UserLevel: "free"},
	})
	data, err := ac.FetchUserData(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "free", data.LegacyUserData.UserLevel)
	assert.Equal(t, "free", settings.GetString(settings.UserLevelKey))
	require.NoError(t, settings.Reload())
	var cached UserData
	require.NoError(t, settings.GetStruct(settings.UserDataKey, &cached))
	assert.Equal(t, "free", cached.LegacyUserData.UserLevel)
}
