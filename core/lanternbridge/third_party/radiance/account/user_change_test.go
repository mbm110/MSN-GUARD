package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/account/protos"
	"github.com/getlantern/radiance/events"
)

func TestAccountChangesNotifyWithoutBackendWrappers(t *testing.T) {
	a, _ := newTestClient(t)
	changes := make(chan struct{}, 16)
	sub := events.Subscribe(func(UserChangeEvent) { changes <- struct{}{} })
	defer sub.Unsubscribe()
	expect := func(count int) {
		t.Helper()
		for range count {
			select {
			case <-changes:
			case <-time.After(3 * time.Second):
				t.Fatal("account event not received")
			}
		}
		select {
		case <-changes:
			t.Fatal("unexpected account event")
		case <-time.After(30 * time.Millisecond):
		}
	}
	ctx := context.Background()
	_, err := a.NewUser(ctx)
	require.NoError(t, err)
	expect(1)
	_, err = a.FetchUserData(ctx)
	require.NoError(t, err)
	expect(0)
	a.setData(&UserData{LegacyUserData: &protos.LoginResponse_UserData{UserLevel: "pro"}})
	expect(1)
	a.setData(&UserData{LegacyUserData: &protos.LoginResponse_UserData{UserLevel: "pro"}})
	expect(0)
	a.setData(&UserData{LegacyID: 456, LegacyToken: "new-token"})
	expect(1)
	a.setData(&UserData{LegacyID: 456, LegacyToken: "new-token"})
	expect(0)
	_, err = a.Logout(ctx, "test@example.com")
	require.NoError(t, err)
	expect(2)
	a.ClearUser()
	expect(1)
	a.ClearUser()
	expect(0)

	token := mockJWT(t, map[string]any{"legacy_user_id": 789, "legacy_token": "oauth-token"})
	require.NoError(t, a.OAuthDeviceLimitCallback(ctx, token))
	expect(1)
	require.NoError(t, a.OAuthDeviceLimitCallback(ctx, token))
	expect(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProtoResponse(w, &protos.SignupResponse{LegacyID: 456, ProToken: "signup-token", Token: "jwt"})
	}))
	defer server.Close()
	a.authURL = server.URL
	_, _, err = a.SignUp(ctx, "test@example.com", "password")
	require.NoError(t, err)
	expect(1)
}
