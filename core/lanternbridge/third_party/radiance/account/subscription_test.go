package account

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/log"
)

func TestSubscriptionPaymentRedirect(t *testing.T) {
	ac, ts := newTestClient(t)
	data := PaymentRedirectData{
		Provider:       "stripe",
		Plan:           "pro",
		DeviceName:     "test-device",
		Email:          "",
		BillingType:    SubscriptionTypeOneTime,
		IdempotencyKey: "subscription-redirect-key",
	}
	url, err := ac.SubscriptionPaymentRedirectURL(context.Background(), data)
	require.NoError(t, err)
	assert.NotEmpty(t, url)
	assert.Equal(t, data.IdempotencyKey, ts.subscriptionPaymentRedirectIdempotencyKey)
}

func TestPaymentRedirect(t *testing.T) {
	ac, ts := newTestClient(t)
	data := PaymentRedirectData{
		Provider:       "stripe",
		Plan:           "pro",
		DeviceName:     "test-device",
		Email:          "",
		IdempotencyKey: "payment-redirect-key",
	}
	url, err := ac.PaymentRedirect(context.Background(), data)
	require.NoError(t, err)
	assert.NotEmpty(t, url)
	assert.Equal(t, data.IdempotencyKey, ts.paymentRedirectIdempotencyKey)
	assert.Equal(t, common.GetVersion(), ts.paymentRedirectAppVersion)
	assert.Equal(t, common.GetVersion(), ts.paymentRedirectLibraryVersion)
}

func TestPaymentRedirectOmitsEmptyIdempotencyKey(t *testing.T) {
	ac, ts := newTestClient(t)
	data := PaymentRedirectData{
		Provider:   "stripe",
		Plan:       "pro",
		DeviceName: "test-device",
		Email:      "",
	}

	url, err := ac.PaymentRedirect(context.Background(), data)
	require.NoError(t, err)
	assert.NotEmpty(t, url)
	assert.False(t, ts.paymentRedirectHasIdempotencyKey)

	url, err = ac.SubscriptionPaymentRedirectURL(context.Background(), data)
	require.NoError(t, err)
	assert.NotEmpty(t, url)
	assert.False(t, ts.subscriptionPaymentRedirectHasIdempotencyKey)
}

func TestPaymentRedirectForwardsCouponCode(t *testing.T) {
	ac, ts := newTestClient(t)
	data := PaymentRedirectData{
		Provider:   "stripe",
		Plan:       "pro",
		DeviceName: "test-device",
		CouponCode: "SAVE20",
	}

	_, err := ac.PaymentRedirect(context.Background(), data)
	require.NoError(t, err)
	assert.True(t, ts.paymentRedirectHasCouponCode)
	assert.Equal(t, data.CouponCode, ts.paymentRedirectCouponCode)

	_, err = ac.SubscriptionPaymentRedirectURL(context.Background(), data)
	require.NoError(t, err)
	assert.True(t, ts.subscriptionPaymentRedirectHasCouponCode)
	assert.Equal(t, data.CouponCode, ts.subscriptionPaymentRedirectCouponCode)
}

func TestPaymentRedirectOmitsEmptyCouponCode(t *testing.T) {
	ac, ts := newTestClient(t)
	data := PaymentRedirectData{
		Provider:   "stripe",
		Plan:       "pro",
		DeviceName: "test-device",
	}

	_, err := ac.PaymentRedirect(context.Background(), data)
	require.NoError(t, err)
	assert.False(t, ts.paymentRedirectHasCouponCode)

	_, err = ac.SubscriptionPaymentRedirectURL(context.Background(), data)
	require.NoError(t, err)
	assert.False(t, ts.subscriptionPaymentRedirectHasCouponCode)
}

func TestPaymentRedirectRequiresRedirectURL(t *testing.T) {
	ac, ts := newTestClient(t)
	ts.paymentRedirectResponse = map[string]string{"status": "error", "error": "try again later"}

	url, err := ac.PaymentRedirect(context.Background(), PaymentRedirectData{
		Provider:   "stripe",
		Plan:       "pro",
		DeviceName: "test-device",
	})
	require.Error(t, err)
	assert.Empty(t, url)
}

func TestNewUser(t *testing.T) {
	ac, _ := newTestClient(t)
	resp, err := ac.NewUser(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerifySubscription(t *testing.T) {
	ac, _ := newTestClient(t)
	data := map[string]string{
		"email":  "test@getlantern.org",
		"planID": "1y-usd-10",
	}
	resp, err := ac.VerifySubscription(context.Background(), AppleService, data)
	require.NoError(t, err)
	assert.NotEmpty(t, resp)
}

func TestRestoreSubscription(t *testing.T) {
	t.Run("apple", func(t *testing.T) {
		ac, _ := newTestClient(t)
		resp, err := ac.RestoreSubscription(context.Background(), AppleService, map[string]string{"receipt": "r"})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "active", resp.Status)
		assert.Equal(t, int64(1234), resp.ActualUserID)
		assert.Equal(t, "token", resp.ActualUserToken)
	})

	t.Run("google", func(t *testing.T) {
		ac, _ := newTestClient(t)
		resp, err := ac.RestoreSubscription(context.Background(), GoogleService, map[string]string{"purchaseToken": "t"})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "active", resp.Status)
	})

	t.Run("unsupported", func(t *testing.T) {
		ac, _ := newTestClient(t)
		resp, err := ac.RestoreSubscription(context.Background(), StripeService, nil)
		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

func TestPlans(t *testing.T) {
	ac, _ := newTestClient(t)
	require.NoError(t, ac.storeIdentity(123, "token"))
	resp, err := ac.SubscriptionPlans(context.Background(), "store")
	require.NoError(t, err)
	assert.NotEmpty(t, resp)
}

func TestPlansWaitsForNewUser(t *testing.T) {
	ac, _ := newTestClient(t)
	require.NoError(t, settings.Clear(settings.UserIDKey)) // InitSettings may migrate a local install's user
	type result struct {
		resp string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := ac.SubscriptionPlans(context.Background(), "store")
		done <- result{resp, err}
	}()

	select {
	case r := <-done:
		t.Fatalf("plans returned before a user existed: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}

	require.NoError(t, ac.storeIdentity(123, "token"))
	select {
	case r := <-done:
		require.NoError(t, r.err)
		assert.NotEmpty(t, r.resp)
	case <-time.After(5 * time.Second):
		t.Fatal("plans did not proceed after the user was created")
	}
}

func TestPlansWithoutUserStopsWithContext(t *testing.T) {
	ac, _ := newTestClient(t)
	require.NoError(t, settings.Clear(settings.UserIDKey)) // InitSettings may migrate a local install's user
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := ac.SubscriptionPlans(ctx, "store")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestNewStripeSubscriptionForwardsCouponCode(t *testing.T) {
	ac, ts := newTestClient(t)
	resp, err := ac.NewStripeSubscription(context.Background(), "test@getlantern.org", "1y-usd-10", "SAVE20")
	require.NoError(t, err)
	assert.NotEmpty(t, resp)
	assert.True(t, ts.stripeSubscriptionHasCouponCode)
	assert.Equal(t, "SAVE20", ts.stripeSubscriptionCouponCode)
}

func TestNewStripeSubscriptionOmitsEmptyCouponCode(t *testing.T) {
	ac, ts := newTestClient(t)
	resp, err := ac.NewStripeSubscription(context.Background(), "test@getlantern.org", "1y-usd-10", "")
	require.NoError(t, err)
	assert.NotEmpty(t, resp)
	assert.False(t, ts.stripeSubscriptionHasCouponCode)
}
func TestPurchaseResponseUnmarshalPlan(t *testing.T) {
	var fromString PurchaseResponse
	require.NoError(t, json.Unmarshal([]byte(`{"status":"ok","provider":"web-license","plan":"1y-usd-10","isPro":true}`), &fromString))
	require.Equal(t, "ok", fromString.Status)
	require.Equal(t, "1y-usd-10", fromString.Plan.Id)

	var fromObject PurchaseResponse
	require.NoError(t, json.Unmarshal([]byte(`{"status":"ok","paymentStatus":"done","plan":{"id":"1y-usd-10","usdPrice":1000}}`), &fromObject))
	require.Equal(t, "done", fromObject.PaymentStatus)
	require.Equal(t, "1y-usd-10", fromObject.Plan.Id)
	require.EqualValues(t, 1000, fromObject.Plan.UsdPrice)

	var withError PurchaseResponse
	require.NoError(t, json.Unmarshal([]byte(`{"error":"bad code","errorId":"reseller-codes"}`), &withError))
	require.NotNil(t, withError.BaseResponse)
	require.Equal(t, "bad code", withError.Error)
}

func TestActivationCodeRequest(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		provider string
		field    string
	}{
		{"reseller code", "ABCD-1234", "reseller-code", "resellerCode"},
		{"pro prefix", "PRO-12345-67890", "web-license", "licenseKey"},
		{"mixed case with leading whitespace", "  pRo-12345", "web-license", "licenseKey"},
		{"pro prefix and suffix", "PRO-12345PRO", "web-license", "licenseKey"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/purchase", r.URL.Path)
				require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}))
			defer srv.Close()

			a := &Client{httpClient: srv.Client(), logger: log.NoOpLogger(), proURL: srv.URL}
			resp, err := a.ActivationCode(context.Background(), "user@example.com", tc.code)
			require.NoError(t, err)
			require.Equal(t, "ok", resp.Status)

			require.Equal(t, tc.provider, got["provider"])
			require.Equal(t, tc.code, got[tc.field], "code must be forwarded unchanged")
			require.Equal(t, "user@example.com", got["email"])
			for _, other := range []string{"licenseKey", "resellerCode"} {
				if other != tc.field {
					require.NotContains(t, got, other)
				}
			}
		})
	}
}
