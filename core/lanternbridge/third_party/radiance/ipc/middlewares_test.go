package ipc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthPeer(t *testing.T) {
	for _, test := range []struct {
		name     string
		lookup   func() (usr, error)
		ownerSID string
		status   int
	}{
		{name: "missing credentials", status: http.StatusUnauthorized},
		{
			name:   "lookup failed",
			lookup: func() (usr, error) { return usr{}, errors.New("credentials unavailable") },
			status: http.StatusUnauthorized,
		},
		{
			name:   "empty identity",
			lookup: func() (usr, error) { return usr{isAdmin: true}, nil },
			status: http.StatusUnauthorized,
		},
		{
			name:   "unrelated user",
			lookup: func() (usr, error) { return usr{uid: "unrelated-user"}, nil },
			status: http.StatusForbidden,
		},
		{
			name:     "enrolled owner",
			ownerSID: "original-user",
			lookup:   func() (usr, error) { return usr{uid: "original-user"}, nil },
			status:   http.StatusNoContent,
		},
		{
			name:     "different enrolled owner",
			ownerSID: "original-user",
			lookup:   func() (usr, error) { return usr{uid: "other-user"}, nil },
			status:   http.StatusForbidden,
		},
		{
			name:   "administrator",
			lookup: func() (usr, error) { return usr{uid: "administrator", isAdmin: true}, nil },
			status: http.StatusNoContent,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request = request.WithContext(context.WithValue(request.Context(), ownerSIDKey{}, test.ownerSID))
			if test.lookup != nil {
				request = request.WithContext(context.WithValue(request.Context(), peerLookupKey{}, test.lookup))
			}
			response := httptest.NewRecorder()
			authPeer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}
