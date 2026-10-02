package httpapi_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/applicaset/auth"
	"github.com/applicaset/auth/hash"
	"github.com/applicaset/auth/httpapi"
	"github.com/applicaset/auth/sqlite"
	"github.com/applicaset/auth/ui"
	"github.com/applicaset/pkg/api/authapi"
	"github.com/applicaset/pkg/httpx"
	"github.com/applicaset/pkg/mail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func newService(t *testing.T) *auth.Service {
	t.Helper()

	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/test.db?_pragma=foreign_keys(ON)")
	require.NoError(t, err)

	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	require.NoError(t, sqlite.Migrate(t.Context(), db))

	// The lowest cost bcrypt accepts, because these tests create accounts repeatedly.
	algorithm, err := hash.NewBcrypt(10)
	require.NoError(t, err)

	passwords, err := hash.NewRegistry(algorithm)
	require.NoError(t, err)

	links, err := ui.NewLinks("http://auth.test")
	require.NoError(t, err)

	service, err := auth.NewService(
		sqlite.NewUserRepository(db),
		sqlite.NewSessionRepository(db),
		sqlite.NewTokenRepository(db),
		sqlite.NewIdentityRepository(db),
		auth.Options{
			Passwords:  passwords,
			SessionTTL: time.Hour,
			Mailer:     &mail.Recorder{},
			Links:      links,
			Logger:     slog.New(slog.DiscardHandler),
		},
	)
	require.NoError(t, err)

	return service
}

func newServer(t *testing.T, service *auth.Service) *httptest.Server {
	t.Helper()

	handler, err := httpapi.NewHandler(service, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	mux := http.NewServeMux()
	handler.Register(mux)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server
}

func post(t *testing.T, server *httptest.Server, path string, request any) (int, []byte) {
	t.Helper()

	body, err := json.Marshal(request)
	require.NoError(t, err)

	httpRequest, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		server.URL+path,
		bytes.NewReader(body),
	)
	require.NoError(t, err)

	httpRequest.Header.Set("Content-Type", "application/json")

	response, err := server.Client().Do(httpRequest)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()

	payload, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	return response.StatusCode, payload
}

func TestResolveSession(t *testing.T) {
	service := newService(t)
	server := newServer(t, service)

	user, err := service.Register(t.Context(), auth.RegisterRequest{
		Username: "alice",
		Email:    "alice@example.com",
		Name:     "Alice",
		Password: "correct-horse-battery",
	})
	require.NoError(t, err)

	token, _, err := service.CreateSession(t.Context(), user.ID, auth.SessionMeta{})
	require.NoError(t, err)

	status, body := post(
		t,
		server,
		authapi.PathResolveSession,
		authapi.ResolveSessionRequest{Token: token},
	)
	require.Equal(t, http.StatusOK, status)

	var response authapi.UserResponse
	require.NoError(t, json.Unmarshal(body, &response))
	assert.Equal(t, "alice", response.User.Username)
	assert.Equal(t, "Alice", response.User.Name)
	assert.Equal(t, "urn:auth:user:"+user.ID, response.User.Ref)

	// Nothing about a credential may cross the wire.
	assert.NotContains(t, string(body), "password")
	assert.NotContains(t, string(body), token)
}

// Separates "no such session" from "the identity service is broken".
func TestResolveSessionReportsAnUnknownTokenAsNotFound(t *testing.T) {
	server := newServer(t, newService(t))

	status, body := post(
		t,
		server,
		authapi.PathResolveSession,
		authapi.ResolveSessionRequest{Token: "nonsense"},
	)
	require.Equal(t, http.StatusNotFound, status)

	var envelope httpx.Envelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, httpx.CodeNotFound, envelope.Code)
	assert.Equal(t, "That account could not be found.", envelope.Message)
}

func TestUpdateProfileReportsAConflict(t *testing.T) {
	service := newService(t)
	server := newServer(t, service)

	alice, err := service.Register(
		t.Context(),
		auth.RegisterRequest{
			Username: "alice",
			Email:    "alice@example.com",
			Password: "correct-horse-battery",
		},
	)
	require.NoError(t, err)

	bob, err := service.Register(
		t.Context(),
		auth.RegisterRequest{
			Username: "bob",
			Email:    "bob@example.com",
			Password: "correct-horse-battery",
		},
	)
	require.NoError(t, err)

	status, body := post(t, server, authapi.PathUpdateProfile, authapi.UpdateProfileRequest{
		UserRef:  bob.Ref(),
		Username: alice.Username,
	})
	require.Equal(t, http.StatusConflict, status)

	var envelope httpx.Envelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, httpx.CodeConflict, envelope.Code)
	assert.Equal(t, "That username is already taken.", envelope.Message)
}

// A malformed reference names no account, the same answer as a missing account. It must never
// reach the site as a system failure.
func TestUpdateProfileReportsAMalformedReferenceAsNotFound(t *testing.T) {
	server := newServer(t, newService(t))

	status, body := post(t, server, authapi.PathUpdateProfile, authapi.UpdateProfileRequest{
		UserRef:  "not-a-reference",
		Username: "alice",
	})
	require.Equal(t, http.StatusNotFound, status)

	var envelope httpx.Envelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, httpx.CodeNotFound, envelope.Code)
}

func TestSetupOpenClosesAfterTheFirstAccount(t *testing.T) {
	service := newService(t)
	server := newServer(t, service)

	status, body := post(t, server, authapi.PathSetupOpen, authapi.Empty{})
	require.Equal(t, http.StatusOK, status)

	var open authapi.SetupOpenResponse
	require.NoError(t, json.Unmarshal(body, &open))
	assert.True(t, open.Open)

	_, err := service.Register(
		t.Context(),
		auth.RegisterRequest{
			Username: "alice",
			Email:    "alice@example.com",
			Password: "correct-horse-battery",
		},
	)
	require.NoError(t, err)

	status, body = post(t, server, authapi.PathSetupOpen, authapi.Empty{})
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, json.Unmarshal(body, &open))
	assert.False(t, open.Open)
}

func TestListUsersCarriesNoCredentials(t *testing.T) {
	service := newService(t)
	server := newServer(t, service)

	_, err := service.Register(
		t.Context(),
		auth.RegisterRequest{
			Username: "alice",
			Email:    "alice@example.com",
			Password: "correct-horse-battery",
		},
	)
	require.NoError(t, err)

	status, body := post(t, server, authapi.PathListUsers, authapi.ListUsersRequest{Limit: 10})
	require.Equal(t, http.StatusOK, status)

	var response authapi.ListUsersResponse
	require.NoError(t, json.Unmarshal(body, &response))
	require.Len(t, response.Users, 1)
	assert.Equal(t, "alice", response.Users[0].Username)
	assert.NotContains(t, string(body), "password_hash")
}

func TestDeleteUser(t *testing.T) {
	service := newService(t)
	server := newServer(t, service)

	alice, err := service.Register(
		t.Context(),
		auth.RegisterRequest{
			Username: "alice",
			Email:    "alice@example.com",
			Password: "correct-horse-battery",
		},
	)
	require.NoError(t, err)

	status, body := post(
		t,
		server,
		authapi.PathDeleteUser,
		authapi.DeleteUserRequest{UserRef: alice.Ref()},
	)
	require.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{}`, string(body))

	status, _ = post(t, server, authapi.PathGetUser, authapi.GetUserRequest{UserRef: alice.Ref()})
	assert.Equal(t, http.StatusNotFound, status)
}

func TestGetUserByUsernameIgnoresCase(t *testing.T) {
	service := newService(t)
	server := newServer(t, service)

	alice, err := service.Register(
		t.Context(),
		auth.RegisterRequest{
			Username: "alice",
			Email:    "alice@example.com",
			Password: "correct-horse-battery",
		},
	)
	require.NoError(t, err)

	status, body := post(
		t,
		server,
		authapi.PathGetUserByUsername,
		authapi.GetUserByUsernameRequest{Username: " Alice "},
	)
	require.Equal(t, http.StatusOK, status)

	var response authapi.UserResponse
	require.NoError(t, json.Unmarshal(body, &response))
	assert.Equal(t, alice.Ref(), response.User.Ref)

	status, _ = post(
		t,
		server,
		authapi.PathGetUserByUsername,
		authapi.GetUserByUsernameRequest{Username: "nobody"},
	)
	assert.Equal(t, http.StatusNotFound, status)
}

// The identity service's own pages hold these operations. Nothing over the network may create a
// session or change a password.
func TestCredentialOperationsAreNotServed(t *testing.T) {
	server := newServer(t, newService(t))

	for _, path := range []string{
		"/v1/register", "/v1/authenticate", "/v1/create-session",
		"/v1/revoke-session", "/v1/change-password", "/v1/complete-setup",
	} {
		status, _ := post(t, server, path, authapi.Empty{})
		assert.Equal(t, http.StatusNotFound, status, path)
	}
}
