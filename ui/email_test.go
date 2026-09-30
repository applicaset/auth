package ui_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mailedLink = regexp.MustCompile(`http://auth\.test(/\S+)`)

// mailedPath is the path and query of the last link mailed to address.
func (h *harness) mailedPath(t *testing.T, address string) string {
	t.Helper()

	message, ok := h.mailer.Last(address)
	require.True(t, ok, "no mail to %s", address)

	match := mailedLink.FindStringSubmatch(message.Text)
	require.NotNil(t, match, "no link in %q", message.Text)

	return match[1]
}

func tokenOf(t *testing.T, path string) string {
	t.Helper()

	parsed, err := url.Parse(path)
	require.NoError(t, err)

	return parsed.Query().Get("token")
}

// signOut drops the session cookie, as a second browser would start.
func (h *harness) signOut(t *testing.T) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	h.client.Jar = jar
}

func (h *harness) emailVerified(t *testing.T, username string) bool {
	t.Helper()

	var verified *string
	require.NoError(t, h.db.QueryRowContext(t.Context(),
		`SELECT email_verified_at FROM users WHERE username = ?`, username).Scan(&verified))

	return verified != nil
}

func TestRegistrationMailsALinkThatConfirmsTheAddress(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusSeeOther, h.post(t, "/setup", setupForm()).StatusCode)
	require.False(t, h.emailVerified(t, "ada"))

	link := h.mailedPath(t, "ada@example.com")
	require.True(t, strings.HasPrefix(link, "/verify-email?"), link)

	response := h.get(t, link)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.True(t, h.emailVerified(t, "ada"))

	assert.Equal(t, http.StatusBadRequest, h.get(t, link).StatusCode, "a link works once")
}

func TestLoginAcceptsTheEmailAddress(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusSeeOther, h.post(t, "/setup", setupForm()).StatusCode)
	h.signOut(t)

	response := h.post(t, "/login", url.Values{
		"login": {"ADA@example.com"}, "password": {"correct horse"},
	})
	assert.Equal(t, http.StatusSeeOther, response.StatusCode)
}

// Mail scanners fetch every link in a message. Opening the link must not use it up.
func TestEmailLinkSignsUpANewAddressOnlyWhenConfirmed(t *testing.T) {
	h := newHarness(t)

	response := h.post(t, "/login/email/request", url.Values{
		"email": {"Grace@Example.com"}, "next": {"/finset/"},
	})
	require.Equal(t, http.StatusOK, response.StatusCode)

	link := h.mailedPath(t, "grace@example.com")
	require.Equal(t, http.StatusOK, h.get(t, link).StatusCode)
	require.Equal(t, http.StatusOK, h.get(t, link).StatusCode)
	require.Empty(t, h.sessionCookie(t))

	response = h.post(t, "/login/email", url.Values{
		"token": {tokenOf(t, link)}, "next": {"/finset/"},
	})
	require.Equal(t, http.StatusSeeOther, response.StatusCode)
	assert.Equal(t, "/finset/", response.Header.Get("Location"))
	assert.NotEmpty(t, h.sessionCookie(t))
	assert.True(t, h.emailVerified(t, "grace"), "the username comes from the address")

	h.signOut(t)

	reused := h.post(t, "/login/email", url.Values{"token": {tokenOf(t, link)}})
	assert.Equal(t, http.StatusBadRequest, reused.StatusCode)
}

func TestEmailLinkSendsNothingToAStrangerWhenSignUpIsClosed(t *testing.T) {
	h := newHarness(t)
	h.signUpOpen = false

	response := h.post(t, "/login/email/request", url.Values{"email": {"nobody@example.com"}})
	require.Equal(t, http.StatusOK, response.StatusCode, "the answer does not reveal the account")

	_, sent := h.mailer.Last("nobody@example.com")
	assert.False(t, sent)
}

func TestPasswordResetReplacesThePasswordAndSignsOutEverywhere(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusSeeOther, h.post(t, "/setup", setupForm()).StatusCode)
	require.Equal(t, 1, h.countSessions(t))
	h.signOut(t)

	unknown := h.post(t, "/forgot-password", url.Values{"email": {"nobody@example.com"}})
	known := h.post(t, "/forgot-password", url.Values{"email": {"ada@example.com"}})
	require.Equal(t, http.StatusOK, unknown.StatusCode)
	require.Equal(t, http.StatusOK, known.StatusCode)
	assert.Equal(t, body(t, unknown), body(t, known), "the answer does not reveal the account")

	link := h.mailedPath(t, "ada@example.com")
	require.True(t, strings.HasPrefix(link, "/reset-password?"), link)

	short := h.post(t, "/reset-password", url.Values{
		"token": {tokenOf(t, link)}, "new_password": {"short"},
	})
	require.Equal(t, http.StatusBadRequest, short.StatusCode, "a rejected password keeps the link")

	response := h.post(t, "/reset-password", url.Values{
		"token": {tokenOf(t, link)}, "new_password": {"a brand new secret"},
	})
	require.Equal(t, http.StatusSeeOther, response.StatusCode)
	assert.Equal(t, 1, h.countSessions(t), "the old session is gone, the new one stays")
	assert.True(t, h.emailVerified(t, "ada"))

	h.signOut(t)

	old := h.post(t, "/login", url.Values{"login": {"ada"}, "password": {"correct horse"}})
	assert.Equal(t, http.StatusUnauthorized, old.StatusCode)

	fresh := h.post(t, "/login", url.Values{"login": {"ada"}, "password": {"a brand new secret"}})
	assert.Equal(t, http.StatusSeeOther, fresh.StatusCode)
}

func TestEmailChangeWaitsForTheNewAddressToConfirm(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusSeeOther, h.post(t, "/setup", setupForm()).StatusCode)

	wrong := h.post(t, "/settings/email", url.Values{
		"email": {"ada@new.example"}, "current_password": {"nope"},
	})
	require.Equal(t, http.StatusUnauthorized, wrong.StatusCode)

	response := h.post(t, "/settings/email", url.Values{
		"email": {"ada@new.example"}, "current_password": {"correct horse"},
	})
	require.Equal(t, http.StatusSeeOther, response.StatusCode)

	var email string
	require.NoError(t, h.db.QueryRowContext(t.Context(),
		`SELECT email FROM users WHERE username = 'ada'`).Scan(&email))
	assert.Equal(t, "ada@example.com", email, "nothing changes before the link is followed")

	link := h.mailedPath(t, "ada@new.example")
	require.Equal(t, http.StatusOK,
		h.post(t, "/email/confirm", url.Values{"token": {tokenOf(t, link)}}).StatusCode)

	require.NoError(t, h.db.QueryRowContext(t.Context(),
		`SELECT email FROM users WHERE username = 'ada'`).Scan(&email))
	assert.Equal(t, "ada@new.example", email)
	assert.True(t, h.emailVerified(t, "ada"))
}

func TestDeletingTheAccountNeedsTheWordAndThePassword(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusSeeOther, h.post(t, "/setup", setupForm()).StatusCode)

	noWord := h.post(t, "/settings/delete", url.Values{"current_password": {"correct horse"}})
	require.Equal(t, http.StatusBadRequest, noWord.StatusCode)

	noPassword := h.post(t, "/settings/delete", url.Values{"confirm": {"DELETE"}})
	require.Equal(t, http.StatusUnauthorized, noPassword.StatusCode)

	response := h.post(t, "/settings/delete", url.Values{
		"confirm": {"DELETE"}, "current_password": {"correct horse"},
	})
	require.Equal(t, http.StatusSeeOther, response.StatusCode)

	var count int
	require.NoError(t, h.db.QueryRowContext(t.Context(), `SELECT count(*) FROM users`).Scan(&count))
	assert.Zero(t, count)
	assert.Zero(t, h.countSessions(t))
}
