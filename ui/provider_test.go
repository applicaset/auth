package ui_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/applicaset/buildset/auth/oidc/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signInWith walks the browser through start, the provider and back, and returns the callback's
// response. The provider signs in at once, so there is no page to fill in.
func (h *harness) signInWith(t *testing.T, provider, query string) *http.Response {
	t.Helper()

	start := h.get(t, "/oauth/"+provider+"/start"+query)
	require.Equal(t, http.StatusSeeOther, start.StatusCode, body(t, start))

	authorize, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, start.Header.Get("Location"), nil)
	require.NoError(t, err)

	atProvider, err := h.client.Do(authorize)
	require.NoError(t, err)

	defer func() { _ = atProvider.Body.Close() }()

	require.Equal(t, http.StatusSeeOther, atProvider.StatusCode)

	// The callback address carries the configured public URL, which is not the test server.
	callback, err := url.Parse(atProvider.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "auth.test", callback.Host)

	return h.get(t, callback.RequestURI())
}

func (h *harness) countUsers(t *testing.T) int {
	t.Helper()

	var count int
	require.NoError(t, h.db.QueryRowContext(t.Context(), `SELECT count(*) FROM users`).Scan(&count))

	return count
}

func TestProviderSignInCreatesAnAccountOnceAndFindsItAfter(t *testing.T) {
	provider := oidctest.New(t)
	h := newHarness(t, provider.Config("google", "Google"))

	provider.SignInAs(oidctest.Person{
		Subject: "g-1", Email: "Grace@Example.com", EmailVerified: true, Name: "Grace Hopper",
	})

	login := body(t, h.get(t, "/login"))
	assert.Contains(t, login, "Continue with Google")

	response := h.signInWith(t, "google", "?next=/finset/")
	require.Equal(t, http.StatusSeeOther, response.StatusCode, body(t, response))
	assert.Equal(t, "/finset/", response.Header.Get("Location"))
	assert.NotEmpty(t, h.sessionCookie(t))
	assert.True(t, h.emailVerified(t, "grace"))

	h.signOut(t)

	again := h.signInWith(t, "google", "")
	require.Equal(t, http.StatusSeeOther, again.StatusCode)
	assert.Equal(t, 1, h.countUsers(t), "the second sign-in finds the same account")
}

func TestProviderSignInLinksOnlyWhenBothSidesProvedTheAddress(t *testing.T) {
	provider := oidctest.New(t)
	h := newHarness(t, provider.Config("google", "Google"))

	require.Equal(t, http.StatusSeeOther, h.post(t, "/setup", setupForm()).StatusCode)
	h.signOut(t)

	provider.SignInAs(
		oidctest.Person{Subject: "g-1", Email: "ada@example.com", EmailVerified: true},
	)

	refused := h.signInWith(t, "google", "")
	require.Equal(t, http.StatusConflict, refused.StatusCode, "ada has not confirmed her address")
	assert.Contains(t, body(t, refused), "link Google from your settings")

	require.Equal(t, http.StatusOK, h.get(t, h.mailedPath(t, "ada@example.com")).StatusCode)

	provider.SignInAs(
		oidctest.Person{Subject: "g-2", Email: "ada@example.com", EmailVerified: false},
	)

	unverified := h.signInWith(t, "google", "")
	require.Equal(t, http.StatusConflict, unverified.StatusCode, "the provider has not either")

	provider.SignInAs(
		oidctest.Person{Subject: "g-1", Email: "ada@example.com", EmailVerified: true},
	)

	linked := h.signInWith(t, "google", "")
	require.Equal(t, http.StatusSeeOther, linked.StatusCode, body(t, linked))
	assert.Equal(t, 1, h.countUsers(t))
}

func TestProviderCallbackRefusesAForeignState(t *testing.T) {
	provider := oidctest.New(t)
	h := newHarness(t, provider.Config("google", "Google"))

	response := h.get(t, "/oauth/google/callback?code=x&state=forged")
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
}

func TestSettingsLinkAndUnlinkAProvider(t *testing.T) {
	provider := oidctest.New(t)
	h := newHarness(t, provider.Config("google", "Google"))

	require.Equal(t, http.StatusSeeOther, h.post(t, "/setup", setupForm()).StatusCode)
	provider.SignInAs(oidctest.Person{Subject: "g-9", Email: "elsewhere@example.com"})

	linked := h.signInWith(t, "google", "?link&next=/settings")
	require.Equal(t, http.StatusSeeOther, linked.StatusCode, body(t, linked))
	assert.True(t, strings.HasPrefix(linked.Header.Get("Location"), "/settings"))

	settings := body(t, h.get(t, "/settings"))
	assert.Contains(t, settings, "elsewhere@example.com")
	assert.NotContains(t, settings, "Link Google", "a linked provider is not offered again")

	h.signOut(t)
	require.Equal(t, http.StatusSeeOther, h.signInWith(t, "google", "").StatusCode,
		"the linked identity signs in to ada")
	assert.Equal(t, 1, h.countUsers(t))

	unlinked := h.post(t, "/settings/identities/unlink", url.Values{
		"provider": {"google"}, "subject": {"g-9"},
	})
	require.Equal(t, http.StatusSeeOther, unlinked.StatusCode)
	assert.Contains(t, body(t, h.get(t, "/settings")), "Link Google")
}
