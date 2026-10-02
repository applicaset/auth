package ui

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/applicaset/auth"
	"github.com/applicaset/pkg/safeurl"
)

func (h *Handler) loginForm(w http.ResponseWriter, r *http.Request) {
	next := safeurl.Next(r.URL.Query().Get("next"))

	// reauth asks a signed-in person to prove it is still them before a sensitive change.
	if _, _, err := h.currentSession(r); err == nil && !r.URL.Query().Has("reauth") {
		http.Redirect(w, r, next, http.StatusSeeOther)

		return
	}

	h.render(w, r, http.StatusOK, "login.gohtml", h.loginPage(r, pageData{Next: next}))
}

// loginPage fills what every rendering of the sign-in page shows.
func (h *Handler) loginPage(r *http.Request, data pageData) pageData {
	data.Title = "Sign in"
	data.RegistrationOpen = h.anonymousMayRegister(r)
	data.Providers = h.providerViews()

	return data
}

func (h *Handler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	var (
		login = r.PostFormValue("login")
		next  = safeurl.Next(r.PostFormValue("next"))
	)

	user, err := h.service.Authenticate(r.Context(), login, r.PostFormValue("password"))
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			h.renderInternalError(w, r, err, "authenticate user")

			return
		}

		// The same message for an unknown account and a wrong password, so the form cannot be
		// used to find out which accounts exist.
		h.render(w, r, http.StatusUnauthorized, "login.gohtml", h.loginPage(r, pageData{
			ErrorMessage: auth.ErrInvalidCredentials.Error(),
			Next:         next,
			Username:     login,
		}))

		return
	}

	if err := h.startSession(w, r, user); err != nil {
		h.renderInternalError(w, r, err, "start session after login")

		return
	}

	http.Redirect(w, r, next, http.StatusSeeOther)
}

// A policy that cannot answer hides the sign-up link rather than failing the page.
func (h *Handler) anonymousMayRegister(r *http.Request) bool {
	allowed, err := h.policy.SignUpOpen(r.Context())
	if err != nil {
		h.logger.WarnContext(r.Context(), "check registration policy", slog.Any("error", err))

		return false
	}

	return allowed
}

// logoutForm only asks. Signing out stays POST only, because a logout reachable by GET can be
// triggered by any image tag on any other site.
func (h *Handler) logoutForm(w http.ResponseWriter, r *http.Request) {
	next := nextTarget(r)

	if h.sessionToken(r) == "" {
		http.Redirect(w, r, next, http.StatusSeeOther)

		return
	}

	h.render(w, r, http.StatusOK, "logout.gohtml", pageData{
		Title:        "Sign out",
		Next:         next,
		HideBackLink: true,
	})
}

func (h *Handler) logoutSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	if token := h.sessionToken(r); token != "" {
		if err := h.service.RevokeSession(r.Context(), token); err != nil {
			h.renderInternalError(w, r, err, "revoke session")

			return
		}
	}

	h.clearSessionCookie(w)
	http.Redirect(w, r, nextTarget(r), http.StatusSeeOther)
}
