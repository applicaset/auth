package ui

import (
	"errors"
	"net/http"
	"time"

	"github.com/applicaset/buildset/auth"
)

const pathSettings = "/settings"

// recentSignIn is how fresh a session must be to stand in for a password on an account that has
// none. Signing in again by email link or provider renews it.
const recentSignIn = 10 * time.Minute

type accountView struct {
	Username      string
	Name          string
	Email         string
	EmailVerified bool
	HasPassword   bool
	// Reauthenticated is true when the session is fresh enough to skip asking for a password.
	Reauthenticated bool
	Identities      []identityView
	Providers       []providerView
}

type identityView struct {
	Provider string
	Label    string
	Subject  string
	Email    string
}

var accountNotices = map[string]string{
	"verification-sent": "A confirmation link is on its way to your email address.",
	"email-sent":        "A confirmation link is on its way to the new address.",
	"profile-saved":     "Your profile has been saved.",
	"linked":            "The sign-in method has been linked.",
	"unlinked":          "The sign-in method has been removed.",
}

func (h *Handler) accountPage(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	h.renderSettings(w, r, http.StatusOK, session, user, pageData{
		Notice: accountNotices[r.URL.Query().Get("notice")],
	})
}

func (h *Handler) renderSettings(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	session *auth.Session,
	user *auth.User,
	data pageData,
) {
	view, err := h.accountView(r, session, user)
	if err != nil {
		h.renderInternalError(w, r, err, "load account")

		return
	}

	data.Title = "Settings"
	data.Account = view

	if data.Next == "" {
		data.Next = nextTarget(r)
	}

	h.render(w, r, status, "settings.gohtml", data)
}

func (h *Handler) accountView(
	r *http.Request,
	session *auth.Session,
	user *auth.User,
) (*accountView, error) {
	view := &accountView{
		Username:        user.Username,
		Name:            user.Name,
		Email:           user.Email,
		EmailVerified:   user.EmailVerified(),
		HasPassword:     user.HasPassword(),
		Reauthenticated: freshSession(session),
	}

	identities, err := h.service.ListIdentities(r.Context(), user.ID)
	if err != nil {
		return nil, err
	}

	linked := make(map[string]bool, len(identities))

	for _, identity := range identities {
		linked[identity.Provider] = true
		view.Identities = append(view.Identities, identityView{
			Provider: identity.Provider,
			Label:    h.providerLabel(identity.Provider),
			Subject:  identity.Subject,
			Email:    identity.Email,
		})
	}

	for _, provider := range h.providerViews() {
		if !linked[provider.Name] {
			view.Providers = append(view.Providers, provider)
		}
	}

	return view, nil
}

func freshSession(session *auth.Session) bool {
	return time.Since(session.CreatedAt) < recentSignIn
}

// reauthenticated holds a sensitive change to a password the person just typed or, on an account
// without one, to a session they just started.
func (h *Handler) reauthenticated(r *http.Request, session *auth.Session, user *auth.User) error {
	if !user.HasPassword() {
		if freshSession(session) {
			return nil
		}

		return errStaleSession
	}

	if _, err := h.service.Authenticate(
		r.Context(), user.Username, r.PostFormValue("current_password"),
	); err != nil {
		return err
	}

	return nil
}

var errStaleSession = errors.New("sign in again to make this change")

func (h *Handler) accountProfileSubmit(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok || !h.parseForm(w, r) {
		return
	}

	_, err := h.service.UpdateProfile(r.Context(), auth.UpdateProfileRequest{
		UserID:   user.ID,
		Username: r.PostFormValue("username"),
		Name:     r.PostFormValue("name"),
	})
	if err != nil {
		if !isValidationError(err) {
			h.renderInternalError(w, r, err, "update profile")

			return
		}

		h.renderSettings(w, r, http.StatusBadRequest, session, user, pageData{
			ErrorMessage: userFacingError(err, "Your profile could not be saved."),
		})

		return
	}

	http.Redirect(w, r, withQuery(h.SettingsURL(nextTarget(r)), "notice", "profile-saved"),
		http.StatusSeeOther)
}

func (h *Handler) accountEmailSubmit(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok || !h.parseForm(w, r) {
		return
	}

	if err := h.reauthenticated(r, session, user); err != nil {
		h.renderReauthError(w, r, session, user, err)

		return
	}

	if err := h.service.RequestEmailChange(
		r.Context(),
		user.ID,
		r.PostFormValue("email"),
	); err != nil {
		if !isValidationError(err) {
			h.renderInternalError(w, r, err, "request email change")

			return
		}

		h.renderSettings(w, r, http.StatusBadRequest, session, user, pageData{
			ErrorMessage: userFacingError(err, "That email address could not be used."),
		})

		return
	}

	http.Redirect(w, r, withQuery(h.SettingsURL(nextTarget(r)), "notice", "email-sent"),
		http.StatusSeeOther)
}

func (h *Handler) renderReauthError(
	w http.ResponseWriter,
	r *http.Request,
	session *auth.Session,
	user *auth.User,
	err error,
) {
	switch {
	case errors.Is(err, errStaleSession):
		h.renderSettings(w, r, http.StatusUnauthorized, session, user, pageData{
			ErrorMessage: "Sign in again to make this change. It keeps someone at an unlocked " +
				"computer from taking over your account.",
		})
	case errors.Is(err, auth.ErrInvalidCredentials):
		h.renderSettings(w, r, http.StatusUnauthorized, session, user, pageData{
			ErrorMessage: "Your current password is not correct.",
		})
	default:
		h.renderInternalError(w, r, err, "re-authenticate")
	}
}

func (h *Handler) deleteAccountForm(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	view, err := h.accountView(r, session, user)
	if err != nil {
		h.renderInternalError(w, r, err, "load account")

		return
	}

	h.render(w, r, http.StatusOK, "delete_account.gohtml", pageData{
		Title:   "Delete your account",
		Next:    nextTarget(r),
		Account: view,
	})
}

// deleteAccountSubmit asks for the word DELETE, so a stray click cannot delete an account.
func (h *Handler) deleteAccountSubmit(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok || !h.parseForm(w, r) {
		return
	}

	renderForm := func(status int, message string) {
		view, err := h.accountView(r, session, user)
		if err != nil {
			h.renderInternalError(w, r, err, "load account")

			return
		}

		h.render(w, r, status, "delete_account.gohtml", pageData{
			Title:        "Delete your account",
			ErrorMessage: message,
			Next:         nextTarget(r),
			Account:      view,
		})
	}

	if r.PostFormValue("confirm") != "DELETE" {
		renderForm(http.StatusBadRequest, "Type DELETE to confirm.")

		return
	}

	if err := h.reauthenticated(r, session, user); err != nil {
		switch {
		case errors.Is(err, errStaleSession):
			renderForm(http.StatusUnauthorized, "Sign in again to delete your account.")
		case errors.Is(err, auth.ErrInvalidCredentials):
			renderForm(http.StatusUnauthorized, "Your current password is not correct.")
		default:
			h.renderInternalError(w, r, err, "re-authenticate")
		}

		return
	}

	// TODO: the account's data in other services (a todoset task tree, blog posts, finset
	// memberships) and its authz grants outlive it. Unblocked once auth can tell each application
	// that an account is going, for example by calling a purge endpoint each one registers.
	if err := h.service.DeleteUser(r.Context(), user.ID); err != nil {
		h.renderInternalError(w, r, err, "delete own account")

		return
	}

	h.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
