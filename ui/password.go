package ui

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/applicaset/auth"
)

func (h *Handler) passwordForm(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	data := h.passwordPage(r, session, user)
	if r.URL.Query().Has("changed") {
		data.Notice = "Your password has been changed."
	}

	h.render(w, r, http.StatusOK, "password.gohtml", data)
}

func (h *Handler) passwordSubmit(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	if !h.parseForm(w, r) {
		return
	}

	// An account without a password proves itself with a fresh session instead.
	if !user.HasPassword() && !freshSession(session) {
		data := h.passwordPage(r, session, user)
		data.ErrorMessage = "Sign in again to set a password."
		h.render(w, r, http.StatusUnauthorized, "password.gohtml", data)

		return
	}

	req := auth.ChangePasswordRequest{
		UserID:          user.ID,
		CurrentPassword: r.PostFormValue("current_password"),
		NewPassword:     r.PostFormValue("new_password"),
		KeepSessionID:   session.ID,
	}

	if err := h.service.ChangePassword(r.Context(), req); err != nil {
		if !isValidationError(err) && !errors.Is(err, auth.ErrInvalidCredentials) {
			h.renderInternalError(w, r, err, "change password")

			return
		}

		message := userFacingError(err, "That password could not be changed.")
		if errors.Is(err, auth.ErrInvalidCredentials) {
			message = "Your current password is not correct."
		}

		data := h.passwordPage(r, session, user)
		data.ErrorMessage = message
		h.render(w, r, http.StatusBadRequest, "password.gohtml", data)

		return
	}

	http.Redirect(
		w,
		r,
		"/password?changed&next="+url.QueryEscape(nextTarget(r)),
		http.StatusSeeOther,
	)
}

// requireSession sends an unauthenticated visitor to the login page and reports whether the caller
// should stop.
func (h *Handler) requireSession(
	w http.ResponseWriter,
	r *http.Request,
) (*auth.Session, *auth.User, bool) {
	session, user, err := h.currentSession(r)
	if err == nil {
		return session, user, true
	}

	if !errors.Is(err, auth.ErrSessionNotFound) {
		h.renderInternalError(w, r, err, "resolve session")

		return nil, nil, false
	}

	h.clearSessionCookie(w)

	if r.Method != http.MethodGet {
		// Redirecting a POST would throw away what the visitor typed, so say so instead.
		h.renderError(
			w,
			r,
			http.StatusUnauthorized,
			"Your session has expired. Sign in again and retry.",
		)

		return nil, nil, false
	}

	http.Redirect(w, r, h.LoginURL(r.URL.RequestURI()), http.StatusSeeOther)

	return nil, nil, false
}

func (h *Handler) passwordPage(r *http.Request, session *auth.Session, user *auth.User) pageData {
	title := "Change your password"
	if !user.HasPassword() {
		title = "Set a password"
	}

	return pageData{
		Title: title,
		Next:  nextTarget(r),
		Account: &accountView{
			HasPassword:     user.HasPassword(),
			Reauthenticated: freshSession(session),
		},
	}
}
