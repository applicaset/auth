package ui

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/applicaset/buildset/auth"
	"github.com/applicaset/buildset/pkg/safeurl"
)

// Links in mail open a page with a button rather than acting on GET. Mail scanners and link
// previews fetch every URL in a message, and a single-use sign-in link must survive that.

func (h *Handler) emailLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	email := r.PostFormValue("email")
	next := nextTarget(r)

	err := h.service.RequestEmailLogin(r.Context(), email, next, h.anonymousMayRegister(r))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidEmail) {
			h.render(w, r, http.StatusBadRequest, "login.gohtml", h.loginPage(r, pageData{
				ErrorMessage: userFacingError(err, ""),
				Next:         next,
				Email:        email,
			}))

			return
		}

		h.renderInternalError(w, r, err, "request email login")

		return
	}

	h.render(w, r, http.StatusOK, "email_sent.gohtml", pageData{
		Title:   "Check your email",
		Message: "If that address can sign in here, a link is on its way. It expires in 15 minutes.",
		Next:    next,
	})
}

func (h *Handler) emailLoginForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "token_confirm.gohtml", pageData{
		Title:  "Sign in",
		Action: pathEmailLogin,
		Token:  r.URL.Query().Get("token"),
		Next:   nextTarget(r),
		Button: "Sign in",
	})
}

func (h *Handler) emailLoginConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	user, err := h.service.ConsumeEmailLogin(
		r.Context(), r.PostFormValue("token"), h.anonymousMayRegister(r))
	if err != nil {
		h.renderTokenError(w, r, err, "consume email login")

		return
	}

	if err := h.startSession(w, r, user); err != nil {
		h.renderInternalError(w, r, err, "start session after email login")

		return
	}

	http.Redirect(w, r, nextTarget(r), http.StatusSeeOther)
}

func (h *Handler) forgotPasswordForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "forgot_password.gohtml", pageData{
		Title: "Reset your password",
		Next:  nextTarget(r),
		Email: r.URL.Query().Get("email"),
	})
}

func (h *Handler) forgotPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	email := r.PostFormValue("email")

	if err := h.service.RequestPasswordReset(r.Context(), email); err != nil {
		if errors.Is(err, auth.ErrInvalidEmail) {
			h.render(w, r, http.StatusBadRequest, "forgot_password.gohtml", pageData{
				Title:        "Reset your password",
				ErrorMessage: userFacingError(err, ""),
				Next:         nextTarget(r),
				Email:        email,
			})

			return
		}

		h.renderInternalError(w, r, err, "request password reset")

		return
	}

	h.render(w, r, http.StatusOK, "email_sent.gohtml", pageData{
		Title: "Check your email",
		Message: "If an account uses that address, a link to reset its password is on its way. " +
			"It expires in 1 hour.",
		Next: nextTarget(r),
	})
}

func (h *Handler) resetPasswordForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "reset_password.gohtml", pageData{
		Title: "Choose a new password",
		Token: r.URL.Query().Get("token"),
		Next:  nextTarget(r),
	})
}

// resetPasswordSubmit signs the person in: following the link proved they own the account.
func (h *Handler) resetPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	token := r.PostFormValue("token")

	user, err := h.service.ResetPassword(r.Context(), token, r.PostFormValue("new_password"))
	if err != nil {
		if isValidationError(err) {
			h.render(w, r, http.StatusBadRequest, "reset_password.gohtml", pageData{
				Title:        "Choose a new password",
				ErrorMessage: userFacingError(err, "That password could not be used."),
				Token:        token,
				Next:         nextTarget(r),
			})

			return
		}

		h.renderTokenError(w, r, err, "reset password")

		return
	}

	if err := h.startSession(w, r, user); err != nil {
		h.renderInternalError(w, r, err, "start session after password reset")

		return
	}

	http.Redirect(w, r, nextTarget(r), http.StatusSeeOther)
}

// verifyEmail acts on GET. Confirming an address is harmless to repeat, and a scanner using up the
// link only confirms what the person meant to confirm anyway.
func (h *Handler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	if _, err := h.service.VerifyEmail(r.Context(), r.URL.Query().Get("token")); err != nil {
		h.renderTokenError(w, r, err, "verify email")

		return
	}

	h.render(w, r, http.StatusOK, "error.gohtml", pageData{
		Title:   "Email confirmed",
		Message: "Thank you. Your email address is confirmed.",
		Next:    nextTarget(r),
	})
}

func (h *Handler) resendVerification(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.requireSession(w, r)
	if !ok || !h.parseForm(w, r) {
		return
	}

	if err := h.service.SendVerification(r.Context(), user.ID); err != nil {
		h.renderInternalError(w, r, err, "resend verification")

		return
	}

	http.Redirect(w, r, withQuery(h.SettingsURL(nextTarget(r)), "notice", "verification-sent"),
		http.StatusSeeOther)
}

func (h *Handler) confirmEmailForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "token_confirm.gohtml", pageData{
		Title:  "Confirm your new email address",
		Action: pathConfirmEmail,
		Token:  r.URL.Query().Get("token"),
		Next:   nextTarget(r),
		Button: "Confirm",
	})
}

func (h *Handler) confirmEmailSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	if _, err := h.service.ConfirmEmailChange(r.Context(), r.PostFormValue("token")); err != nil {
		if errors.Is(err, auth.ErrEmailTaken) {
			h.renderError(w, r, http.StatusConflict, userFacingError(err, ""))

			return
		}

		h.renderTokenError(w, r, err, "confirm email change")

		return
	}

	h.render(w, r, http.StatusOK, "error.gohtml", pageData{
		Title:   "Email changed",
		Message: "Your account now uses the new email address.",
		Next:    nextTarget(r),
	})
}

// renderTokenError answers a used, expired or unknown link with one message.
func (h *Handler) renderTokenError(w http.ResponseWriter, r *http.Request, err error, op string) {
	switch {
	case errors.Is(err, auth.ErrTokenNotFound):
		h.renderError(w, r, http.StatusBadRequest,
			"That link is invalid or has expired. Ask for a new one.")
	case errors.Is(err, auth.ErrSignUpClosed):
		h.renderError(w, r, http.StatusForbidden, "New accounts cannot be created here.")
	default:
		h.renderInternalError(w, r, err, op)
	}
}

func withQuery(target, key, value string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return safeurl.Next("")
	}

	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()

	return parsed.String()
}
