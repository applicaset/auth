package ui

import (
	"errors"
	"net/http"

	"github.com/buildset/buildset/auth"
)

const (
	registerTitle = "Create an account"
	newUserTitle  = "New user"
)

// signUpGate answers 404 when sign-up is closed, so a closed instance does not advertise the route.
// Someone already signed in has an account and goes home.
func (h *Handler) signUpGate(w http.ResponseWriter, r *http.Request) bool {
	_, actor, err := h.currentSession(r)
	if err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
		h.renderInternalError(w, r, err, "resolve session")

		return false
	}

	if actor != nil {
		http.Redirect(w, r, nextTarget(r), http.StatusSeeOther)

		return false
	}

	open, err := h.policy.SignUpOpen(r.Context())
	if err != nil {
		h.renderInternalError(w, r, err, "check registration policy")

		return false
	}

	if !open {
		h.renderError(w, r, http.StatusNotFound, "There is nothing here.")

		return false
	}

	return true
}

// addUserGate answers 404 to anyone who may not add accounts, for the same reason as signUpGate.
func (h *Handler) addUserGate(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	_, actor, err := h.currentSession(r)
	if err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
		h.renderInternalError(w, r, err, "resolve session")

		return nil, false
	}

	if actor == nil {
		http.Redirect(w, r, h.LoginURL(r.URL.RequestURI()), http.StatusSeeOther)

		return nil, false
	}

	allowed, err := h.policy.MayAddUser(r.Context(), actor.Ref())
	if err != nil {
		h.renderInternalError(w, r, err, "check registration policy")

		return nil, false
	}

	if !allowed {
		h.renderError(w, r, http.StatusNotFound, "There is nothing here.")

		return nil, false
	}

	return actor, true
}

func (h *Handler) registerForm(w http.ResponseWriter, r *http.Request) {
	if !h.signUpGate(w, r) {
		return
	}

	h.render(w, r, http.StatusOK, "register.gohtml", pageData{
		Title: registerTitle,
		Next:  nextTarget(r),
	})
}

func (h *Handler) registerSubmit(w http.ResponseWriter, r *http.Request) {
	if !h.signUpGate(w, r) {
		return
	}

	user, ok := h.createUser(w, r, "register.gohtml", registerTitle)
	if !ok {
		return
	}

	if err := h.startSession(w, r, user); err != nil {
		h.renderInternalError(w, r, err, "start session after registration")

		return
	}

	http.Redirect(w, r, nextTarget(r), http.StatusSeeOther)
}

func (h *Handler) newUserForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.addUserGate(w, r); !ok {
		return
	}

	h.render(w, r, http.StatusOK, "new_user.gohtml", pageData{
		Title: newUserTitle,
		Next:  nextTarget(r),
	})
}

// Adding somebody else's account leaves the browser signed in as the person who added it.
func (h *Handler) newUserSubmit(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.addUserGate(w, r); !ok {
		return
	}

	if _, ok := h.createUser(w, r, "new_user.gohtml", newUserTitle); !ok {
		return
	}

	http.Redirect(w, r, nextTarget(r), http.StatusSeeOther)
}

// createUser registers the account in the submitted form, re-rendering page with the problem when
// the input is at fault.
func (h *Handler) createUser(
	w http.ResponseWriter,
	r *http.Request,
	page, title string,
) (*auth.User, bool) {
	if !h.parseForm(w, r) {
		return nil, false
	}

	req := auth.RegisterRequest{
		Username: r.PostFormValue("username"),
		Name:     r.PostFormValue("name"),
		Password: r.PostFormValue("password"),
	}

	user, err := h.service.Register(r.Context(), req)
	if err == nil {
		return user, true
	}

	if !isValidationError(err) {
		h.renderInternalError(w, r, err, "register user")

		return nil, false
	}

	status := http.StatusBadRequest
	if errors.Is(err, auth.ErrUsernameTaken) {
		status = http.StatusConflict
	}

	h.render(w, r, status, page, pageData{
		Title:        title,
		ErrorMessage: userFacingError(err, "That account could not be created."),
		Next:         nextTarget(r),
		Username:     req.Username,
		Name:         req.Name,
	})

	return nil, false
}
