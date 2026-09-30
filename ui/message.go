package ui

import (
	"errors"

	"github.com/applicaset/buildset/auth"
	"github.com/applicaset/buildset/auth/hash"
)

// userFacingError decides which failures are safe and useful to show on a form. Anything not
// listed here becomes the fallback, so an internal message never reaches the browser.
func userFacingError(err error, fallback string) string {
	switch {
	case errors.Is(err, auth.ErrUsernameTaken):
		return "That username is already taken."
	case errors.Is(err, auth.ErrEmailTaken):
		return "That email address is already in use."
	case errors.Is(err, auth.ErrInvalidUsername),
		errors.Is(err, auth.ErrInvalidEmail),
		errors.Is(err, hash.ErrPasswordTooShort):
		return err.Error()
	case errors.Is(err, hash.ErrPasswordTooLong):
		// The wrapped detail is a byte limit, which means nothing to someone typing a password.
		return "That password is too long."
	case errors.Is(err, auth.ErrInvalidCredentials):
		return auth.ErrInvalidCredentials.Error()
	default:
		return fallback
	}
}

// isValidationError separates what the visitor can fix by retyping from what is the system's fault
// and must not be rendered as a form error.
func isValidationError(err error) bool {
	return errors.Is(err, auth.ErrUsernameTaken) ||
		errors.Is(err, auth.ErrInvalidUsername) ||
		errors.Is(err, auth.ErrEmailTaken) ||
		errors.Is(err, auth.ErrInvalidEmail) ||
		errors.Is(err, hash.ErrPasswordTooShort) ||
		errors.Is(err, hash.ErrPasswordTooLong)
}
