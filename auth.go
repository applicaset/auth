// Package auth owns identity: users, their credentials, and their sessions. It is the only place
// in the system that handles a password, and the only place that can turn a session token into a
// user. Other services hold a user reference and nothing else.
package auth

import "errors"

const (
	// ServiceName is the service segment of every reference this package owns.
	ServiceName = "auth"
	// UserResourceType is the type segment of a user reference.
	UserResourceType = "user"
)

var (
	// ErrInvalidCredentials covers an unknown account, a wrong password and an account with no
	// password alike. Telling them apart would turn the login form into an account oracle.
	ErrInvalidCredentials = errors.New("invalid username, email or password")

	ErrUserNotFound = errors.New("user not found")
	// ErrInvalidUsername wraps every username rule failure, so callers can show the reason without
	// matching on message text.
	ErrInvalidUsername = errors.New("invalid username")
	ErrUsernameTaken   = errors.New("username is already taken")
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrEmailTaken      = errors.New("email address is already in use")
	ErrSessionNotFound = errors.New("session not found")
	// ErrTokenNotFound covers a token that never existed, was used, has expired, or is for another
	// purpose. A link that does not work gets one answer whatever the reason.
	ErrTokenNotFound = errors.New("link is invalid or has expired")

	ErrIdentityNotFound = errors.New("identity not found")
	ErrIdentityTaken    = errors.New("identity is linked to another account")
	// ErrAccountExists stops a provider sign-in from taking over an account whose email address
	// nobody has proved. The person signs in another way and links the provider from settings.
	ErrAccountExists = errors.New("an account with this email address already exists")
	// ErrLastSignInMethod keeps an account from losing its only way in.
	ErrLastSignInMethod = errors.New("this is the account's only way to sign in")
	ErrSignUpClosed     = errors.New("sign-up is closed")

	// ErrSetupClosed is returned once the first user exists. Setup never reopens.
	ErrSetupClosed = errors.New("setup is already complete")
)
