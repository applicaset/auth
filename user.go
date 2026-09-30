package auth

import (
	"time"

	"github.com/applicaset/buildset/pkg/ref"
)

type User struct {
	ID       string
	Username string
	// Email is empty only for accounts created before email addresses were collected.
	Email string
	// EmailVerifiedAt is set once the person follows a link sent to Email, or a provider vouches
	// for it.
	EmailVerifiedAt *time.Time
	Name            string
	// PasswordHash must never leave this service. Nothing outside auth has a reason to read it.
	// It is empty for an account that signs in by email link or a provider only.
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (u *User) Ref() string {
	return ref.MustNew(ServiceName, UserResourceType, u.ID).String()
}

func (u *User) HasPassword() bool { return u.PasswordHash != "" }

func (u *User) EmailVerified() bool { return u.Email != "" && u.EmailVerifiedAt != nil }

type TokenPurpose string

const (
	TokenVerifyEmail   TokenPurpose = "verify-email"
	TokenResetPassword TokenPurpose = "reset-password"
	TokenEmailLogin    TokenPurpose = "email-login"
	TokenChangeEmail   TokenPurpose = "change-email"
)

// Token is a single-use secret mailed as a link. Like a session, only its hash is stored.
type Token struct {
	TokenHash string
	Purpose   TokenPurpose
	// UserID is empty for an email-login token addressed to someone with no account yet.
	UserID string
	// Email is where the link was sent. For a change-email token it is the new address.
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (t *Token) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

// Identity links an account at an external provider, such as Google, to a user.
type Identity struct {
	Provider string
	// Subject is the provider's stable id for the account. An email address can change; this
	// cannot.
	Subject   string
	UserID    string
	Email     string
	CreatedAt time.Time
}

type Session struct {
	ID     string
	UserID string
	// TokenHash is the SHA-256 of the token handed to the browser. The token is never stored, so a
	// copy of the database does not hand over live sessions.
	TokenHash string
	CreatedAt time.Time
	// ExpiresAt is absolute, not sliding. A stolen token that is in constant use still dies.
	ExpiresAt time.Time
	LastSeen  time.Time
	UserAgent string
	IP        string
}

func (s *Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}
