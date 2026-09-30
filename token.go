package auth

import (
	"context"
	"time"
)

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

// TokenRepository returns ErrTokenNotFound for an absent token.
type TokenRepository interface {
	Insert(ctx context.Context, token *Token) error
	// Consume deletes the token and returns it, so a link works once however many requests
	// race to use it. An expired token or one for another purpose is not found.
	Consume(
		ctx context.Context,
		tokenHash string,
		purpose TokenPurpose,
		now time.Time,
	) (*Token, error)
	DeleteByUser(ctx context.Context, userID string, purpose TokenPurpose) error
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

func (t *Token) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}
