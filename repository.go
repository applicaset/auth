package auth

import (
	"context"
	"time"
)

// Repository is the persistence contract. Implementations return ErrUserNotFound,
// ErrSessionNotFound, ErrTokenNotFound and ErrIdentityNotFound for absent rows, and ErrUsernameTaken,
// ErrEmailTaken and ErrIdentityTaken for collisions. Deleting a user removes its sessions, tokens and
// identities with it.
type Repository interface {
	InsertUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, limit int) ([]User, error)
	CountUsers(ctx context.Context) (int, error)

	InsertSession(ctx context.Context, session *Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	TouchSession(ctx context.Context, id string, lastSeen time.Time) error
	DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error
	// DeleteSessionsByUser removes every session of a user except exceptSessionID, which may be
	// empty to remove all of them.
	DeleteSessionsByUser(ctx context.Context, userID, exceptSessionID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)

	InsertToken(ctx context.Context, token *Token) error
	// ConsumeToken deletes the token and returns it, so a link works once however many requests
	// race to use it. An expired token or one for another purpose is not found.
	ConsumeToken(
		ctx context.Context,
		tokenHash string,
		purpose TokenPurpose,
		now time.Time,
	) (*Token, error)
	DeleteTokensByUser(ctx context.Context, userID string, purpose TokenPurpose) error
	DeleteExpiredTokens(ctx context.Context, now time.Time) (int64, error)

	InsertIdentity(ctx context.Context, identity *Identity) error
	GetIdentity(ctx context.Context, provider, subject string) (*Identity, error)
	// ListIdentities orders by provider, then subject.
	ListIdentities(ctx context.Context, userID string) ([]Identity, error)
	DeleteIdentity(ctx context.Context, userID, provider, subject string) error
}
