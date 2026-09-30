package auth

import (
	"context"
	"time"
)

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

// SessionRepository returns ErrSessionNotFound for an absent session.
type SessionRepository interface {
	Insert(ctx context.Context, session *Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	Touch(ctx context.Context, id string, lastSeen time.Time) error
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
	// DeleteByUser removes every session of a user except exceptSessionID, which may be
	// empty to remove all of them.
	DeleteByUser(ctx context.Context, userID, exceptSessionID string) error
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

func (s *Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}
