package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/auth"
)

const tableSessions = "sessions"

const (
	sessionColumnID        = "id"
	sessionColumnUserID    = "user_id"
	sessionColumnTokenHash = "token_hash"
	sessionColumnCreatedAt = "created_at"
	sessionColumnExpiresAt = "expires_at"
	sessionColumnLastSeen  = "last_seen"
	sessionColumnUserAgent = "user_agent"
	sessionColumnIP        = "ip"
)

func sessionColumns() []string {
	return []string{
		sessionColumnID,
		sessionColumnUserID,
		sessionColumnTokenHash,
		sessionColumnCreatedAt,
		sessionColumnExpiresAt,
		sessionColumnLastSeen,
		sessionColumnUserAgent,
		sessionColumnIP,
	}
}

type SessionRepository struct {
	db *sql.DB
}

var _ auth.SessionRepository = (*SessionRepository)(nil)

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Insert(ctx context.Context, session *auth.Session) error {
	_, err := builder(r.db).
		Insert(tableSessions).
		Columns(sessionColumns()...).
		Values(
			session.ID,
			session.UserID,
			session.TokenHash,
			session.CreatedAt,
			session.ExpiresAt,
			session.LastSeen,
			session.UserAgent,
			session.IP,
		).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}

	return nil
}

func (r *SessionRepository) GetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*auth.Session, error) {
	var session auth.Session

	err := builder(r.db).
		Select(sessionColumns()...).
		From(tableSessions).
		Where(squirrel.Eq{sessionColumnTokenHash: tokenHash}).
		QueryRowContext(ctx).
		Scan(
			&session.ID, &session.UserID, &session.TokenHash,
			&session.CreatedAt, &session.ExpiresAt, &session.LastSeen, &session.UserAgent, &session.IP,
		)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrSessionNotFound
		}

		return nil, fmt.Errorf("select session: %w", err)
	}

	// A timestamptz comes back in the session's time zone; everything above this layer wants an
	// instant.
	session.CreatedAt = session.CreatedAt.UTC()
	session.ExpiresAt = session.ExpiresAt.UTC()
	session.LastSeen = session.LastSeen.UTC()

	return &session, nil
}

func (r *SessionRepository) Touch(ctx context.Context, id string, lastSeen time.Time) error {
	_, err := builder(r.db).
		Update(tableSessions).
		Set(sessionColumnLastSeen, lastSeen).
		Where(squirrel.Eq{sessionColumnID: id}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}

	return nil
}

func (r *SessionRepository) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	_, err := builder(r.db).
		Delete(tableSessions).
		Where(squirrel.Eq{sessionColumnTokenHash: tokenHash}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

func (r *SessionRepository) DeleteByUser(
	ctx context.Context,
	userID, exceptSessionID string,
) error {
	// An empty exceptSessionID matches no row, so every session of the user is removed.
	_, err := builder(r.db).
		Delete(tableSessions).
		Where(squirrel.Eq{sessionColumnUserID: userID}).
		Where(squirrel.NotEq{sessionColumnID: exceptSessionID}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("delete sessions of user: %w", err)
	}

	return nil
}

func (r *SessionRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	result, err := builder(r.db).
		Delete(tableSessions).
		Where(squirrel.LtOrEq{sessionColumnExpiresAt: now}).
		ExecContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count deleted sessions: %w", err)
	}

	return deleted, nil
}
