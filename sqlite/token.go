package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/buildset/auth"
)

const tableTokens = "tokens"

const (
	tokenColumnHash      = "token_hash"
	tokenColumnPurpose   = "purpose"
	tokenColumnUserID    = "user_id"
	tokenColumnEmail     = "email"
	tokenColumnCreatedAt = "created_at"
	tokenColumnExpiresAt = "expires_at"
)

func tokenColumns() []string {
	return []string{
		tokenColumnHash,
		tokenColumnPurpose,
		tokenColumnUserID,
		tokenColumnEmail,
		tokenColumnCreatedAt,
		tokenColumnExpiresAt,
	}
}

type TokenRepository struct {
	db *sql.DB
}

var _ auth.TokenRepository = (*TokenRepository)(nil)

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Insert(ctx context.Context, token *auth.Token) error {
	_, err := builder(r.db).
		Insert(tableTokens).
		Columns(tokenColumns()...).
		Values(
			token.TokenHash,
			string(token.Purpose),
			nullableString(token.UserID),
			token.Email,
			formatTime(token.CreatedAt),
			formatTime(token.ExpiresAt),
		).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}

	return nil
}

func (r *TokenRepository) Consume(
	ctx context.Context,
	tokenHash string,
	purpose auth.TokenPurpose,
	now time.Time,
) (*auth.Token, error) {
	query, args, err := squirrel.
		Delete(tableTokens).
		Where(squirrel.Eq{tokenColumnHash: tokenHash, tokenColumnPurpose: string(purpose)}).
		Where(squirrel.Gt{tokenColumnExpiresAt: formatTime(now)}).
		Suffix("RETURNING " + strings.Join(tokenColumns(), ", ")).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build consume token: %w", err)
	}

	var (
		token                auth.Token
		purposeValue         string
		userID               sql.NullString
		createdAt, expiresAt string
	)

	err = r.db.QueryRowContext(ctx, query, args...).Scan(
		&token.TokenHash,
		&purposeValue,
		&userID,
		&token.Email,
		&createdAt,
		&expiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrTokenNotFound
		}

		return nil, fmt.Errorf("consume token: %w", err)
	}

	token.Purpose = auth.TokenPurpose(purposeValue)
	token.UserID = userID.String

	if token.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, fmt.Errorf("parse token created_at: %w", err)
	}

	if token.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, fmt.Errorf("parse token expires_at: %w", err)
	}

	return &token, nil
}

func (r *TokenRepository) DeleteByUser(
	ctx context.Context,
	userID string,
	purpose auth.TokenPurpose,
) error {
	_, err := builder(r.db).
		Delete(tableTokens).
		Where(squirrel.Eq{tokenColumnUserID: userID, tokenColumnPurpose: string(purpose)}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("delete tokens of user: %w", err)
	}

	return nil
}

func (r *TokenRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	result, err := builder(r.db).
		Delete(tableTokens).
		Where(squirrel.LtOrEq{tokenColumnExpiresAt: formatTime(now)}).
		ExecContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired tokens: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count deleted tokens: %w", err)
	}

	return deleted, nil
}
