package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/buildset/auth"
)

const tableIdentities = "identities"

const (
	identityColumnProvider  = "provider"
	identityColumnSubject   = "subject"
	identityColumnUserID    = "user_id"
	identityColumnEmail     = "email"
	identityColumnCreatedAt = "created_at"
)

func identityColumns() []string {
	return []string{
		identityColumnProvider,
		identityColumnSubject,
		identityColumnUserID,
		identityColumnEmail,
		identityColumnCreatedAt,
	}
}

func (r *Repository) InsertIdentity(ctx context.Context, identity *auth.Identity) error {
	_, err := r.builder().
		Insert(tableIdentities).
		Columns(identityColumns()...).
		Values(
			identity.Provider,
			identity.Subject,
			identity.UserID,
			identity.Email,
			identity.CreatedAt,
		).
		ExecContext(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s", auth.ErrIdentityTaken, identity.Provider)
		}

		return fmt.Errorf("insert identity: %w", err)
	}

	return nil
}

func (r *Repository) GetIdentity(
	ctx context.Context,
	provider, subject string,
) (*auth.Identity, error) {
	row := r.builder().
		Select(identityColumns()...).
		From(tableIdentities).
		Where(squirrel.Eq{identityColumnProvider: provider, identityColumnSubject: subject}).
		QueryRowContext(ctx)

	return scanIdentity(row)
}

func (r *Repository) ListIdentities(ctx context.Context, userID string) ([]auth.Identity, error) {
	rows, err := r.builder().
		Select(identityColumns()...).
		From(tableIdentities).
		Where(squirrel.Eq{identityColumnUserID: userID}).
		OrderBy(identityColumnProvider, identityColumnSubject).
		QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("select identities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	identities := make([]auth.Identity, 0)

	for rows.Next() {
		identity, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}

		identities = append(identities, *identity)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identities: %w", err)
	}

	return identities, nil
}

func (r *Repository) DeleteIdentity(ctx context.Context, userID, provider, subject string) error {
	result, err := r.builder().
		Delete(tableIdentities).
		Where(squirrel.Eq{
			identityColumnUserID:   userID,
			identityColumnProvider: provider,
			identityColumnSubject:  subject,
		}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("delete identity: %w", err)
	}

	return requireOneRow(result, auth.ErrIdentityNotFound)
}

func scanIdentity(row rowScanner) (*auth.Identity, error) {
	var identity auth.Identity

	err := row.Scan(
		&identity.Provider,
		&identity.Subject,
		&identity.UserID,
		&identity.Email,
		&identity.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrIdentityNotFound
		}

		return nil, fmt.Errorf("scan identity: %w", err)
	}

	identity.CreatedAt = identity.CreatedAt.UTC()

	return &identity, nil
}
