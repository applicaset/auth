package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/auth"
)

const tableUsers = "users"

const (
	userColumnID           = "id"
	userColumnUsername     = "username"
	userColumnEmail        = "email"
	userColumnVerifiedAt   = "email_verified_at"
	userColumnName         = "name"
	userColumnPasswordHash = "password_hash"
	userColumnCreatedAt    = "created_at"
	userColumnUpdatedAt    = "updated_at"
)

func userColumns() []string {
	return []string{
		userColumnID,
		userColumnUsername,
		userColumnEmail,
		userColumnVerifiedAt,
		userColumnName,
		userColumnPasswordHash,
		userColumnCreatedAt,
		userColumnUpdatedAt,
	}
}

type UserRepository struct {
	db *sql.DB
}

var _ auth.UserRepository = (*UserRepository)(nil)

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Insert(ctx context.Context, user *auth.User) error {
	_, err := builder(r.db).
		Insert(tableUsers).
		Columns(userColumns()...).
		Values(
			user.ID,
			user.Username,
			nullableString(user.Email),
			user.EmailVerifiedAt,
			user.Name,
			user.PasswordHash,
			user.CreatedAt,
			user.UpdatedAt,
		).
		ExecContext(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return userConflict(err, user)
		}

		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

func (r *UserRepository) Update(ctx context.Context, user *auth.User) error {
	result, err := builder(r.db).
		Update(tableUsers).
		Set(userColumnUsername, user.Username).
		Set(userColumnEmail, nullableString(user.Email)).
		Set(userColumnVerifiedAt, user.EmailVerifiedAt).
		Set(userColumnName, user.Name).
		Set(userColumnPasswordHash, user.PasswordHash).
		Set(userColumnUpdatedAt, user.UpdatedAt).
		Where(squirrel.Eq{userColumnID: user.ID}).
		ExecContext(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return userConflict(err, user)
		}

		return fmt.Errorf("update user: %w", err)
	}

	return requireOneRow(result, fmt.Errorf("%w: %s", auth.ErrUserNotFound, user.ID))
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	result, err := builder(r.db).
		Delete(tableUsers).
		Where(squirrel.Eq{userColumnID: id}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	return requireOneRow(result, fmt.Errorf("%w: %s", auth.ErrUserNotFound, id))
}

func (r *UserRepository) Get(ctx context.Context, id string) (*auth.User, error) {
	row := builder(r.db).
		Select(userColumns()...).
		From(tableUsers).
		Where(squirrel.Eq{userColumnID: id}).
		QueryRowContext(ctx)

	return scanUser(row, fmt.Errorf("%w: %s", auth.ErrUserNotFound, id))
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*auth.User, error) {
	row := builder(r.db).
		Select(userColumns()...).
		From(tableUsers).
		Where(squirrel.Eq{userColumnEmail: email}).
		QueryRowContext(ctx)

	return scanUser(row, fmt.Errorf("%w: %s", auth.ErrUserNotFound, email))
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*auth.User, error) {
	row := builder(r.db).
		Select(userColumns()...).
		From(tableUsers).
		Where(squirrel.Eq{userColumnUsername: username}).
		QueryRowContext(ctx)

	return scanUser(row, fmt.Errorf("%w: %s", auth.ErrUserNotFound, username))
}

func (r *UserRepository) List(ctx context.Context, limit int) ([]auth.User, error) {
	rows, err := builder(r.db).
		Select(userColumns()...).
		From(tableUsers).
		OrderBy(userColumnCreatedAt, userColumnID).
		Limit(uint64(limit)).
		QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("select users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	users := make([]auth.User, 0)

	for rows.Next() {
		user, err := scanUser(rows, auth.ErrUserNotFound)
		if err != nil {
			return nil, err
		}

		users = append(users, *user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}

	return users, nil
}

func (r *UserRepository) Count(ctx context.Context) (int, error) {
	var count int

	err := builder(r.db).
		Select("count(*)").
		From(tableUsers).
		QueryRowContext(ctx).
		Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}

	return count, nil
}

func scanUser(row rowScanner, notFound error) (*auth.User, error) {
	var (
		user       auth.User
		email      sql.NullString
		verifiedAt sql.NullTime
	)

	err := row.Scan(
		&user.ID,
		&user.Username,
		&email,
		&verifiedAt,
		&user.Name,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, notFound
		}

		return nil, fmt.Errorf("scan user: %w", err)
	}

	user.Email = email.String

	if verifiedAt.Valid {
		verified := verifiedAt.Time.UTC()
		user.EmailVerifiedAt = &verified
	}

	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()

	return &user, nil
}
