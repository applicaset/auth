// Package sqlite stores auth's users and sessions in SQLite. It owns its schema and migrates
// itself, so wiring auth to a different backend runs none of this.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/buildset/buildset/auth"
	"github.com/buildset/buildset/pkg/sqlmigrate"
	sqlitedriver "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrations embed.FS

// timeFormat sorts lexicographically, so ordering and range queries work on the stored text.
const timeFormat = "2006-01-02T15:04:05.000Z"

type Repository struct {
	db *sql.DB
}

// NewRepository migrates the schema and returns a repository over it.
func NewRepository(ctx context.Context, db *sql.DB) (*Repository, error) {
	runner := sqlmigrate.Runner{
		FileSystem: migrations,
		Directory:  "migrations",
		TableName:  "auth_schema_migrations",
	}

	if err := runner.Up(ctx, db); err != nil {
		return nil, fmt.Errorf("migrate auth schema: %w", err)
	}

	return &Repository{db: db}, nil
}

// SQLite takes ? placeholders, squirrel's default, so this is the only place the dialect is named.
func (r *Repository) builder() squirrel.StatementBuilderType {
	return squirrel.StatementBuilder.RunWith(r.db)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func requireOneRow(result sql.Result, notFound error) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count affected rows: %w", err)
	}

	if affected == 0 {
		return notFound
	}

	return nil
}

func isUniqueViolation(err error) bool {
	var sqliteError *sqlitedriver.Error

	return errors.As(err, &sqliteError) && sqliteError.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

func formatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(timeFormat, value)
}

var _ auth.Repository = (*Repository)(nil)

// userConflict names the column a unique violation hit. The driver reports it only in the message,
// as "UNIQUE constraint failed: users.email".
func userConflict(err error, user *auth.User) error {
	if strings.Contains(err.Error(), tableUsers+"."+userColumnEmail) {
		return fmt.Errorf("%w: %s", auth.ErrEmailTaken, user.Email)
	}

	return fmt.Errorf("%w: %s", auth.ErrUsernameTaken, user.Username)
}

// nullableString stores an empty string as NULL, so a UNIQUE column accepts any number of blanks.
func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullableTime(value *time.Time) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}

	return sql.NullString{String: formatTime(*value), Valid: true}
}

func isPrimaryKeyViolation(err error) bool {
	var sqliteError *sqlitedriver.Error

	return errors.As(err, &sqliteError) &&
		sqliteError.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}
