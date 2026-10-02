// Package postgres stores auth's users and sessions in Postgres. It owns its schema, applied by
// Migrate, so wiring auth to a different backend runs none of this.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/pkg/sqlmigrate"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Migrate(ctx context.Context, db *sql.DB) error {
	runner := sqlmigrate.Runner{
		FileSystem: migrations,
		Directory:  "migrations",
		TableName:  "auth_schema_migrations",
		Dialect:    sqlmigrate.Postgres{},
	}

	if err := runner.Up(ctx, db); err != nil {
		return fmt.Errorf("migrate auth schema: %w", err)
	}

	return nil
}

// The only place this package names a placeholder style.
func builder(db *sql.DB) squirrel.StatementBuilderType {
	return squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar).RunWith(db)
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
