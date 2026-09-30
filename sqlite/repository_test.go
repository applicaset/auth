package sqlite_test

import (
	"database/sql"
	"testing"

	"github.com/applicaset/buildset/auth/repotest"
	"github.com/applicaset/buildset/auth/sqlite"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestRepository(t *testing.T) {
	repotest.Run(t, func(t *testing.T) repotest.Repositories {
		t.Helper()

		// Opened with foreign_keys on, like the application's database. SQLite defaults it to off,
		// and the cascade from users to sessions is part of the contract.
		db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/test.db?_pragma=foreign_keys(ON)")
		require.NoError(t, err)

		db.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = db.Close() })

		require.NoError(t, sqlite.Migrate(t.Context(), db))

		return repotest.Repositories{
			User:     sqlite.NewUserRepository(db),
			Session:  sqlite.NewSessionRepository(db),
			Token:    sqlite.NewTokenRepository(db),
			Identity: sqlite.NewIdentityRepository(db),
		}
	})
}
