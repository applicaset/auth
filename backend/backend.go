// Package backend is the one place that maps a storage driver to auth's repositories.
package backend

import (
	"context"

	"github.com/applicaset/auth"
	authpostgres "github.com/applicaset/auth/postgres"
	authsqlite "github.com/applicaset/auth/sqlite"
	"github.com/applicaset/pkg/storage"
)

type Repositories struct {
	User     auth.UserRepository
	Session  auth.SessionRepository
	Token    auth.TokenRepository
	Identity auth.IdentityRepository
}

// New migrates the schema before returning repositories over it.
func New(ctx context.Context, driver string, handle *storage.Handle) (*Repositories, error) {
	db := handle.SQL

	switch driver {
	case storage.DriverPostgres:
		if err := authpostgres.Migrate(ctx, db); err != nil {
			return nil, err
		}

		return &Repositories{
			User:     authpostgres.NewUserRepository(db),
			Session:  authpostgres.NewSessionRepository(db),
			Token:    authpostgres.NewTokenRepository(db),
			Identity: authpostgres.NewIdentityRepository(db),
		}, nil
	default:
		if err := authsqlite.Migrate(ctx, db); err != nil {
			return nil, err
		}

		return &Repositories{
			User:     authsqlite.NewUserRepository(db),
			Session:  authsqlite.NewSessionRepository(db),
			Token:    authsqlite.NewTokenRepository(db),
			Identity: authsqlite.NewIdentityRepository(db),
		}, nil
	}
}
