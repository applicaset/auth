// Package backend is the one place that maps a storage driver to an auth repository.
package backend

import (
	"context"

	"github.com/applicaset/buildset/auth"
	authpostgres "github.com/applicaset/buildset/auth/postgres"
	authsqlite "github.com/applicaset/buildset/auth/sqlite"
	"github.com/applicaset/buildset/pkg/storage"
)

func New(ctx context.Context, driver string, handle *storage.Handle) (auth.Repository, error) {
	switch driver {
	case storage.DriverPostgres:
		return authpostgres.NewRepository(ctx, handle.SQL)
	default:
		return authsqlite.NewRepository(ctx, handle.SQL)
	}
}
