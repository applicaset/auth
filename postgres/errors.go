package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/applicaset/buildset/auth"
)

// sqlStater is implemented by the driver's error type. Matching the method rather than the concrete
// type keeps the driver out of this package's imports.
type sqlStater interface {
	error
	SQLState() string
}

func sqlState(err error) string {
	if stater, ok := errors.AsType[sqlStater](err); ok {
		return stater.SQLState()
	}

	return ""
}

// https://www.postgresql.org/docs/current/errcodes-appendix.html
const uniqueViolation = "23505"

func isUniqueViolation(err error) bool {
	return sqlState(err) == uniqueViolation
}

// userConflict names the constraint a unique violation hit. Postgres names it
// users_<column>_key, and the driver's message carries that name.
func userConflict(err error, user *auth.User) error {
	if strings.Contains(err.Error(), "users_email_key") {
		return fmt.Errorf("%w: %s", auth.ErrEmailTaken, user.Email)
	}

	return fmt.Errorf("%w: %s", auth.ErrUsernameTaken, user.Username)
}

// nullableString stores an empty string as NULL, so a UNIQUE column accepts any number of blanks.
func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
