package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/applicaset/auth"
	authui "github.com/applicaset/auth/ui"
	authzclient "github.com/applicaset/authz/client"
	"github.com/applicaset/pkg/action"
)

// The first user's role assignment is the only retried call in this binary, with a long timeout
// to wait out a cold authorization service. It is idempotent and runs once per installation.
// Losing it leaves an instance nobody can administer.
const (
	firstUserTimeout = 10 * time.Second
	firstUserRetries = 2
)

// firstUserHook makes the first account an administrator over the network. Setup fails if the
// authorization service is down, so compose starts it first.
func firstUserHook(
	client *authzclient.Client,
	role string,
	logger *slog.Logger,
) auth.FirstUserHook {
	return auth.FirstUserHookFunc(func(ctx context.Context, userRef string) error {
		var err error

		for attempt := range firstUserRetries {
			attemptCtx, cancel := context.WithTimeout(ctx, firstUserTimeout)
			err = client.AssignRole(attemptCtx, userRef, role)
			cancel()

			if err == nil {
				logger.InfoContext(ctx, "first user is now an administrator",
					slog.String("user_ref", userRef),
					slog.String("role", role),
				)

				return nil
			}

			logger.WarnContext(ctx, "assign first user role",
				slog.String("user_ref", userRef),
				slog.Int("attempt", attempt+1),
				slog.Any("error", err),
			)
		}

		// Logged, not compensated: a second call could fail the same way. The account is about to
		// be rolled back, so a late assignment leaves a role row naming a deleted account.
		// Identifiers are never reused, so that row can never match a future account.
		logger.ErrorContext(ctx, "first user rolled back after an uncertain role assignment",
			slog.String("user_ref", userRef),
			slog.String("role", role),
		)

		return fmt.Errorf("assign %s role to %s: %w", role, userRef, err)
	})
}

// registrationPolicy asks the authorization service who may add accounts. Public sign-up is a
// configuration switch.
func registrationPolicy(open bool, client *authzclient.Client) authui.SwitchPolicy {
	return authui.SwitchPolicy{
		Open: open,
		CanAddUser: func(ctx context.Context, actorRef string) (bool, error) {
			return client.Can(ctx, actorRef, action.UserCreate, action.AnyUser)
		},
	}
}
