// Package repotest is the contract every auth repository must satisfy. Both backends run it, so a
// behaviour that differs between SQLite and Postgres fails here rather than in production.
package repotest

import (
	"context"
	"fmt"
	"testing"
	"time"
	"uuid"

	"github.com/applicaset/buildset/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Repositories struct {
	User     auth.UserRepository
	Session  auth.SessionRepository
	Token    auth.TokenRepository
	Identity auth.IdentityRepository
}

// New builds repositories over empty storage, once per subtest, so no test sees another's rows.
type New func(t *testing.T) Repositories

// Run exercises the whole contract.
func Run(t *testing.T, newRepositories New) {
	t.Helper()

	t.Run("User.Insert rejects a duplicate username", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.User.Insert(context.Background(), user("alice")))

		duplicate := user("alice")
		duplicate.ID = uuid.NewV7().String()

		err := repos.User.Insert(context.Background(), duplicate)
		require.ErrorIs(t, err, auth.ErrUsernameTaken)
	})

	t.Run("User.Update rejects a username another account holds", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		bob := user("bob")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(t, repos.User.Insert(context.Background(), bob))

		bob.Username = "alice"

		err := repos.User.Update(context.Background(), bob)
		require.ErrorIs(t, err, auth.ErrUsernameTaken)
	})

	t.Run("User.Update reports a missing account", func(t *testing.T) {
		repos := newRepositories(t)

		err := repos.User.Update(context.Background(), user("ghost"))
		require.ErrorIs(t, err, auth.ErrUserNotFound)
	})

	t.Run("User.Delete reports a missing account", func(t *testing.T) {
		repos := newRepositories(t)

		err := repos.User.Delete(context.Background(), uuid.NewV7().String())
		require.ErrorIs(t, err, auth.ErrUserNotFound)
	})

	t.Run("User.Get reports a missing account", func(t *testing.T) {
		repos := newRepositories(t)

		_, err := repos.User.Get(context.Background(), uuid.NewV7().String())
		require.ErrorIs(t, err, auth.ErrUserNotFound)
	})

	t.Run("User.GetByUsername reports a missing account", func(t *testing.T) {
		repos := newRepositories(t)

		_, err := repos.User.GetByUsername(context.Background(), "nobody")
		require.ErrorIs(t, err, auth.ErrUserNotFound)
	})

	t.Run("round-trips a user to the millisecond", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		alice.Name = "Alice Example"
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		stored, err := repos.User.Get(context.Background(), alice.ID)
		require.NoError(t, err)

		assert.Equal(t, alice.Username, stored.Username)
		assert.Equal(t, alice.Name, stored.Name)
		assert.Equal(t, alice.PasswordHash, stored.PasswordHash)
		// The stored format carries milliseconds and nothing finer, on both backends.
		assert.True(t, alice.CreatedAt.Truncate(time.Millisecond).Equal(stored.CreatedAt),
			"created_at %s became %s", alice.CreatedAt, stored.CreatedAt)
		assert.Equal(t, time.UTC, stored.CreatedAt.Location())
	})

	t.Run("User.List orders by created_at then id", func(t *testing.T) {
		repos := newRepositories(t)

		// Two users share a timestamp, so the id tiebreak decides. The ids differ by punctuation,
		// where a locale collation would disagree with byte order.
		base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

		first := user("carol")
		first.ID, first.CreatedAt = "aa-bb", base

		second := user("dave")
		second.ID, second.CreatedAt = "aaXbb", base

		third := user("erin")
		third.CreatedAt = base.Add(time.Second)

		for _, u := range []*auth.User{third, second, first} {
			require.NoError(t, repos.User.Insert(context.Background(), u))
		}

		users, err := repos.User.List(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, users, 3)

		// "-" is 0x2D and "X" is 0x58, so byte order puts aa-bb first.
		assert.Equal(
			t,
			[]string{"aa-bb", "aaXbb", third.ID},
			[]string{users[0].ID, users[1].ID, users[2].ID},
		)
	})

	t.Run("User.List honours the limit", func(t *testing.T) {
		repos := newRepositories(t)

		for i := range 5 {
			require.NoError(
				t,
				repos.User.Insert(context.Background(), user(fmt.Sprintf("user%d", i))),
			)
		}

		users, err := repos.User.List(context.Background(), 2)
		require.NoError(t, err)
		assert.Len(t, users, 2)
	})

	t.Run("User.Count counts", func(t *testing.T) {
		repos := newRepositories(t)

		count, err := repos.User.Count(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 0, count)

		require.NoError(t, repos.User.Insert(context.Background(), user("alice")))

		count, err = repos.User.Count(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("User.Delete cascades to sessions", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		session := session(alice.ID, "hash-1", time.Now().Add(time.Hour))
		require.NoError(t, repos.Session.Insert(context.Background(), session))

		require.NoError(t, repos.User.Delete(context.Background(), alice.ID))

		_, err := repos.Session.GetByTokenHash(context.Background(), "hash-1")
		require.ErrorIs(t, err, auth.ErrSessionNotFound)
	})

	t.Run("Session.GetByTokenHash reports a missing session", func(t *testing.T) {
		repos := newRepositories(t)

		_, err := repos.Session.GetByTokenHash(context.Background(), "nothing")
		require.ErrorIs(t, err, auth.ErrSessionNotFound)
	})

	t.Run("round-trips a session", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		expires := time.Now().Add(time.Hour)
		original := session(alice.ID, "hash-1", expires)
		original.UserAgent = "probe/1.0"
		original.IP = "203.0.113.7"
		require.NoError(t, repos.Session.Insert(context.Background(), original))

		stored, err := repos.Session.GetByTokenHash(context.Background(), "hash-1")
		require.NoError(t, err)

		assert.Equal(t, original.ID, stored.ID)
		assert.Equal(t, alice.ID, stored.UserID)
		assert.Equal(t, "probe/1.0", stored.UserAgent)
		assert.Equal(t, "203.0.113.7", stored.IP)
		assert.True(t, expires.UTC().Truncate(time.Millisecond).Equal(stored.ExpiresAt))
	})

	t.Run("Session.Touch moves last_seen", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(
			t,
			repos.Session.Insert(
				context.Background(),
				session(alice.ID, "hash-1", time.Now().Add(time.Hour)),
			),
		)

		later := time.Now().Add(time.Minute).UTC().Truncate(time.Millisecond)
		require.NoError(t, repos.Session.Touch(context.Background(), "session-hash-1", later))

		stored, err := repos.Session.GetByTokenHash(context.Background(), "hash-1")
		require.NoError(t, err)
		assert.True(t, later.Equal(stored.LastSeen), "want %s, got %s", later, stored.LastSeen)
	})

	t.Run("Session.DeleteByUser keeps the exception", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		for _, hash := range []string{"hash-1", "hash-2", "hash-3"} {
			require.NoError(
				t,
				repos.Session.Insert(
					context.Background(),
					session(alice.ID, hash, time.Now().Add(time.Hour)),
				),
			)
		}

		require.NoError(
			t,
			repos.Session.DeleteByUser(context.Background(), alice.ID, "session-hash-2"),
		)

		_, err := repos.Session.GetByTokenHash(context.Background(), "hash-2")
		require.NoError(t, err)

		for _, gone := range []string{"hash-1", "hash-3"} {
			_, err := repos.Session.GetByTokenHash(context.Background(), gone)
			require.ErrorIs(t, err, auth.ErrSessionNotFound)
		}
	})

	t.Run("Session.DeleteByUser with no exception removes all", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(
			t,
			repos.Session.Insert(
				context.Background(),
				session(alice.ID, "hash-1", time.Now().Add(time.Hour)),
			),
		)

		require.NoError(t, repos.Session.DeleteByUser(context.Background(), alice.ID, ""))

		_, err := repos.Session.GetByTokenHash(context.Background(), "hash-1")
		require.ErrorIs(t, err, auth.ErrSessionNotFound)
	})

	t.Run("Session.DeleteExpired is inclusive at the boundary", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

		require.NoError(
			t,
			repos.Session.Insert(
				context.Background(),
				session(alice.ID, "past", now.Add(-time.Hour)),
			),
		)
		require.NoError(
			t,
			repos.Session.Insert(context.Background(), session(alice.ID, "exact", now)),
		)
		require.NoError(
			t,
			repos.Session.Insert(
				context.Background(),
				session(alice.ID, "future", now.Add(time.Hour)),
			),
		)

		// The comparison is <=, so a session expiring exactly now goes.
		deleted, err := repos.Session.DeleteExpired(context.Background(), now)
		require.NoError(t, err)
		assert.Equal(t, int64(2), deleted)

		_, err = repos.Session.GetByTokenHash(context.Background(), "future")
		require.NoError(t, err)
	})

	t.Run("Session.DeleteByTokenHash is quiet about a missing session", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.Session.DeleteByTokenHash(context.Background(), "nothing"))
	})

	runEmail(t, newRepositories)
	runTokens(t, newRepositories)
	runIdentities(t, newRepositories)
}

func user(username string) *auth.User {
	now := time.Now().UTC().Truncate(time.Millisecond)

	return &auth.User{
		ID:           uuid.NewV7().String(),
		Username:     username,
		PasswordHash: "$2a$10$" + username,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func session(userID, tokenHash string, expires time.Time) *auth.Session {
	now := time.Now().UTC().Truncate(time.Millisecond)

	return &auth.Session{
		ID:        "session-" + tokenHash,
		UserID:    userID,
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: expires.UTC().Truncate(time.Millisecond),
		LastSeen:  now,
	}
}
