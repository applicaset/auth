package repotest

import (
	"context"
	"testing"
	"time"

	"github.com/applicaset/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runEmail(t *testing.T, newRepositories New) {
	t.Helper()

	t.Run("User.Insert rejects a duplicate email as an email conflict", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		alice.Email = "alice@example.com"
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		other := user("other")
		other.Email = "alice@example.com"

		err := repos.User.Insert(context.Background(), other)
		require.ErrorIs(t, err, auth.ErrEmailTaken)
		require.NotErrorIs(t, err, auth.ErrUsernameTaken)
	})

	t.Run("any number of users may have no email", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.User.Insert(context.Background(), user("alice")))
		require.NoError(t, repos.User.Insert(context.Background(), user("bob")))
	})

	t.Run("User.Update rejects an email another account holds", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		alice.Email = "alice@example.com"
		bob := user("bob")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(t, repos.User.Insert(context.Background(), bob))

		bob.Email = "alice@example.com"

		err := repos.User.Update(context.Background(), bob)
		require.ErrorIs(t, err, auth.ErrEmailTaken)
	})

	t.Run("round-trips email, verification and an empty password", func(t *testing.T) {
		repos := newRepositories(t)

		verified := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

		alice := user("alice")
		alice.Email = "alice@example.com"
		alice.EmailVerifiedAt = &verified
		alice.PasswordHash = ""
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		stored, err := repos.User.GetByEmail(context.Background(), "alice@example.com")
		require.NoError(t, err)

		assert.Equal(t, alice.ID, stored.ID)
		assert.Equal(t, "alice@example.com", stored.Email)
		require.NotNil(t, stored.EmailVerifiedAt)
		assert.True(t, verified.Equal(*stored.EmailVerifiedAt))
		assert.Empty(t, stored.PasswordHash)

		stored.Email = ""
		stored.EmailVerifiedAt = nil
		require.NoError(t, repos.User.Update(context.Background(), stored))

		cleared, err := repos.User.Get(context.Background(), alice.ID)
		require.NoError(t, err)
		assert.Empty(t, cleared.Email)
		assert.Nil(t, cleared.EmailVerifiedAt)
	})

	t.Run("User.GetByEmail reports a missing account", func(t *testing.T) {
		repos := newRepositories(t)

		_, err := repos.User.GetByEmail(context.Background(), "nobody@example.com")
		require.ErrorIs(t, err, auth.ErrUserNotFound)
	})
}

func runTokens(t *testing.T, newRepositories New) {
	t.Helper()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	t.Run("Token.Consume returns the token once", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		original := token("hash-1", auth.TokenResetPassword, alice.ID, now.Add(time.Hour))
		require.NoError(t, repos.Token.Insert(context.Background(), original))

		stored, err := repos.Token.Consume(
			context.Background(), "hash-1", auth.TokenResetPassword, now)
		require.NoError(t, err)

		assert.Equal(t, alice.ID, stored.UserID)
		assert.Equal(t, auth.TokenResetPassword, stored.Purpose)
		assert.Equal(t, original.Email, stored.Email)
		assert.True(t, original.ExpiresAt.Equal(stored.ExpiresAt))

		_, err = repos.Token.Consume(
			context.Background(),
			"hash-1",
			auth.TokenResetPassword,
			now,
		)
		require.ErrorIs(t, err, auth.ErrTokenNotFound)
	})

	t.Run("Token.Consume ignores a token for another purpose", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.Token.Insert(context.Background(),
			token("hash-1", auth.TokenVerifyEmail, "", now.Add(time.Hour))))

		_, err := repos.Token.Consume(context.Background(), "hash-1", auth.TokenEmailLogin, now)
		require.ErrorIs(t, err, auth.ErrTokenNotFound)

		_, err = repos.Token.Consume(context.Background(), "hash-1", auth.TokenVerifyEmail, now)
		require.NoError(t, err, "the wrong purpose must not use the token up")
	})

	t.Run("Token.Consume refuses a token expiring exactly now", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.Token.Insert(context.Background(),
			token("hash-1", auth.TokenEmailLogin, "", now)))

		_, err := repos.Token.Consume(context.Background(), "hash-1", auth.TokenEmailLogin, now)
		require.ErrorIs(t, err, auth.ErrTokenNotFound)
	})

	t.Run("a token without a user round-trips its email", func(t *testing.T) {
		repos := newRepositories(t)

		original := token("hash-1", auth.TokenEmailLogin, "", now.Add(time.Hour))
		original.Email = "new@example.com"
		require.NoError(t, repos.Token.Insert(context.Background(), original))

		stored, err := repos.Token.Consume(
			context.Background(), "hash-1", auth.TokenEmailLogin, now)
		require.NoError(t, err)
		assert.Empty(t, stored.UserID)
		assert.Equal(t, "new@example.com", stored.Email)
	})

	t.Run("Token.DeleteByUser removes one purpose only", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(t, repos.Token.Insert(context.Background(),
			token("reset", auth.TokenResetPassword, alice.ID, now.Add(time.Hour))))
		require.NoError(t, repos.Token.Insert(context.Background(),
			token("verify", auth.TokenVerifyEmail, alice.ID, now.Add(time.Hour))))

		require.NoError(
			t,
			repos.Token.DeleteByUser(context.Background(), alice.ID, auth.TokenResetPassword),
		)

		_, err := repos.Token.Consume(
			context.Background(),
			"reset",
			auth.TokenResetPassword,
			now,
		)
		require.ErrorIs(t, err, auth.ErrTokenNotFound)

		_, err = repos.Token.Consume(context.Background(), "verify", auth.TokenVerifyEmail, now)
		require.NoError(t, err)
	})

	t.Run("Token.DeleteExpired is inclusive at the boundary", func(t *testing.T) {
		repos := newRepositories(t)

		for hash, expires := range map[string]time.Time{
			"past":   now.Add(-time.Hour),
			"exact":  now,
			"future": now.Add(time.Hour),
		} {
			require.NoError(t, repos.Token.Insert(context.Background(),
				token(hash, auth.TokenEmailLogin, "", expires)))
		}

		deleted, err := repos.Token.DeleteExpired(context.Background(), now)
		require.NoError(t, err)
		assert.Equal(t, int64(2), deleted)
	})

	t.Run("User.Delete cascades to tokens", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(t, repos.Token.Insert(context.Background(),
			token("hash-1", auth.TokenResetPassword, alice.ID, now.Add(time.Hour))))

		require.NoError(t, repos.User.Delete(context.Background(), alice.ID))

		_, err := repos.Token.Consume(
			context.Background(),
			"hash-1",
			auth.TokenResetPassword,
			now,
		)
		require.ErrorIs(t, err, auth.ErrTokenNotFound)
	})
}

func runIdentities(t *testing.T, newRepositories New) {
	t.Helper()

	t.Run("Identity.Insert rejects a subject already linked", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		bob := user("bob")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(t, repos.User.Insert(context.Background(), bob))
		require.NoError(t, repos.Identity.Insert(context.Background(),
			identity("google", "sub-1", alice.ID)))

		err := repos.Identity.Insert(context.Background(), identity("google", "sub-1", bob.ID))
		require.ErrorIs(t, err, auth.ErrIdentityTaken)
	})

	t.Run("Identity.Get round-trips and reports a missing one", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		original := identity("google", "sub-1", alice.ID)
		original.Email = "alice@example.com"
		require.NoError(t, repos.Identity.Insert(context.Background(), original))

		stored, err := repos.Identity.Get(context.Background(), "google", "sub-1")
		require.NoError(t, err)
		assert.Equal(t, alice.ID, stored.UserID)
		assert.Equal(t, "alice@example.com", stored.Email)
		assert.True(t, original.CreatedAt.Equal(stored.CreatedAt))

		_, err = repos.Identity.Get(context.Background(), "apple", "sub-1")
		require.ErrorIs(t, err, auth.ErrIdentityNotFound)
	})

	t.Run("Identity.ListByUser orders by provider then subject", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))

		for _, linked := range []*auth.Identity{
			identity("google", "b", alice.ID),
			identity("apple", "z", alice.ID),
			identity("google", "a", alice.ID),
		} {
			require.NoError(t, repos.Identity.Insert(context.Background(), linked))
		}

		identities, err := repos.Identity.ListByUser(context.Background(), alice.ID)
		require.NoError(t, err)
		require.Len(t, identities, 3)

		assert.Equal(t,
			[]string{"apple/z", "google/a", "google/b"},
			[]string{
				identities[0].Provider + "/" + identities[0].Subject,
				identities[1].Provider + "/" + identities[1].Subject,
				identities[2].Provider + "/" + identities[2].Subject,
			},
		)
	})

	t.Run("Identity.Delete removes only the owner's link", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		bob := user("bob")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(t, repos.User.Insert(context.Background(), bob))
		require.NoError(t, repos.Identity.Insert(context.Background(),
			identity("google", "sub-1", alice.ID)))

		err := repos.Identity.Delete(context.Background(), bob.ID, "google", "sub-1")
		require.ErrorIs(t, err, auth.ErrIdentityNotFound)

		require.NoError(
			t,
			repos.Identity.Delete(context.Background(), alice.ID, "google", "sub-1"),
		)

		_, err = repos.Identity.Get(context.Background(), "google", "sub-1")
		require.ErrorIs(t, err, auth.ErrIdentityNotFound)
	})

	t.Run("User.Delete cascades to identities", func(t *testing.T) {
		repos := newRepositories(t)

		alice := user("alice")
		require.NoError(t, repos.User.Insert(context.Background(), alice))
		require.NoError(t, repos.Identity.Insert(context.Background(),
			identity("google", "sub-1", alice.ID)))

		require.NoError(t, repos.User.Delete(context.Background(), alice.ID))

		_, err := repos.Identity.Get(context.Background(), "google", "sub-1")
		require.ErrorIs(t, err, auth.ErrIdentityNotFound)
	})
}

func token(hash string, purpose auth.TokenPurpose, userID string, expires time.Time) *auth.Token {
	return &auth.Token{
		TokenHash: hash,
		Purpose:   purpose,
		UserID:    userID,
		Email:     "someone@example.com",
		CreatedAt: expires.Add(-time.Hour).UTC().Truncate(time.Millisecond),
		ExpiresAt: expires.UTC().Truncate(time.Millisecond),
	}
}

func identity(provider, subject, userID string) *auth.Identity {
	return &auth.Identity{
		Provider:  provider,
		Subject:   subject,
		UserID:    userID,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
}
