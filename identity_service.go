package auth

import (
	"context"
	"errors"
	"fmt"
	"uuid"
)

// ProviderClaims is what a provider vouches for about the person signing in.
type ProviderClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// SignInWithProvider returns the account the provider identity belongs to. An identity seen for
// the first time links to the account with the same address when both sides have proved that
// address, and otherwise creates an account when allowSignUp is set.
func (s *Service) SignInWithProvider(
	ctx context.Context,
	provider string,
	claims ProviderClaims,
	allowSignUp bool,
) (*User, error) {
	identity, err := s.repository.GetIdentity(ctx, provider, claims.Subject)
	if err == nil {
		user, err := s.repository.GetUser(ctx, identity.UserID)
		if err != nil {
			return nil, fmt.Errorf("get user of identity: %w", err)
		}

		return user, nil
	}

	if !errors.Is(err, ErrIdentityNotFound) {
		return nil, fmt.Errorf("get identity: %w", err)
	}

	email := NormalizeEmail(claims.Email)

	if email != "" {
		user, err := s.repository.GetUserByEmail(ctx, email)

		switch {
		case err == nil:
			// Linking on an address neither side proved would let whoever registered it first,
			// here or at the provider, take the other's account.
			if !claims.EmailVerified || !user.EmailVerified() {
				return nil, ErrAccountExists
			}

			if err := s.link(ctx, user.ID, provider, claims.Subject, email); err != nil {
				return nil, err
			}

			return user, nil
		case !errors.Is(err, ErrUserNotFound):
			return nil, fmt.Errorf("get user by email: %w", err)
		}
	}

	if !allowSignUp {
		return nil, ErrSignUpClosed
	}

	return s.createProviderUser(ctx, provider, claims, email)
}

func (s *Service) createProviderUser(
	ctx context.Context,
	provider string,
	claims ProviderClaims,
	email string,
) (*User, error) {
	now := currentTime()

	user := &User{
		ID:        uuid.NewV7().String(),
		Name:      normalizeName(claims.Name),
		CreatedAt: now,
		UpdatedAt: now,
	}

	// An address the provider has not verified is left off rather than stored unproven: keeping
	// it would let the next sign-in link on it.
	if email != "" && claims.EmailVerified && ValidateEmail(email) == nil {
		user.Email = email
		user.EmailVerifiedAt = &now
	}

	// With no address to go on, the provider's name seeds the username.
	source := user.Email
	if source == "" {
		source = provider
	}

	created, err := s.createNamedUser(ctx, user, UsernameFromEmail(source))
	if err != nil {
		return nil, err
	}

	// TODO: not a transaction. A failure here leaves an account with no way to sign in except an
	// email link to its verified address. The account is removed to keep that window small.
	if err := s.link(ctx, created.ID, provider, claims.Subject, email); err != nil {
		if deleteErr := s.repository.DeleteUser(ctx, created.ID); deleteErr != nil {
			return nil, errors.Join(err, fmt.Errorf("roll back provider user: %w", deleteErr))
		}

		return nil, err
	}

	return created, nil
}

// createNamedUser inserts user under username, adding a numeric suffix while the name is taken.
func (s *Service) createNamedUser(ctx context.Context, user *User, username string) (*User, error) {
	for attempt := range derivedUsernameAttempts {
		user.Username = username
		if attempt > 0 {
			user.Username = withNumericSuffix(username)
		}

		err := s.repository.InsertUser(ctx, user)
		if err == nil {
			return user, nil
		}

		if !errors.Is(err, ErrUsernameTaken) {
			return nil, fmt.Errorf("insert user: %w", err)
		}
	}

	return nil, fmt.Errorf("insert user: no free username from %q: %w", username, ErrUsernameTaken)
}

func (s *Service) link(ctx context.Context, userID, provider, subject, email string) error {
	err := s.repository.InsertIdentity(ctx, &Identity{
		Provider:  provider,
		Subject:   subject,
		UserID:    userID,
		Email:     email,
		CreatedAt: currentTime(),
	})
	if err != nil {
		if errors.Is(err, ErrIdentityTaken) {
			return ErrIdentityTaken
		}

		return fmt.Errorf("insert identity: %w", err)
	}

	return nil
}

// LinkProvider adds a provider identity to a signed-in account. An identity already on this
// account is no error; one on another account is.
func (s *Service) LinkProvider(
	ctx context.Context,
	userID, provider string,
	claims ProviderClaims,
) error {
	identity, err := s.repository.GetIdentity(ctx, provider, claims.Subject)
	if err == nil {
		if identity.UserID == userID {
			return nil
		}

		return ErrIdentityTaken
	}

	if !errors.Is(err, ErrIdentityNotFound) {
		return fmt.Errorf("get identity: %w", err)
	}

	return s.link(ctx, userID, provider, claims.Subject, NormalizeEmail(claims.Email))
}

// UnlinkProvider refuses to remove the account's last way in: no password, no address an email
// link can reach, and no other provider.
func (s *Service) UnlinkProvider(ctx context.Context, userID, provider, subject string) error {
	user, err := s.repository.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	identities, err := s.repository.ListIdentities(ctx, userID)
	if err != nil {
		return fmt.Errorf("list identities: %w", err)
	}

	if !user.HasPassword() && user.Email == "" && len(identities) <= 1 {
		return ErrLastSignInMethod
	}

	if err := s.repository.DeleteIdentity(ctx, userID, provider, subject); err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			return ErrIdentityNotFound
		}

		return fmt.Errorf("delete identity: %w", err)
	}

	return nil
}
