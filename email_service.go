package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"github.com/buildset/buildset/pkg/mail"
)

type Mailer interface {
	Send(ctx context.Context, message mail.Message) error
}

// Links turns a token into the absolute URL mailed to the person. The pages own their paths, so
// they build the links.
type Links interface {
	VerifyEmail(token string) string
	ResetPassword(token string) string
	EmailLogin(token, next string) string
	ConfirmEmailChange(token string) string
}

// Each lifetime is as short as the person needs to reach their inbox. Links that sign someone in
// or change their credentials get the least.
const (
	verifyEmailTTL   = 48 * time.Hour
	resetPasswordTTL = time.Hour
	emailLoginTTL    = 15 * time.Minute
	changeEmailTTL   = 24 * time.Hour
)

// derivedUsernameAttempts bounds the retries when a username derived from an email is taken.
const derivedUsernameAttempts = 5

func (s *Service) userByLogin(ctx context.Context, login string) (*User, error) {
	if strings.Contains(login, "@") {
		return s.repository.GetUserByEmail(ctx, NormalizeEmail(login))
	}

	return s.repository.GetUserByUsername(ctx, NormalizeUsername(login))
}

// GetUserByEmail takes the address in any case.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user, err := s.repository.GetUserByEmail(ctx, NormalizeEmail(email))
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return user, nil
}

// issueToken stores a new token and returns the secret for the link. Only its hash is kept.
func (s *Service) issueToken(
	ctx context.Context,
	purpose TokenPurpose,
	userID, email string,
	ttl time.Duration,
) (string, error) {
	secret := newSessionToken()
	now := currentTime()

	err := s.repository.InsertToken(ctx, &Token{
		TokenHash: hashSessionToken(secret),
		Purpose:   purpose,
		UserID:    userID,
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return "", fmt.Errorf("insert %s token: %w", purpose, err)
	}

	return secret, nil
}

func (s *Service) consumeToken(
	ctx context.Context,
	secret string,
	purpose TokenPurpose,
) (*Token, error) {
	if secret == "" {
		return nil, ErrTokenNotFound
	}

	token, err := s.repository.ConsumeToken(ctx, hashSessionToken(secret), purpose, currentTime())
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, ErrTokenNotFound
		}

		return nil, fmt.Errorf("consume %s token: %w", purpose, err)
	}

	return token, nil
}

// SendVerification mails a link that proves the account's address. An address already verified is
// left alone.
func (s *Service) SendVerification(ctx context.Context, userID string) error {
	user, err := s.repository.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	if user.Email == "" || user.EmailVerified() {
		return nil
	}

	if err := s.repository.DeleteTokensByUser(ctx, user.ID, TokenVerifyEmail); err != nil {
		return fmt.Errorf("delete earlier verification tokens: %w", err)
	}

	secret, err := s.issueToken(ctx, TokenVerifyEmail, user.ID, user.Email, verifyEmailTTL)
	if err != nil {
		return err
	}

	return s.send(ctx, user.Email, "Confirm your email address", fmt.Sprintf(
		"Confirm that %s is your email address by opening this link:\n\n%s\n\n"+
			"The link works once and expires in %s. If you did not create an account, ignore this email.",
		user.Email, s.links.VerifyEmail(secret), humanDuration(verifyEmailTTL),
	))
}

// VerifyEmail fails if the account's address changed after the link was sent, since the link
// proves the old one.
func (s *Service) VerifyEmail(ctx context.Context, secret string) (*User, error) {
	token, err := s.consumeToken(ctx, secret, TokenVerifyEmail)
	if err != nil {
		return nil, err
	}

	user, err := s.repository.GetUser(ctx, token.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrTokenNotFound
		}

		return nil, fmt.Errorf("get user: %w", err)
	}

	if user.Email != token.Email {
		return nil, ErrTokenNotFound
	}

	return s.markVerified(ctx, user)
}

func (s *Service) markVerified(ctx context.Context, user *User) (*User, error) {
	if user.EmailVerified() {
		return user, nil
	}

	now := currentTime()
	user.EmailVerifiedAt = &now
	user.UpdatedAt = now

	if err := s.repository.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("mark email verified: %w", err)
	}

	return user, nil
}

// RequestPasswordReset answers the same whether or not the address has an account, so the form
// cannot be used to find out which addresses are registered.
//
// FIXME: no rate limiting, so anyone can make this send mail to any address repeatedly. It shares
// the limiter Register is waiting for.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return err
	}

	user, err := s.repository.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil
		}

		return fmt.Errorf("get user by email: %w", err)
	}

	if err := s.repository.DeleteTokensByUser(ctx, user.ID, TokenResetPassword); err != nil {
		return fmt.Errorf("delete earlier reset tokens: %w", err)
	}

	secret, err := s.issueToken(ctx, TokenResetPassword, user.ID, user.Email, resetPasswordTTL)
	if err != nil {
		return err
	}

	return s.send(ctx, user.Email, "Reset your password", fmt.Sprintf(
		"Someone asked to reset the password for %s. Choose a new one here:\n\n%s\n\n"+
			"The link works once and expires in %s. If it was not you, ignore this email; your "+
			"password has not changed.",
		user.Username, s.links.ResetPassword(secret), humanDuration(resetPasswordTTL),
	))
}

// ResetPassword also verifies the address, since following the link proved it, and signs out
// every session: whoever knew the old password is out.
func (s *Service) ResetPassword(ctx context.Context, secret, newPassword string) (*User, error) {
	// Hashed first, so a password the rules reject leaves the link usable for another try.
	passwordHash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return nil, err
	}

	token, err := s.consumeToken(ctx, secret, TokenResetPassword)
	if err != nil {
		return nil, err
	}

	user, err := s.repository.GetUser(ctx, token.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrTokenNotFound
		}

		return nil, fmt.Errorf("get user: %w", err)
	}

	now := currentTime()
	user.PasswordHash = passwordHash
	user.UpdatedAt = now

	if user.Email == token.Email && !user.EmailVerified() {
		user.EmailVerifiedAt = &now
	}

	if err := s.repository.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	if err := s.repository.DeleteSessionsByUser(ctx, user.ID, ""); err != nil {
		return nil, fmt.Errorf("delete sessions: %w", err)
	}

	if err := s.repository.DeleteTokensByUser(ctx, user.ID, TokenResetPassword); err != nil {
		return nil, fmt.Errorf("delete reset tokens: %w", err)
	}

	return user, nil
}

// RequestEmailLogin mails a sign-in link. An address with no account gets a link that creates one
// when allowSignUp is set, and nothing otherwise. The answer is the same either way.
//
// FIXME: no rate limiting, as for RequestPasswordReset.
func (s *Service) RequestEmailLogin(
	ctx context.Context,
	email, next string,
	allowSignUp bool,
) error {
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return err
	}

	userID := ""

	user, err := s.repository.GetUserByEmail(ctx, email)

	switch {
	case err == nil:
		userID = user.ID
	case !errors.Is(err, ErrUserNotFound):
		return fmt.Errorf("get user by email: %w", err)
	case !allowSignUp:
		return nil
	}

	secret, err := s.issueToken(ctx, TokenEmailLogin, userID, email, emailLoginTTL)
	if err != nil {
		return err
	}

	return s.send(ctx, email, "Your sign-in link", fmt.Sprintf(
		"Open this link to sign in:\n\n%s\n\n"+
			"The link works once and expires in %s. If you did not ask for it, ignore this email.",
		s.links.EmailLogin(secret, next), humanDuration(emailLoginTTL),
	))
}

// ConsumeEmailLogin returns the account the link signs in to, creating it for a link that was
// sent to an address with no account.
func (s *Service) ConsumeEmailLogin(
	ctx context.Context,
	secret string,
	allowSignUp bool,
) (*User, error) {
	token, err := s.consumeToken(ctx, secret, TokenEmailLogin)
	if err != nil {
		return nil, err
	}

	// A link addressed to someone without an account may find one: they could have signed up
	// another way in the minutes since.
	user, err := s.repository.GetUserByEmail(ctx, token.Email)

	switch {
	case err == nil:
		if token.UserID != "" && token.UserID != user.ID {
			return nil, ErrTokenNotFound
		}

		return s.markVerified(ctx, user)
	case !errors.Is(err, ErrUserNotFound):
		return nil, fmt.Errorf("get user by email: %w", err)
	case token.UserID != "" || !allowSignUp:
		// The account the link was for is gone, or sign-up closed since the link was sent.
		return nil, ErrSignUpClosed
	}

	now := currentTime()

	return s.createNamedUser(ctx, &User{
		ID:              uuid.NewV7().String(),
		Email:           token.Email,
		EmailVerifiedAt: &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, UsernameFromEmail(token.Email))
}

// RequestEmailChange mails a confirmation link to the new address. The account keeps its current
// address until the link is followed, so a typo cannot lock anyone out.
func (s *Service) RequestEmailChange(ctx context.Context, userID, newEmail string) error {
	email := NormalizeEmail(newEmail)
	if err := ValidateEmail(email); err != nil {
		return err
	}

	user, err := s.repository.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	if user.Email == email {
		return nil
	}

	if _, err := s.repository.GetUserByEmail(ctx, email); err == nil {
		return fmt.Errorf("%w: %s", ErrEmailTaken, email)
	} else if !errors.Is(err, ErrUserNotFound) {
		return fmt.Errorf("get user by email: %w", err)
	}

	if err := s.repository.DeleteTokensByUser(ctx, user.ID, TokenChangeEmail); err != nil {
		return fmt.Errorf("delete earlier change tokens: %w", err)
	}

	secret, err := s.issueToken(ctx, TokenChangeEmail, user.ID, email, changeEmailTTL)
	if err != nil {
		return err
	}

	return s.send(ctx, email, "Confirm your new email address", fmt.Sprintf(
		"Confirm that %s should become the email address of %s:\n\n%s\n\n"+
			"The link works once and expires in %s. If you did not ask for this, ignore this email.",
		email, user.Username, s.links.ConfirmEmailChange(secret), humanDuration(changeEmailTTL),
	))
}

func (s *Service) ConfirmEmailChange(ctx context.Context, secret string) (*User, error) {
	token, err := s.consumeToken(ctx, secret, TokenChangeEmail)
	if err != nil {
		return nil, err
	}

	user, err := s.repository.GetUser(ctx, token.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrTokenNotFound
		}

		return nil, fmt.Errorf("get user: %w", err)
	}

	now := currentTime()
	user.Email = token.Email
	user.EmailVerifiedAt = &now
	user.UpdatedAt = now

	if err := s.repository.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	return user, nil
}

func (s *Service) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	deleted, err := s.repository.DeleteExpiredTokens(ctx, currentTime())
	if err != nil {
		return 0, fmt.Errorf("delete expired tokens: %w", err)
	}

	return deleted, nil
}

func (s *Service) send(ctx context.Context, to, subject, text string) error {
	if err := s.mailer.Send(ctx, mail.Message{To: to, Subject: subject, Text: text}); err != nil {
		s.logger.ErrorContext(
			ctx,
			"send mail",
			slog.String("subject", subject),
			slog.Any("error", err),
		)

		return fmt.Errorf("send %q: %w", subject, err)
	}

	return nil
}

func humanDuration(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		hours := int(d / time.Hour)
		if hours == 1 {
			return "1 hour"
		}

		return fmt.Sprintf("%d hours", hours)
	}

	return fmt.Sprintf("%d minutes", int(d/time.Minute))
}

func (s *Service) ListIdentities(ctx context.Context, userID string) ([]Identity, error) {
	identities, err := s.repository.ListIdentities(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}

	return identities, nil
}
