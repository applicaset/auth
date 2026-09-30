package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"github.com/applicaset/buildset/auth/hash"
	"github.com/applicaset/buildset/pkg/ref"
)

const (
	sessionTokenBytes = 32
	// touchInterval keeps last_seen useful without writing to the database on every request.
	touchInterval = time.Hour
	maxUserLimit  = 500
)

var (
	errInvalidSessionTTL = errors.New("session ttl must be positive")
	errMissingMailer     = errors.New("a mailer and links must be provided")
)

type Service struct {
	userRepo      UserRepository
	sessionRepo   SessionRepository
	tokenRepo     TokenRepository
	identityRepo  IdentityRepository
	passwords     *hash.Registry
	firstUserHook FirstUserHook
	sessionTTL    time.Duration
	mailer        Mailer
	links         Links
	logger        *slog.Logger
	// dummyHash is compared against when the username is unknown, so a failed login takes the same
	// time whether or not the account exists.
	dummyHash string
}

// Options are the dependencies a Service needs beyond its storage.
type Options struct {
	Passwords     *hash.Registry
	FirstUserHook FirstUserHook
	SessionTTL    time.Duration
	Mailer        Mailer
	Links         Links
	Logger        *slog.Logger
}

func NewService(
	userRepo UserRepository,
	sessionRepo SessionRepository,
	tokenRepo TokenRepository,
	identityRepo IdentityRepository,
	options Options,
) (*Service, error) {
	if options.SessionTTL <= 0 {
		return nil, fmt.Errorf("%w: got %s", errInvalidSessionTTL, options.SessionTTL)
	}

	if options.Mailer == nil || options.Links == nil {
		return nil, errMissingMailer
	}

	passwords := options.Passwords

	dummyHash, err := passwords.Hash(rand.Text())
	if err != nil {
		return nil, fmt.Errorf("build dummy password hash: %w", err)
	}

	return &Service{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		tokenRepo:     tokenRepo,
		identityRepo:  identityRepo,
		passwords:     passwords,
		firstUserHook: options.FirstUserHook,
		sessionTTL:    options.SessionTTL,
		mailer:        options.Mailer,
		links:         options.Links,
		logger:        options.Logger,
		dummyHash:     dummyHash,
	}, nil
}

type RegisterRequest struct {
	Username string
	Email    string
	Name     string
	Password string
}

type UpdateProfileRequest struct {
	UserID   string
	Username string
	Name     string
}

type ChangePasswordRequest struct {
	UserID          string
	CurrentPassword string
	NewPassword     string
	// KeepSessionID survives the revocation of the user's other sessions, so changing a password
	// does not log the browser doing it straight back out.
	KeepSessionID string
}

type SessionMeta struct {
	UserAgent string
	IP        string
}

// FIXME: no rate limiting. Registration, login, and password change are all open to unlimited
// attempts (OWASP ASVS V2.2.1). A limiter keyed by username and client address is the next step.
//
// A verification link goes to the new address. Failing to send it does not fail the registration:
// the person can ask for another from their settings.
func (svc *Service) Register(ctx context.Context, req RegisterRequest) (*User, error) {
	username := NormalizeUsername(req.Username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}

	email := NormalizeEmail(req.Email)
	if err := ValidateEmail(email); err != nil {
		return nil, err
	}

	passwordHash, err := svc.passwords.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	now := currentTime()

	user := &User{
		ID:           uuid.NewV7().String(),
		Username:     username,
		Email:        email,
		Name:         normalizeName(req.Name),
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := svc.userRepo.Insert(ctx, user); err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	if err := svc.SendVerification(ctx, user.ID); err != nil {
		svc.logger.WarnContext(ctx, "send verification after registration",
			slog.String("user_id", user.ID), slog.Any("error", err))
	}

	return user, nil
}

// Authenticate takes a username or an email address as login.
func (svc *Service) Authenticate(ctx context.Context, login, password string) (*User, error) {
	user, err := svc.userByLogin(ctx, login)
	if err == nil && !user.HasPassword() {
		err = ErrUserNotFound
	}

	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Spend the same work as a real comparison so response time does not reveal the answer.
			_ = svc.passwords.Verify(svc.dummyHash, password)

			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("get user by login: %w", err)
	}

	if err := svc.passwords.Verify(user.PasswordHash, password); err != nil {
		if errors.Is(err, hash.ErrMismatch) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("verify password: %w", err)
	}

	svc.rehashIfNeeded(ctx, user, password)

	return user, nil
}

// rehashIfNeeded upgrades a hash written by a superseded algorithm. Login is the only moment the
// plaintext is available. A failure here must not fail the login.
func (svc *Service) rehashIfNeeded(ctx context.Context, user *User, password string) {
	if !svc.passwords.NeedsRehash(user.PasswordHash) {
		return
	}

	passwordHash, err := svc.passwords.Hash(password)
	if err != nil {
		svc.logger.WarnContext(
			ctx,
			"rehash password",
			slog.String("user_id", user.ID),
			slog.Any("error", err),
		)

		return
	}

	user.PasswordHash = passwordHash
	user.UpdatedAt = currentTime()

	if err := svc.userRepo.Update(ctx, user); err != nil {
		svc.logger.WarnContext(
			ctx,
			"store rehashed password",
			slog.String("user_id", user.ID),
			slog.Any("error", err),
		)
	}
}

// CreateSession issues a new token. It is called on every login, so there is no existing session
// identifier an attacker could have fixed beforehand.
func (svc *Service) CreateSession(
	ctx context.Context,
	userID string,
	meta SessionMeta,
) (string, *Session, error) {
	token := newSessionToken()
	now := currentTime()

	session := &Session{
		ID:        uuid.NewV7().String(),
		UserID:    userID,
		TokenHash: hashSessionToken(token),
		CreatedAt: now,
		ExpiresAt: now.Add(svc.sessionTTL),
		LastSeen:  now,
		UserAgent: truncate(meta.UserAgent, 512),
		IP:        truncate(meta.IP, 64),
	}

	if err := svc.sessionRepo.Insert(ctx, session); err != nil {
		return "", nil, fmt.Errorf("insert session: %w", err)
	}

	return token, session, nil
}

// ResolveSession turns a token into its session and user. An expired session is deleted and
// reported as absent so a stale cookie heals itself on the next request.
func (svc *Service) ResolveSession(ctx context.Context, token string) (*Session, *User, error) {
	tokenHash := hashSessionToken(token)

	session, err := svc.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	now := currentTime()

	if session.Expired(now) {
		if err := svc.sessionRepo.DeleteByTokenHash(ctx, tokenHash); err != nil {
			svc.logger.WarnContext(
				ctx,
				"delete expired session",
				slog.String("session_id", session.ID),
				slog.Any("error", err),
			)
		}

		return nil, nil, ErrSessionNotFound
	}

	user, err := svc.userRepo.Get(ctx, session.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session user: %w", err)
	}

	if now.Sub(session.LastSeen) >= touchInterval {
		if err := svc.sessionRepo.Touch(ctx, session.ID, now); err != nil {
			svc.logger.WarnContext(
				ctx,
				"touch session",
				slog.String("session_id", session.ID),
				slog.Any("error", err),
			)
		}
	}

	return session, user, nil
}

func (svc *Service) RevokeSession(ctx context.Context, token string) error {
	if err := svc.sessionRepo.DeleteByTokenHash(ctx, hashSessionToken(token)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

func (svc *Service) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	deleted, err := svc.sessionRepo.DeleteExpired(ctx, currentTime())
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}

	return deleted, nil
}

func (svc *Service) GetUser(ctx context.Context, id string) (*User, error) {
	user, err := svc.userRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	return user, nil
}

// Sessions go with the account, so anyone signed in as it is signed out at once.
//
// TODO: resources this user created in other services still carry their reference. References are
// opaque and never dereferenced, so nothing breaks, but an operator may want them reassigned.
func (svc *Service) DeleteUser(ctx context.Context, id string) error {
	if err := svc.userRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	return nil
}

func (svc *Service) GetUserByRef(ctx context.Context, userRef string) (*User, error) {
	parsed, err := ref.Parse(userRef)
	if err != nil {
		return nil, err
	}

	if parsed.Service != ServiceName || parsed.ResourceType != UserResourceType {
		return nil, fmt.Errorf("%w: %s is not a user reference", ErrUserNotFound, userRef)
	}

	return svc.GetUser(ctx, parsed.ID)
}

// GetUserByUsername takes the username in any case.
func (svc *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user, err := svc.userRepo.GetByUsername(ctx, NormalizeUsername(username))
	if err != nil {
		return nil, fmt.Errorf("get user by username: %w", err)
	}

	return user, nil
}

func (svc *Service) ListUsers(ctx context.Context, limit int) ([]User, error) {
	if limit <= 0 || limit > maxUserLimit {
		limit = maxUserLimit
	}

	users, err := svc.userRepo.List(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	return users, nil
}

func (svc *Service) UpdateProfile(ctx context.Context, req UpdateProfileRequest) (*User, error) {
	username := NormalizeUsername(req.Username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}

	user, err := svc.userRepo.Get(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	user.Username = username
	user.Name = normalizeName(req.Name)
	user.UpdatedAt = currentTime()

	if err := svc.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	return user, nil
}

// ChangePassword checks the current password only when the account has one. Setting a first
// password on an account without one relies on the caller having just re-authenticated the person.
func (svc *Service) ChangePassword(ctx context.Context, req ChangePasswordRequest) error {
	user, err := svc.userRepo.Get(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	if user.HasPassword() {
		if err := svc.passwords.Verify(user.PasswordHash, req.CurrentPassword); err != nil {
			if errors.Is(err, hash.ErrMismatch) {
				return ErrInvalidCredentials
			}

			return fmt.Errorf("verify current password: %w", err)
		}
	}

	passwordHash, err := svc.passwords.Hash(req.NewPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = passwordHash
	user.UpdatedAt = currentTime()

	if err := svc.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	// Anyone holding a session from before the change loses it. The caller keeps its own.
	if err := svc.sessionRepo.DeleteByUser(ctx, user.ID, req.KeepSessionID); err != nil {
		return fmt.Errorf("delete other sessions: %w", err)
	}

	return nil
}

// SetupOpen reports whether the instance still has no users.
func (svc *Service) SetupOpen(ctx context.Context) (bool, error) {
	count, err := svc.userRepo.Count(ctx)
	if err != nil {
		return false, fmt.Errorf("count users: %w", err)
	}

	return count == 0, nil
}

// CompleteSetup creates the first user and hands its reference to the first-user hook. A failing
// hook removes the user, so setup stays open rather than leaving an account nobody can use.
func (svc *Service) CompleteSetup(ctx context.Context, req RegisterRequest) (*User, error) {
	open, err := svc.SetupOpen(ctx)
	if err != nil {
		return nil, err
	}

	if !open {
		return nil, ErrSetupClosed
	}

	user, err := svc.Register(ctx, req)
	if err != nil {
		return nil, err
	}

	// Two setup submissions racing past the check above would both succeed with different
	// usernames. Re-counting after the insert leaves exactly one winner.
	count, err := svc.userRepo.Count(ctx)
	if err != nil || count != 1 {
		svc.rollbackSetup(ctx, user)

		if err != nil {
			return nil, fmt.Errorf("count users: %w", err)
		}

		return nil, ErrSetupClosed
	}

	if err := svc.firstUserHook.OnFirstUser(ctx, user.Ref()); err != nil {
		svc.rollbackSetup(ctx, user)

		return nil, fmt.Errorf("run first user hook: %w", err)
	}

	return user, nil
}

// TODO: best-effort, not a transaction. The hook writes to another service, possibly another
// database, and cross-service transactions are out of scope. A failure here leaves an account with
// no administrator role for an operator to clean up by hand.
func (svc *Service) rollbackSetup(ctx context.Context, user *User) {
	if err := svc.userRepo.Delete(ctx, user.ID); err != nil {
		svc.logger.ErrorContext(
			ctx,
			"roll back setup user",
			slog.String("user_id", user.ID),
			slog.Any("error", err),
		)
	}
}

// currentTime is truncated to the precision the stored timestamps keep, so a value held in memory
// and the same value read back from storage compare equal.
func currentTime() time.Time {
	return time.Now().UTC().Truncate(time.Millisecond)
}

func newSessionToken() string {
	buf := make([]byte, sessionTokenBytes)
	// crypto/rand.Read never returns an error; it crashes the program if the system source fails.
	rand.Read(buf)

	return base64.RawURLEncoding.EncodeToString(buf)
}

// hashSessionToken is SHA-256 rather than a password hash: the token is 256 bits of random data,
// so there is nothing to brute force, and this runs on every authenticated request.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:])
}

func normalizeName(name string) string {
	return truncate(strings.TrimSpace(name), 128)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}

	return value[:limit]
}
