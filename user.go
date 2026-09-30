package auth

import (
	"context"
	"time"

	"github.com/applicaset/buildset/pkg/ref"
)

type User struct {
	ID       string
	Username string
	// Email is empty only for accounts created before email addresses were collected.
	Email string
	// EmailVerifiedAt is set once the person follows a link sent to Email, or a provider vouches
	// for it.
	EmailVerifiedAt *time.Time
	Name            string
	// PasswordHash must never leave this service. Nothing outside auth has a reason to read it.
	// It is empty for an account that signs in by email link or a provider only.
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserRepository returns ErrUserNotFound for an absent user, and ErrUsernameTaken and ErrEmailTaken
// for collisions. Deleting a user removes its sessions, tokens and identities with it.
type UserRepository interface {
	Insert(ctx context.Context, user *User) error
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	Get(ctx context.Context, id string) (*User, error)
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	List(ctx context.Context, limit int) ([]User, error)
	Count(ctx context.Context) (int, error)
}

func (u *User) Ref() string {
	return ref.MustNew(ServiceName, UserResourceType, u.ID).String()
}

func (u *User) HasPassword() bool { return u.PasswordHash != "" }

func (u *User) EmailVerified() bool { return u.Email != "" && u.EmailVerifiedAt != nil }
