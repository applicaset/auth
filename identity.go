package auth

import (
	"context"
	"time"
)

// Identity links an account at an external provider, such as Google, to a user.
type Identity struct {
	Provider string
	// Subject is the provider's stable id for the account. An email address can change; this
	// cannot.
	Subject   string
	UserID    string
	Email     string
	CreatedAt time.Time
}

// IdentityRepository returns ErrIdentityNotFound for an absent identity and ErrIdentityTaken for a
// collision.
type IdentityRepository interface {
	Insert(ctx context.Context, identity *Identity) error
	Get(ctx context.Context, provider, subject string) (*Identity, error)
	// ListByUser orders by provider, then subject.
	ListByUser(ctx context.Context, userID string) ([]Identity, error)
	Delete(ctx context.Context, userID, provider, subject string) error
}
