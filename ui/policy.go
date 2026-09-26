package ui

import "context"

// RegistrationPolicy decides who may create accounts, so this package can keep the forms while the
// decision is made elsewhere. Signing yourself up and adding somebody else are separate questions.
type RegistrationPolicy interface {
	SignUpOpen(ctx context.Context) (bool, error)
	MayAddUser(ctx context.Context, actorRef string) (bool, error)
}

// SwitchPolicy opens sign-up by a configuration switch and leaves adding accounts to a permission.
type SwitchPolicy struct {
	Open       bool
	CanAddUser func(ctx context.Context, actorRef string) (bool, error)
}

func (p SwitchPolicy) SignUpOpen(context.Context) (bool, error) {
	return p.Open, nil
}

func (p SwitchPolicy) MayAddUser(ctx context.Context, actorRef string) (bool, error) {
	return p.CanAddUser(ctx, actorRef)
}
