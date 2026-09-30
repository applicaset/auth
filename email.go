package auth

import (
	"fmt"
	"net/mail"
	"strings"
)

const MaxEmailLength = 254

// NormalizeEmail lowercases the whole address. The local part is case-sensitive by the letter of
// RFC 5321, but no mainstream provider treats it so, and two accounts differing only in case would
// be a support problem rather than a feature.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidateEmail accepts a normalized bare address: no display name, no angle brackets.
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: it must not be empty", ErrInvalidEmail)
	}

	if len(email) > MaxEmailLength {
		return fmt.Errorf("%w: it must be at most %d characters", ErrInvalidEmail, MaxEmailLength)
	}

	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || parsed.Name != "" {
		return fmt.Errorf("%w: enter an address like name@example.com", ErrInvalidEmail)
	}

	if !strings.Contains(email[strings.LastIndex(email, "@")+1:], ".") {
		return fmt.Errorf("%w: enter an address like name@example.com", ErrInvalidEmail)
	}

	return nil
}
