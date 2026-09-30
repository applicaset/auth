package auth

import (
	"fmt"
	mathrand "math/rand/v2"
	"strings"
)

const (
	MinUsernameLength = 3
	MaxUsernameLength = 32
)

// NormalizeUsername is applied before every lookup and every insert, so "Ada" and "ada" are the
// same account rather than two.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// ValidateUsername accepts a normalized username.
//
// TODO: usernames are not NFKC-normalized or checked for confusables (UTS #39), so two visually
// identical names can coexist. That matters once usernames are shown as an identity claim.
func ValidateUsername(username string) error {
	if len(username) < MinUsernameLength || len(username) > MaxUsernameLength {
		return fmt.Errorf(
			"%w: it must be between %d and %d characters",
			ErrInvalidUsername,
			MinUsernameLength,
			MaxUsernameLength,
		)
	}

	for i, c := range username {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case (c == '-' || c == '_') && i > 0:
		default:
			return fmt.Errorf(
				"%w: it may contain only lowercase letters, digits, hyphen, and underscore, and must not start with a hyphen or underscore",
				ErrInvalidUsername,
			)
		}
	}

	return nil
}

// UsernameFromEmail proposes a valid username for an account whose owner never picked one: the
// email's local part with every other character turned into a hyphen.
func UsernameFromEmail(email string) string {
	local, _, _ := strings.Cut(NormalizeEmail(email), "@")

	var builder strings.Builder

	for _, c := range local {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
			builder.WriteRune(c)
		default:
			builder.WriteRune('-')
		}
	}

	username := strings.TrimLeft(builder.String(), "-_")
	// Room for the suffix withNumericSuffix may add.
	username = username[:min(len(username), MaxUsernameLength-suffixLength)]

	if len(username) < MinUsernameLength {
		username = strings.TrimSuffix("user-"+username, "-")
	}

	return username
}

const suffixLength = 5

// withNumericSuffix appends a hyphen and four random digits.
func withNumericSuffix(username string) string {
	return fmt.Sprintf("%s-%04d", username[:min(len(username), MaxUsernameLength-suffixLength)],
		mathrand.IntN(10000))
}
