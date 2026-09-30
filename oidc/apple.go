package oidc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

const appleAudience = "https://appleid.apple.com"

// appleSecretLifetime is well under Apple's six-month cap. A fresh secret is signed per exchange,
// so a short one costs nothing.
const appleSecretLifetime = 5 * time.Minute

// AppleKey signs the client secret Sign in with Apple takes in place of a fixed one.
type AppleKey struct {
	TeamID     string
	KeyID      string
	PrivateKey *ecdsa.PrivateKey
}

// ParseAppleKey reads the .p8 file Apple issues: a PKCS #8 P-256 key in PEM.
func ParseAppleKey(teamID, keyID string, pemBytes []byte) (*AppleKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: apple key is not PEM", errInvalidConfig)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse apple key: %w", errInvalidConfig, err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: apple key is not an EC key", errInvalidConfig)
	}

	if teamID == "" || keyID == "" {
		return nil, fmt.Errorf("%w: apple needs a team id and a key id", errInvalidConfig)
	}

	return &AppleKey{TeamID: teamID, KeyID: keyID, PrivateKey: key}, nil
}

func (k *AppleKey) clientSecret(clientID string, now time.Time) (string, error) {
	head, err := json.Marshal(map[string]string{"alg": "ES256", "kid": k.KeyID})
	if err != nil {
		return "", fmt.Errorf("encode header: %w", err)
	}

	claims, err := json.Marshal(map[string]any{
		"iss": k.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(appleSecretLifetime).Unix(),
		"aud": appleAudience,
		"sub": clientID,
	})
	if err != nil {
		return "", fmt.Errorf("encode claims: %w", err)
	}

	signed := base64.RawURLEncoding.EncodeToString(head) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))

	r, s, err := ecdsa.Sign(rand.Reader, k.PrivateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign client secret: %w", err)
	}

	// JWS wants the fixed-width r||s form, not ASN.1 (RFC 7518 §3.4).
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
