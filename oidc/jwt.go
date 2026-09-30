package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// clockSkew tolerates a provider's clock running slightly ahead of or behind this one.
const clockSkew = 2 * time.Minute

// keyRefreshInterval limits how often an unknown key id sends us back to the provider, so a
// stream of forged tokens cannot turn into a stream of requests.
const keyRefreshInterval = 5 * time.Minute

type keySet struct {
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type idTokenClaims struct {
	Issuer   string          `json:"iss"`
	Audience json.RawMessage `json:"aud"`
	Subject  string          `json:"sub"`
	Expiry   int64           `json:"exp"`
	IssuedAt int64           `json:"iat"`
	Nonce    string          `json:"nonce"`
	Email    string          `json:"email"`
	// EmailVerified is a boolean at Google and, at times, the string "true" at Apple.
	EmailVerified json.RawMessage `json:"email_verified"`
	Name          string          `json:"name"`
}

func (p *Provider) verify(ctx context.Context, token, nonce string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrInvalidToken)
	}

	var head header
	if err := decodeSegment(parts[0], &head); err != nil {
		return nil, err
	}

	key, err := p.key(ctx, head.Kid)
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrInvalidToken)
	}

	if err := verifySignature(head.Alg, key, parts[0]+"."+parts[1], signature); err != nil {
		return nil, err
	}

	var claims idTokenClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, err
	}

	if err := p.checkClaims(claims, nonce, time.Now()); err != nil {
		return nil, err
	}

	return &Claims{
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: truthy(claims.EmailVerified),
		Name:          claims.Name,
	}, nil
}

// checkClaims applies OpenID Connect Core 1.0 §3.1.3.7.
func (p *Provider) checkClaims(claims idTokenClaims, nonce string, now time.Time) error {
	switch {
	case claims.Issuer != p.config.Issuer:
		return fmt.Errorf("%w: issuer %q", ErrInvalidToken, claims.Issuer)
	case !audienceMatches(claims.Audience, p.config.ClientID):
		return fmt.Errorf("%w: audience", ErrInvalidToken)
	case claims.Subject == "":
		return fmt.Errorf("%w: no subject", ErrInvalidToken)
	case claims.Nonce != nonce:
		return fmt.Errorf("%w: nonce", ErrInvalidToken)
	case now.Add(-clockSkew).Unix() >= claims.Expiry:
		return fmt.Errorf("%w: expired", ErrInvalidToken)
	case claims.IssuedAt > now.Add(clockSkew).Unix():
		return fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	}

	return nil
}

func truthy(raw json.RawMessage) bool {
	var flag bool
	if json.Unmarshal(raw, &flag) == nil {
		return flag
	}

	var text string

	return json.Unmarshal(raw, &text) == nil && text == "true"
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("%w: segment encoding", ErrInvalidToken)
	}

	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%w: segment json", ErrInvalidToken)
	}

	return nil
}

// verifySignature accepts only the two algorithms Google and Apple sign with. Anything else,
// "none" included, is refused before a key is looked at.
func verifySignature(alg string, key crypto.PublicKey, signed string, signature []byte) error {
	digest := sha256.Sum256([]byte(signed))

	switch alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key is not RSA", ErrInvalidToken)
		}

		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("%w: signature", ErrInvalidToken)
		}
	case "ES256":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok || len(signature) != 64 {
			return fmt.Errorf("%w: key or signature is not P-256", ErrInvalidToken)
		}

		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])

		if !ecdsa.Verify(ecKey, digest[:], r, s) {
			return fmt.Errorf("%w: signature", ErrInvalidToken)
		}
	default:
		return fmt.Errorf("%w: algorithm %q", ErrInvalidToken, alg)
	}

	return nil
}

// key returns the provider's signing key by id, refetching the set when the id is new: providers
// rotate keys and publish the new one before signing with it.
func (p *Provider) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	meta, err := p.metadata(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.keys != nil {
		if key, ok := p.keys.keys[kid]; ok {
			return key, nil
		}

		if time.Since(p.keys.fetchedAt) < keyRefreshInterval {
			return nil, fmt.Errorf("%w: unknown key %q", ErrInvalidToken, kid)
		}
	}

	var document struct {
		Keys []jwk `json:"keys"`
	}

	if err := p.getJSON(ctx, meta.JWKSURI, &document); err != nil {
		return nil, fmt.Errorf("fetch signing keys: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(document.Keys))

	for _, candidate := range document.Keys {
		if candidate.Use != "" && candidate.Use != "sig" {
			continue
		}

		key, err := candidate.publicKey()
		if err != nil {
			continue
		}

		keys[candidate.Kid] = key
	}

	p.keys = &keySet{keys: keys, fetchedAt: time.Now()}

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: unknown key %q", ErrInvalidToken, kid)
	}

	return key, nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode modulus: %w", err)
		}

		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode exponent: %w", err)
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("%w: curve %q", ErrInvalidToken, k.Crv)
		}

		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decode x: %w", err)
		}

		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y: %w", err)
		}

		// An uncompressed point, so the standard library checks it lies on the curve.
		point := append(append([]byte{4}, leftPad(x, 32)...), leftPad(y, 32)...)

		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, fmt.Errorf("parse ec key: %w", err)
		}

		return key, nil
	default:
		return nil, fmt.Errorf("%w: key type %q", ErrInvalidToken, k.Kty)
	}
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}

	return append(make([]byte, size-len(b)), b...)
}
