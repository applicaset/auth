package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testProvider(t *testing.T) (*Provider, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider, err := New(Config{
		Name: "test", Issuer: "https://issuer.test", ClientID: "client", ClientSecret: "secret",
	}, nil)
	require.NoError(t, err)

	provider.discovery = &discovery{Issuer: "https://issuer.test", JWKSURI: "unused"}
	provider.keys = &keySet{
		keys:      map[string]crypto.PublicKey{"k1": &key.PublicKey},
		fetchedAt: time.Now(),
	}

	return provider, key
}

func sign(t *testing.T, key *rsa.PrivateKey, alg string, claims map[string]any) string {
	t.Helper()

	head, err := json.Marshal(map[string]string{"alg": alg, "kid": "k1"})
	require.NoError(t, err)

	body, err := json.Marshal(claims)
	require.NoError(t, err)

	signed := base64.RawURLEncoding.EncodeToString(head) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signed))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)

	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func validClaims() map[string]any {
	now := time.Now()

	return map[string]any{
		"iss":            "https://issuer.test",
		"aud":            []string{"other", "client"},
		"sub":            "person",
		"nonce":          "n",
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"email":          "a@example.com",
		"email_verified": "true",
	}
}

func TestVerifyAcceptsAGoodToken(t *testing.T) {
	provider, key := testProvider(t)

	claims, err := provider.verify(t.Context(), sign(t, key, "RS256", validClaims()), "n")
	require.NoError(t, err)

	assert.Equal(t, "person", claims.Subject)
	assert.True(t, claims.EmailVerified, "Apple's string form counts")
}

func TestVerifyRefusesTampering(t *testing.T) {
	provider, key := testProvider(t)

	for name, mutate := range map[string]func(map[string]any){
		"issuer":   func(c map[string]any) { c["iss"] = "https://evil.test" },
		"audience": func(c map[string]any) { c["aud"] = "other" },
		"nonce":    func(c map[string]any) { c["nonce"] = "replayed" },
		"expired":  func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"future":   func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() },
		"subject":  func(c map[string]any) { delete(c, "sub") },
	} {
		claims := validClaims()
		mutate(claims)

		_, err := provider.verify(t.Context(), sign(t, key, "RS256", claims), "n")
		require.ErrorIs(t, err, ErrInvalidToken, name)
	}

	token := sign(t, key, "RS256", validClaims())
	parts := strings.Split(token, ".")

	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))
	_, err := provider.verify(t.Context(), none+"."+parts[1]+".", "n")
	require.ErrorIs(t, err, ErrInvalidToken, "alg none")

	forgedBody := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"someone else"}`))
	_, err = provider.verify(t.Context(), parts[0]+"."+forgedBody+"."+parts[2], "n")
	require.ErrorIs(t, err, ErrInvalidToken, "body swapped under a valid signature")
}

func TestAppleClientSecretVerifiesWithTheKey(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)

	key, err := ParseAppleKey("TEAM", "KEY", pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: der,
	}))
	require.NoError(t, err)

	secret, err := key.clientSecret("com.example.web", time.Now())
	require.NoError(t, err)

	parts := strings.Split(secret, ".")
	require.Len(t, parts, 3)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	assert.True(t, ecdsa.Verify(&private.PublicKey, digest[:],
		new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])))

	var claims map[string]any
	require.NoError(t, decodeSegment(parts[1], &claims))
	assert.Equal(t, "TEAM", claims["iss"])
	assert.Equal(t, "com.example.web", claims["sub"])
	assert.Equal(t, appleAudience, claims["aud"])
}
