// Package oidctest runs an OpenID Connect provider in the test process, so sign-in with Google or
// Apple can be tested end to end without either.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/applicaset/buildset/auth/oidc"
	"github.com/stretchr/testify/require"
)

const (
	ClientID     = "test-client"
	ClientSecret = "test-secret"
	keyID        = "test-key"
)

// Person is who the next sign-in at the provider will be.
type Person struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

type Provider struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	mu     sync.Mutex
	next   Person
	grants map[string]grant
}

type grant struct {
	person      Person
	nonce       string
	challenge   string
	redirectURI string
}

func New(t *testing.T) *Provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p := &Provider{key: key, grants: map[string]grant{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)

	return p
}

func (p *Provider) Config(name, label string) oidc.Config {
	return oidc.Config{
		Name:         name,
		Label:        label,
		Issuer:       p.server.URL,
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
	}
}

// SignInAs sets who the next visit to the authorize endpoint signs in as.
func (p *Provider) SignInAs(person Person) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.next = person
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"issuer":                 p.server.URL,
		"authorization_endpoint": p.server.URL + "/authorize",
		"token_endpoint":         p.server.URL + "/token",
		"jwks_uri":               p.server.URL + "/jwks",
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
	}}})
}

// authorize signs in at once as the chosen person and sends the browser back with a code.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("client_id") != ClientID || query.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)

		return
	}

	code := rand.Text()

	p.mu.Lock()
	p.grants[code] = grant{
		person:      p.next,
		nonce:       query.Get("nonce"),
		challenge:   query.Get("code_challenge"),
		redirectURI: query.Get("redirect_uri"),
	}
	p.mu.Unlock()

	back, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect uri", http.StatusBadRequest)

		return
	}

	values := back.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	back.RawQuery = values.Encode()

	http.Redirect(w, r, back.String(), http.StatusSeeOther)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)

		return
	}

	p.mu.Lock()
	granted, ok := p.grants[r.PostFormValue("code")]
	delete(p.grants, r.PostFormValue("code"))
	p.mu.Unlock()

	verifier := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))

	if !ok ||
		r.PostFormValue("client_secret") != ClientSecret ||
		r.PostFormValue("redirect_uri") != granted.redirectURI ||
		base64.RawURLEncoding.EncodeToString(verifier[:]) != granted.challenge {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})

		return
	}

	now := time.Now()

	idToken := p.sign(map[string]any{
		"iss":            p.server.URL,
		"aud":            ClientID,
		"sub":            granted.person.Subject,
		"email":          granted.person.Email,
		"email_verified": granted.person.EmailVerified,
		"name":           granted.person.Name,
		"nonce":          granted.nonce,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	})

	writeJSON(w, map[string]string{"id_token": idToken, "token_type": "Bearer"})
}

func (p *Provider) sign(claims map[string]any) string {
	head, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		panic(err)
	}

	body, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	signed := base64.RawURLEncoding.EncodeToString(head) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signed))

	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}

	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
