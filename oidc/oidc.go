// Package oidc signs people in with an OpenID Connect provider, such as Google or Apple, using the
// authorization code flow with PKCE. It verifies ID tokens itself against the provider's published
// keys, so no library sits between a provider's answer and the account it opens.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken  = errors.New("invalid id token")
	errInvalidConfig = errors.New("invalid provider configuration")
	errProvider      = errors.New("provider error")
)

// Config describes one provider. Name is the path segment and the stored provider name, so it must
// never change once people have linked accounts with it.
type Config struct {
	Name     string
	Label    string
	Issuer   string
	ClientID string
	// ClientSecret is a fixed secret. Apple takes a signed JWT instead, which Apple builds.
	ClientSecret string
	Apple        *AppleKey
	Scopes       []string
	// FormPost asks the provider to POST the result to the callback rather than redirect with a
	// query. Apple requires it whenever the email or name scope is requested.
	FormPost bool
}

func (c Config) Validate() error {
	if c.Name == "" || strings.ContainsAny(c.Name, "/?#") {
		return fmt.Errorf("%w: name %q", errInvalidConfig, c.Name)
	}

	if c.Issuer == "" || c.ClientID == "" {
		return fmt.Errorf("%w: %s needs an issuer and a client id", errInvalidConfig, c.Name)
	}

	if c.ClientSecret == "" && c.Apple == nil {
		return fmt.Errorf("%w: %s needs a client secret", errInvalidConfig, c.Name)
	}

	return nil
}

// Claims are what a verified ID token says about the person.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Flow is the per-attempt secret state the browser carries between start and callback.
type Flow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

func NewFlow() Flow {
	return Flow{State: rand.Text(), Nonce: rand.Text(), Verifier: rand.Text() + rand.Text()}
}

type Provider struct {
	config Config
	client *http.Client

	mu        sync.Mutex
	discovery *discovery
	keys      *keySet
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// requestTimeout bounds each call to the provider, so a slow provider fails the sign-in rather
// than holding the request.
const requestTimeout = 10 * time.Second

func New(config Config, client *http.Client) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}

	return &Provider{config: config, client: client}, nil
}

func (p *Provider) Name() string  { return p.config.Name }
func (p *Provider) Label() string { return p.config.Label }

// AuthCodeURL is where the browser goes to sign in. Discovery runs on first use rather than at
// start-up, so a provider being down never stops the service from booting.
func (p *Provider) AuthCodeURL(ctx context.Context, flow Flow, redirectURI string) (string, error) {
	meta, err := p.metadata(ctx)
	if err != nil {
		return "", err
	}

	challenge := sha256.Sum256([]byte(flow.Verifier))

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.config.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(p.scopes(), " ")},
		"state":                 {flow.State},
		"nonce":                 {flow.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}

	if p.config.FormPost {
		query.Set("response_mode", "form_post")
	}

	return meta.AuthorizationEndpoint + "?" + query.Encode(), nil
}

func (p *Provider) scopes() []string {
	if len(p.config.Scopes) > 0 {
		return p.config.Scopes
	}

	return []string{"openid", "email", "profile"}
}

// Exchange trades the code for an ID token and verifies it against the flow's nonce.
func (p *Provider) Exchange(
	ctx context.Context,
	flow Flow,
	code, redirectURI string,
) (*Claims, error) {
	meta, err := p.metadata(ctx)
	if err != nil {
		return nil, err
	}

	secret, err := p.clientSecret()
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {p.config.ClientID},
		"client_secret": {secret},
		"code_verifier": {flow.Verifier},
	}

	var response struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}

	if err := p.postForm(ctx, meta.TokenEndpoint, form, &response); err != nil {
		return nil, err
	}

	if response.IDToken == "" {
		return nil, fmt.Errorf("%w: no id token in the token response", errProvider)
	}

	return p.verify(ctx, response.IDToken, flow.Nonce)
}

func (p *Provider) clientSecret() (string, error) {
	if p.config.Apple != nil {
		return p.config.Apple.clientSecret(p.config.ClientID, time.Now())
	}

	return p.config.ClientSecret, nil
}

func (p *Provider) metadata(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.discovery != nil {
		return p.discovery, nil
	}

	var meta discovery

	wellKnown := strings.TrimRight(p.config.Issuer, "/") + "/.well-known/openid-configuration"
	if err := p.getJSON(ctx, wellKnown, &meta); err != nil {
		return nil, fmt.Errorf("discover %s: %w", p.config.Name, err)
	}

	// OpenID Connect Discovery 1.0 §4.3: the document must name the issuer it was fetched for.
	if meta.Issuer != p.config.Issuer {
		return nil, fmt.Errorf("%w: discovery names issuer %q, want %q",
			errProvider, meta.Issuer, p.config.Issuer)
	}

	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
		return nil, fmt.Errorf("%w: discovery document is incomplete", errProvider)
	}

	p.discovery = &meta

	return p.discovery, nil
}

func (p *Provider) getJSON(ctx context.Context, target string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	return p.do(request, into)
}

func (p *Provider) postForm(ctx context.Context, target string, form url.Values, into any) error {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return p.do(request, into)
}

// maxResponseBytes caps what is read from a provider; its documents are a few kilobytes.
const maxResponseBytes = 1 << 20

func (p *Provider) do(request *http.Request, into any) error {
	request.Header.Set("Accept", "application/json")

	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %w", errProvider, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%w: read response: %w", errProvider, err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", errProvider, request.URL.Host, response.StatusCode)
	}

	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%w: decode response: %w", errProvider, err)
	}

	return nil
}

// audienceMatches accepts aud as a string or an array, as RFC 7519 §4.1.3 allows.
func audienceMatches(raw json.RawMessage, clientID string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == clientID
	}

	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return slices.Contains(many, clientID)
	}

	return false
}
func (p *Provider) PostsBack() bool { return p.config.FormPost }
