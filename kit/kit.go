// Package kit builds the identity service and its pages from configuration, so every binary that
// runs auth, on its own or inside an application, wires it the same way.
package kit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/applicaset/buildset/auth"
	"github.com/applicaset/buildset/auth/hash"
	"github.com/applicaset/buildset/auth/oidc"
	authui "github.com/applicaset/buildset/auth/ui"
	"github.com/applicaset/buildset/pkg/mail"
	"github.com/nasermirzaei89/env"
)

var errInvalidConfig = errors.New("invalid configuration")

// Expiry is enforced on every lookup; sweeping only keeps the tables from growing forever.
const sweepInterval = time.Hour

type Config struct {
	BcryptCost       int
	SessionTTL       time.Duration
	RegistrationOpen bool
	// PublicURL is where browsers reach the auth pages. Mailed links start with it.
	PublicURL string
	Mail      mail.Config
	// Providers are the OpenID Connect providers offered as sign-in buttons.
	Providers []oidc.Config
}

func LoadConfig() (Config, error) {
	providers, err := LoadProviders()
	if err != nil {
		return Config{}, err
	}

	return Config{
		BcryptCost:       env.GetInt("AUTH_BCRYPT_COST", 12),
		SessionTTL:       env.GetDuration("AUTH_SESSION_TTL", 14*24*time.Hour),
		RegistrationOpen: env.GetBool("AUTH_REGISTRATION_OPEN", true),
		PublicURL:        env.GetString("AUTH_PUBLIC_URL", "http://localhost:8080"),
		Mail:             mail.Load(),
		Providers:        providers,
	}, nil
}

// LoadProviders reads each provider whose client id is set. Apple's private key is read from a
// file, the .p8 Apple hands out, so the key never sits in the environment.
func LoadProviders() ([]oidc.Config, error) {
	var providers []oidc.Config

	if clientID := env.GetString("AUTH_GOOGLE_CLIENT_ID", ""); clientID != "" {
		providers = append(providers, oidc.Config{
			Name:         "google",
			Label:        "Google",
			Issuer:       "https://accounts.google.com",
			ClientID:     clientID,
			ClientSecret: env.GetString("AUTH_GOOGLE_CLIENT_SECRET", ""),
		})
	}

	if clientID := env.GetString("AUTH_APPLE_CLIENT_ID", ""); clientID != "" {
		keyFile := env.GetString("AUTH_APPLE_PRIVATE_KEY_FILE", "")

		pemBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: read AUTH_APPLE_PRIVATE_KEY_FILE: %w",
				errInvalidConfig,
				err,
			)
		}

		key, err := oidc.ParseAppleKey(
			env.GetString("AUTH_APPLE_TEAM_ID", ""),
			env.GetString("AUTH_APPLE_KEY_ID", ""),
			pemBytes,
		)
		if err != nil {
			return nil, err
		}

		providers = append(providers, oidc.Config{
			Name:     "apple",
			Label:    "Apple",
			Issuer:   "https://appleid.apple.com",
			ClientID: clientID,
			Apple:    key,
			// Apple accepts only these two, and the name only through form_post.
			Scopes:   []string{"openid", "email", "name"},
			FormPost: true,
		})
	}

	return providers, nil
}

func (c Config) Validate() error {
	// bcrypt rejects costs outside [4, 31]; bounding here fails at boot rather than per login.
	if c.BcryptCost < 10 || c.BcryptCost > 31 {
		return fmt.Errorf(
			"%w: AUTH_BCRYPT_COST must be between 10 and 31, got %d",
			errInvalidConfig,
			c.BcryptCost,
		)
	}

	if c.SessionTTL <= 0 {
		return fmt.Errorf(
			"%w: AUTH_SESSION_TTL must be positive, got %s",
			errInvalidConfig,
			c.SessionTTL,
		)
	}

	if _, err := authui.NewLinks(c.PublicURL); err != nil {
		return fmt.Errorf("AUTH_PUBLIC_URL: %w", err)
	}

	if err := c.Mail.Validate(); err != nil {
		return err
	}

	for _, provider := range c.Providers {
		if err := provider.Validate(); err != nil {
			return err
		}
	}

	return nil
}

type Options struct {
	Config        Config
	UserRepo      auth.UserRepository
	SessionRepo   auth.SessionRepository
	TokenRepo     auth.TokenRepository
	IdentityRepo  auth.IdentityRepository
	FirstUserHook auth.FirstUserHook
	Registration  authui.RegistrationPolicy
	Cookie        authui.Config
	// Mailer replaces the one Config.Mail describes. Tests set it to read what was sent.
	Mailer auth.Mailer
	// HTTPClient reaches the providers. Nil uses a client with a timeout.
	HTTPClient *http.Client
	Logger     *slog.Logger
}

func Build(options Options) (*auth.Service, *authui.Handler, error) {
	cfg := options.Config

	bcryptAlgorithm, err := hash.NewBcrypt(cfg.BcryptCost)
	if err != nil {
		return nil, nil, fmt.Errorf("build bcrypt algorithm: %w", err)
	}

	// TODO: register argon2id here and prefer it once implemented. Existing bcrypt hashes keep
	// verifying, and each user is upgraded on their next login.
	passwords, err := hash.NewRegistry(bcryptAlgorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("build password registry: %w", err)
	}

	links, err := authui.NewLinks(cfg.PublicURL)
	if err != nil {
		return nil, nil, err
	}

	mailer := options.Mailer
	if mailer == nil {
		mailer = mail.New(cfg.Mail, options.Logger)
	}

	service, err := auth.NewService(
		options.UserRepo,
		options.SessionRepo,
		options.TokenRepo,
		options.IdentityRepo,
		auth.Options{
			Passwords:     passwords,
			FirstUserHook: options.FirstUserHook,
			SessionTTL:    cfg.SessionTTL,
			Mailer:        mailer,
			Links:         links,
			Logger:        options.Logger,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("build auth service: %w", err)
	}

	providers := make([]*oidc.Provider, 0, len(cfg.Providers))

	for _, providerConfig := range cfg.Providers {
		provider, err := oidc.New(providerConfig, options.HTTPClient)
		if err != nil {
			return nil, nil, fmt.Errorf("build provider %s: %w", providerConfig.Name, err)
		}

		providers = append(providers, provider)
	}

	pageConfig := options.Cookie
	pageConfig.Links = links
	pageConfig.Providers = providers

	pages, err := authui.NewHandler(service, options.Registration, pageConfig, options.Logger)
	if err != nil {
		return nil, nil, fmt.Errorf("build auth handler: %w", err)
	}

	return service, pages, nil
}

// Sweep deletes expired sessions and tokens every hour until the context is cancelled.
func Sweep(ctx context.Context, service *auth.Service, logger *slog.Logger) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepOnce(ctx, "sessions", service.DeleteExpiredSessions, logger)
			sweepOnce(ctx, "tokens", service.DeleteExpiredTokens, logger)
		}
	}
}

func sweepOnce(
	ctx context.Context,
	what string,
	sweep func(context.Context) (int64, error),
	logger *slog.Logger,
) {
	deleted, err := sweep(ctx)
	if err != nil {
		logger.WarnContext(ctx, "sweep expired "+what, slog.Any("error", err))

		return
	}

	if deleted > 0 {
		logger.InfoContext(ctx, "swept expired "+what, slog.Int64("count", deleted))
	}
}
