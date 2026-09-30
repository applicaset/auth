// Package app is the composition root of the identity service running on its own. It serves the
// sign-in pages and the small API the site calls on one port. Credential operations are reachable
// only from the pages, so nothing on the network can create a session or change a password.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/applicaset/buildset/auth"
	"github.com/applicaset/buildset/auth/backend"
	"github.com/applicaset/buildset/auth/httpapi"
	"github.com/applicaset/buildset/auth/kit"
	authui "github.com/applicaset/buildset/auth/ui"
	authzclient "github.com/applicaset/buildset/authz/client"
	"github.com/applicaset/buildset/pkg/config"
	"github.com/applicaset/buildset/pkg/httpx"
	"github.com/applicaset/buildset/pkg/serve"
	"github.com/applicaset/buildset/pkg/storage"
	"github.com/nasermirzaei89/env"
)

// schema is the Postgres schema this service owns. SQLite ignores it.
const schema = "auth"

var errInvalidConfig = errors.New("invalid configuration")

type Config struct {
	config.Server

	Log      config.Log
	Cookie   config.Cookie
	Database storage.Config
	Auth     kit.Config
	// AdminRole is the application's vocabulary; authz only stores the string.
	AdminRole string

	AuthzURL    string
	HTTPTimeout time.Duration
	// Mailer replaces the SMTP sender Auth.Mail describes. Tests set it to read what was sent.
	Mailer auth.Mailer
}

func LoadConfig(ctx context.Context) (*Config, error) {
	log, err := config.LoadLog()
	if err != nil {
		return nil, err
	}

	authzURL, err := config.LoadURL("AUTHZ_URL")
	if err != nil {
		return nil, err
	}

	authConfig, err := kit.LoadConfig()
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Server:      config.LoadServer(),
		Log:         log,
		Cookie:      config.LoadCookie(),
		Database:    storage.Load(),
		Auth:        authConfig,
		AdminRole:   env.GetString("AUTH_ADMIN_ROLE", "admin"),
		AuthzURL:    authzURL,
		HTTPTimeout: env.GetDuration("HTTP_TIMEOUT", 5*time.Second),
	}

	if err := cfg.Validate(ctx); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate(ctx context.Context) error {
	if err := c.Server.Validate(ctx); err != nil {
		return err
	}

	if err := c.Database.Validate(); err != nil {
		return err
	}

	if err := c.Auth.Validate(); err != nil {
		return err
	}

	if c.AdminRole == "" {
		return fmt.Errorf("%w: AUTH_ADMIN_ROLE must not be empty", errInvalidConfig)
	}

	return nil
}

type Service struct {
	handle  *storage.Handle
	service *auth.Service
	routes  http.Handler
	logger  *slog.Logger
}

func New(ctx context.Context, cfg *Config, logger *slog.Logger) (*Service, error) {
	handle, err := storage.OpenHandle(ctx, cfg.Database, schema)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	service, routes, err := build(ctx, cfg, handle, logger)
	if err != nil {
		_ = handle.Close()

		return nil, err
	}

	return &Service{handle: handle, service: service, routes: routes, logger: logger}, nil
}

func build(
	ctx context.Context,
	cfg *Config,
	handle *storage.Handle,
	logger *slog.Logger,
) (*auth.Service, http.Handler, error) {
	repos, err := backend.New(ctx, cfg.Database.Driver, handle)
	if err != nil {
		return nil, nil, fmt.Errorf("build auth repositories: %w", err)
	}

	authzClient, err := authzclient.New(cfg.AuthzURL, httpx.ClientOptions{Timeout: cfg.HTTPTimeout})
	if err != nil {
		return nil, nil, fmt.Errorf("build authz client: %w", err)
	}

	service, pages, err := kit.Build(kit.Options{
		Config:        cfg.Auth,
		UserRepo:      repos.User,
		SessionRepo:   repos.Session,
		TokenRepo:     repos.Token,
		IdentityRepo:  repos.Identity,
		FirstUserHook: firstUserHook(authzClient, cfg.AdminRole, logger),
		Registration:  registrationPolicy(cfg.Auth.RegistrationOpen, authzClient),
		Cookie: authui.Config{
			SessionCookieName: cfg.Cookie.Name,
			SecureCookies:     cfg.Cookie.Secure,
		},
		Mailer: cfg.Mailer,
		Logger: logger,
	})
	if err != nil {
		return nil, nil, err
	}

	api, err := httpapi.NewHandler(service, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("build auth api: %w", err)
	}

	mux := http.NewServeMux()
	// The pages keep unprefixed paths. The gateway routes them so the browser sees one origin,
	// which the session cookie and the same-origin checks need.
	pages.Register(mux)
	api.Register(mux)

	return service, mux, nil
}

func (svc *Service) Routes() http.Handler { return svc.routes }

func (svc *Service) Ping(ctx context.Context) error { return svc.handle.Ping(ctx) }

func (svc *Service) Close() error { return svc.handle.Close() }

// Sweep deletes expired sessions and tokens until the context is cancelled.
func (svc *Service) Sweep(ctx context.Context) { kit.Sweep(ctx, svc.service, svc.logger) }

func Run(ctx context.Context) error {
	cfg, err := LoadConfig(ctx)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := serve.NewLogger(cfg.Log)
	slog.SetDefault(logger)

	service, err := New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := service.Close(); err != nil {
			logger.ErrorContext(ctx, "close service", slog.Any("error", err))
		}
	}()

	return serve.Run(ctx, serve.Options{
		Name:            "auth",
		Address:         cfg.Address(),
		ShutdownTimeout: cfg.ShutdownTimeout,
		Logger:          logger,
		Routes:          service.Routes(),
		Ready:           service.Ping,
		// Browsers post sign-in forms here through the gateway. Cross-origin protection applies,
		// and an inbound request identifier is not trusted.
		CrossOrigin:       true,
		CrossOriginBypass: authui.CrossOriginBypass,
		TrustRequestID:    false,
		Background:        []func(context.Context){service.Sweep},
	})
}
