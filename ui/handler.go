// Package ui serves the browser pages that must handle a password: sign in, register, first-run
// setup, and password change. No other service renders these, so no other service ever receives a
// password from a browser.
package ui

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"

	"github.com/applicaset/auth"
	"github.com/applicaset/auth/oidc"
	"github.com/applicaset/pkg/safeurl"
)

const newUserPath = "/users/new"

// maxFormBytes caps a form submission; these forms are a handful of short fields.
const maxFormBytes = 16 << 10

var (
	errInvalidConfig     = errors.New("invalid configuration")
	errMissingDependency = errors.New("missing dependency")
)

type Config struct {
	SessionCookieName string
	SecureCookies     bool
	// Links builds the URLs mailed out and the providers' callback address.
	Links Links
	// Providers are offered as sign-in buttons, in this order.
	Providers []*oidc.Provider
}

type Handler struct {
	service   *auth.Service
	policy    RegistrationPolicy
	config    Config
	links     Links
	providers []*oidc.Provider
	templates map[string]*template.Template
	logger    *slog.Logger
}

func NewHandler(
	service *auth.Service,
	policy RegistrationPolicy,
	config Config,
	logger *slog.Logger,
) (*Handler, error) {
	if config.SessionCookieName == "" {
		return nil, fmt.Errorf("%w: session cookie name must not be empty", errInvalidConfig)
	}

	if config.Links.base == "" {
		return nil, fmt.Errorf("%w: links must be built with NewLinks", errInvalidConfig)
	}

	if policy == nil {
		return nil, fmt.Errorf("%w: a registration policy must be provided", errMissingDependency)
	}

	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	return &Handler{
		service:   service,
		policy:    policy,
		config:    config,
		links:     config.Links,
		providers: config.Providers,
		templates: templates,
		logger:    logger,
	}, nil
}

// Register mounts auth's pages at top-level paths, so moving auth to its own host later is a
// configuration change and not a change to any link.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET "+stylesheet.Path, stylesheet)
	mux.HandleFunc("GET /setup", h.setupForm)
	mux.HandleFunc("POST /setup", h.setupSubmit)
	mux.HandleFunc("GET /login", h.loginForm)
	mux.HandleFunc("POST /login", h.loginSubmit)
	mux.HandleFunc("GET /logout", h.logoutForm)
	mux.HandleFunc("POST /logout", h.logoutSubmit)
	mux.HandleFunc("GET /register", h.registerForm)
	mux.HandleFunc("POST /register", h.registerSubmit)
	mux.HandleFunc("GET "+newUserPath, h.newUserForm)
	mux.HandleFunc("POST "+newUserPath, h.newUserSubmit)
	mux.HandleFunc("GET /password", h.passwordForm)
	mux.HandleFunc("POST /password", h.passwordSubmit)
	mux.HandleFunc("POST "+pathEmailLogin+"/request", h.emailLoginSubmit)
	mux.HandleFunc("GET "+pathEmailLogin, h.emailLoginForm)
	mux.HandleFunc("POST "+pathEmailLogin, h.emailLoginConfirm)
	mux.HandleFunc("GET "+pathForgotPassword, h.forgotPasswordForm)
	mux.HandleFunc("POST "+pathForgotPassword, h.forgotPasswordSubmit)
	mux.HandleFunc("GET "+pathResetPassword, h.resetPasswordForm)
	mux.HandleFunc("POST "+pathResetPassword, h.resetPasswordSubmit)
	mux.HandleFunc("GET "+pathVerifyEmail, h.verifyEmail)
	mux.HandleFunc("POST "+pathResendVerify, h.resendVerification)
	mux.HandleFunc("GET "+pathConfirmEmail, h.confirmEmailForm)
	mux.HandleFunc("POST "+pathConfirmEmail, h.confirmEmailSubmit)
	mux.HandleFunc("GET "+pathOAuth+"/{provider}/start", h.oauthStart)
	mux.HandleFunc("GET "+pathOAuth+"/{provider}/callback", h.oauthCallback)
	mux.HandleFunc("POST "+pathOAuth+"/{provider}/callback", h.oauthCallback)
	mux.HandleFunc("POST "+pathSettings+"/identities/unlink", h.unlinkProvider)
	mux.HandleFunc("GET "+pathSettings, h.accountPage)
	mux.HandleFunc("POST "+pathSettings+"/profile", h.accountProfileSubmit)
	mux.HandleFunc("POST "+pathSettings+"/email", h.accountEmailSubmit)
	mux.HandleFunc("GET "+pathSettings+"/delete", h.deleteAccountForm)
	mux.HandleFunc("POST "+pathSettings+"/delete", h.deleteAccountSubmit)
}

// LoginURL keeps the rest of the system out of auth's routing. An OAuth2 authorization endpoint
// would be returned from here instead.
func (h *Handler) LoginURL(next string) string { return safeurl.WithNext("/login", next) }

// The URLs below take next too: several sites can link here, and each wants its visitor back.

func (h *Handler) LogoutURL(next string) string   { return safeurl.WithNext("/logout", next) }
func (h *Handler) PasswordURL(next string) string { return safeurl.WithNext("/password", next) }
func (h *Handler) NewUserURL(next string) string  { return safeurl.WithNext(newUserPath, next) }
func (h *Handler) SetupURL(next string) string    { return safeurl.WithNext("/setup", next) }
func (h *Handler) SettingsURL(next string) string { return safeurl.WithNext(pathSettings, next) }

// nextTarget is where the linking site asked to have the visitor sent back. It reads the body only
// once parseForm has capped and parsed it.
func nextTarget(r *http.Request) string {
	if r.Form == nil {
		return safeurl.Next(r.URL.Query().Get("next"))
	}

	return safeurl.Next(r.Form.Get("next"))
}

// parseForm bounds the request body before reading it, so a large upload cannot be turned into
// memory pressure by an unauthenticated client.
func (h *Handler) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)

	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "That form could not be read.")

		return false
	}

	return true
}

func (h *Handler) sessionMeta(r *http.Request) auth.SessionMeta {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// TODO: behind a reverse proxy this records the proxy. Reading X-Forwarded-For needs a list of
	// trusted proxies first, otherwise any client can write whatever address it likes.
	return auth.SessionMeta{UserAgent: r.UserAgent(), IP: host}
}

// startSession replaces whatever session the browser presented, so there is no identifier for an
// attacker to fix in advance.
func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, user *auth.User) error {
	if presented := h.sessionToken(r); presented != "" {
		if err := h.service.RevokeSession(r.Context(), presented); err != nil {
			return fmt.Errorf("revoke presented session: %w", err)
		}
	}

	token, session, err := h.service.CreateSession(r.Context(), user.ID, h.sessionMeta(r))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	h.setSessionCookie(w, token, session.ExpiresAt)

	return nil
}

// An absent or expired session is not an error here; the caller decides what to do about it.
func (h *Handler) currentSession(r *http.Request) (*auth.Session, *auth.User, error) {
	token := h.sessionToken(r)
	if token == "" {
		return nil, nil, auth.ErrSessionNotFound
	}

	return h.service.ResolveSession(r.Context(), token)
}
