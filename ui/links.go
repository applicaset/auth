package ui

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/applicaset/pkg/safeurl"
)

const (
	pathVerifyEmail    = "/verify-email"
	pathResendVerify   = "/verify-email/resend"
	pathForgotPassword = "/forgot-password"
	pathResetPassword  = "/reset-password"
	pathEmailLogin     = "/login/email"
	pathConfirmEmail   = "/email/confirm"
)

// Links builds the absolute URLs auth mails out. The base comes from configuration, never from the
// request: a Host header is the client's to write, and a reset link pointing at the attacker's host
// would hand them the token.
type Links struct {
	base string
}

func NewLinks(publicURL string) (Links, error) {
	parsed, err := url.Parse(publicURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return Links{}, fmt.Errorf("%w: public URL must be an absolute http(s) URL, got %q",
			errInvalidConfig, publicURL)
	}

	return Links{base: strings.TrimRight(parsed.String(), "/")}, nil
}

func (l Links) VerifyEmail(token string) string {
	return l.withToken(pathVerifyEmail, token, "")
}

func (l Links) ResetPassword(token string) string {
	return l.withToken(pathResetPassword, token, "")
}

func (l Links) EmailLogin(token, next string) string {
	return l.withToken(pathEmailLogin, token, safeurl.Next(next))
}

func (l Links) ConfirmEmailChange(token string) string {
	return l.withToken(pathConfirmEmail, token, "")
}

func (l Links) OAuthCallback(provider string) string {
	return l.base + pathOAuth + "/" + provider + "/callback"
}

func (l Links) withToken(path, token, next string) string {
	query := url.Values{"token": {token}}
	if next != "" && next != "/" {
		query.Set("next", next)
	}

	return l.base + path + "?" + query.Encode()
}

// Paths are the exact paths a gateway must send to these pages, and Prefixes the path prefixes.
// deploy/Caddyfile lists the same; the test gateways read these so they cannot drift from Register.
var (
	Paths = []string{
		"/setup", "/login", "/logout", "/register", newUserPath, "/password",
		pathEmailLogin, pathEmailLogin + "/request", pathForgotPassword, pathResetPassword,
		pathVerifyEmail, pathResendVerify, pathConfirmEmail, pathSettings,
	}
	Prefixes = []string{"/auth/", pathSettings + "/", pathOAuth + "/"}
)
