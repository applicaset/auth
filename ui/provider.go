package ui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/buildset/buildset/auth"
	"github.com/buildset/buildset/auth/oidc"
	"github.com/buildset/buildset/pkg/safeurl"
)

const pathOAuth = "/oauth"

// CrossOriginBypass are the patterns that must skip cross-origin protection: Sign in with Apple
// POSTs its answer from appleid.apple.com. The state check in the handler stands in for it.
var CrossOriginBypass = []string{"POST " + pathOAuth + "/{provider}/callback"}

const (
	flowCookieName = "auth_oauth"
	// flowLifetime is how long someone has at the provider before the attempt is void.
	flowLifetime = 10 * time.Minute
)

// providerView is a sign-in provider button.
type providerView struct {
	Name  string
	Label string
	// StartURL begins the provider's sign-in flow.
	StartURL string
}

// flowCookie is what the browser carries from start to callback. It holds the flow's secrets, so
// it is HttpOnly and scoped to the callback path.
type flowCookie struct {
	oidc.Flow

	Provider string `json:"provider"`
	Next     string `json:"next"`
	// Link adds the identity to the signed-in account instead of signing in.
	Link bool `json:"link"`
}

func (h *Handler) providerViews() []providerView {
	views := make([]providerView, 0, len(h.providers))

	for _, provider := range h.providers {
		views = append(views, providerView{
			Name:     provider.Name(),
			Label:    provider.Label(),
			StartURL: pathOAuth + "/" + provider.Name() + "/start",
		})
	}

	return views
}

func (h *Handler) providerLabel(name string) string {
	if provider := h.provider(name); provider != nil {
		return provider.Label()
	}

	return name
}

func (h *Handler) provider(name string) *oidc.Provider {
	for _, provider := range h.providers {
		if provider.Name() == name {
			return provider
		}
	}

	return nil
}

func (h *Handler) oauthStart(w http.ResponseWriter, r *http.Request) {
	provider := h.provider(r.PathValue("provider"))
	if provider == nil {
		h.renderError(w, r, http.StatusNotFound, "There is nothing here.")

		return
	}

	link := r.URL.Query().Has("link")

	if link {
		if _, _, ok := h.requireSession(w, r); !ok {
			return
		}
	}

	flow := oidc.NewFlow()

	target, err := provider.AuthCodeURL(r.Context(), flow, h.links.OAuthCallback(provider.Name()))
	if err != nil {
		h.renderProviderError(w, r, err, "start provider sign-in")

		return
	}

	h.setFlowCookie(w, provider, flowCookie{
		Flow:     flow,
		Provider: provider.Name(),
		Next:     nextTarget(r),
		Link:     link,
	})

	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (h *Handler) oauthCallback(w http.ResponseWriter, r *http.Request) {
	provider := h.provider(r.PathValue("provider"))
	if provider == nil {
		h.renderError(w, r, http.StatusNotFound, "There is nothing here.")

		return
	}

	if r.Method == http.MethodPost && !h.parseForm(w, r) {
		return
	}

	flow, ok := h.readFlowCookie(r, provider.Name())
	h.clearFlowCookie(w, provider)

	// The state ties the answer to this browser's attempt. Without the check, anyone could send a
	// victim a callback URL that signs them in to the sender's account.
	if !ok || r.FormValue("state") == "" || r.FormValue("state") != flow.State {
		h.renderError(w, r, http.StatusBadRequest,
			"That sign-in attempt expired or was started elsewhere. Please try again.")

		return
	}

	if r.FormValue("error") != "" {
		http.Redirect(w, r, h.LoginURL(flow.Next), http.StatusSeeOther)

		return
	}

	claims, err := provider.Exchange(
		r.Context(), flow.Flow, r.FormValue("code"), h.links.OAuthCallback(provider.Name()))
	if err != nil {
		h.renderProviderError(w, r, err, "exchange provider code")

		return
	}

	providerClaims := auth.ProviderClaims{
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
	}

	if providerClaims.Name == "" {
		providerClaims.Name = appleName(r.FormValue("user"))
	}

	if flow.Link {
		h.finishLink(w, r, provider, flow, providerClaims)

		return
	}

	user, err := h.service.SignInWithProvider(
		r.Context(), provider.Name(), providerClaims, h.anonymousMayRegister(r))
	if err != nil {
		h.renderSignInError(w, r, provider, flow, err)

		return
	}

	if err := h.startSession(w, r, user); err != nil {
		h.renderInternalError(w, r, err, "start session after provider sign-in")

		return
	}

	http.Redirect(w, r, flow.Next, http.StatusSeeOther)
}

func (h *Handler) finishLink(
	w http.ResponseWriter,
	r *http.Request,
	provider *oidc.Provider,
	flow flowCookie,
	claims auth.ProviderClaims,
) {
	session, user, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	if err := h.service.LinkProvider(r.Context(), user.ID, provider.Name(), claims); err != nil {
		if errors.Is(err, auth.ErrIdentityTaken) {
			h.renderSettings(w, r, http.StatusConflict, session, user, pageData{
				ErrorMessage: "That " + provider.Label() + " account is linked to another account.",
				Next:         flow.Next,
			})

			return
		}

		h.renderInternalError(w, r, err, "link provider")

		return
	}

	http.Redirect(
		w,
		r,
		withQuery(h.SettingsURL(flow.Next), "notice", "linked"),
		http.StatusSeeOther,
	)
}

func (h *Handler) renderSignInError(
	w http.ResponseWriter,
	r *http.Request,
	provider *oidc.Provider,
	flow flowCookie,
	err error,
) {
	switch {
	case errors.Is(err, auth.ErrAccountExists):
		h.render(w, r, http.StatusConflict, "login.gohtml", h.loginPage(r, pageData{
			ErrorMessage: "An account with that email address already exists. Sign in another " +
				"way, then link " + provider.Label() + " from your settings.",
			Next: flow.Next,
		}))
	case errors.Is(err, auth.ErrSignUpClosed):
		h.render(w, r, http.StatusForbidden, "login.gohtml", h.loginPage(r, pageData{
			ErrorMessage: "No account is linked to that " + provider.Label() + " account, and " +
				"new accounts cannot be created here.",
			Next: flow.Next,
		}))
	default:
		h.renderInternalError(w, r, err, "sign in with provider")
	}
}

func (h *Handler) renderProviderError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	op string,
) {
	if errors.Is(err, oidc.ErrInvalidToken) {
		h.logger.WarnContext(r.Context(), op, slog.Any("error", err))
		h.renderError(w, r, http.StatusBadRequest, "The provider's answer could not be verified.")

		return
	}

	h.logger.ErrorContext(r.Context(), op, slog.Any("error", err))
	h.renderError(w, r, http.StatusBadGateway,
		"The sign-in provider could not be reached. Please try again.")
}

func (h *Handler) unlinkProvider(w http.ResponseWriter, r *http.Request) {
	session, user, ok := h.requireSession(w, r)
	if !ok || !h.parseForm(w, r) {
		return
	}

	err := h.service.UnlinkProvider(
		r.Context(), user.ID, r.PostFormValue("provider"), r.PostFormValue("subject"))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrLastSignInMethod):
			h.renderSettings(w, r, http.StatusConflict, session, user, pageData{
				ErrorMessage: "Set a password or add an email address before removing your only " +
					"sign-in method.",
			})
		case errors.Is(err, auth.ErrIdentityNotFound):
			http.Redirect(w, r, h.SettingsURL(nextTarget(r)), http.StatusSeeOther)
		default:
			h.renderInternalError(w, r, err, "unlink provider")
		}

		return
	}

	http.Redirect(w, r, withQuery(h.SettingsURL(nextTarget(r)), "notice", "unlinked"),
		http.StatusSeeOther)
}

// setFlowCookie uses SameSite=None for a provider that POSTs back, since a Lax cookie is not sent
// on a cross-site POST. None requires Secure, so such a provider works only over HTTPS, which Apple
// demands anyway.
func (h *Handler) setFlowCookie(w http.ResponseWriter, provider *oidc.Provider, flow flowCookie) {
	value, err := json.Marshal(flow)
	if err != nil {
		return
	}

	cookie := h.baseFlowCookie(provider)
	cookie.Value = base64.RawURLEncoding.EncodeToString(value)
	cookie.MaxAge = int(flowLifetime.Seconds())

	http.SetCookie(w, cookie)
}

func (h *Handler) clearFlowCookie(w http.ResponseWriter, provider *oidc.Provider) {
	cookie := h.baseFlowCookie(provider)
	cookie.MaxAge = -1

	http.SetCookie(w, cookie)
}

func (h *Handler) baseFlowCookie(provider *oidc.Provider) *http.Cookie {
	sameSite := http.SameSiteLaxMode
	if provider.PostsBack() && h.config.SecureCookies {
		sameSite = http.SameSiteNoneMode
	}

	return &http.Cookie{
		Name:     flowCookieName,
		Path:     pathOAuth + "/" + provider.Name() + "/",
		HttpOnly: true,
		Secure:   h.config.SecureCookies,
		SameSite: sameSite,
	}
}

func (h *Handler) readFlowCookie(r *http.Request, provider string) (flowCookie, bool) {
	cookie, err := r.Cookie(flowCookieName)
	if err != nil {
		return flowCookie{}, false
	}

	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return flowCookie{}, false
	}

	var flow flowCookie
	if err := json.Unmarshal(raw, &flow); err != nil || flow.Provider != provider {
		return flowCookie{}, false
	}

	flow.Next = safeurl.Next(flow.Next)

	return flow, true
}

// appleName reads the name Apple sends, once, beside the code on the first sign-in. It is not in
// the ID token and is not signed, so it is used only as a display name.
func appleName(raw string) string {
	if raw == "" {
		return ""
	}

	var user struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}

	if json.Unmarshal([]byte(raw), &user) != nil {
		return ""
	}

	return strings.TrimSpace(user.Name.FirstName + " " + user.Name.LastName)
}
