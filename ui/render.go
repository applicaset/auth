package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/applicaset/pkg/asset"
)

//go:embed templates/*.gohtml templates/icons/*.svg
var templateFiles embed.FS

//go:embed static/style.min.css
var stylesheetContent []byte

// The path sits under /auth so a gateway can route it to this service by prefix.
var stylesheet = asset.New(
	"/auth/static/style.min.css",
	"text/css; charset=utf-8",
	stylesheetContent,
)

// pageData is what every template in this package receives.
type pageData struct {
	Title         string
	StylesheetURL string
	ErrorMessage  string
	Notice        string
	Message       string
	// Next is where the page sends the visitor back to: the linking site's page, or "/".
	Next             string
	Username         string
	Email            string
	Name             string
	RegistrationOpen bool
	// Token is the secret from a mailed link, carried into the form that uses it.
	Token string
	// Action and Button configure the one-button page that confirms a mailed link.
	Action    string
	Button    string
	Providers []providerView
	// Account is the signed-in person on the settings page.
	Account *accountView
	// HideBackLink drops the link back from a page that already offers a way out.
	HideBackLink bool
}

// One template set per page, each with its own copy of the layout, because every page defines the
// same "content" block.
func parseTemplates() (map[string]*template.Template, error) {
	names := []string{
		"setup.gohtml",
		"login.gohtml",
		"register.gohtml",
		"new_user.gohtml",
		"password.gohtml",
		"logout.gohtml",
		"error.gohtml",
		"email_sent.gohtml",
		"token_confirm.gohtml",
		"forgot_password.gohtml",
		"reset_password.gohtml",
		"settings.gohtml",
		"delete_account.gohtml",
	}
	pages := make(map[string]*template.Template, len(names))

	for _, name := range names {
		page, err := template.ParseFS(
			templateFiles,
			"templates/layout.gohtml",
			"templates/icons/*.svg",
			"templates/"+name,
		)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}

		pages[name] = page
	}

	return pages, nil
}

// The template runs into a buffer first, so a failure becomes an error page rather than a
// truncated one sent with a success status.
func (h *Handler) render(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	page string,
	data pageData,
) {
	tmpl, ok := h.templates[page]
	if !ok {
		h.logger.ErrorContext(r.Context(), "unknown template", slog.String("page", page))
		http.Error(w, "internal server error", http.StatusInternalServerError)

		return
	}

	data.StylesheetURL = stylesheet.URL
	if data.Next == "" {
		data.Next = "/"
	}

	var buf bytes.Buffer

	if err := tmpl.ExecuteTemplate(&buf, "layout.gohtml", data); err != nil {
		h.logger.ErrorContext(
			r.Context(),
			"execute template",
			slog.String("page", page),
			slog.Any("error", err),
		)
		http.Error(w, "internal server error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// These pages carry credentials and session state, so no cache may keep a copy.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, status int, message string) {
	h.render(
		w,
		r,
		status,
		"error.gohtml",
		pageData{Title: http.StatusText(status), Message: message},
	)
}

// renderInternalError hides the cause from the browser and puts it in the log instead.
func (h *Handler) renderInternalError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	message string,
) {
	h.logger.ErrorContext(r.Context(), message, slog.Any("error", err))
	h.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}
