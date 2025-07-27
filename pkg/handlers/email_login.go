package handlers

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
)

// EmailLoginHandler handles the email-based login flow
type EmailLoginHandler struct {
	providerFactory *discovery.ProviderFactory
	template        *template.Template
	redirectURL     *url.URL
	fallbackURL     string
}

// EmailLoginData represents data passed to the email login template
type EmailLoginData struct {
	Error       string
	Email       string
	FallbackURL string
}

// NewEmailLoginHandler creates a new email login handler
func NewEmailLoginHandler(
	providerFactory *discovery.ProviderFactory,
	templateContent string,
	redirectURL *url.URL,
	fallbackURL string,
) (*EmailLoginHandler, error) {
	tmpl, err := template.New("email_login").Parse(templateContent)
	if err != nil {
		return nil, err
	}

	return &EmailLoginHandler{
		providerFactory: providerFactory,
		template:        tmpl,
		redirectURL:     redirectURL,
		fallbackURL:     fallbackURL,
	}, nil
}

// ServeHTTP handles the HTTP request for email login
func (h *EmailLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleGetEmailForm(w, r)
	case http.MethodPost:
		h.handlePostEmailForm(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetEmailForm displays the email input form
func (h *EmailLoginHandler) handleGetEmailForm(w http.ResponseWriter, r *http.Request) {
	data := EmailLoginData{
		FallbackURL: h.fallbackURL,
		Email:       r.URL.Query().Get("email"),
		Error:       r.URL.Query().Get("error"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.template.Execute(w, data); err != nil {
		logger.Errorf("Failed to render email login template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// handlePostEmailForm processes the submitted email and returns provider info
func (h *EmailLoginHandler) handlePostEmailForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, "Invalid form data")
		return
	}

	email := strings.TrimSpace(r.Form.Get("email"))
	if email == "" {
		h.redirectWithError(w, r, "Email address is required")
		return
	}

	// Validate email format
	if err := discovery.ValidateEmail(email); err != nil {
		h.redirectWithError(w, r, "Invalid email address format")
		return
	}

	// Discover provider for email domain
	providerInfo, err := h.providerFactory.GetProviderInfoForEmail(email)
	if err != nil {
		logger.Errorf("Failed to discover provider for email %s: %v", email, err)
		h.redirectWithError(w, r, "Unable to find identity provider for your email domain")
		return
	}

	logger.Printf("Successfully discovered provider for email %s: %s (%s)", 
		email, providerInfo.IssuerURL, providerInfo.ProviderType)

	// Redirect to OAuth start with email parameter for dynamic provider selection
	oauthStartURL := "/oauth2/start"
	params := url.Values{}
	params.Set("email", email)
	
	// Preserve any existing redirect URL
	if rd := r.URL.Query().Get("rd"); rd != "" {
		params.Set("rd", rd)
	}
	
	redirectURL := oauthStartURL + "?" + params.Encode()
	logger.Printf("Redirecting to OAuth start with email parameter: %s", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// redirectWithError redirects back to the email form with an error message
func (h *EmailLoginHandler) redirectWithError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	email := r.Form.Get("email")
	
	params := url.Values{}
	params.Set("error", errorMsg)
	if email != "" {
		params.Set("email", email)
	}
	
	redirectURL := "/oauth2/email-login?" + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// GetProviderInfoForEmail exposes provider discovery for testing
func (h *EmailLoginHandler) GetProviderInfoForEmail(email string) (*discovery.ExtendedProviderInfo, error) {
	return h.providerFactory.GetProviderInfoForEmail(email)
}