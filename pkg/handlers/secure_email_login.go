package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
)

// Context key for request ID
type secureEmailContextKey string

const requestIDKey secureEmailContextKey = "request_id"

// SecureEmailLoginHandler provides a hardened email login handler with security controls
type SecureEmailLoginHandler struct {
	providerFactory  *discovery.ProviderFactory
	template         *template.Template
	fallbackURL      string
	validator        *discovery.SecureEmailValidator
	rateLimiter      *discovery.RateLimiter
	csrf             *CSRFProtection
	allowedRedirects []string
	sessionManager   SessionManager
	auditLogger      AuditLogger
}

// SecureEmailLoginData represents secure data passed to the email login template
type SecureEmailLoginData struct {
	Error       string
	Email       string
	FallbackURL string
	CSRFToken   string
	Timestamp   string
	RequestID   string
}

// SessionManager interface for secure session management
type SessionManager interface {
	GetSessionID(r *http.Request) string
	StoreEmailInSession(sessionID, email string) error
	GetEmailFromSession(sessionID string) (string, error)
	InvalidateSession(sessionID string) error
	CreateSecureSession(w http.ResponseWriter, r *http.Request) (string, error)
}

// AuditLogger interface for security audit logging
type AuditLogger interface {
	LogDiscoveryAttempt(event discovery.AuditEvent)
	LogSecurityViolation(event SecurityViolationEvent)
	LogAuthenticationEvent(event AuthenticationEvent)
}

// SecurityViolationEvent represents a security violation
type SecurityViolationEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	RequestID   string    `json:"request_id"`
	Severity    string    `json:"severity"`
}

// AuthenticationEvent represents an authentication attempt
type AuthenticationEvent struct {
	Timestamp time.Time `json:"timestamp"`
	EmailHash string    `json:"email_hash"`
	Success   bool      `json:"success"`
	Method    string    `json:"method"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	RequestID string    `json:"request_id"`
}

// NewSecureEmailLoginHandler creates a new secure email login handler
func NewSecureEmailLoginHandler(
	providerFactory *discovery.ProviderFactory,
	templateContent string,
	fallbackURL string,
	validator *discovery.SecureEmailValidator,
	rateLimiter *discovery.RateLimiter,
	allowedRedirects []string,
	sessionManager SessionManager,
	auditLogger AuditLogger,
) (*SecureEmailLoginHandler, error) {
	tmpl, err := template.New("secure_email_login").Parse(templateContent)
	if err != nil {
		return nil, err
	}

	csrf, err := NewCSRFProtection()
	if err != nil {
		return nil, err
	}

	return &SecureEmailLoginHandler{
		providerFactory:  providerFactory,
		template:         tmpl,
		fallbackURL:      fallbackURL,
		validator:        validator,
		rateLimiter:      rateLimiter,
		csrf:             csrf,
		allowedRedirects: allowedRedirects,
		sessionManager:   sessionManager,
		auditLogger:      auditLogger,
	}, nil
}

// ServeHTTP handles the HTTP request for secure email login
func (h *SecureEmailLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Generate request ID for audit trail
	requestID := generateRequestID()
	r = r.WithContext(context.WithValue(r.Context(), requestIDKey, requestID))

	// Security headers
	h.setSecurityHeaders(w)

	// Rate limiting check
	clientIP := getClientIP(r)
	if err := h.rateLimiter.CheckRateLimit("email_login", clientIP); err != nil {
		h.logSecurityViolation(r, "rate_limit_exceeded", err.Error(), "medium")
		http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetEmailFormSecure(w, r)
	case http.MethodPost:
		h.handlePostEmailFormSecure(w, r)
	default:
		h.logSecurityViolation(r, "invalid_method", "Unsupported HTTP method: "+r.Method, "low")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetEmailFormSecure handles GET requests with security controls
func (h *SecureEmailLoginHandler) handleGetEmailFormSecure(w http.ResponseWriter, r *http.Request) {
	// Get or create session
	sessionID := h.sessionManager.GetSessionID(r)
	if sessionID == "" {
		var err error
		sessionID, err = h.sessionManager.CreateSecureSession(w, r)
		if err != nil {
			logger.Errorf("Failed to create session: %v", err)
			http.Error(w, "Session creation failed", http.StatusInternalServerError)
			return
		}
	}

	// Generate CSRF token
	csrfToken, err := h.csrf.GenerateToken(sessionID)
	if err != nil {
		logger.Errorf("Failed to generate CSRF token: %v", err)
		http.Error(w, "Security token generation failed", http.StatusInternalServerError)
		return
	}

	// Set CSRF cookie
	h.csrf.SetTokenCookie(w, csrfToken, r.TLS != nil)

	// Prepare template data
	data := SecureEmailLoginData{
		Error:       r.URL.Query().Get("error"),
		Email:       r.URL.Query().Get("email"),
		FallbackURL: h.fallbackURL,
		CSRFToken:   csrfToken,
		Timestamp:   time.Now().Format(time.RFC3339),
		RequestID:   getRequestID(r),
	}

	// Validate and sanitize email parameter
	if data.Email != "" {
		if err := h.validator.ValidateEmail(data.Email); err != nil {
			h.logSecurityViolation(r, "invalid_email_parameter",
				"Invalid email in URL parameter: "+err.Error(), "medium")
			data.Email = "" // Clear invalid email
			data.Error = "Invalid email format"
		}
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.template.Execute(w, data); err != nil {
		logger.Errorf("Template execution failed: %v", err)
		http.Error(w, "Template rendering failed", http.StatusInternalServerError)
	}
}

// handlePostEmailFormSecure handles POST requests with security controls
func (h *SecureEmailLoginHandler) handlePostEmailFormSecure(w http.ResponseWriter, r *http.Request) {
	// Parse form with size limit
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit
	if err := r.ParseForm(); err != nil {
		h.logSecurityViolation(r, "form_parse_error", err.Error(), "medium")
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Get session ID
	sessionID := h.sessionManager.GetSessionID(r)
	if sessionID == "" {
		h.logSecurityViolation(r, "missing_session", "No session found", "high")
		http.Error(w, "Session required", http.StatusUnauthorized)
		return
	}

	// Validate CSRF token
	if err := h.csrf.ValidateRequest(r, sessionID); err != nil {
		h.logSecurityViolation(r, "csrf_validation_failed", err.Error(), "high")
		http.Error(w, "Security validation failed", http.StatusForbidden)
		return
	}

	// Extract and validate email
	email := strings.TrimSpace(r.Form.Get("email"))
	if email == "" {
		h.redirectWithError(w, r, "Email address is required")
		return
	}

	// Comprehensive email validation
	if err := h.validator.ValidateEmail(email); err != nil {
		h.logSecurityViolation(r, "email_validation_failed",
			"Email validation failed for "+discovery.HashEmail(email)+": "+err.Error(), "medium")
		h.redirectWithError(w, r, "Invalid email address format")
		return
	}

	// Audit log the authentication attempt
	h.auditLogger.LogAuthenticationEvent(AuthenticationEvent{
		Timestamp: time.Now(),
		EmailHash: discovery.HashEmail(email),
		Success:   false, // Will be updated based on discovery result
		Method:    "email_discovery",
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: getRequestID(r),
	})

	// Attempt provider discovery
	domain, err := discovery.ExtractDomainFromEmail(email)
	if err != nil {
		h.logSecurityViolation(r, "domain_extraction_failed", err.Error(), "medium")
		h.redirectWithError(w, r, "Invalid email format")
		return
	}

	// Rate limiting for discovery operations
	clientIP := getClientIP(r)
	if err := h.rateLimiter.CheckRateLimit(domain, clientIP); err != nil {
		h.logSecurityViolation(r, "discovery_rate_limit", err.Error(), "medium")
		h.redirectWithError(w, r, "Too many requests. Please try again later.")
		return
	}

	// Discover provider
	providerInfo, err := h.providerFactory.GetProviderInfoForEmail(email)
	if err != nil {
		logger.Printf("Provider discovery failed for email hash %s: %v",
			discovery.HashEmail(email), err)
		h.redirectWithError(w, r, "Unable to find identity provider for your email domain")
		return
	}

	// Store email securely in session (not in URL)
	if err := h.sessionManager.StoreEmailInSession(sessionID, email); err != nil {
		logger.Errorf("Failed to store email in session: %v", err)
		h.redirectWithError(w, r, "Session storage failed")
		return
	}

	// Log successful discovery
	logger.Printf("Successfully discovered provider for email hash %s: %s",
		discovery.HashEmail(email), providerInfo.ProviderType)

	// Validate and prepare redirect URL
	redirectURL := h.validateRedirectURL(r.Form.Get("rd"))

	// Generate OAuth state parameter for CSRF protection
	oauthState, err := h.generateOAuthState(sessionID, email, redirectURL)
	if err != nil {
		logger.Errorf("Failed to generate OAuth state: %v", err)
		h.redirectWithError(w, r, "Authentication state generation failed")
		return
	}

	// Redirect to OAuth start with secure state
	oauthStartURL := "/oauth2/start"
	params := url.Values{}
	params.Set("state", oauthState)
	if redirectURL != "" {
		params.Set("rd", redirectURL)
	}

	finalURL := oauthStartURL + "?" + params.Encode()
	logger.Printf("Redirecting to OAuth start for email hash %s", discovery.HashEmail(email))

	// Update audit log with success
	h.auditLogger.LogAuthenticationEvent(AuthenticationEvent{
		Timestamp: time.Now(),
		EmailHash: discovery.HashEmail(email),
		Success:   true,
		Method:    "email_discovery",
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: getRequestID(r),
	})

	http.Redirect(w, r, finalURL, http.StatusFound)
}

// validateRedirectURL validates and sanitizes redirect URLs
func (h *SecureEmailLoginHandler) validateRedirectURL(rd string) string {
	if rd == "" {
		return ""
	}

	// Parse URL
	parsedURL, err := url.Parse(rd)
	if err != nil {
		return ""
	}

	// Only allow relative URLs or whitelisted absolute URLs
	if parsedURL.IsAbs() {
		// Check against allowlist
		for _, allowed := range h.allowedRedirects {
			if parsedURL.Host == allowed {
				return rd
			}
		}
		return "" // Reject unlisted absolute URLs
	}

	// Validate relative URL
	if strings.HasPrefix(rd, "//") || strings.Contains(rd, "..") ||
		strings.Contains(rd, "\\") || strings.Contains(rd, "\n") ||
		strings.Contains(rd, "\r") {
		return ""
	}

	return rd
}

// generateOAuthState creates a secure OAuth state parameter with provider info
func (h *SecureEmailLoginHandler) generateOAuthState(sessionID, email, redirectURL string) (string, error) {
	// Get provider info for the email domain
	providerInfo, err := h.providerFactory.GetProviderInfoForEmail(email)
	if err != nil {
		return "", err
	}

	// Create state object with provider information
	stateData := map[string]interface{}{
		"session_id":    sessionID,
		"email_hash":    discovery.HashEmail(email),
		"provider_type": providerInfo.ProviderType,
		"issuer_url":    providerInfo.IssuerURL,
		"redirect_url":  redirectURL,
		"timestamp":     time.Now().Unix(),
	}

	// Encode as JSON
	jsonData, err := json.Marshal(stateData)
	if err != nil {
		return "", err
	}

	// Base64 encode for URL safety
	return base64.URLEncoding.EncodeToString(jsonData), nil
}

// redirectWithError redirects back to the form with an error message
func (h *SecureEmailLoginHandler) redirectWithError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	params := url.Values{}
	params.Set("error", errorMsg)

	if email := r.Form.Get("email"); email != "" {
		// Only include email if it passed basic validation
		if err := h.validator.ValidateEmail(email); err == nil {
			params.Set("email", email)
		}
	}

	redirectURL := "/oauth2/email-login?" + params.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// setSecurityHeaders sets security-related HTTP headers
func (h *SecureEmailLoginHandler) setSecurityHeaders(w http.ResponseWriter) {
	headers := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self';",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Cache-Control":             "no-cache, no-store, must-revalidate, max-age=0",
		"Pragma":                    "no-cache",
		"Expires":                   "Thu, 01 Jan 1970 00:00:00 GMT",
	}

	for header, value := range headers {
		w.Header().Set(header, value)
	}
}

// logSecurityViolation logs security violations for monitoring
func (h *SecureEmailLoginHandler) logSecurityViolation(r *http.Request, violationType, description, severity string) {
	event := SecurityViolationEvent{
		Timestamp:   time.Now(),
		Type:        violationType,
		Description: description,
		IPAddress:   getClientIP(r),
		UserAgent:   r.UserAgent(),
		RequestID:   getRequestID(r),
		Severity:    severity,
	}

	h.auditLogger.LogSecurityViolation(event)
	logger.Errorf("Security violation [%s]: %s from %s", violationType, description, event.IPAddress)
}

// Utility functions

// getClientIP extracts the real client IP address
func getClientIP(r *http.Request) string {
	// Check various headers for real IP
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// Take the first IP in the chain
		if idx := strings.Index(ip, ","); idx != -1 {
			ip = ip[:idx]
		}
		return strings.TrimSpace(ip)
	}

	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}

	if ip := r.Header.Get("X-Client-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}

	// Fallback to remote address
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

// generateRequestID creates a unique request ID for audit trail
func generateRequestID() string {
	// Implement secure random ID generation
	return "req_placeholder_" + time.Now().Format("20060102150405")
}

// getRequestID retrieves request ID from context
func getRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey).(string); ok {
		return id
	}
	return "unknown"
}
