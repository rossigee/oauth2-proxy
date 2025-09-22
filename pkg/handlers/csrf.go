package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	CSRFTokenName    = "csrf_token"
	CSRFCookieName   = "_oauth2_proxy_csrf"
	CSRFTokenMaxAge  = 15 * time.Minute
	CSRFCookieMaxAge = 15 * time.Minute
)

// CSRFProtection provides CSRF protection for forms
type CSRFProtection struct {
	secret     []byte
	cookieName string
	tokenName  string
	maxAge     time.Duration
}

// NewCSRFProtection creates a new CSRF protection instance
func NewCSRFProtection() (*CSRFProtection, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate CSRF secret: %v", err)
	}

	return &CSRFProtection{
		secret:     secret,
		cookieName: CSRFCookieName,
		tokenName:  CSRFTokenName,
		maxAge:     CSRFTokenMaxAge,
	}, nil
}

// GenerateToken generates a CSRF token for the given session
func (c *CSRFProtection) GenerateToken(sessionID string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("session ID cannot be empty")
	}

	// Create timestamp-based token
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", sessionID, timestamp)

	// Create HMAC signature
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	// Combine timestamp and signature
	token := fmt.Sprintf("%d:%s", timestamp, base64.URLEncoding.EncodeToString(signature))
	return base64.URLEncoding.EncodeToString([]byte(token)), nil
}

// ValidateToken validates a CSRF token for the given session
func (c *CSRFProtection) ValidateToken(token, sessionID string) error {
	if token == "" {
		return fmt.Errorf("CSRF token is required")
	}

	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	// Decode the token
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("invalid CSRF token encoding: %v", err)
	}

	// Split timestamp and signature
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid CSRF token format")
	}

	// Parse timestamp
	timestamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid CSRF token timestamp: %v", err)
	}

	// Check token age
	tokenAge := time.Now().Unix() - timestamp
	if tokenAge > int64(c.maxAge.Seconds()) {
		return fmt.Errorf("CSRF token has expired")
	}

	if tokenAge < 0 {
		return fmt.Errorf("CSRF token timestamp is in the future")
	}

	// Decode signature
	signature, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid CSRF token signature encoding: %v", err)
	}

	// Validate signature
	message := fmt.Sprintf("%s:%d", sessionID, timestamp)
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(message))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return fmt.Errorf("CSRF token signature validation failed")
	}

	return nil
}

// SetTokenCookie sets a CSRF token as a secure cookie
func (c *CSRFProtection) SetTokenCookie(w http.ResponseWriter, token string, secure bool) {
	cookie := &http.Cookie{
		Name:     c.cookieName,
		Value:    token,
		MaxAge:   int(CSRFCookieMaxAge.Seconds()),
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, cookie)
}

// GetTokenFromCookie retrieves CSRF token from cookie
func (c *CSRFProtection) GetTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ValidateRequest validates CSRF token from request
func (c *CSRFProtection) ValidateRequest(r *http.Request, sessionID string) error {
	// Get token from form or header
	token := r.FormValue(c.tokenName)
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
		token = c.GetTokenFromCookie(r)
	}

	if token == "" {
		return fmt.Errorf("CSRF token not found in request")
	}

	return c.ValidateToken(token, sessionID)
}

// CSRFMiddleware provides CSRF protection middleware
type CSRFMiddleware struct {
	csrf        *CSRFProtection
	exemptPaths []string
}

// NewCSRFMiddleware creates a new CSRF middleware
func NewCSRFMiddleware(exemptPaths []string) (*CSRFMiddleware, error) {
	csrf, err := NewCSRFProtection()
	if err != nil {
		return nil, err
	}

	return &CSRFMiddleware{
		csrf:        csrf,
		exemptPaths: exemptPaths,
	}, nil
}

// Handler returns HTTP middleware function
func (m *CSRFMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path is exempt from CSRF protection
		if m.isExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Get session ID (implement based on your session management)
		sessionID := m.getSessionID(r)
		if sessionID == "" {
			http.Error(w, "Session required", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Generate and set CSRF token for safe methods
			token, err := m.csrf.GenerateToken(sessionID)
			if err != nil {
				http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
				return
			}

			m.csrf.SetTokenCookie(w, token, r.TLS != nil)

			// Add token to request context for template use
			r = r.WithContext(WithCSRFToken(r.Context(), token))

		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			// Validate CSRF token for unsafe methods
			if err := m.csrf.ValidateRequest(r, sessionID); err != nil {
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isExemptPath checks if a path is exempt from CSRF protection
func (m *CSRFMiddleware) isExemptPath(path string) bool {
	for _, exempt := range m.exemptPaths {
		if strings.HasPrefix(path, exempt) {
			return true
		}
	}
	return false
}

// getSessionID extracts session ID from request
func (m *CSRFMiddleware) getSessionID(r *http.Request) string {
	// This is a placeholder - implement based on your session management
	// For example, extract from session cookie or JWT token
	cookie, err := r.Cookie("_oauth2_proxy")
	if err != nil {
		return ""
	}

	// In a real implementation, you would decrypt/decode the session
	// and extract the session ID. For now, we use the cookie value as ID.
	return cookie.Value
}

// Context helpers for CSRF tokens
type contextKey string

const csrfTokenKey contextKey = "csrf_token"

// WithCSRFToken adds CSRF token to request context
func WithCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfTokenKey, token)
}

// GetCSRFToken retrieves CSRF token from request context
func GetCSRFToken(ctx context.Context) string {
	if token, ok := ctx.Value(csrfTokenKey).(string); ok {
		return token
	}
	return ""
}

// Utility functions for template use
func GetCSRFTokenFromRequest(r *http.Request) string {
	return GetCSRFToken(r.Context())
}

// CSRFTokenHTML returns HTML input field for CSRF token
func CSRFTokenHTML(token string) string {
	if token == "" {
		return ""
	}
	return fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, CSRFTokenName, token)
}
