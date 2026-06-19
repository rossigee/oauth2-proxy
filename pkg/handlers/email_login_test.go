package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
)

func createTestFactory() *discovery.ProviderFactory {
	config := discovery.DiscoveryConfig{
		Methods: []discovery.DiscoveryMethod{discovery.MethodConfig},
		DomainMaps: []discovery.DomainProviderConfig{
			{
				Domain:       "test.com",
				IssuerURL:    "https://auth.test.com",
				ProviderType: "oidc",
				ClientID:     "test-client",
			},
		},
		DNSEnabled:       false,
		WellKnownEnabled: false,
	}

	fallbackInfo := &discovery.ExtendedProviderInfo{
		ProviderInfo: &discovery.ProviderInfo{
			IssuerURL:    "https://fallback.example.com",
			ProviderType: "oidc",
			ClientID:     "fallback-client",
		},
		ClientSecret: "fallback-secret",
		Scope:        "openid email profile",
	}

	return discovery.NewProviderFactory(config, fallbackInfo)
}

func TestEmailLoginHandler(t *testing.T) {
	factory := createTestFactory()

	template := `<html><body>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		<form method="post">
			<input type="email" name="email" value="{{.Email}}" required>
			<button type="submit">Continue</button>
		</form>
		{{if .FallbackURL}}<a href="{{.FallbackURL}}">Fallback</a>{{end}}
	</body></html>`

	redirectURL, _ := url.Parse("https://oauth2-proxy.example.com/oauth2/callback")
	fallbackURL := "/oauth2/sign_in"

	handler, err := NewEmailLoginHandler(factory, template, redirectURL, fallbackURL)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	t.Run("GET request displays form", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/oauth2/email-login", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, `<form method="post">`) {
			t.Errorf("Expected form in response body")
		}

		if !strings.Contains(body, `<input type="email" name="email"`) {
			t.Errorf("Expected email input in response body")
		}
	})

	t.Run("GET request with error parameter", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/oauth2/email-login?error=Test+error&email=user@test.com", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Test error") {
			t.Errorf("Expected error message in response body")
		}

		if !strings.Contains(body, `value="user@test.com"`) {
			t.Errorf("Expected email value to be preserved")
		}
	})

	t.Run("POST request with valid email", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", "user@test.com")

		req := httptest.NewRequest("POST", "/oauth2/email-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got: %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "/oauth2/start") {
			t.Errorf("Expected redirect to OAuth start URL, got: %s", location)
		}

		if !strings.Contains(location, "email=user%40test.com") {
			t.Errorf("Expected email parameter in redirect URL, got: %s", location)
		}
	})

	t.Run("POST request with empty email", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", "")

		req := httptest.NewRequest("POST", "/oauth2/email-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got: %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "error=Email+address+is+required") {
			t.Errorf("Expected error message in redirect URL: %s", location)
		}
	})

	t.Run("POST request with invalid email", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", "invalid-email")

		req := httptest.NewRequest("POST", "/oauth2/email-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got: %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "error=Invalid+email+address+format") {
			t.Errorf("Expected validation error in redirect URL: %s", location)
		}
	})

	t.Run("POST request with unknown domain uses fallback", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", "user@unknown.com")

		req := httptest.NewRequest("POST", "/oauth2/email-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got: %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "/oauth2/start") {
			t.Errorf("Expected redirect to OAuth start URL, got: %s", location)
		}

		if !strings.Contains(location, "email=user%40unknown.com") {
			t.Errorf("Expected email parameter in redirect URL, got: %s", location)
		}
	})

	t.Run("invalid HTTP method", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/oauth2/email-login", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got: %d", w.Code)
		}
	})

	t.Run("POST request with malformed form data", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/oauth2/email-login", strings.NewReader("%invalid%form%data"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got: %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "error=Invalid+form+data") {
			t.Errorf("Expected form data error in redirect URL: %s", location)
		}
	})

	t.Run("get provider info for email method", func(t *testing.T) {
		info, err := handler.GetProviderInfoForEmail("user@test.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.IssuerURL != "https://auth.test.com" {
			t.Errorf("Expected issuer https://auth.test.com, got: %s", info.IssuerURL)
		}
	})
}

func TestEmailLoginHandlerTemplateError(t *testing.T) {
	factory := createTestFactory()

	// Invalid template syntax
	invalidTemplate := `<html><body>{{.InvalidSyntax</body></html>`

	redirectURL, _ := url.Parse("https://oauth2-proxy.example.com/oauth2/callback")
	fallbackURL := "/oauth2/sign_in"

	_, err := NewEmailLoginHandler(factory, invalidTemplate, redirectURL, fallbackURL)
	if err == nil {
		t.Errorf("Expected error for invalid template")
	}
}

func TestEmailLoginHandlerFactoryError(t *testing.T) {
	// Create factory that will fail for all domains
	config := discovery.DiscoveryConfig{
		Methods:          []discovery.DiscoveryMethod{discovery.MethodConfig},
		DomainMaps:       []discovery.DomainProviderConfig{}, // No mappings
		DNSEnabled:       false,
		WellKnownEnabled: false,
	}

	factory := discovery.NewProviderFactory(config, nil) // No fallback

	template := `<html><body><form method="post"><input type="email" name="email" required><button type="submit">Continue</button></form></body></html>`
	redirectURL, _ := url.Parse("https://oauth2-proxy.example.com/oauth2/callback")
	fallbackURL := "/oauth2/sign_in"

	handler, err := NewEmailLoginHandler(factory, template, redirectURL, fallbackURL)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	t.Run("POST request with email that fails discovery", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", "user@unknown.com")

		req := httptest.NewRequest("POST", "/oauth2/email-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status 302 (redirect), got: %d", w.Code)
		}

		location := w.Header().Get("Location")
		if !strings.Contains(location, "error=Unable+to+find+identity+provider") {
			t.Errorf("Expected provider discovery error in redirect URL: %s", location)
		}
	})
}
