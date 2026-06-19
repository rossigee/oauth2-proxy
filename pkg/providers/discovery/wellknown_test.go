package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWellKnownDiscovery(t *testing.T) {
	// Create test server for well-known responses
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth2-proxy-oidc":
			response := WellKnownResponse{
				IssuerURL:    "https://auth.testserver.com",
				ProviderType: "oidc",
				ClientID:     "test-client",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		case "/minimal/.well-known/oauth2-proxy-oidc":
			response := WellKnownResponse{
				IssuerURL: "https://auth.minimal.com",
				// No type or client_id - should default
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		case "/invalid/.well-known/oauth2-proxy-oidc":
			w.WriteHeader(http.StatusNotFound)
		case "/malformed/.well-known/oauth2-proxy-oidc":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{invalid json`))
		case "/empty/.well-known/oauth2-proxy-oidc":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(WellKnownResponse{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer testServer.Close()

	discovery := NewWellKnownDiscovery()

	// Extract domain from test server URL for testing
	// We'll mock the domain lookup by modifying the test
	t.Run("successful discovery", func(t *testing.T) {
		// We need to test the fetchProviderInfo method directly since
		// DiscoverProvider tries both HTTPS and HTTP with domain prefixes
		url := testServer.URL + "/.well-known/oauth2-proxy-oidc"
		info, err := discovery.fetchProviderInfo(url)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.IssuerURL != "https://auth.testserver.com" {
			t.Errorf("Expected issuer https://auth.testserver.com, got: %s", info.IssuerURL)
		}

		if info.ProviderType != "oidc" {
			t.Errorf("Expected type oidc, got: %s", info.ProviderType)
		}

		if info.ClientID != "test-client" {
			t.Errorf("Expected client ID test-client, got: %s", info.ClientID)
		}
	})

	t.Run("minimal response with defaults", func(t *testing.T) {
		url := testServer.URL + "/minimal/.well-known/oauth2-proxy-oidc"
		info, err := discovery.fetchProviderInfo(url)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.IssuerURL != "https://auth.minimal.com" {
			t.Errorf("Expected issuer https://auth.minimal.com, got: %s", info.IssuerURL)
		}

		if info.ProviderType != "oidc" {
			t.Errorf("Expected default type oidc, got: %s", info.ProviderType)
		}
	})

	t.Run("not found response", func(t *testing.T) {
		url := testServer.URL + "/invalid/.well-known/oauth2-proxy-oidc"
		_, err := discovery.fetchProviderInfo(url)
		if err == nil {
			t.Errorf("Expected error for 404 response")
		}
	})

	t.Run("malformed json response", func(t *testing.T) {
		url := testServer.URL + "/malformed/.well-known/oauth2-proxy-oidc"
		_, err := discovery.fetchProviderInfo(url)
		if err == nil {
			t.Errorf("Expected error for malformed JSON")
		}
	})

	t.Run("empty issuer response", func(t *testing.T) {
		url := testServer.URL + "/empty/.well-known/oauth2-proxy-oidc"
		_, err := discovery.fetchProviderInfo(url)
		if err == nil {
			t.Errorf("Expected error for empty issuer")
		}
	})

	t.Run("timeout configuration", func(t *testing.T) {
		shortTimeout := NewWellKnownDiscoveryWithTimeout(1 * time.Millisecond)
		if shortTimeout.timeout != 1*time.Millisecond {
			t.Errorf("Expected timeout 1ms, got: %v", shortTimeout.timeout)
		}

		if shortTimeout.httpClient.Timeout != 1*time.Millisecond {
			t.Errorf("Expected HTTP client timeout 1ms, got: %v", shortTimeout.httpClient.Timeout)
		}
	})

	t.Run("custom http client", func(t *testing.T) {
		customClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		discovery.SetHTTPClient(customClient)
		if discovery.httpClient != customClient {
			t.Errorf("Expected custom HTTP client to be set")
		}
	})

	t.Run("set timeout", func(t *testing.T) {
		newTimeout := 3 * time.Second
		discovery.SetTimeout(newTimeout)

		if discovery.timeout != newTimeout {
			t.Errorf("Expected timeout %v, got: %v", newTimeout, discovery.timeout)
		}

		if discovery.httpClient.Timeout != newTimeout {
			t.Errorf("Expected HTTP client timeout %v, got: %v", newTimeout, discovery.httpClient.Timeout)
		}
	})
}

func TestWellKnownDiscoveryIntegration(t *testing.T) {
	// This test would normally test actual HTTP requests, but we'll skip
	// external network calls in unit tests
	t.Run("discover unknown domain", func(t *testing.T) {
		discovery := NewWellKnownDiscovery()

		// This should fail for a non-existent domain
		_, err := discovery.DiscoverProvider("nonexistent-domain-for-testing.invalid")
		if err == nil {
			t.Errorf("Expected error for non-existent domain")
		}
	})
}
