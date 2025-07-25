package discovery

import (
	"testing"
)

func TestUnifiedDiscovery(t *testing.T) {
	// Create test configuration with static mappings
	config := DiscoveryConfig{
		Methods: []DiscoveryMethod{MethodConfig, MethodDNS},
		DomainMaps: []DomainProviderConfig{
			{
				Domain:       "example.com",
				IssuerURL:    "https://auth.example.com",
				ProviderType: "oidc",
				ClientID:     "test-client",
			},
			{
				Domain:       "google.com",
				IssuerURL:    "https://accounts.google.com",
				ProviderType: "google",
				ClientID:     "google-client",
			},
		},
		DNSEnabled:       true,
		WellKnownEnabled: false,
	}
	
	discovery := NewUnifiedDiscovery(config)
	
	t.Run("discover configured domain", func(t *testing.T) {
		info, err := discovery.DiscoverProvider("example.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		
		if info.IssuerURL != "https://auth.example.com" {
			t.Errorf("Expected issuer https://auth.example.com, got: %s", info.IssuerURL)
		}
		
		if info.ProviderType != "oidc" {
			t.Errorf("Expected type oidc, got: %s", info.ProviderType)
		}
		
		if info.ClientID != "test-client" {
			t.Errorf("Expected client ID test-client, got: %s", info.ClientID)
		}
	})
	
	t.Run("discover google domain", func(t *testing.T) {
		info, err := discovery.DiscoverProvider("google.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		
		if info.IssuerURL != "https://accounts.google.com" {
			t.Errorf("Expected issuer https://accounts.google.com, got: %s", info.IssuerURL)
		}
		
		if info.ProviderType != "google" {
			t.Errorf("Expected type google, got: %s", info.ProviderType)
		}
	})
	
	t.Run("discover from email", func(t *testing.T) {
		info, err := discovery.DiscoverProviderFromEmail("user@example.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		
		if info.IssuerURL != "https://auth.example.com" {
			t.Errorf("Expected issuer https://auth.example.com, got: %s", info.IssuerURL)
		}
	})
	
	t.Run("unknown domain", func(t *testing.T) {
		_, err := discovery.DiscoverProvider("unknown.com")
		if err == nil {
			t.Errorf("Expected error for unknown domain")
		}
	})
	
	t.Run("invalid email", func(t *testing.T) {
		_, err := discovery.DiscoverProviderFromEmail("invalid-email")
		if err == nil {
			t.Errorf("Expected error for invalid email")
		}
	})
}

func TestConfigDiscovery(t *testing.T) {
	configs := []DomainProviderConfig{
		{
			Domain:       "test.com",
			IssuerURL:    "https://auth.test.com",
			ProviderType: "oidc",
			ClientID:     "test-client",
		},
		{
			Domain:       "CAPS.COM", // Test case insensitivity
			IssuerURL:    "https://auth.caps.com",
			ProviderType: "oidc",
			ClientID:     "caps-client",
		},
	}
	
	discovery := NewConfigDiscovery(configs)
	
	t.Run("discover configured domain", func(t *testing.T) {
		info, err := discovery.DiscoverProvider("test.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		
		if info.IssuerURL != "https://auth.test.com" {
			t.Errorf("Expected issuer https://auth.test.com, got: %s", info.IssuerURL)
		}
	})
	
	t.Run("case insensitive lookup", func(t *testing.T) {
		info, err := discovery.DiscoverProvider("caps.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		
		if info.ClientID != "caps-client" {
			t.Errorf("Expected client ID caps-client, got: %s", info.ClientID)
		}
	})
	
	t.Run("domain not found", func(t *testing.T) {
		_, err := discovery.DiscoverProvider("notfound.com")
		if err == nil {
			t.Errorf("Expected error for domain not found")
		}
	})
	
	t.Run("add and remove domains", func(t *testing.T) {
		// Add a new domain
		newInfo := &ProviderInfo{
			IssuerURL:    "https://new.example.com",
			ProviderType: "oidc",
			ClientID:     "new-client",
		}
		discovery.AddDomainProvider("new.example.com", newInfo)
		
		// Verify it was added
		info, err := discovery.DiscoverProvider("new.example.com")
		if err != nil {
			t.Fatalf("Expected no error after adding domain, got: %v", err)
		}
		
		if info.IssuerURL != "https://new.example.com" {
			t.Errorf("Expected issuer https://new.example.com, got: %s", info.IssuerURL)
		}
		
		// Remove the domain
		discovery.RemoveDomainProvider("new.example.com")
		
		// Verify it was removed
		_, err = discovery.DiscoverProvider("new.example.com")
		if err == nil {
			t.Errorf("Expected error after removing domain")
		}
	})
	
	t.Run("get configured domains", func(t *testing.T) {
		domains := discovery.GetConfiguredDomains()
		if len(domains) < 2 {
			t.Errorf("Expected at least 2 configured domains, got: %d", len(domains))
		}
		
		// Check if our test domains are present
		foundTest := false
		foundCaps := false
		for _, domain := range domains {
			if domain == "test.com" {
				foundTest = true
			}
			if domain == "caps.com" {
				foundCaps = true
			}
		}
		
		if !foundTest {
			t.Errorf("Expected to find test.com in configured domains")
		}
		
		if !foundCaps {
			t.Errorf("Expected to find caps.com in configured domains")
		}
	})
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		expectError bool
	}{
		{
			name:        "valid email",
			email:       "user@example.com",
			expectError: false,
		},
		{
			name:        "valid email with subdomain",
			email:       "admin@mail.company.co.uk",
			expectError: false,
		},
		{
			name:        "empty email",
			email:       "",
			expectError: true,
		},
		{
			name:        "invalid email format",
			email:       "not-an-email",
			expectError: true,
		},
		{
			name:        "email with invalid domain",
			email:       "user@invalid-domain",
			expectError: true,
		},
		{
			name:        "email with special characters in domain",
			email:       "user@domain!.com",
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			
			if tt.expectError && err == nil {
				t.Errorf("Expected error for email %s, but got none", tt.email)
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for email %s, but got: %v", tt.email, err)
			}
		})
	}
}