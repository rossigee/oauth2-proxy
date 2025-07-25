package discovery

import (
	"testing"
)

func TestProviderFactory(t *testing.T) {
	// Create test configuration
	config := DiscoveryConfig{
		Methods: []DiscoveryMethod{MethodConfig},
		DomainMaps: []DomainProviderConfig{
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

	// Create fallback info
	fallbackInfo := &ExtendedProviderInfo{
		ProviderInfo: &ProviderInfo{
			IssuerURL:    "https://fallback.example.com",
			ProviderType: "oidc",
			ClientID:     "fallback-client",
		},
		ClientSecret: "fallback-secret",
		Scope:        "openid email profile",
	}

	factory := NewProviderFactory(config, fallbackInfo)

	t.Run("get provider info for configured email", func(t *testing.T) {
		info, err := factory.GetProviderInfoForEmail("user@test.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.IssuerURL != "https://auth.test.com" {
			t.Errorf("Expected issuer https://auth.test.com, got: %s", info.IssuerURL)
		}

		if info.ProviderType != "oidc" {
			t.Errorf("Expected type oidc, got: %s", info.ProviderType)
		}

		if info.ClientID != "test-client" {
			t.Errorf("Expected client ID test-client, got: %s", info.ClientID)
		}

		// Should inherit fallback values
		if info.ClientSecret != "fallback-secret" {
			t.Errorf("Expected client secret fallback-secret, got: %s", info.ClientSecret)
		}

		if info.Scope != "openid email profile" {
			t.Errorf("Expected scope 'openid email profile', got: %s", info.Scope)
		}
	})

	t.Run("get provider info for unknown email uses fallback", func(t *testing.T) {
		info, err := factory.GetProviderInfoForEmail("user@unknown.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.IssuerURL != "https://fallback.example.com" {
			t.Errorf("Expected fallback issuer, got: %s", info.IssuerURL)
		}

		if info.ClientID != "fallback-client" {
			t.Errorf("Expected fallback client ID, got: %s", info.ClientID)
		}
	})

	t.Run("get provider info for domain", func(t *testing.T) {
		info, err := factory.GetProviderInfoForDomain("test.com")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.IssuerURL != "https://auth.test.com" {
			t.Errorf("Expected issuer https://auth.test.com, got: %s", info.IssuerURL)
		}
	})

	t.Run("invalid email format", func(t *testing.T) {
		_, err := factory.GetProviderInfoForEmail("invalid-email")
		if err == nil {
			t.Errorf("Expected error for invalid email")
		}
	})

	t.Run("get configured domains", func(t *testing.T) {
		domains := factory.GetConfiguredDomains()
		if len(domains) != 1 {
			t.Errorf("Expected 1 configured domain, got: %d", len(domains))
		}

		if domains[0] != "test.com" {
			t.Errorf("Expected domain test.com, got: %s", domains[0])
		}
	})

	t.Run("has configured domain", func(t *testing.T) {
		if !factory.HasConfiguredDomain("test.com") {
			t.Errorf("Expected test.com to be configured")
		}

		if factory.HasConfiguredDomain("unknown.com") {
			t.Errorf("Expected unknown.com to not be configured")
		}
	})

	t.Run("add configured provider", func(t *testing.T) {
		newInfo := &ProviderInfo{
			IssuerURL:    "https://new.example.com",
			ProviderType: "oidc",
			ClientID:     "new-client",
		}

		err := factory.AddConfiguredProvider("new.example.com", newInfo)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// Verify it was added
		if !factory.HasConfiguredDomain("new.example.com") {
			t.Errorf("Expected new.example.com to be configured after adding")
		}

		// Test retrieval
		info, err := factory.GetProviderInfoForDomain("new.example.com")
		if err != nil {
			t.Fatalf("Expected no error retrieving added domain, got: %v", err)
		}

		if info.IssuerURL != "https://new.example.com" {
			t.Errorf("Expected issuer https://new.example.com, got: %s", info.IssuerURL)
		}
	})
}

func TestProviderFactoryWithoutFallback(t *testing.T) {
	config := DiscoveryConfig{
		Methods:          []DiscoveryMethod{MethodConfig},
		DomainMaps:       []DomainProviderConfig{},
		DNSEnabled:       false,
		WellKnownEnabled: false,
	}

	factory := NewProviderFactory(config, nil)

	t.Run("unknown domain without fallback", func(t *testing.T) {
		_, err := factory.GetProviderInfoForEmail("user@unknown.com")
		if err == nil {
			t.Errorf("Expected error for unknown domain without fallback")
		}
	})
}

func TestExtendedProviderInfo(t *testing.T) {
	t.Run("extended provider info composition", func(t *testing.T) {
		baseInfo := &ProviderInfo{
			IssuerURL:    "https://test.example.com",
			ProviderType: "oidc",
			ClientID:     "test-client",
		}

		extendedInfo := &ExtendedProviderInfo{
			ProviderInfo:     baseInfo,
			ClientSecret:     "test-secret",
			ClientSecretFile: "/path/to/secret",
			Scope:            "openid email profile groups",
		}

		// Test that all fields are accessible
		if extendedInfo.IssuerURL != "https://test.example.com" {
			t.Errorf("Expected issuer from embedded struct")
		}

		if extendedInfo.ClientSecret != "test-secret" {
			t.Errorf("Expected client secret test-secret, got: %s", extendedInfo.ClientSecret)
		}

		if extendedInfo.ClientSecretFile != "/path/to/secret" {
			t.Errorf("Expected client secret file /path/to/secret, got: %s", extendedInfo.ClientSecretFile)
		}

		if extendedInfo.Scope != "openid email profile groups" {
			t.Errorf("Expected scope 'openid email profile groups', got: %s", extendedInfo.Scope)
		}
	})
}