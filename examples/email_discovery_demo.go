package main

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
)

func main() {
	fmt.Println("OAuth2-Proxy Email-Domain Discovery Demo")
	fmt.Println("========================================")

	// Configure discovery with some example domain mappings
	config := discovery.DiscoveryConfig{
		Methods: []discovery.DiscoveryMethod{
			discovery.MethodConfig,
			discovery.MethodDNS,
			discovery.MethodWellKnown,
		},
		DomainMaps: []discovery.DomainProviderConfig{
			{
				Domain:       "gmail.com",
				IssuerURL:    "https://accounts.google.com",
				ProviderType: "google",
				ClientID:     "demo-gmail-client",
			},
			{
				Domain:       "github.com",
				IssuerURL:    "https://github.com/login/oauth/authorize",
				ProviderType: "github",
				ClientID:     "demo-github-client",
			},
			{
				Domain:       "company.example",
				IssuerURL:    "https://auth.company.example",
				ProviderType: "oidc",
				ClientID:     "demo-company-client",
			},
		},
		DNSEnabled:       true,
		WellKnownEnabled: true,
	}

	// Create discovery system
	discoverySystem := discovery.NewUnifiedDiscovery(config)

	// Test emails
	testEmails := []string{
		"user@gmail.com",
		"developer@github.com",
		"employee@company.example",
		"unknown@random.com",
		"invalid-email",
	}

	fmt.Println("\nTesting email-domain discovery:")
	fmt.Println("-------------------------------")

	for _, email := range testEmails {
		fmt.Printf("\nEmail: %s\n", email)

		// Validate email first
		if err := discovery.ValidateEmail(email); err != nil {
			fmt.Printf("  ❌ Invalid email: %v\n", err)
			continue
		}

		// Try to discover provider
		providerInfo, err := discoverySystem.DiscoverProviderFromEmail(email)
		if err != nil {
			fmt.Printf("  ❌ Discovery failed: %v\n", err)
			continue
		}

		fmt.Printf("  ✅ Discovery successful!\n")
		fmt.Printf("     Issuer URL: %s\n", providerInfo.IssuerURL)
		fmt.Printf("     Provider Type: %s\n", providerInfo.ProviderType)
		if providerInfo.ClientID != "" {
			fmt.Printf("     Client ID: %s\n", providerInfo.ClientID)
		}
	}

	// Test domain extraction
	fmt.Println("\n\nTesting domain extraction:")
	fmt.Println("--------------------------")

	extractionTests := []string{
		"user@example.com",
		"admin@mail.company.co.uk",
		"test@subdomain.example.org",
		"invalid@",
		"@domain.com",
		"no-at-sign",
	}

	for _, email := range extractionTests {
		fmt.Printf("\nEmail: %s\n", email)
		domain, err := discovery.ExtractDomainFromEmail(email)
		if err != nil {
			fmt.Printf("  ❌ Error: %v\n", err)
		} else {
			fmt.Printf("  ✅ Domain: %s\n", domain)
		}
	}

	// Test provider factory
	fmt.Println("\n\nTesting provider factory:")
	fmt.Println("-------------------------")

	// Create fallback provider info
	fallbackInfo := &discovery.ExtendedProviderInfo{
		ProviderInfo: &discovery.ProviderInfo{
			IssuerURL:    "https://fallback.example.com",
			ProviderType: "oidc",
			ClientID:     "fallback-client-id",
		},
		ClientSecret: "fallback-secret",
		Scope:        "openid email profile",
	}

	factory := discovery.NewProviderFactory(config, fallbackInfo)

	factoryTestEmails := []string{
		"user@gmail.com",
		"unknown@missing.domain",
	}

	for _, email := range factoryTestEmails {
		fmt.Printf("\nEmail: %s\n", email)
		providerInfo, err := factory.GetProviderInfoForEmail(email)
		if err != nil {
			fmt.Printf("  ❌ Factory error: %v\n", err)
			continue
		}

		fmt.Printf("  ✅ Provider info retrieved!\n")
		fmt.Printf("     Issuer URL: %s\n", providerInfo.IssuerURL)
		fmt.Printf("     Provider Type: %s\n", providerInfo.ProviderType)
		fmt.Printf("     Client ID: %s\n", providerInfo.ClientID)
		if providerInfo.Scope != "" {
			fmt.Printf("     Scope: %s\n", providerInfo.Scope)
		}
	}

	fmt.Println("\n\nDemo completed!")
	fmt.Println("================")
	fmt.Println("\nTo set up DNS discovery for your domain, add a TXT record like:")
	fmt.Println("_oidc.yourdomain.com TXT \"issuer=https://auth.yourdomain.com;type=oidc\"")
	fmt.Println("\nTo set up HTTP well-known discovery, serve a JSON file at:")
	fmt.Println("https://yourdomain.com/.well-known/oauth2-proxy-oidc")
	fmt.Println("with content like:")
	fmt.Println(`{
  "issuer": "https://auth.yourdomain.com",
  "type": "oidc"
}`)
}
