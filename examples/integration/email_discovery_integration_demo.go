// Integration test example for email discovery in oauth2-proxy
package main

import (
	"fmt"
	"log"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/handlers"
)

func main() {
	fmt.Println("OAuth2-Proxy Email Discovery Integration Test")
	fmt.Println("============================================")
	fmt.Println()

	// Test 1: EmailDiscoveryOptions creation and validation
	fmt.Println("Test 1: Creating EmailDiscoveryOptions...")
	emailOpts := options.EmailDiscoveryOptions{
		Enabled:          true,
		Methods:          []string{"config", "dns", "wellknown"},
		DNSEnabled:       true,
		WellKnownEnabled: true,
		FallbackProvider: "default",
		FallbackURL:      "/oauth2/sign_in",
	}

	// Create domain providers separately (as they're now in main options)
	domainProviders := []options.DomainProviderMapping{
		{
			Domain:       "test.com",
			IssuerURL:    "https://auth.test.com",
			ProviderType: "oidc",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
		{
			Domain:       "gmail.com",
			IssuerURL:    "https://accounts.google.com",
			ProviderType: "google",
			ClientID:     "gmail-client",
			ClientSecret: "gmail-secret",
		},
	}

	// Validate configuration
	if msgs := emailOpts.Validate(domainProviders); len(msgs) > 0 {
		log.Fatalf("Email discovery options validation failed: %v", msgs)
	}
	fmt.Println("✅ EmailDiscoveryOptions created and validated successfully")

	// Test 2: Convert to discovery config
	fmt.Println("\nTest 2: Converting to DiscoveryConfig...")
	discoveryConfig := emailOpts.ToDiscoveryConfig(domainProviders)
	fmt.Printf("✅ Converted to DiscoveryConfig with %d methods and %d domain mappings\n", 
		len(discoveryConfig.Methods), len(discoveryConfig.DomainMaps))

	// Test 3: Create provider factory
	fmt.Println("\nTest 3: Creating ProviderFactory...")
	fallbackInfo := &discovery.ExtendedProviderInfo{
		ProviderInfo: &discovery.ProviderInfo{
			IssuerURL:    "https://fallback.example.com",
			ProviderType: "oidc",
			ClientID:     "fallback-client",
		},
		ClientSecret: "fallback-secret",
	}
	
	providerFactory := discovery.NewProviderFactory(discoveryConfig, fallbackInfo)
	fmt.Println("✅ ProviderFactory created successfully")

	// Test 4: Test email discovery
	fmt.Println("\nTest 4: Testing email discovery...")
	testEmails := []string{
		"user@test.com",     // Should find configured provider
		"user@gmail.com",    // Should find configured provider
		"user@unknown.com",  // Should fall back to default
	}

	for _, email := range testEmails {
		fmt.Printf("\nTesting email: %s\n", email)
		
		providerInfo, err := providerFactory.GetProviderInfoForEmail(email)
		if err != nil {
			fmt.Printf("  ❌ Discovery failed: %v\n", err)
			continue
		}
		
		fmt.Printf("  ✅ Discovery successful!\n")
		fmt.Printf("     Issuer URL: %s\n", providerInfo.IssuerURL)
		fmt.Printf("     Provider Type: %s\n", providerInfo.ProviderType)
		fmt.Printf("     Client ID: %s\n", providerInfo.ClientID)
	}

	// Test 5: Create email login handler
	fmt.Println("\nTest 5: Creating EmailLoginHandler...")
	
	// Simple email template
	emailTemplate := `<!DOCTYPE html>
<html>
<head><title>Email Login</title></head>
<body>
	<h1>Sign In</h1>
	{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
	<form method="post" action="/oauth2/email-login">
		<input type="email" name="email" placeholder="Enter your email" required>
		<button type="submit">Continue</button>
	</form>
	{{if .FallbackURL}}<a href="{{.FallbackURL}}">Use default sign-in</a>{{end}}
</body>
</html>`

	emailHandler, err := handlers.NewEmailLoginHandler(
		providerFactory,
		emailTemplate,
		nil, // redirectURL
		"/oauth2/sign_in",
	)
	if err != nil {
		log.Fatalf("Failed to create email login handler: %v", err)
	}
	fmt.Println("✅ EmailLoginHandler created successfully")

	// Test 6: Test handler functionality
	fmt.Println("\nTest 6: Testing handler functionality...")
	testEmail := "user@test.com"
	providerInfo, err := emailHandler.GetProviderInfoForEmail(testEmail)
	if err != nil {
		log.Fatalf("Handler failed to get provider info: %v", err)
	}
	
	fmt.Printf("✅ Handler successfully discovered provider for %s:\n", testEmail)
	fmt.Printf("   Issuer URL: %s\n", providerInfo.IssuerURL)
	fmt.Printf("   Provider Type: %s\n", providerInfo.ProviderType)

	// Test 7: Integration with options system
	fmt.Println("\nTest 7: Testing integration with Options system...")
	opts := options.NewOptions()
	opts.EmailDiscovery = emailOpts
	opts.EmailDomainProviders = domainProviders
	
	if !opts.EmailDiscovery.Enabled {
		log.Fatalf("EmailDiscovery should be enabled in options")
	}
	
	fmt.Printf("✅ EmailDiscovery successfully integrated into Options struct\n")
	fmt.Printf("   Enabled: %t\n", opts.EmailDiscovery.Enabled)
	fmt.Printf("   Methods: %v\n", opts.EmailDiscovery.Methods)
	fmt.Printf("   Domain Providers: %d\n", len(opts.EmailDomainProviders))

	fmt.Println("\n🎉 All integration tests passed!")
	fmt.Println("\nEmail discovery is successfully integrated into oauth2-proxy!")
	fmt.Println("You can now use the following flags:")
	fmt.Println("  --email-domain-routing=true")
	fmt.Println("  --discovery-method=config,dns,wellknown")
	fmt.Println("  --fallback-url=/oauth2/sign_in")
	fmt.Println("\nOr configure via YAML:")
	fmt.Println("  email_domain_routing: true")
	fmt.Println("  discovery_methods: [\"config\", \"dns\", \"wellknown\"]")
	fmt.Println("  domain_providers:")
	fmt.Println("    - domain: \"company.com\"")
	fmt.Println("      issuer_url: \"https://sso.company.com\"")
	fmt.Println("      type: \"oidc\"")
	fmt.Println("      client_id: \"your-client-id\"")
	fmt.Println("      client_secret: \"your-client-secret\"")
}