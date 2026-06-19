package options

import "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"

const (
	methodDNS       = "dns"
	methodConfig    = "config"
	methodWellKnown = "wellknown"
)

// EmailDiscoveryOptions contains configuration for email-domain based provider discovery
type EmailDiscoveryOptions struct {
	// Enable email-domain based provider routing
	Enabled bool `flag:"email-domain-routing" cfg:"email_domain_routing" env:"OAUTH2_PROXY_EMAIL_DOMAIN_ROUTING"`

	// Discovery methods to use in priority order
	Methods []string `flag:"discovery-method" cfg:"discovery_methods" env:"OAUTH2_PROXY_DISCOVERY_METHODS"`

	// Enable DNS TXT record discovery
	DNSEnabled bool `flag:"dns-discovery" cfg:"dns_discovery" env:"OAUTH2_PROXY_DNS_DISCOVERY"`

	// Enable HTTP well-known discovery
	WellKnownEnabled bool `flag:"wellknown-discovery" cfg:"wellknown_discovery" env:"OAUTH2_PROXY_WELLKNOWN_DISCOVERY"`

	// Fallback provider ID when discovery fails
	FallbackProvider string `flag:"fallback-provider" cfg:"fallback_provider" env:"OAUTH2_PROXY_FALLBACK_PROVIDER"`

	// URL to redirect to for fallback authentication
	FallbackURL string `flag:"fallback-url" cfg:"fallback_url" env:"OAUTH2_PROXY_FALLBACK_URL"`
}

// DomainProviderMapping represents a mapping from domain to provider configuration
type DomainProviderMapping struct {
	Domain       string `yaml:"domain" json:"domain"`
	IssuerURL    string `yaml:"issuer_url" json:"issuer_url"`
	ProviderType string `yaml:"type" json:"type"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
}

// ToDiscoveryConfig converts EmailDiscoveryOptions to discovery.DiscoveryConfig
func (e *EmailDiscoveryOptions) ToDiscoveryConfig(domainProviders []DomainProviderMapping) discovery.DiscoveryConfig {
	// Convert method strings to DiscoveryMethod types
	methods := make([]discovery.DiscoveryMethod, 0, len(e.Methods))
	for _, method := range e.Methods {
		switch method {
		case methodDNS:
			methods = append(methods, discovery.MethodDNS)
		case methodConfig:
			methods = append(methods, discovery.MethodConfig)
		case methodWellKnown:
			methods = append(methods, discovery.MethodWellKnown)
		}
	}

	// Convert domain mappings
	domainMaps := make([]discovery.DomainProviderConfig, 0, len(domainProviders))
	for _, mapping := range domainProviders {
		domainMaps = append(domainMaps, discovery.DomainProviderConfig{
			Domain:       mapping.Domain,
			IssuerURL:    mapping.IssuerURL,
			ProviderType: mapping.ProviderType,
			ClientID:     mapping.ClientID,
			ClientSecret: mapping.ClientSecret,
		})
	}

	return discovery.DiscoveryConfig{
		Methods:          methods,
		DomainMaps:       domainMaps,
		DNSEnabled:       e.DNSEnabled,
		WellKnownEnabled: e.WellKnownEnabled,
	}
}

// GetDefaultEmailDiscoveryOptions returns default email discovery options
func GetDefaultEmailDiscoveryOptions() EmailDiscoveryOptions {
	return EmailDiscoveryOptions{
		Enabled:          false, // Disabled by default for backward compatibility
		Methods:          []string{methodConfig, methodDNS, methodWellKnown},
		DNSEnabled:       true,
		WellKnownEnabled: true,
		FallbackProvider: "",
		FallbackURL:      "/oauth2/sign_in", // Default fallback to standard sign-in
	}
}

// Validate validates the email discovery configuration
func (e *EmailDiscoveryOptions) Validate(domainProviders []DomainProviderMapping) []string {
	var msgs []string

	if !e.Enabled {
		return msgs // No validation needed if disabled
	}

	// Validate methods
	validMethods := map[string]bool{
		methodDNS:       true,
		methodConfig:    true,
		methodWellKnown: true,
	}

	for _, method := range e.Methods {
		if !validMethods[method] {
			msgs = append(msgs, "invalid discovery method: "+method+" (valid: "+methodConfig+", "+methodDNS+", "+methodWellKnown+")")
		}
	}

	// Validate domain mappings
	domainsSeen := make(map[string]bool)
	for _, mapping := range domainProviders {
		if mapping.Domain == "" {
			msgs = append(msgs, "domain_providers: domain is required")
			continue
		}

		if domainsSeen[mapping.Domain] {
			msgs = append(msgs, "domain_providers: duplicate domain "+mapping.Domain)
		}
		domainsSeen[mapping.Domain] = true

		if mapping.IssuerURL == "" {
			msgs = append(msgs, "domain_providers: issuer_url is required for domain "+mapping.Domain)
		}

		if mapping.ClientID == "" {
			msgs = append(msgs, "domain_providers: client_id is required for domain "+mapping.Domain)
		}
	}

	return msgs
}
