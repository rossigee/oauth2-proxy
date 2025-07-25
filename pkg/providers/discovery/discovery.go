package discovery

import (
	"fmt"
	"log"
)

// DiscoveryMethod represents the type of discovery method
type DiscoveryMethod string

const (
	MethodDNS       DiscoveryMethod = "dns"
	MethodConfig    DiscoveryMethod = "config"
	MethodWellKnown DiscoveryMethod = "wellknown"
)

// Discoverer is the interface for provider discovery implementations
type Discoverer interface {
	DiscoverProvider(domain string) (*ProviderInfo, error)
}

// UnifiedDiscovery coordinates multiple discovery methods in priority order
type UnifiedDiscovery struct {
	methods   []DiscoveryMethod
	dns       *DNSDiscovery
	config    *ConfigDiscovery
	wellKnown *WellKnownDiscovery
}

// DiscoveryConfig represents configuration for the unified discovery system
type DiscoveryConfig struct {
	Methods       []DiscoveryMethod        `yaml:"methods" json:"methods"`
	DomainMaps    []DomainProviderConfig   `yaml:"domain_providers" json:"domain_providers"`
	DNSEnabled    bool                     `yaml:"dns_enabled" json:"dns_enabled"`
	WellKnownEnabled bool                  `yaml:"wellknown_enabled" json:"wellknown_enabled"`
}

// NewUnifiedDiscovery creates a new unified discovery client
func NewUnifiedDiscovery(config DiscoveryConfig) *UnifiedDiscovery {
	discovery := &UnifiedDiscovery{
		methods: config.Methods,
	}
	
	// Initialize discovery methods based on configuration
	for _, method := range config.Methods {
		switch method {
		case MethodDNS:
			if config.DNSEnabled {
				discovery.dns = NewDNSDiscovery()
			}
		case MethodConfig:
			if len(config.DomainMaps) > 0 {
				discovery.config = NewConfigDiscovery(config.DomainMaps)
			}
		case MethodWellKnown:
			if config.WellKnownEnabled {
				discovery.wellKnown = NewWellKnownDiscovery()
			}
		}
	}
	
	// Set default methods if none specified
	if len(discovery.methods) == 0 {
		discovery.methods = []DiscoveryMethod{MethodConfig, MethodDNS, MethodWellKnown}
		discovery.config = NewConfigDiscovery(config.DomainMaps)
		discovery.dns = NewDNSDiscovery()
		discovery.wellKnown = NewWellKnownDiscovery()
	}
	
	return discovery
}

// DiscoverProvider attempts to discover provider information using configured methods in priority order
func (u *UnifiedDiscovery) DiscoverProvider(domain string) (*ProviderInfo, error) {
	var lastErr error
	
	for _, method := range u.methods {
		var discoverer Discoverer
		
		switch method {
		case MethodDNS:
			if u.dns != nil {
				discoverer = u.dns
			}
		case MethodConfig:
			if u.config != nil {
				discoverer = u.config
			}
		case MethodWellKnown:
			if u.wellKnown != nil {
				discoverer = u.wellKnown
			}
		}
		
		if discoverer == nil {
			continue
		}
		
		info, err := discoverer.DiscoverProvider(domain)
		if err == nil && info != nil {
			log.Printf("Successfully discovered provider for domain %s using method %s", domain, method)
			return info, nil
		}
		
		lastErr = err
		log.Printf("Discovery method %s failed for domain %s: %v", method, domain, err)
	}
	
	if lastErr != nil {
		return nil, fmt.Errorf("all discovery methods failed for domain %s, last error: %v", domain, lastErr)
	}
	
	return nil, fmt.Errorf("no discovery methods configured for domain %s", domain)
}

// DiscoverProviderFromEmail extracts the domain from an email and discovers the provider
func (u *UnifiedDiscovery) DiscoverProviderFromEmail(email string) (*ProviderInfo, error) {
	domain, err := ExtractDomainFromEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to extract domain from email %s: %v", email, err)
	}
	
	return u.DiscoverProvider(domain)
}

// AddConfiguredProvider adds a domain-to-provider mapping to the configuration discovery
func (u *UnifiedDiscovery) AddConfiguredProvider(domain string, info *ProviderInfo) error {
	if u.config == nil {
		u.config = NewConfigDiscovery([]DomainProviderConfig{})
	}
	
	u.config.AddDomainProvider(domain, info)
	return nil
}

// GetConfiguredDomains returns all domains configured in the config discovery
func (u *UnifiedDiscovery) GetConfiguredDomains() []string {
	if u.config == nil {
		return []string{}
	}
	return u.config.GetConfiguredDomains()
}

// HasConfiguredDomain checks if a domain is configured in the config discovery
func (u *UnifiedDiscovery) HasConfiguredDomain(domain string) bool {
	if u.config == nil {
		return false
	}
	return u.config.HasDomain(domain)
}

// ValidateEmail performs basic email validation
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	
	domain, err := ExtractDomainFromEmail(email)
	if err != nil {
		return err
	}
	
	if !IsValidDomain(domain) {
		return fmt.Errorf("invalid domain in email: %s", domain)
	}
	
	return nil
}