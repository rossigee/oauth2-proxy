package discovery

import (
	"fmt"
	"sync"
)

// ProviderInfo now includes additional fields needed for creating providers
type ExtendedProviderInfo struct {
	*ProviderInfo
	ClientSecret     string
	ClientSecretFile string
	Scope            string
}

// ProviderFactory manages dynamic provider discovery based on email domains
type ProviderFactory struct {
	discovery     *UnifiedDiscovery
	cacheMutex    sync.RWMutex
	fallbackInfo  *ExtendedProviderInfo
}

// NewProviderFactory creates a new provider factory with discovery capabilities
func NewProviderFactory(discoveryConfig DiscoveryConfig, fallbackInfo *ExtendedProviderInfo) *ProviderFactory {
	return &ProviderFactory{
		discovery:    NewUnifiedDiscovery(discoveryConfig),
		fallbackInfo: fallbackInfo,
	}
}

// GetProviderInfoForEmail discovers provider information for the given email address
func (f *ProviderFactory) GetProviderInfoForEmail(email string) (*ExtendedProviderInfo, error) {
	// Extract domain from email
	domain, err := ExtractDomainFromEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email format: %v", err)
	}
	
	return f.GetProviderInfoForDomain(domain)
}

// GetProviderInfoForDomain discovers provider information for the given domain
func (f *ProviderFactory) GetProviderInfoForDomain(domain string) (*ExtendedProviderInfo, error) {
	// Discover provider information
	providerInfo, err := f.discovery.DiscoverProvider(domain)
	if err != nil {
		// If discovery fails, use fallback provider if available
		if f.fallbackInfo != nil {
			return f.fallbackInfo, nil
		}
		return nil, fmt.Errorf("failed to discover provider for domain %s: %v", domain, err)
	}
	
	// Create extended provider info from discovered information
	extendedInfo := &ExtendedProviderInfo{
		ProviderInfo: providerInfo,
	}
	
	// If we have fallback info, use it to fill in missing fields
	if f.fallbackInfo != nil {
		if extendedInfo.ClientSecret == "" {
			extendedInfo.ClientSecret = f.fallbackInfo.ClientSecret
		}
		if extendedInfo.ClientSecretFile == "" {
			extendedInfo.ClientSecretFile = f.fallbackInfo.ClientSecretFile
		}
		if extendedInfo.Scope == "" {
			extendedInfo.Scope = f.fallbackInfo.Scope
		}
	}
	
	return extendedInfo, nil
}

// GetConfiguredDomains returns all domains configured in the discovery system
func (f *ProviderFactory) GetConfiguredDomains() []string {
	return f.discovery.GetConfiguredDomains()
}

// HasConfiguredDomain checks if a domain is configured in the discovery system
func (f *ProviderFactory) HasConfiguredDomain(domain string) bool {
	return f.discovery.HasConfiguredDomain(domain)
}

// AddConfiguredProvider adds a domain-to-provider mapping to the configuration discovery
func (f *ProviderFactory) AddConfiguredProvider(domain string, info *ProviderInfo) error {
	return f.discovery.AddConfiguredProvider(domain, info)
}