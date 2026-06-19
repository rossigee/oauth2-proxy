package discovery

import (
	"fmt"
	"strings"
)

// ConfigDiscovery implements domain-to-provider discovery using static configuration
type ConfigDiscovery struct {
	domainMap map[string]*ProviderInfo
}

// DomainProviderConfig represents configuration for domain-to-provider mapping
type DomainProviderConfig struct {
	Domain       string `yaml:"domain" json:"domain"`
	IssuerURL    string `yaml:"issuer_url" json:"issuer_url"`
	ProviderType string `yaml:"type" json:"type"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
}

// NewConfigDiscovery creates a new configuration-based discovery client
func NewConfigDiscovery(configs []DomainProviderConfig) *ConfigDiscovery {
	domainMap := make(map[string]*ProviderInfo)

	for _, config := range configs {
		// Normalize domain to lowercase
		domain := strings.ToLower(strings.TrimSpace(config.Domain))
		if domain == "" {
			continue
		}

		providerType := config.ProviderType
		if providerType == "" {
			providerType = defaultProviderType // Default to OIDC
		}

		domainMap[domain] = &ProviderInfo{
			IssuerURL:    config.IssuerURL,
			ProviderType: providerType,
			ClientID:     config.ClientID,
		}
	}

	return &ConfigDiscovery{
		domainMap: domainMap,
	}
}

// DiscoverProvider looks up provider information for a domain in the configuration
func (c *ConfigDiscovery) DiscoverProvider(domain string) (*ProviderInfo, error) {
	// Normalize domain to lowercase for lookup
	normalizedDomain := strings.ToLower(strings.TrimSpace(domain))

	if info, exists := c.domainMap[normalizedDomain]; exists {
		// Return a copy to avoid external modification
		return &ProviderInfo{
			IssuerURL:    info.IssuerURL,
			ProviderType: info.ProviderType,
			ClientID:     info.ClientID,
		}, nil
	}

	return nil, fmt.Errorf("no provider configuration found for domain: %s", domain)
}

// AddDomainProvider adds a new domain-to-provider mapping
func (c *ConfigDiscovery) AddDomainProvider(domain string, info *ProviderInfo) {
	normalizedDomain := strings.ToLower(strings.TrimSpace(domain))
	if normalizedDomain != "" && info != nil {
		c.domainMap[normalizedDomain] = info
	}
}

// RemoveDomainProvider removes a domain-to-provider mapping
func (c *ConfigDiscovery) RemoveDomainProvider(domain string) {
	normalizedDomain := strings.ToLower(strings.TrimSpace(domain))
	delete(c.domainMap, normalizedDomain)
}

// GetConfiguredDomains returns a list of all configured domains
func (c *ConfigDiscovery) GetConfiguredDomains() []string {
	domains := make([]string, 0, len(c.domainMap))
	for domain := range c.domainMap {
		domains = append(domains, domain)
	}
	return domains
}

// HasDomain checks if a domain is configured
func (c *ConfigDiscovery) HasDomain(domain string) bool {
	normalizedDomain := strings.ToLower(strings.TrimSpace(domain))
	_, exists := c.domainMap[normalizedDomain]
	return exists
}
