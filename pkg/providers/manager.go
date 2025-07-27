package providers

import (
	"fmt"
	"sync"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

// Manager handles dynamic provider creation and caching
type Manager struct {
	providerFactory *discovery.ProviderFactory
	providerCache   map[string]providers.Provider
	cacheMutex      sync.RWMutex
	defaultProvider providers.Provider
	metrics         *discovery.Metrics
}

// NewManager creates a new provider manager
func NewManager(factory *discovery.ProviderFactory, defaultProvider providers.Provider) *Manager {
	return &Manager{
		providerFactory: factory,
		providerCache:   make(map[string]providers.Provider),
		defaultProvider: defaultProvider,
		metrics:         discovery.GetMetrics(),
	}
}

// GetProviderForEmail discovers and creates a provider for the given email domain
func (m *Manager) GetProviderForEmail(email string) (providers.Provider, error) {
	// Extract domain from email
	domain, err := discovery.ExtractDomainFromEmail(email)
	if err != nil {
		m.metrics.ValidationError("email_format", "invalid_email_format")
		return m.defaultProvider, fmt.Errorf("invalid email format: %v", err)
	}

	// Check cache first
	m.cacheMutex.RLock()
	if cachedProvider, exists := m.providerCache[domain]; exists {
		m.cacheMutex.RUnlock()
		m.metrics.CacheHit("provider", domain)
		return cachedProvider, nil
	}
	m.cacheMutex.RUnlock()
	
	// Cache miss
	m.metrics.CacheMiss("provider", domain)

	// Discover provider info
	providerInfo, err := m.providerFactory.GetProviderInfoForEmail(email)
	if err != nil {
		// If discovery fails, use default provider
		m.metrics.ProviderError("unknown", domain, "discovery_failed")
		return m.defaultProvider, nil
	}

	// Create provider from discovered info
	provider, err := m.createProviderFromInfo(providerInfo)
	if err != nil {
		m.metrics.ProviderError(providerInfo.ProviderType, domain, "creation_failed")
		return m.defaultProvider, fmt.Errorf("failed to create provider: %v", err)
	}

	// Successfully created provider
	m.metrics.ProviderCreated(providerInfo.ProviderType, domain)

	// Cache the provider
	m.cacheMutex.Lock()
	m.providerCache[domain] = provider
	m.cacheMutex.Unlock()

	return provider, nil
}

// GetDefaultProvider returns the default provider
func (m *Manager) GetDefaultProvider() providers.Provider {
	return m.defaultProvider
}

// createProviderFromInfo creates a provider instance from discovered provider info
func (m *Manager) createProviderFromInfo(info *discovery.ExtendedProviderInfo) (providers.Provider, error) {
	// Map provider type string to ProviderType enum
	var providerType options.ProviderType
	switch info.ProviderType {
	case "oidc":
		providerType = options.OIDCProvider
	case "google":
		providerType = options.GoogleProvider
	case "github":
		providerType = options.GitHubProvider
	case "gitlab":
		providerType = options.GitLabProvider
	case "keycloak-oidc":
		providerType = options.KeycloakOIDCProvider
	default:
		// Default to OIDC for unknown provider types
		providerType = options.OIDCProvider
	}

	// Create provider options from discovered info
	providerOpts := options.Provider{
		Type:         providerType,
		ClientID:     info.ClientID,
		ClientSecret: info.ClientSecret,
		Scope:        info.Scope,
	}

	// For OIDC providers, set the issuer URL in the OIDC config
	if providerType == options.OIDCProvider || providerType == options.KeycloakOIDCProvider {
		providerOpts.OIDCConfig = options.OIDCOptions{
			IssuerURL: info.IssuerURL,
		}
	}

	// Set default scope if empty
	if providerOpts.Scope == "" {
		providerOpts.Scope = "openid email profile"
	}

	// Create the provider using the providers package
	provider, err := providers.NewProvider(providerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s provider: %v", info.ProviderType, err)
	}

	return provider, nil
}

// ClearCache clears the provider cache
func (m *Manager) ClearCache() {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	
	// Track removed providers
	for _, provider := range m.providerCache {
		// Get provider type from provider data
		if providerData := provider.Data(); providerData != nil {
			// Note: This is a simple approach - in production you might want 
			// to track provider types more explicitly
			m.metrics.ProviderRemoved("cached_provider")
		}
	}
	
	m.providerCache = make(map[string]providers.Provider)
}

// GetCachedProviders returns a copy of currently cached providers
func (m *Manager) GetCachedProviders() map[string]providers.Provider {
	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()
	
	result := make(map[string]providers.Provider)
	for domain, provider := range m.providerCache {
		result[domain] = provider
	}
	return result
}