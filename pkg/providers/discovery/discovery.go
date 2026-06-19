package discovery

import (
	"fmt"
	"log"
)

// Method represents the type of discovery method
type Method string

// DiscoveryMethod is an alias for Method to maintain backward compatibility
//
//nolint:revive // Keep backward compatibility
type DiscoveryMethod = Method

const (
	MethodDNS       DiscoveryMethod = "dns"
	MethodConfig    DiscoveryMethod = "config"
	MethodWellKnown DiscoveryMethod = "wellknown"
)

const (
	errTypeTimeout   = "timeout"
	errTypeForbidden = "forbidden"
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
	metrics   *Metrics
}

// Config represents configuration for the unified discovery system
type Config struct {
	Methods          []DiscoveryMethod      `yaml:"methods" json:"methods"`
	DomainMaps       []DomainProviderConfig `yaml:"domain_providers" json:"domain_providers"`
	DNSEnabled       bool                   `yaml:"dns_enabled" json:"dns_enabled"`
	WellKnownEnabled bool                   `yaml:"wellknown_enabled" json:"wellknown_enabled"`
}

// DiscoveryConfig is an alias for Config to maintain backward compatibility
//
//nolint:revive // Keep backward compatibility
type DiscoveryConfig = Config

// NewUnifiedDiscovery creates a new unified discovery client
func NewUnifiedDiscovery(config DiscoveryConfig) *UnifiedDiscovery {
	discovery := &UnifiedDiscovery{
		methods: config.Methods,
		metrics: GetMetrics(),
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

	// Initialize metrics for each method
	for _, method := range discovery.methods {
		discovery.metrics.MethodUsage(string(method), "initialization")
	}

	return discovery
}

// DiscoverProvider attempts to discover provider information using configured methods in priority order
func (u *UnifiedDiscovery) DiscoverProvider(domain string) (*ProviderInfo, error) {
	// Start overall discovery timer
	timer := u.metrics.StartTimer()

	// Track discovery request
	u.metrics.DiscoveryRequest("unified", domain)

	var lastErr error

	for _, method := range u.methods {
		methodStr := string(method)

		var discoverer Discoverer
		var fallbackReason string

		switch method {
		case MethodDNS:
			if u.dns != nil {
				discoverer = u.dns
			} else {
				fallbackReason = "dns_disabled"
			}
		case MethodConfig:
			if u.config != nil {
				discoverer = u.config
			} else {
				fallbackReason = "config_disabled"
			}
		case MethodWellKnown:
			if u.wellKnown != nil {
				discoverer = u.wellKnown
			} else {
				fallbackReason = "wellknown_disabled"
			}
		}

		if discoverer == nil {
			u.metrics.MethodUsage(methodStr, fallbackReason)
			continue
		}

		// Start method-specific timer
		methodTimer := u.metrics.StartTimer()
		u.metrics.DiscoveryRequest(methodStr, domain)

		info, err := discoverer.DiscoverProvider(domain)
		if err == nil && info != nil {
			// Success metrics
			methodTimer.ObserveDiscovery(methodStr, domain, info.ProviderType, true, "")
			timer.ObserveDiscovery("unified", domain, info.ProviderType, true, "")

			u.metrics.MethodUsage(methodStr, "success")
			log.Printf("Successfully discovered provider for domain %s using method %s", domain, method)
			return info, nil
		}

		// Error metrics
		errorType := unknownState
		if err != nil {
			errorType = classifyError(err)
			lastErr = err
		}

		methodTimer.ObserveDiscovery(methodStr, domain, "", false, errorType)
		u.metrics.MethodUsage(methodStr, "fallback_"+errorType)

		log.Printf("Discovery method %s failed for domain %s: %v", method, domain, err)
	}

	// All methods failed
	var finalErrorType string
	if lastErr != nil {
		finalErrorType = classifyError(lastErr)
	} else {
		finalErrorType = "all_methods_failed"
	}
	timer.ObserveDiscovery("unified", domain, "", false, finalErrorType)
	return nil, fmt.Errorf("all discovery methods failed for domain %s, last error: %v", domain, lastErr)
}

// classifyError categorizes errors for metrics tracking
func classifyError(err error) string {
	if err == nil {
		return "none"
	}

	errStr := err.Error()
	switch {
	case contains(errStr, errTypeTimeout):
		return errTypeTimeout
	case contains(errStr, "dns"):
		return "dns_error"
	case contains(errStr, "network"):
		return "network_error"
	case contains(errStr, "invalid"):
		return "validation_error"
	case contains(errStr, "not found"):
		return "not_found"
	case contains(errStr, errTypeForbidden):
		return errTypeForbidden
	case contains(errStr, "rate limit"):
		return "rate_limited"
	default:
		return unknownState
	}
}

// contains is a simple string contains helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			indexOfSubstring(s, substr) >= 0)))
}

func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// DiscoverProviderFromEmail extracts the domain from an email and discovers the provider
func (u *UnifiedDiscovery) DiscoverProviderFromEmail(email string) (*ProviderInfo, error) {
	// Validate email format and track validation metrics
	if err := ValidateEmail(email); err != nil {
		u.metrics.ValidationError("email_format", err.Error())
		return nil, fmt.Errorf("email validation failed: %v", err)
	}

	domain, err := ExtractDomainFromEmail(email)
	if err != nil {
		u.metrics.ValidationError("domain_extraction", err.Error())
		return nil, fmt.Errorf("failed to extract domain from email %s: %v", email, err)
	}

	// Track the email-to-provider request
	u.metrics.DiscoveryRequest("email_discovery", domain)

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
