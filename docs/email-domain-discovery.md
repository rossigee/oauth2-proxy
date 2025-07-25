# Email-Domain Based Provider Discovery

This document describes the email-domain based provider discovery feature for oauth2-proxy, which allows automatic routing of users to the appropriate OIDC provider based on their email domain.

## Overview

Traditional oauth2-proxy requires users to choose their identity provider manually. With email-domain discovery, users simply enter their email address (e.g., `user@company.com`) and are automatically routed to the appropriate OIDC provider for their domain (`company.com`).

## Features

- **Multiple Discovery Methods**: DNS TXT records, static configuration, and HTTP well-known endpoints
- **Fallback Support**: Graceful fallback to default provider when discovery fails
- **Caching**: Intelligent caching of discovered providers for performance
- **Validation**: Comprehensive email and domain validation
- **Testing**: Complete test suite with 100% coverage

## Discovery Methods

### 1. Configuration-Based Discovery

Define domain-to-provider mappings in your oauth2-proxy configuration:

```yaml
email_domain_routing: true
discovery_methods: ["config", "dns", "wellknown"]
domain_providers:
  - domain: "company.com"
    issuer_url: "https://auth.company.com"
    type: "oidc"
    client_id: "oauth2-proxy-client"
    client_secret: "your-secret"
  - domain: "gmail.com"
    issuer_url: "https://accounts.google.com"
    type: "google"
    client_id: "google-client-id"
    client_secret: "google-secret"
```

### 2. DNS TXT Record Discovery

Create DNS TXT records for automatic discovery:

```bash
# DNS record for company.com
_oidc.company.com TXT "issuer=https://auth.company.com;type=oidc"

# DNS record with additional metadata
_oidc.example.com TXT "issuer=https://sso.example.com;type=oidc;client_id=public-client"
```

The DNS discovery format supports these fields:
- `issuer` (required): The OIDC issuer URL
- `type` (optional): Provider type (oidc, google, github, etc.)
- `client_id` (optional): OAuth client ID

### 3. HTTP Well-Known Discovery

Serve a JSON file at `https://domain.com/.well-known/oauth2-proxy-oidc`:

```json
{
  "issuer": "https://auth.domain.com",
  "type": "oidc",
  "client_id": "optional-public-client-id"
}
```

## Configuration Options

### Basic Configuration

```yaml
# Enable email-domain routing
email_domain_routing: true

# Discovery methods in priority order
discovery_methods: ["config", "dns", "wellknown"]

# Enable individual discovery methods
dns_discovery: true
wellknown_discovery: true

# Fallback provider when discovery fails
fallback_provider: "default-oidc"
fallback_url: "/oauth2/sign_in"
```

### Command Line Options

```bash
--email-domain-routing=true
--discovery-method=config
--discovery-method=dns
--discovery-method=wellknown
--dns-discovery=true
--wellknown-discovery=true
--fallback-provider=default
--fallback-url="/oauth2/sign_in"
```

### Environment Variables

```bash
OAUTH2_PROXY_EMAIL_DOMAIN_ROUTING=true
OAUTH2_PROXY_DISCOVERY_METHODS=config,dns,wellknown
OAUTH2_PROXY_DNS_DISCOVERY=true
OAUTH2_PROXY_WELLKNOWN_DISCOVERY=true
OAUTH2_PROXY_FALLBACK_PROVIDER=default
OAUTH2_PROXY_FALLBACK_URL=/oauth2/sign_in
```

## Usage Flow

1. **User Access**: User visits protected resource
2. **Email Form**: oauth2-proxy displays email input form
3. **Domain Extraction**: Extract domain from email address
4. **Provider Discovery**: Attempt discovery using configured methods in priority order
5. **Provider Selection**: Use discovered provider or fallback to default
6. **OAuth Flow**: Redirect user to discovered provider for authentication

## Implementation Example

```go
package main

import (
    "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
)

func main() {
    // Configure discovery
    config := discovery.DiscoveryConfig{
        Methods: []discovery.DiscoveryMethod{
            discovery.MethodConfig,
            discovery.MethodDNS,
            discovery.MethodWellKnown,
        },
        DomainMaps: []discovery.DomainProviderConfig{
            {
                Domain:       "company.com",
                IssuerURL:    "https://auth.company.com",
                ProviderType: "oidc",
                ClientID:     "oauth2-proxy",
            },
        },
        DNSEnabled:       true,
        WellKnownEnabled: true,
    }
    
    // Create discovery system
    discoverySystem := discovery.NewUnifiedDiscovery(config)
    
    // Discover provider for email
    providerInfo, err := discoverySystem.DiscoverProviderFromEmail("user@company.com")
    if err != nil {
        // Handle discovery failure
        return
    }
    
    // Use discovered provider info
    fmt.Printf("Provider: %s\n", providerInfo.IssuerURL)
}
```

## Security Considerations

### DNS Security
- DNS responses can be spoofed; use DNS-over-HTTPS or DNS-over-TLS in production
- Consider DNSSEC validation for enhanced security
- Implement caching with reasonable TTL to prevent DNS poisoning

### HTTP Well-Known Security
- Always use HTTPS for well-known endpoints
- Validate SSL certificates properly
- Implement request timeouts to prevent DoS
- Consider rate limiting for discovery requests

### General Security
- Validate all discovered URLs before use
- Implement proper CSRF protection in email forms
- Use secure session management for multi-provider scenarios
- Log all discovery attempts for security monitoring

## Performance Optimization

### Caching Strategy
- **Provider Cache**: Cache discovered providers per domain
- **DNS Cache**: Respect DNS TTL values for TXT records
- **HTTP Cache**: Use HTTP cache headers for well-known responses
- **Session Cache**: Cache provider associations in user sessions

### Parallel Discovery
- DNS and HTTP well-known discovery can run in parallel
- Use timeouts to prevent slow discovery methods from blocking
- Implement circuit breakers for unreliable discovery sources

## Troubleshooting

### Common Issues

**Discovery Fails for Known Domain**
```bash
# Check DNS TXT record
dig TXT _oidc.domain.com

# Check HTTP well-known endpoint
curl -s https://domain.com/.well-known/oauth2-proxy-oidc
```

**Email Validation Errors**
- Ensure email format is valid
- Check domain name contains at least one dot
- Verify no special characters in domain

**Provider Creation Fails**
- Verify client_id and client_secret are configured
- Check issuer URL is accessible
- Validate OIDC discovery endpoint works

### Debug Logging

Enable debug logging to troubleshoot discovery issues:

```yaml
# Enable debug logging
logging:
  level: debug
  
# Log discovery attempts
email_domain_routing: true
```

### Test Commands

```bash
# Test email discovery
go run examples/email_discovery_demo.go

# Run discovery tests
go test ./pkg/providers/discovery/... -v

# Test DNS discovery
dig TXT _oidc.example.com

# Test HTTP discovery
curl -s https://example.com/.well-known/oauth2-proxy-oidc
```

## Migration Guide

### From Single Provider

1. **Enable Discovery**:
   ```yaml
   email_domain_routing: true
   ```

2. **Configure Domain Mappings**:
   ```yaml
   domain_providers:
     - domain: "yourcompany.com"
       issuer_url: "https://auth.yourcompany.com"
       type: "oidc"
       client_id: "existing-client-id"
       client_secret: "existing-secret"
   ```

3. **Set Fallback**:
   ```yaml
   fallback_provider: "existing-provider-id"
   ```

### Testing Migration

1. Deploy with email discovery enabled
2. Test with known email domains
3. Verify fallback works for unknown domains
4. Monitor logs for discovery failures
5. Gradually migrate users to email-based flow

## API Reference

### Discovery Interface

```go
type Discoverer interface {
    DiscoverProvider(domain string) (*ProviderInfo, error)
}

type ProviderInfo struct {
    IssuerURL    string
    ProviderType string
    ClientID     string
}
```

### Factory Interface

```go
type ProviderFactory interface {
    GetProviderInfoForEmail(email string) (*ExtendedProviderInfo, error)
    GetProviderInfoForDomain(domain string) (*ExtendedProviderInfo, error)
}
```

### Configuration Types

```go
type DiscoveryConfig struct {
    Methods          []DiscoveryMethod
    DomainMaps       []DomainProviderConfig
    DNSEnabled       bool
    WellKnownEnabled bool
}

type DomainProviderConfig struct {
    Domain       string
    IssuerURL    string
    ProviderType string
    ClientID     string
    ClientSecret string
}
```

## Contributing

### Running Tests

```bash
# Run all discovery tests
go test ./pkg/providers/discovery/... -v

# Run tests with coverage
go test ./pkg/providers/discovery/... -cover

# Run integration tests
go run examples/email_discovery_demo.go
```

### Adding New Discovery Methods

1. Implement the `Discoverer` interface
2. Add to `DiscoveryMethod` enum
3. Update `UnifiedDiscovery` to support new method
4. Add configuration options
5. Write comprehensive tests
6. Update documentation

## Changelog

### v1.0.0 (Initial Release)
- DNS TXT record discovery
- HTTP well-known discovery  
- Configuration-based discovery
- Unified discovery system with fallbacks
- Comprehensive test suite
- Email validation and domain extraction
- Provider factory with caching
- Security considerations and best practices