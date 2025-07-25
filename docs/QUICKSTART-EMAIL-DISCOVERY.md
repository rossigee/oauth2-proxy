# Email-Domain Discovery Quick Start Guide

Get started with email-domain based provider discovery in 5 minutes.

## Basic Setup

### 1. Configuration File

Create `config.yaml`:

```yaml
# Enable email-domain routing
email_domain_routing: true

# Discovery methods in priority order
discovery_methods: ["config", "dns", "wellknown"]

# Domain provider mappings
domain_providers:
  - domain: "company.com"
    issuer_url: "https://auth.company.com"
    type: "oidc"
    client_id: "your-client-id"
    client_secret: "your-client-secret"
  - domain: "gmail.com"
    issuer_url: "https://accounts.google.com"
    type: "google"
    client_id: "google-client-id"
    client_secret: "google-client-secret"

# Fallback for unknown domains
fallback_provider: "default-oidc"
fallback_url: "/oauth2/sign_in"
```

### 2. Command Line

```bash
oauth2-proxy \
  --email-domain-routing=true \
  --discovery-method=config \
  --discovery-method=dns \
  --discovery-method=wellknown \
  --fallback-url="/oauth2/sign_in" \
  --config=config.yaml
```

### 3. Environment Variables

```bash
export OAUTH2_PROXY_EMAIL_DOMAIN_ROUTING=true
export OAUTH2_PROXY_DISCOVERY_METHODS="config,dns,wellknown"
export OAUTH2_PROXY_FALLBACK_URL="/oauth2/sign_in"
```

## Advanced Discovery Methods

### DNS TXT Records

Add DNS records for automatic discovery:

```bash
# Basic OIDC discovery
_oidc.company.com TXT "issuer=https://auth.company.com;type=oidc"

# With provider type
_oidc.github.com TXT "issuer=https://github.com/login/oauth/authorize;type=github"

# With client ID (for public clients)
_oidc.example.com TXT "issuer=https://sso.example.com;type=oidc;client_id=public-client"
```

### HTTP Well-Known

Serve JSON at `https://domain.com/.well-known/oauth2-proxy-oidc`:

```json
{
  "issuer": "https://auth.domain.com",
  "type": "oidc",
  "client_id": "optional-public-client-id"
}
```

## Quick Test

### 1. Run Demo

```bash
go run examples/email_discovery_demo.go
```

### 2. Test Discovery

```go
package main

import (
    "fmt"
    "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/discovery"
)

func main() {
    config := discovery.DiscoveryConfig{
        Methods: []discovery.DiscoveryMethod{discovery.MethodConfig},
        DomainMaps: []discovery.DomainProviderConfig{
            {
                Domain:       "test.com",
                IssuerURL:    "https://auth.test.com",
                ProviderType: "oidc",
                ClientID:     "test-client",
            },
        },
        DNSEnabled: true,
        WellKnownEnabled: true,
    }

    discoverySystem := discovery.NewUnifiedDiscovery(config)
    
    info, err := discoverySystem.DiscoverProviderFromEmail("user@test.com")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Found provider: %s (%s)\n", info.IssuerURL, info.ProviderType)
}
```

## Common Scenarios

### Corporate SSO

```yaml
domain_providers:
  - domain: "company.com"
    issuer_url: "https://sso.company.com"
    type: "oidc"
    client_id: "oauth2-proxy"
    client_secret: "supersecret"
```

### Multi-Provider Support

```yaml
domain_providers:
  - domain: "company.com"
    issuer_url: "https://sso.company.com"
    type: "oidc"
    client_id: "company-client"
    client_secret: "company-secret"
  - domain: "gmail.com"
    issuer_url: "https://accounts.google.com"
    type: "google"
    client_id: "google-client"
    client_secret: "google-secret"
  - domain: "github.com"
    issuer_url: "https://github.com/login/oauth/authorize"
    type: "github"
    client_id: "github-client"
    client_secret: "github-secret"
```

### Public + Private Discovery

```yaml
# Private domains via config
domain_providers:
  - domain: "internal.company.com"
    issuer_url: "https://internal-sso.company.com"
    type: "oidc"
    client_id: "internal-client"
    client_secret: "internal-secret"

# Public domains via DNS/HTTP
discovery_methods: ["config", "dns", "wellknown"]
dns_discovery: true
wellknown_discovery: true
```

## Troubleshooting

### Check Discovery

```bash
# Test DNS discovery
dig TXT _oidc.domain.com

# Test HTTP discovery
curl -s https://domain.com/.well-known/oauth2-proxy-oidc

# Test with demo
go run examples/email_discovery_demo.go
```

### Debug Logging

```yaml
# Enable debug logging
logging:
  level: debug

# Test email discovery
email_domain_routing: true
discovery_methods: ["config", "dns", "wellknown"]
```

### Common Issues

1. **Discovery Fails**: Check DNS records and HTTP endpoints
2. **Email Validation Errors**: Ensure proper email format
3. **Provider Creation Fails**: Verify client credentials
4. **Timeouts**: Adjust discovery timeouts in configuration

## Migration

### From Single Provider

1. **Keep Existing**: Your current provider becomes the fallback
2. **Add Discovery**: Enable email-domain routing
3. **Test Gradually**: Start with known domains
4. **Monitor**: Watch logs for discovery failures

```yaml
# Your existing provider becomes fallback
fallback_provider: "existing-provider-id"

# Add email discovery
email_domain_routing: true
domain_providers:
  - domain: "newcompany.com"
    issuer_url: "https://auth.newcompany.com"
    type: "oidc"
    client_id: "new-client"
    client_secret: "new-secret"
```

## Security Notes

- Always use HTTPS for issuer URLs
- Validate DNS responses in production
- Implement rate limiting for discovery
- Monitor discovery logs for suspicious activity
- Use secure client credentials storage

## Next Steps

- Read the [full documentation](email-domain-discovery.md)
- Explore [advanced configuration options](email-domain-discovery.md#configuration-options)
- Set up [monitoring and logging](email-domain-discovery.md#troubleshooting)
- Implement [custom discovery methods](email-domain-discovery.md#contributing)