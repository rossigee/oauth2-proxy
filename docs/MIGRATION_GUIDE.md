# Migration Guide: Enhanced OAuth2-Proxy with Email Discovery

This guide helps existing oauth2-proxy users migrate to the enhanced version with email-domain based provider discovery.

## Overview

Our enhanced oauth2-proxy fork adds enterprise-grade email discovery capabilities while maintaining full backward compatibility with the upstream oauth2-proxy project.

### Key Enhancements

- **Email-Domain Discovery**: Automatic provider discovery based on user email domains
- **Multi-Provider Support**: Dynamic provider creation and routing
- **Enterprise Security**: Rate limiting, circuit breakers, and comprehensive monitoring
- **DNS-Based Discovery**: Automatic OIDC configuration via DNS TXT records
- **HTTP Well-Known Discovery**: Standard OIDC discovery endpoints
- **Configuration-Based Mapping**: Static domain-to-provider mappings

## Compatibility

✅ **100% Backward Compatible** - All existing configurations work unchanged  
✅ **Drop-in Replacement** - Same command-line flags and configuration format  
✅ **Upstream Alignment** - Based on oauth2-proxy v7.6.0 with Go 1.24.5  
✅ **Security Hardened** - Additional security features with secure defaults  

## Migration Paths

### Path 1: Zero-Change Migration (Recommended for Start)

**Use Case**: Test the enhanced version without any configuration changes.

**Steps**:
1. Replace the oauth2-proxy binary/container
2. No configuration changes needed
3. All existing functionality works as before

```bash
# Replace binary
wget https://github.com/rossigee/oauth2-proxy/releases/latest/download/oauth2-proxy-linux-amd64
chmod +x oauth2-proxy-linux-amd64
./oauth2-proxy-linux-amd64 --config=/path/to/existing/config.cfg

# Or replace Docker container
docker run -p 4180:4180 \
  -v /path/to/config:/etc/oauth2-proxy \
  rossigee/oauth-proxy:latest \
  --config=/etc/oauth2-proxy/oauth2-proxy.cfg
```

**Result**: Identical behavior to upstream oauth2-proxy with enhanced reliability.

### Path 2: Enable Email Discovery (Gradual)

**Use Case**: Add email discovery while keeping existing provider as fallback.

**Configuration Changes**:
```bash
# Add to existing configuration
--email-discovery-enabled=true
--email-discovery-fallback-provider=default
```

**YAML Configuration**:
```yaml
# Add to existing oauth2_proxy.yml
email_discovery:
  enabled: true
  fallback_provider: "default"
  methods: ["config", "dns", "wellknown"]
```

**Benefits**:
- Users can still login with existing provider
- Email-based discovery available for configured domains
- Graceful fallback for unknown domains

### Path 3: Full Email Discovery (Advanced)

**Use Case**: Complete migration to email-based authentication.

**Configuration Example**:
```yaml
# oauth2_proxy.yml
http_address: "0.0.0.0:4180"
upstreams: ["http://localhost:8080/"]
cookie_secret: "your-cookie-secret"
cookie_secure: true

# Email Discovery Configuration
email_discovery:
  enabled: true
  methods: ["config", "dns", "wellknown"]
  fallback_provider: "none"  # Force email discovery
  
  # Domain-specific providers
  domain_providers:
    - domain: "company.com"
      provider_type: "oidc"
      issuer_url: "https://sso.company.com"
      client_id: "oauth2-proxy"
      client_secret: "your-client-secret"
      
    - domain: "gmail.com"
      provider_type: "google"
      client_id: "your-google-client-id"
      client_secret: "your-google-client-secret"

# Enhanced Security (Optional)
security:
  rate_limits:
    global_per_second: 50
    domain_per_minute: 10
    ip_per_minute: 30
  
  circuit_breaker:
    failure_threshold: 5
    timeout: "30s"
```

## Configuration Reference

### Email Discovery Options

| Flag | YAML | Default | Description |
|------|------|---------|-------------|
| `--email-discovery-enabled` | `email_discovery.enabled` | `false` | Enable email discovery |
| `--email-discovery-methods` | `email_discovery.methods` | `["config","dns","wellknown"]` | Discovery methods |
| `--email-discovery-fallback-provider` | `email_discovery.fallback_provider` | `"default"` | Fallback provider name |
| `--email-discovery-dns-enabled` | `email_discovery.dns_enabled` | `true` | Enable DNS discovery |
| `--email-discovery-wellknown-enabled` | `email_discovery.wellknown_enabled` | `true` | Enable well-known discovery |

### Domain Provider Mapping

```yaml
email_discovery:
  domain_providers:
    - domain: "example.com"
      provider_type: "oidc"
      issuer_url: "https://sso.example.com"
      client_id: "oauth2-proxy"
      client_secret: "secret"
      scopes: ["openid", "email", "profile"]
      
    - domain: "contractor.com"  
      provider_type: "github"
      client_id: "github-client-id"
      client_secret: "github-secret"
      org: "your-org"
```

### Security Configuration

```yaml
security:
  rate_limits:
    global_per_second: 50      # Global rate limit
    domain_per_minute: 10      # Per-domain limit
    ip_per_minute: 30          # Per-IP limit
    user_per_minute: 20        # Per-user limit
    enable_priority: true      # Priority-based limiting
    
  circuit_breaker:
    failure_threshold: 5       # Failures before opening
    success_threshold: 3       # Successes to close
    timeout: "30s"            # Recovery timeout
    
  validation:
    max_email_length: 254     # RFC limit
    max_domain_length: 253    # RFC limit
    blocked_domains:          # Blocked domain patterns
      - ".*\\.local$"
      - ".*\\.internal$"
```

## DNS-Based Discovery Setup

Enable automatic provider discovery via DNS TXT records:

### DNS Configuration

```bash
# Add TXT record to your domain
_oauth2-proxy-oidc.company.com. TXT "issuer=https://sso.company.com client_id=oauth2-proxy"
_oauth2-proxy-oidc.partner.com. TXT "provider_type=github org=partner-org"
```

### Verification

```bash
# Test DNS discovery
dig TXT _oauth2-proxy-oidc.company.com

# Test with oauth2-proxy
curl -X POST http://localhost:4180/oauth2/email \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=user@company.com"
```

## HTTP Well-Known Discovery

Set up standard OIDC discovery endpoints:

### Server Configuration

```json
# https://company.com/.well-known/oauth2-proxy-oidc
{
  "provider_type": "oidc",
  "issuer_url": "https://sso.company.com",
  "client_id": "oauth2-proxy",
  "scopes": ["openid", "email", "profile"]
}
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name company.com;
    
    location /.well-known/oauth2-proxy-oidc {
        return 200 '{"provider_type":"oidc","issuer_url":"https://sso.company.com","client_id":"oauth2-proxy"}';
        add_header Content-Type application/json;
    }
}
```

## Testing Migration

### 1. Validate Configuration

```bash
# Test configuration without starting
oauth2-proxy --config=oauth2_proxy.yml --check-config

# Test with dry-run
oauth2-proxy --config=oauth2_proxy.yml --dry-run
```

### 2. Test Email Discovery

```bash
# Test email form endpoint
curl -X GET http://localhost:4180/oauth2/email-form

# Test email submission
curl -X POST http://localhost:4180/oauth2/email \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@company.com"
```

### 3. Monitor Metrics

```bash
# Check Prometheus metrics
curl -s http://localhost:9090/metrics | grep oauth2_proxy_email_discovery

# Health check
curl -s http://localhost:4180/ping
```

## Deployment Strategies

### Blue-Green Deployment

1. **Deploy Enhanced Version**: Set up new environment with enhanced oauth2-proxy
2. **Configuration Sync**: Use identical configuration initially
3. **Traffic Switch**: Route traffic to new environment
4. **Enable Features**: Gradually enable email discovery features
5. **Monitor**: Watch metrics and logs for issues

### Canary Deployment

1. **Partial Traffic**: Route 10% of traffic to enhanced version
2. **Monitor Metrics**: Compare performance and error rates
3. **Gradual Increase**: Increase traffic percentage over time
4. **Full Rollout**: Complete migration when confidence is high

### Rolling Update

1. **Update Containers**: Replace containers one by one
2. **Health Checks**: Verify each instance before proceeding
3. **Rollback Plan**: Keep previous version ready for quick rollback

## Monitoring and Observability

### Prometheus Metrics

The enhanced version provides 30+ additional metrics:

```promql
# Email discovery success rate
rate(oauth2_proxy_email_discovery_discovery_success_total[5m])

# Rate limiting effectiveness  
rate(oauth2_proxy_email_discovery_rate_limiter_rejects_total[5m])

# Circuit breaker state
oauth2_proxy_email_discovery_circuit_breaker_state

# Provider distribution
oauth2_proxy_email_discovery_domain_distribution_total
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "OAuth2-Proxy Email Discovery",
    "panels": [
      {
        "title": "Discovery Success Rate",
        "targets": [
          {
            "expr": "rate(oauth2_proxy_email_discovery_discovery_success_total[5m])"
          }
        ]
      }
    ]
  }
}
```

### Log Analysis

```bash
# Filter email discovery logs
kubectl logs deployment/oauth2-proxy | grep "email.discovery"

# Monitor errors
kubectl logs deployment/oauth2-proxy | grep -i error | grep discovery
```

## Troubleshooting

### Common Issues

#### 1. Email Discovery Not Working

**Symptoms**: Users can't login with email, falling back to default provider

**Diagnosis**:
```bash
# Check configuration
oauth2-proxy --config=config.yml --check-config

# Test discovery manually
curl -X POST http://localhost:4180/oauth2/email -d "email=test@domain.com"

# Check DNS records
dig TXT _oauth2-proxy-oidc.domain.com
```

**Solutions**:
- Verify `email_discovery.enabled = true`
- Check domain provider configuration
- Validate DNS TXT records
- Test well-known endpoints

#### 2. Rate Limiting Too Aggressive

**Symptoms**: Legitimate users getting rate limited

**Diagnosis**:
```bash
# Check rate limit metrics
curl -s http://localhost:9090/metrics | grep rate_limiter_rejects

# Monitor logs
kubectl logs deployment/oauth2-proxy | grep "rate limit"
```

**Solutions**:
```yaml
security:
  rate_limits:
    global_per_second: 100    # Increase limits
    domain_per_minute: 50
    ip_per_minute: 100
    enable_priority: true     # Use priority levels
```

#### 3. Circuit Breakers Opening

**Symptoms**: Discovery always failing, circuit breakers open

**Diagnosis**:
```bash
# Check circuit breaker state
curl -s http://localhost:9090/metrics | grep circuit_breaker_state

# Check upstream health
curl -s https://sso.company.com/.well-known/openid_configuration
```

**Solutions**:
```yaml
security:
  circuit_breaker:
    failure_threshold: 10     # Increase threshold
    timeout: "60s"           # Longer recovery time
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
oauth2-proxy --config=config.yml --logging-level=debug
```

```yaml
# In YAML config
logging:
  level: debug
  format: json
```

## Security Considerations

### Baseline Security

The enhanced version includes additional security measures:

1. **Input Validation**: All email and domain inputs validated
2. **Rate Limiting**: Protection against DoS attacks
3. **Circuit Breakers**: Prevent cascade failures
4. **CSRF Protection**: Token-based CSRF protection
5. **TLS Hardening**: Secure TLS configuration for discovery

### Security Hardening

```yaml
security:
  # Strict validation
  validation:
    require_verification: true
    audit_logging: true
    max_email_length: 254
    blocked_domains: ["*.local", "*.internal"]
    
  # Rate limiting
  rate_limits:
    global_per_second: 10     # Conservative for security
    enable_exponential_backoff: true
    
  # Additional protection
  csrf_protection: true
  secure_headers: true
```

### Audit Logging

```yaml
logging:
  audit_enabled: true
  audit_file: "/var/log/oauth2-proxy-audit.log"
  format: json
```

## Performance Considerations

### Resource Usage

The enhanced version has minimal overhead:

- **Memory**: +10-20MB for discovery cache and metrics
- **CPU**: <1% additional overhead for rate limiting/circuit breakers
- **Network**: Additional DNS/HTTP requests for discovery only

### Optimization

```yaml
# Performance tuning
email_discovery:
  cache_ttl: "24h"           # Cache provider discoveries
  dns_timeout: "2s"          # Fast DNS timeouts
  http_timeout: "5s"         # Reasonable HTTP timeouts
  
performance:
  cleanup_interval: "1h"     # Regular cleanup
  metrics_interval: "30s"    # Metrics collection frequency
```

### Scaling

The enhanced version scales horizontally:

```yaml
# Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-proxy
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: oauth2-proxy
        image: rossigee/oauth-proxy:latest
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi" 
            cpu: "100m"
```

## Rollback Procedures

### Quick Rollback

If issues occur, rollback is straightforward:

```bash
# Docker rollback
docker run -p 4180:4180 oauth2-proxy/oauth2-proxy:v7.6.0

# Kubernetes rollback
kubectl rollout undo deployment/oauth2-proxy

# Binary rollback
cp oauth2-proxy.backup oauth2-proxy
systemctl restart oauth2-proxy
```

### Configuration Rollback

```bash
# Remove email discovery configuration
sed -i '/email_discovery/,+10d' oauth2_proxy.yml

# Or use backup config
cp oauth2_proxy.yml.backup oauth2_proxy.yml
```

## Support and Resources

### Documentation

- [Email Discovery Guide](./EMAIL_DISCOVERY.md)
- [Rate Limiting Configuration](./RATE_LIMITING.md)
- [Security Hardening](./SECURITY.md)
- [Monitoring Setup](./MONITORING.md)

### Examples

- [Basic Configuration](../examples/basic-email-discovery.yml)
- [Enterprise Setup](../examples/enterprise-config.yml)
- [Multi-Provider](../examples/multi-provider.yml)

### Community

- **GitHub Issues**: [Report bugs and feature requests](https://github.com/rossigee/oauth2-proxy/issues)
- **Discussions**: [Community discussions and support](https://github.com/rossigee/oauth2-proxy/discussions)
- **Security**: [Report security issues](mailto:security@example.com)

## Conclusion

The enhanced oauth2-proxy provides a smooth migration path for existing users while adding powerful email discovery capabilities. Start with zero-change migration to verify compatibility, then gradually enable email discovery features based on your requirements.

The comprehensive security, monitoring, and reliability features make this suitable for enterprise deployments while maintaining the simplicity and flexibility of the original oauth2-proxy.