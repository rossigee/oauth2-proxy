# OAuth2-Proxy Email Discovery Security Guide

## Overview

This document outlines the security features, threat model, and best practices for the email-domain based provider discovery system in oauth2-proxy.

## Security Architecture

### Threat Model

The email discovery system protects against the following attack vectors:

1. **Input Validation Attacks**
   - Email injection attacks
   - Domain validation bypass
   - Unicode/IDN homograph attacks
   - Path traversal attempts

2. **Network-Based Attacks**
   - DNS poisoning and cache poisoning
   - Server-Side Request Forgery (SSRF)
   - Man-in-the-middle attacks
   - HTTP downgrade attacks

3. **Session-Based Attacks**
   - Cross-Site Request Forgery (CSRF)
   - Session fixation
   - Session hijacking
   - Open redirect vulnerabilities

4. **Denial of Service Attacks**
   - DNS query flooding
   - HTTP request flooding
   - Resource exhaustion
   - Rate limit bypass

5. **Information Disclosure**
   - Email address logging
   - Provider configuration exposure
   - Error message enumeration
   - Timing attacks

## Security Controls

### 1. Input Validation and Sanitization

#### Email Validation
- **RFC 5322 Compliance**: Uses `net/mail` package for proper email parsing
- **Length Limits**: 254 characters for email (RFC 5321), 253 for domain (RFC 1035)
- **Character Validation**: Strict character set validation to prevent injection
- **Punycode Prevention**: Blocks IDN domains to prevent homograph attacks

```go
// Example of secure email validation
validator := discovery.NewSecureEmailValidator(policy)
if err := validator.ValidateEmail(email); err != nil {
    return fmt.Errorf("email validation failed: %v", err)
}
```

#### Domain Validation
- **Format Validation**: RFC 1123 compliant domain validation
- **Private IP Prevention**: Blocks resolution to private IP ranges
- **Special Character Prevention**: Prevents header injection attacks
- **Length Validation**: Individual label length limits (63 chars)

### 2. Network Security

#### DNS Security
- **DNS over TLS**: Encrypted DNS queries to prevent eavesdropping
- **DNSSEC Validation**: Cryptographic validation of DNS responses
- **Rate Limiting**: Prevents DNS amplification attacks
- **Query Validation**: Sanitizes DNS queries to prevent injection

```go
// Example of secure DNS discovery
dnsDiscovery := discovery.NewSecureDNSDiscovery()
dnsDiscovery.SetResolver("1.1.1.1:853") // Cloudflare DNS over TLS
```

#### HTTP Security
- **HTTPS Only**: No HTTP fallback, prevents downgrade attacks
- **Certificate Validation**: Strict TLS certificate verification
- **SSRF Prevention**: URL validation and private IP blocking
- **Request Size Limits**: Prevents resource exhaustion attacks

### 3. Session Security

#### CSRF Protection
- **Time-based Tokens**: HMAC-signed tokens with expiration
- **Double Submit Cookies**: Token in both cookie and form
- **SameSite Cookies**: Strict SameSite policy for CSRF cookies
- **State Parameters**: OAuth state parameters for flow protection

```go
// Example of CSRF protection
csrf, _ := handlers.NewCSRFProtection()
token, _ := csrf.GenerateToken(sessionID)
csrf.SetTokenCookie(w, token, true) // secure=true for HTTPS
```

#### Session Management
- **Secure Session Storage**: Encrypted session data
- **Session Regeneration**: New session ID after authentication
- **Session Timeout**: Automatic expiration of inactive sessions
- **Session Invalidation**: Secure logout with session cleanup

### 4. Rate Limiting

#### Multi-Level Rate Limiting
- **Global Limits**: 10 requests/second across all endpoints
- **Domain Limits**: 5 requests/minute per domain
- **IP Limits**: 20 requests/minute per IP address
- **Discovery Limits**: 1 request/5 seconds per domain for discovery

```go
// Example of rate limiting configuration
rateLimiter := discovery.NewRateLimiter(discovery.RateLimit{
    GlobalPerSecond: 10,
    DomainPerMinute: 5,
    IPPerMinute:     20,
})
```

### 5. Audit Logging

#### Security Event Logging
- **Hashed Email Addresses**: Privacy-preserving email logging
- **Request Correlation**: Unique request IDs for audit trails
- **Security Violations**: Detailed logging of attack attempts
- **Authentication Events**: Success/failure tracking with context

#### Log Data Protection
- **Structured Logging**: JSON format for automated analysis
- **Sensitive Data Masking**: No plaintext passwords or tokens
- **Retention Policies**: Automated log rotation and archival
- **Access Controls**: Restricted access to audit logs

## Configuration

### Security Policy Configuration

```yaml
email_discovery:
  security_policy:
    allowed_domains:
      - "*.company.com"
      - "trusted-partner.net"
    blocked_domains:
      - ".*\\.local$"
      - ".*\\.localhost$"
      - ".*\\.internal$"
    require_verification: true
    audit_logging: true
    rate_limits:
      global_per_second: 10
      domain_per_minute: 5
      ip_per_minute: 20
    max_email_length: 254
    max_domain_length: 253
```

### TLS Configuration

```yaml
tls_config:
  min_version: "1.2"
  cipher_suites:
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
  certificate_validation: "strict"
  dns_over_tls: true
```

## Deployment Security

### Production Hardening

1. **HTTPS Only**
   ```bash
   # Force HTTPS redirect
   --force-https=true
   # HSTS headers
   --set-xauthrequest=true
   ```

2. **Security Headers**
   ```
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   X-XSS-Protection: 1; mode=block
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   Content-Security-Policy: default-src 'self'
   ```

3. **Network Security**
   ```bash
   # Restrict upstream access
   --upstream=https://internal.app.com
   # Configure trusted IPs
   --trusted-ip=10.0.0.0/8
   ```

### Monitoring and Alerting

#### Security Metrics
- Discovery attempt rates by domain and IP
- CSRF validation failure rates
- Rate limit violations
- DNS resolution failures
- Authentication success/failure rates

#### Alert Thresholds
- **Critical**: >10 CSRF failures/minute from single IP
- **High**: >50 rate limit violations/minute
- **Medium**: >100 failed discovery attempts/hour
- **Low**: Unusual domain access patterns

### Incident Response

#### Security Incident Types
1. **Authentication Bypass**: Unauthorized access attempts
2. **Rate Limit Abuse**: Potential DDoS or brute force
3. **CSRF Attacks**: Cross-site request forgery attempts
4. **DNS Manipulation**: Potential DNS poisoning
5. **SSRF Attempts**: Server-side request forgery

#### Response Procedures
1. **Immediate**: Block offending IPs at network level
2. **Short-term**: Increase rate limits and monitoring
3. **Investigation**: Analyze audit logs and attack patterns
4. **Recovery**: Validate system integrity and update defenses

## Security Testing

### Automated Security Testing

```bash
# Run security test suite
go test ./pkg/providers/discovery -run TestSecurity
go test ./pkg/handlers -run TestSecure

# Static security analysis
gosec ./...

# Dependency vulnerability scanning
go mod audit
```

### Manual Security Testing

1. **Input Validation Testing**
   ```bash
   # Test email injection
   curl -d "email=user@domain.com%0Amalicious" /oauth2/email-login
   
   # Test domain validation bypass
   curl -d "email=user@.evil.com" /oauth2/email-login
   ```

2. **CSRF Testing**
   ```bash
   # Test missing CSRF token
   curl -X POST -d "email=test@example.com" /oauth2/email-login
   
   # Test invalid CSRF token
   curl -X POST -d "email=test@example.com&csrf_token=invalid" /oauth2/email-login
   ```

3. **Rate Limiting Testing**
   ```bash
   # Test rate limits
   for i in {1..100}; do
     curl -d "email=test$i@example.com" /oauth2/email-login &
   done
   ```

## Compliance

### Standards Compliance
- **OWASP Top 10**: Protection against all OWASP Top 10 vulnerabilities
- **NIST Cybersecurity Framework**: Implements identify, protect, detect, respond, recover
- **ISO 27001**: Information security management best practices
- **SOC 2 Type II**: Security, availability, and confidentiality controls

### Privacy Compliance
- **GDPR**: Email address hashing, data minimization, right to erasure
- **CCPA**: Privacy notices, data access controls, opt-out mechanisms
- **PIPEDA**: Consent management, data protection safeguards

## Security Updates

### Staying Current
1. **Upstream Monitoring**: Track oauth2-proxy security advisories
2. **Dependency Scanning**: Regular vulnerability scans of dependencies
3. **Security Patches**: Automated security update pipeline
4. **Threat Intelligence**: Monitor for new attack vectors

### Update Process
1. **Assessment**: Evaluate security impact and urgency
2. **Testing**: Validate fixes in staging environment
3. **Deployment**: Coordinated production deployment
4. **Verification**: Post-deployment security validation

## Contact

For security issues and vulnerabilities:
- **Security Email**: security@oauth2-proxy.github.io
- **Bug Bounty**: See SECURITY.md in main repository
- **Urgent Issues**: Create private security advisory on GitHub

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [RFC 6749: OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6819: OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
- [NIST SP 800-63B: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)