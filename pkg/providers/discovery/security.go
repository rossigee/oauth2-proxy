package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"sync"

	"golang.org/x/time/rate"
)

// SecurityPolicy defines security controls for email discovery
type SecurityPolicy struct {
	AllowedDomains      []string  `yaml:"allowed_domains"`
	BlockedDomains      []string  `yaml:"blocked_domains"`
	RequireVerification bool      `yaml:"require_verification"`
	AuditLogging        bool      `yaml:"audit_logging"`
	RateLimits          RateLimit `yaml:"rate_limits"`
	MaxEmailLength      int       `yaml:"max_email_length"`
	MaxDomainLength     int       `yaml:"max_domain_length"`
}

// RateLimit configuration for discovery operations
type RateLimit struct {
	GlobalPerSecond int `yaml:"global_per_second"`
	DomainPerMinute int `yaml:"domain_per_minute"`
	IPPerMinute     int `yaml:"ip_per_minute"`
}

// AuditEvent represents a security audit event
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	EmailHash string    `json:"email_hash"`
	Domain    string    `json:"domain"`
	Method    string    `json:"discovery_method"`
	Success   bool      `json:"success"`
	Provider  string    `json:"provider,omitempty"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Risk      string    `json:"risk_level"`
	ErrorCode string    `json:"error_code,omitempty"`
}

// SecureEmailValidator provides RFC-compliant email validation with security controls
type SecureEmailValidator struct {
	policy       SecurityPolicy
	blockedRegex []*regexp.Regexp
}

// NewSecureEmailValidator creates a new secure email validator
func NewSecureEmailValidator(policy SecurityPolicy) *SecureEmailValidator {
	validator := &SecureEmailValidator{
		policy: policy,
	}

	// Compile blocked domain patterns
	for _, pattern := range policy.BlockedDomains {
		if regex, err := regexp.Compile(pattern); err == nil {
			validator.blockedRegex = append(validator.blockedRegex, regex)
		}
	}

	return validator
}

// ValidateEmail performs comprehensive email validation with security checks
func (v *SecureEmailValidator) ValidateEmail(email string) error {
	// Length validation
	if len(email) > v.policy.MaxEmailLength {
		return fmt.Errorf("email address exceeds maximum length of %d characters", v.policy.MaxEmailLength)
	}

	// Basic format validation using net/mail (RFC 5322 compliant)
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format: %v", err)
	}

	// Extract domain for further validation
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format")
	}

	domain := strings.ToLower(strings.TrimSpace(parts[1]))

	// Domain validation
	if err := v.validateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain: %v", err)
	}

	// Security policy checks
	if err := v.checkSecurityPolicy(domain); err != nil {
		return fmt.Errorf("security policy violation: %v", err)
	}

	return nil
}

// validateDomain performs comprehensive domain validation
func (v *SecureEmailValidator) validateDomain(domain string) error {
	// Length checks
	if len(domain) == 0 || len(domain) > v.policy.MaxDomainLength {
		return fmt.Errorf("domain length must be between 1 and %d characters", v.policy.MaxDomainLength)
	}

	// No leading/trailing dots or dashes
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return fmt.Errorf("domain cannot start or end with dot or dash")
	}

	// No consecutive dots
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain cannot contain consecutive dots")
	}

	// Check for invalid characters (prevent injection attacks)
	for _, char := range domain {
		if !isValidDomainChar(char) {
			return fmt.Errorf("domain contains invalid character: %c", char)
		}
	}

	// Validate each label
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain must contain at least one dot")
	}

	// RFC 1123 compliant label validation
	labelRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("domain label length must be between 1 and 63 characters")
		}
		if !labelRegex.MatchString(label) {
			return fmt.Errorf("invalid domain label format: %s", label)
		}
	}

	// Check for punycode/IDN attacks
	if strings.Contains(domain, "xn--") {
		return fmt.Errorf("punycode domains not allowed for security reasons")
	}

	return nil
}

// isValidDomainChar checks if a character is valid in a domain name
func isValidDomainChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '.' || char == '-'
}

// checkSecurityPolicy validates domain against security policies
func (v *SecureEmailValidator) checkSecurityPolicy(domain string) error {
	// Check blocked domains
	for _, regex := range v.blockedRegex {
		if regex.MatchString(domain) {
			return fmt.Errorf("domain is blocked by security policy")
		}
	}

	// Check allowed domains (if allowlist is configured)
	if len(v.policy.AllowedDomains) > 0 {
		allowed := false
		for _, allowedDomain := range v.policy.AllowedDomains {
			if strings.HasSuffix(domain, allowedDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("domain not in allowed list")
		}
	}

	// Check for private/internal domains
	if isPrivateDomain(domain) {
		return fmt.Errorf("private/internal domains not allowed")
	}

	return nil
}

// isPrivateDomain checks if a domain resolves to private IP space
func isPrivateDomain(domain string) bool {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false // DNS resolution failed, not necessarily private
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return true
		}
	}

	return false
}

// HashEmail creates a privacy-preserving hash of an email address for logging
func HashEmail(email string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(email)))
	hash := hex.EncodeToString(h.Sum(nil))
	return hash[:12] // Use first 12 characters for correlation
}

// RateLimiter provides rate limiting for discovery operations
type RateLimiter struct {
	globalLimiter  *rate.Limiter
	domainLimiters map[string]*rate.Limiter
	ipLimiters     map[string]*rate.Limiter
	mutex          sync.RWMutex
	policy         RateLimit
}

// NewRateLimiter creates a new rate limiter with the specified policy
func NewRateLimiter(policy RateLimit) *RateLimiter {
	return &RateLimiter{
		globalLimiter:  rate.NewLimiter(rate.Limit(policy.GlobalPerSecond), policy.GlobalPerSecond),
		domainLimiters: make(map[string]*rate.Limiter),
		ipLimiters:     make(map[string]*rate.Limiter),
		policy:         policy,
	}
}

// CheckRateLimit validates if a request is within rate limits
func (rl *RateLimiter) CheckRateLimit(domain, ipAddress string) error {
	// Check global rate limit
	if !rl.globalLimiter.Allow() {
		return fmt.Errorf("global rate limit exceeded")
	}

	// Check domain-specific rate limit
	if !rl.checkDomainLimit(domain) {
		return fmt.Errorf("domain rate limit exceeded for: %s", domain)
	}

	// Check IP-specific rate limit
	if !rl.checkIPLimit(ipAddress) {
		return fmt.Errorf("IP rate limit exceeded for: %s", ipAddress)
	}

	return nil
}

// checkDomainLimit checks rate limit for a specific domain
func (rl *RateLimiter) checkDomainLimit(domain string) bool {
	rl.mutex.RLock()
	limiter, exists := rl.domainLimiters[domain]
	rl.mutex.RUnlock()

	if !exists {
		rl.mutex.Lock()
		// Double-check after acquiring write lock
		if limiter, exists = rl.domainLimiters[domain]; !exists {
			// Create new limiter for this domain
			perMinute := rate.Every(time.Minute / time.Duration(rl.policy.DomainPerMinute))
			limiter = rate.NewLimiter(perMinute, rl.policy.DomainPerMinute)
			rl.domainLimiters[domain] = limiter
		}
		rl.mutex.Unlock()
	}

	return limiter.Allow()
}

// checkIPLimit checks rate limit for a specific IP address
func (rl *RateLimiter) checkIPLimit(ipAddress string) bool {
	rl.mutex.RLock()
	limiter, exists := rl.ipLimiters[ipAddress]
	rl.mutex.RUnlock()

	if !exists {
		rl.mutex.Lock()
		// Double-check after acquiring write lock
		if limiter, exists = rl.ipLimiters[ipAddress]; !exists {
			// Create new limiter for this IP
			perMinute := rate.Every(time.Minute / time.Duration(rl.policy.IPPerMinute))
			limiter = rate.NewLimiter(perMinute, rl.policy.IPPerMinute)
			rl.ipLimiters[ipAddress] = limiter
		}
		rl.mutex.Unlock()
	}

	return limiter.Allow()
}

// GetDefaultSecurityPolicy returns a secure default policy
func GetDefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		AllowedDomains: []string{}, // Empty = allow all (configure per deployment)
		BlockedDomains: []string{
			`.*\.local$`,     // Block .local domains
			`.*\.localhost$`, // Block localhost variants
			`.*\.internal$`,  // Block .internal domains
			`^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)`, // Block private IP ranges
		},
		RequireVerification: true,
		AuditLogging:        true,
		RateLimits: RateLimit{
			GlobalPerSecond: 10, // 10 requests per second globally
			DomainPerMinute: 5,  // 5 requests per minute per domain
			IPPerMinute:     20, // 20 requests per minute per IP
		},
		MaxEmailLength:  254, // RFC 5321 limit
		MaxDomainLength: 253, // RFC 1035 limit
	}
}
