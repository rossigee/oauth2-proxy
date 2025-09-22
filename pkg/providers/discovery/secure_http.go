package discovery

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SecureHTTPClient provides a hardened HTTP client for well-known discovery
type SecureHTTPClient struct {
	client         *http.Client
	allowedDomains []string
	timeout        time.Duration
}

// NewSecureHTTPClient creates a new secure HTTP client
func NewSecureHTTPClient(allowedDomains []string, timeout time.Duration) *SecureHTTPClient {
	// Create secure transport with hardened TLS configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			InsecureSkipVerify:       false, // Always verify certificates
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				// Only use secure cipher suites
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			},
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		},
		DisableKeepAlives:     true, // Prevent connection reuse
		MaxIdleConns:          0,    // No connection pooling
		IdleConnTimeout:       0,    // Immediate cleanup
		DisableCompression:    true, // Prevent compression attacks
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Prevent any redirects to avoid redirect-based attacks
			return http.ErrUseLastResponse
		},
	}

	return &SecureHTTPClient{
		client:         client,
		allowedDomains: allowedDomains,
		timeout:        timeout,
	}
}

// FetchProviderInfo securely fetches provider information from a well-known endpoint
func (c *SecureHTTPClient) FetchProviderInfo(domain string) (*ProviderInfo, error) {
	// Validate domain is allowed
	if !c.isDomainAllowed(domain) {
		return nil, fmt.Errorf("domain not in allowlist: %s", domain)
	}

	// Only use HTTPS - NO HTTP fallback
	discoveryURL := fmt.Sprintf("https://%s/.well-known/oauth2-proxy-oidc", domain)

	// Validate URL to prevent SSRF
	if err := c.validateURL(discoveryURL); err != nil {
		return nil, fmt.Errorf("URL validation failed: %v", err)
	}

	// Create request with security headers
	req, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add security headers
	req.Header.Set("User-Agent", "oauth2-proxy-discovery/1.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("X-Requested-With", "oauth2-proxy")

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// Validate response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("invalid content type: %s", contentType)
	}

	// Limit response size to prevent DoS
	maxSize := int64(1024 * 1024) // 1MB limit
	if resp.ContentLength > maxSize {
		return nil, fmt.Errorf("response too large: %d bytes", resp.ContentLength)
	}

	// Parse response with size limit
	body := http.MaxBytesReader(nil, resp.Body, maxSize)
	return parseProviderInfoFromJSON(body)
}

// validateURL validates a URL to prevent SSRF and other attacks
func (c *SecureHTTPClient) validateURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Only allow HTTPS
	if parsedURL.Scheme != "https" {
		return fmt.Errorf("only HTTPS URLs allowed")
	}

	// Validate hostname format (prevent header injection)
	hostname := parsedURL.Hostname()
	if strings.Contains(hostname, "\n") || strings.Contains(hostname, "\r") ||
		strings.Contains(hostname, "\t") || strings.Contains(hostname, " ") {
		return fmt.Errorf("invalid characters in hostname")
	}

	// Prevent private IP access
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("private IP addresses not allowed: %s", ip)
		}
	}

	// Validate port (if specified)
	if port := parsedURL.Port(); port != "" {
		if port != "443" && port != "80" {
			return fmt.Errorf("non-standard ports not allowed: %s", port)
		}
	}

	// Validate path (prevent path traversal)
	if strings.Contains(parsedURL.Path, "..") ||
		strings.Contains(parsedURL.Path, "//") ||
		strings.Contains(parsedURL.Path, "\\") {
		return fmt.Errorf("invalid path characters")
	}

	// Check for suspicious query parameters
	if len(parsedURL.RawQuery) > 0 {
		return fmt.Errorf("query parameters not allowed in discovery URLs")
	}

	return nil
}

// isDomainAllowed checks if a domain is in the allowlist
func (c *SecureHTTPClient) isDomainAllowed(domain string) bool {
	// If no allowlist is configured, allow all domains
	if len(c.allowedDomains) == 0 {
		return true
	}

	domain = strings.ToLower(domain)
	for _, allowed := range c.allowedDomains {
		allowed = strings.ToLower(allowed)
		// Support wildcard matching
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[2:]
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		} else if domain == allowed {
			return true
		}
	}

	return false
}

// parseProviderInfoFromJSON parses provider information from JSON response
func parseProviderInfoFromJSON(_ io.ReadCloser) (*ProviderInfo, error) {
	// This is a placeholder - implement JSON parsing with security controls
	// TODO: Implement secure JSON parsing with:
	// - Schema validation
	// - Maximum depth limits
	// - Field validation
	// - No unsafe unmarshaling

	return nil, fmt.Errorf("JSON parsing not yet implemented")
}

// SecureWellKnownDiscovery provides secure well-known endpoint discovery
type SecureWellKnownDiscovery struct {
	httpClient  *SecureHTTPClient
	validator   *SecureEmailValidator
	rateLimiter *RateLimiter
}

// NewSecureWellKnownDiscovery creates a new secure well-known discovery service
func NewSecureWellKnownDiscovery(
	allowedDomains []string,
	validator *SecureEmailValidator,
	rateLimiter *RateLimiter,
) *SecureWellKnownDiscovery {
	return &SecureWellKnownDiscovery{
		httpClient:  NewSecureHTTPClient(allowedDomains, 10*time.Second),
		validator:   validator,
		rateLimiter: rateLimiter,
	}
}

// DiscoverProvider discovers a provider using secure well-known endpoint lookup
func (d *SecureWellKnownDiscovery) DiscoverProvider(domain string, clientIP string) (*ProviderInfo, error) {
	// Rate limiting check
	if err := d.rateLimiter.CheckRateLimit(domain, clientIP); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	// Domain validation
	if err := d.validator.validateDomain(domain); err != nil {
		return nil, fmt.Errorf("domain validation failed: %v", err)
	}

	// Security policy check
	if err := d.validator.checkSecurityPolicy(domain); err != nil {
		return nil, fmt.Errorf("security policy violation: %v", err)
	}

	// Fetch provider information securely
	return d.httpClient.FetchProviderInfo(domain)
}
