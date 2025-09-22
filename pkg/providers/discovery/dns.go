package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSDiscovery implements domain-to-provider discovery using DNS TXT records
type DNSDiscovery struct {
	metrics *Metrics
}

// ProviderInfo contains discovered provider information
type ProviderInfo struct {
	IssuerURL    string
	ProviderType string
	ClientID     string
	// Additional fields can be added as needed
}

// NewDNSDiscovery creates a new DNS-based discovery client
func NewDNSDiscovery() *DNSDiscovery {
	return &DNSDiscovery{
		metrics: GetMetrics(),
	}
}

// DiscoverProvider attempts to discover OIDC provider information for a domain
// using DNS TXT records. It looks for records in the format:
// _oidc.domain.com TXT "issuer=https://accounts.google.com;type=oidc"
func (d *DNSDiscovery) DiscoverProvider(domain string) (*ProviderInfo, error) {
	// Start DNS query timer
	timer := d.metrics.StartTimer()

	// Construct the DNS query for _oidc subdomain
	queryDomain := fmt.Sprintf("_oidc.%s", domain)

	// Track DNS query start
	startTime := time.Now()

	// Look up TXT records
	txtRecords, err := net.LookupTXT(queryDomain)
	queryDuration := time.Since(startTime)

	if err != nil {
		// DNS query failed
		timer.ObserveDNS(domain, "TXT", false, classifyError(err))
		d.metrics.DNSQuery(domain, "TXT", queryDuration, false)
		return nil, fmt.Errorf("DNS lookup failed for %s: %v", queryDomain, err)
	}

	// DNS query succeeded
	d.metrics.DNSQuery(domain, "TXT", queryDuration, true)

	if len(txtRecords) == 0 {
		timer.ObserveDNS(domain, "TXT", false, "no_records")
		return nil, fmt.Errorf("no TXT records found for %s", queryDomain)
	}

	// Parse TXT records to find OIDC provider information
	var parseErrors []string
	for _, record := range txtRecords {
		info, err := d.parseTXTRecord(record)
		if err != nil {
			parseErrors = append(parseErrors, err.Error())
			d.metrics.ValidationError("txt_record_parse", err.Error())
			continue // Skip invalid records
		}
		if info != nil {
			// Success - found valid provider info
			timer.ObserveDNS(domain, "TXT", true, "")
			return info, nil
		}
	}

	// No valid records found
	timer.ObserveDNS(domain, "TXT", false, "no_valid_records")
	if len(parseErrors) > 0 {
		return nil, fmt.Errorf("no valid OIDC provider information found in DNS for domain %s, parse errors: %v", domain, parseErrors)
	}

	return nil, fmt.Errorf("no valid OIDC provider information found in DNS for domain %s", domain)
}

// parseTXTRecord parses a TXT record string and extracts provider information
// Expected format: "issuer=https://accounts.google.com;type=oidc;client_id=optional"
func (d *DNSDiscovery) parseTXTRecord(record string) (*ProviderInfo, error) {
	info := &ProviderInfo{
		ProviderType: "oidc", // Default to OIDC
	}

	// Split the record into key=value pairs
	pairs := strings.Split(record, ";")
	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		switch key {
		case "issuer":
			info.IssuerURL = value
		case "type":
			info.ProviderType = value
		case "client_id":
			info.ClientID = value
		}
	}

	// Validate that we have at least an issuer URL
	if info.IssuerURL == "" {
		return nil, fmt.Errorf("no issuer URL found in TXT record: %s", record)
	}

	return info, nil
}

// IsValidDomain performs basic validation on a domain name
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Basic domain validation - must contain at least one dot
	// and no invalid characters
	if !strings.Contains(domain, ".") {
		return false
	}

	// Check for invalid characters
	for _, char := range domain {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '.' && char != '-' {
			return false
		}
	}

	return true
}

// ExtractDomainFromEmail extracts the domain portion from an email address
func ExtractDomainFromEmail(email string) (string, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid email format: %s", email)
	}

	domain := strings.TrimSpace(parts[1])
	if !IsValidDomain(domain) {
		return "", fmt.Errorf("invalid domain in email: %s", domain)
	}

	return domain, nil
}
