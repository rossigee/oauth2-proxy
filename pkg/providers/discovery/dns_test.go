package discovery

import (
	"testing"
)

func TestExtractDomainFromEmail(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		expected    string
		expectError bool
	}{
		{
			name:        "valid gmail email",
			email:       "user@gmail.com",
			expected:    "gmail.com",
			expectError: false,
		},
		{
			name:        "valid corporate email",
			email:       "john.doe@company.co.uk",
			expected:    "company.co.uk",
			expectError: false,
		},
		{
			name:        "email with subdomain",
			email:       "admin@mail.company.com",
			expected:    "mail.company.com",
			expectError: false,
		},
		{
			name:        "invalid email - no @",
			email:       "notanemail",
			expected:    "",
			expectError: true,
		},
		{
			name:        "invalid email - multiple @",
			email:       "user@@domain.com",
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty email",
			email:       "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "email with spaces",
			email:       "user@domain.com ",
			expected:    "domain.com",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractDomainFromEmail(tt.email)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "valid simple domain",
			domain:   "example.com",
			expected: true,
		},
		{
			name:     "valid subdomain",
			domain:   "mail.example.com",
			expected: true,
		},
		{
			name:     "valid country code domain",
			domain:   "example.co.uk",
			expected: true,
		},
		{
			name:     "invalid - no dot",
			domain:   "localhost",
			expected: false,
		},
		{
			name:     "invalid - empty",
			domain:   "",
			expected: false,
		},
		{
			name:     "invalid - special characters",
			domain:   "example@domain.com",
			expected: false,
		},
		{
			name:     "valid with hyphen",
			domain:   "my-site.com",
			expected: true,
		},
		{
			name:     "valid with numbers",
			domain:   "test123.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("Expected %v for domain %s, got %v", tt.expected, tt.domain, result)
			}
		})
	}
}

func TestParseTXTRecord(t *testing.T) {
	dns := NewDNSDiscovery()

	tests := []struct {
		name        string
		record      string
		expectError bool
		expected    *ProviderInfo
	}{
		{
			name:        "valid basic record",
			record:      "issuer=https://accounts.google.com",
			expectError: false,
			expected: &ProviderInfo{
				IssuerURL:    "https://accounts.google.com",
				ProviderType: "oidc",
			},
		},
		{
			name:        "valid full record",
			record:      "issuer=https://accounts.google.com;type=oidc;client_id=test-client",
			expectError: false,
			expected: &ProviderInfo{
				IssuerURL:    "https://accounts.google.com",
				ProviderType: "oidc",
				ClientID:     "test-client",
			},
		},
		{
			name:        "record with spaces",
			record:      "issuer = https://accounts.google.com ; type = google",
			expectError: false,
			expected: &ProviderInfo{
				IssuerURL:    "https://accounts.google.com",
				ProviderType: "google",
			},
		},
		{
			name:        "invalid - no issuer",
			record:      "type=oidc;client_id=test",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "invalid - malformed",
			record:      "not-a-valid-record",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "empty record",
			record:      "",
			expectError: true,
			expected:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := dns.parseTXTRecord(tt.record)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if result == nil {
					t.Errorf("Expected result but got nil")
					return
				}

				if result.IssuerURL != tt.expected.IssuerURL {
					t.Errorf("Expected IssuerURL %s, got %s", tt.expected.IssuerURL, result.IssuerURL)
				}

				if result.ProviderType != tt.expected.ProviderType {
					t.Errorf("Expected ProviderType %s, got %s", tt.expected.ProviderType, result.ProviderType)
				}

				if result.ClientID != tt.expected.ClientID {
					t.Errorf("Expected ClientID %s, got %s", tt.expected.ClientID, result.ClientID)
				}
			}
		})
	}
}
