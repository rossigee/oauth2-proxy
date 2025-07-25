package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WellKnownDiscovery implements domain-to-provider discovery using HTTP well-known endpoints
type WellKnownDiscovery struct {
	httpClient *http.Client
	timeout    time.Duration
}

// WellKnownResponse represents the response from a well-known discovery endpoint
type WellKnownResponse struct {
	IssuerURL    string `json:"issuer"`
	ProviderType string `json:"type"`
	ClientID     string `json:"client_id,omitempty"`
}

// NewWellKnownDiscovery creates a new HTTP well-known discovery client
func NewWellKnownDiscovery() *WellKnownDiscovery {
	return &WellKnownDiscovery{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		timeout: 10 * time.Second,
	}
}

// NewWellKnownDiscoveryWithTimeout creates a new HTTP well-known discovery client with custom timeout
func NewWellKnownDiscoveryWithTimeout(timeout time.Duration) *WellKnownDiscovery {
	return &WellKnownDiscovery{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// DiscoverProvider attempts to discover OIDC provider information for a domain
// using HTTP well-known endpoints. It tries both HTTP and HTTPS.
func (w *WellKnownDiscovery) DiscoverProvider(domain string) (*ProviderInfo, error) {
	// Try HTTPS first, then HTTP as fallback
	urls := []string{
		fmt.Sprintf("https://%s/.well-known/oauth2-proxy-oidc", domain),
		fmt.Sprintf("http://%s/.well-known/oauth2-proxy-oidc", domain),
	}
	
	for _, url := range urls {
		info, err := w.fetchProviderInfo(url)
		if err == nil && info != nil {
			return info, nil
		}
	}
	
	return nil, fmt.Errorf("no valid OIDC provider information found via well-known endpoints for domain %s", domain)
}

// fetchProviderInfo makes an HTTP request to fetch provider information
func (w *WellKnownDiscovery) fetchProviderInfo(url string) (*ProviderInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oauth2-proxy/discovery")
	
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request returned status %d", resp.StatusCode)
	}
	
	var wellKnownResp WellKnownResponse
	if err := json.NewDecoder(resp.Body).Decode(&wellKnownResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}
	
	// Validate response
	if wellKnownResp.IssuerURL == "" {
		return nil, fmt.Errorf("missing issuer URL in well-known response")
	}
	
	providerType := wellKnownResp.ProviderType
	if providerType == "" {
		providerType = "oidc" // Default to OIDC
	}
	
	return &ProviderInfo{
		IssuerURL:    wellKnownResp.IssuerURL,
		ProviderType: providerType,
		ClientID:     wellKnownResp.ClientID,
	}, nil
}

// SetHTTPClient allows customization of the HTTP client
func (w *WellKnownDiscovery) SetHTTPClient(client *http.Client) {
	w.httpClient = client
}

// SetTimeout sets the timeout for HTTP requests
func (w *WellKnownDiscovery) SetTimeout(timeout time.Duration) {
	w.timeout = timeout
	w.httpClient.Timeout = timeout
}