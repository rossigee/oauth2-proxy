package discovery

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	// Create a new registry for testing
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	t.Run("DiscoveryMetrics", func(t *testing.T) {
		// Test discovery request (this will be called twice - once explicitly, once by success)
		metrics.DiscoveryRequest("dns", "example.com")
		
		// Test successful discovery
		metrics.DiscoverySuccess("dns", "example.com", "oidc", 100*time.Millisecond)
		
		// Test failed discovery
		metrics.DiscoveryError("dns", "example.com", "timeout", 500*time.Millisecond)
		
		// Verify metrics
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		
		// Check that we have the expected metrics
		var foundRequestsMetric, foundSuccessMetric, foundErrorMetric bool
		for _, mf := range metricFamilies {
			switch *mf.Name {
			case "oauth2_proxy_email_discovery_discovery_requests_total":
				foundRequestsMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"method": "dns", "domain": "example.com"}))
			case "oauth2_proxy_email_discovery_discovery_success_total":
				foundSuccessMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"method": "dns", "domain": "example.com", "provider_type": "oidc"}))
			case "oauth2_proxy_email_discovery_discovery_errors_total":
				foundErrorMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"method": "dns", "domain": "example.com", "error_type": "timeout"}))
			}
		}
		
		assert.True(t, foundRequestsMetric, "Should have discovery requests metric")
		assert.True(t, foundSuccessMetric, "Should have discovery success metric")
		assert.True(t, foundErrorMetric, "Should have discovery error metric")
	})

	t.Run("CacheMetrics", func(t *testing.T) {
		metrics.CacheHit("provider", "example.com")
		metrics.CacheMiss("provider", "example.com")
		
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		
		var foundHitsMetric, foundMissesMetric bool
		for _, mf := range metricFamilies {
			switch *mf.Name {
			case "oauth2_proxy_email_discovery_cache_hits_total":
				foundHitsMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"cache_type": "provider", "domain": "example.com"}))
			case "oauth2_proxy_email_discovery_cache_misses_total":
				foundMissesMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"cache_type": "provider", "domain": "example.com"}))
			}
		}
		
		assert.True(t, foundHitsMetric, "Should have cache hits metric")
		assert.True(t, foundMissesMetric, "Should have cache misses metric")
	})

	t.Run("ProviderMetrics", func(t *testing.T) {
		metrics.ProviderCreated("oidc", "example.com")
		metrics.ProviderError("oidc", "example.com", "invalid_config")
		
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		
		var foundCreationsMetric, foundErrorsMetric bool
		for _, mf := range metricFamilies {
			switch *mf.Name {
			case "oauth2_proxy_email_discovery_provider_creations_total":
				foundCreationsMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"provider_type": "oidc", "domain": "example.com"}))
			case "oauth2_proxy_email_discovery_provider_errors_total":
				foundErrorsMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"provider_type": "oidc", "domain": "example.com", "error_type": "invalid_config"}))
			}
		}
		
		assert.True(t, foundCreationsMetric, "Should have provider creations metric")
		assert.True(t, foundErrorsMetric, "Should have provider errors metric")
	})

	t.Run("DNSMetrics", func(t *testing.T) {
		metrics.DNSQuery("example.com", "TXT", 50*time.Millisecond, true)
		metrics.DNSError("example.com", "timeout")
		
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		
		var foundQueriesMetric, foundErrorsMetric bool
		for _, mf := range metricFamilies {
			switch *mf.Name {
			case "oauth2_proxy_email_discovery_dns_queries_total":
				foundQueriesMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"domain": "example.com", "record_type": "TXT"}))
			case "oauth2_proxy_email_discovery_dns_errors_total":
				foundErrorsMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"domain": "example.com", "error_type": "timeout"}))
			}
		}
		
		assert.True(t, foundQueriesMetric, "Should have DNS queries metric")
		assert.True(t, foundErrorsMetric, "Should have DNS errors metric")
	})

	t.Run("SecurityMetrics", func(t *testing.T) {
		metrics.ValidationError("email_format", "invalid_format")
		metrics.RateLimitHit("discovery", "192.168.1.1")
		metrics.SuspiciousActivity("repeated_failures", "suspicious.com")
		
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		
		var foundValidationMetric, foundRateLimitMetric, foundSuspiciousMetric bool
		for _, mf := range metricFamilies {
			switch *mf.Name {
			case "oauth2_proxy_email_discovery_validation_errors_total":
				foundValidationMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"validation_type": "email_format", "error_reason": "invalid_format"}))
			case "oauth2_proxy_email_discovery_rate_limit_hits_total":
				foundRateLimitMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"limit_type": "discovery", "client_ip": "192.168.1.1"}))
			case "oauth2_proxy_email_discovery_suspicious_activity_total":
				foundSuspiciousMetric = true
				assert.Equal(t, float64(1), getCounterValue(mf, map[string]string{"activity_type": "repeated_failures", "domain": "suspicious.com"}))
			}
		}
		
		assert.True(t, foundValidationMetric, "Should have validation errors metric")
		assert.True(t, foundRateLimitMetric, "Should have rate limit hits metric")
		assert.True(t, foundSuspiciousMetric, "Should have suspicious activity metric")
	})

	t.Run("PerformanceMetrics", func(t *testing.T) {
		metrics.UpdateMemoryUsage(1024 * 1024) // 1MB
		metrics.UpdateGoroutineCount(50)
		
		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		
		var foundMemoryMetric, foundGoroutineMetric bool
		for _, mf := range metricFamilies {
			switch *mf.Name {
			case "oauth2_proxy_email_discovery_memory_usage_bytes":
				foundMemoryMetric = true
				assert.Equal(t, float64(1024*1024), getGaugeValue(mf))
			case "oauth2_proxy_email_discovery_goroutines_count":
				foundGoroutineMetric = true
				assert.Equal(t, float64(50), getGaugeValue(mf))
			}
		}
		
		assert.True(t, foundMemoryMetric, "Should have memory usage metric")
		assert.True(t, foundGoroutineMetric, "Should have goroutine count metric")
	})
}

func TestTimer(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	
	timer := metrics.StartTimer()
	
	// Simulate some work
	time.Sleep(10 * time.Millisecond)
	
	// Test discovery timer
	timer.ObserveDiscovery("dns", "example.com", "oidc", true, "")
	
	// Test DNS timer
	timer2 := metrics.StartTimer()
	time.Sleep(5 * time.Millisecond)
	timer2.ObserveDNS("example.com", "TXT", true, "")
	
	// Test HTTP timer
	timer3 := metrics.StartTimer()
	time.Sleep(15 * time.Millisecond)
	timer3.ObserveHTTP("example.com", "well-known", "200", true, "")
	
	// Verify that duration metrics were recorded
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	
	var foundDiscoveryDuration, foundDNSDuration, foundHTTPDuration bool
	for _, mf := range metricFamilies {
		switch *mf.Name {
		case "oauth2_proxy_email_discovery_discovery_duration_seconds":
			foundDiscoveryDuration = true
		case "oauth2_proxy_email_discovery_dns_query_duration_seconds":
			foundDNSDuration = true
		case "oauth2_proxy_email_discovery_http_request_duration_seconds":
			foundHTTPDuration = true
		}
	}
	
	assert.True(t, foundDiscoveryDuration, "Should have discovery duration metric")
	assert.True(t, foundDNSDuration, "Should have DNS duration metric")
	assert.True(t, foundHTTPDuration, "Should have HTTP duration metric")
}

func TestGetMetrics(t *testing.T) {
	// Test singleton behavior
	metrics1 := GetMetrics()
	metrics2 := GetMetrics()
	
	assert.Same(t, metrics1, metrics2, "GetMetrics should return the same instance")
}

func TestMetricsFamilies(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	
	// Add some metrics
	metrics.DiscoveryRequest("dns", "example.com")
	metrics.CacheHit("provider", "example.com")
	
	families, err := metrics.GetMetricFamilies()
	require.NoError(t, err)
	assert.NotEmpty(t, families, "Should return metric families")
}

// Helper function to get counter value from metric family
func getCounterValue(mf *dto.MetricFamily, labels map[string]string) float64 {
	for _, metric := range mf.Metric {
		if labelsMatch(metric.Label, labels) {
			return metric.Counter.GetValue()
		}
	}
	return 0
}

// Helper function to get gauge value from metric family
func getGaugeValue(mf *dto.MetricFamily) float64 {
	if len(mf.Metric) > 0 {
		return mf.Metric[0].Gauge.GetValue()
	}
	return 0
}

// Helper function to check if labels match
func labelsMatch(metricLabels []*dto.LabelPair, expectedLabels map[string]string) bool {
	if len(metricLabels) != len(expectedLabels) {
		return false
	}
	
	for _, label := range metricLabels {
		expectedValue, exists := expectedLabels[label.GetName()]
		if !exists || label.GetValue() != expectedValue {
			return false
		}
	}
	
	return true
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      string
		expected string
	}{
		{"timeout", "operation timeout", "timeout"},
		{"dns error", "dns lookup failed", "dns_error"},
		{"network error", "network unreachable", "network_error"},
		{"validation error", "invalid email format", "validation_error"},
		{"not found", "resource not found", "not_found"},
		{"forbidden", "access forbidden", "forbidden"},
		{"rate limit", "rate limit exceeded", "rate_limited"},
		{"unknown", "something else", "unknown"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{msg: tt.err}
			result := classifyError(err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected bool
	}{
		{"exact match", "timeout", "timeout", true},
		{"contains at start", "timeout error", "timeout", true},
		{"contains at end", "operation timeout", "timeout", true},
		{"contains in middle", "a timeout occurred", "timeout", true},
		{"not contains", "network error", "timeout", false},
		{"empty substring", "test", "", true},
		{"empty string", "", "test", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Benchmark tests for performance monitoring
func BenchmarkMetricsDiscoveryRequest(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.DiscoveryRequest("dns", "example.com")
	}
}

func BenchmarkMetricsTimer(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		timer := metrics.StartTimer()
		timer.ObserveDiscovery("dns", "example.com", "oidc", true, "")
	}
}

func BenchmarkClassifyError(b *testing.B) {
	err := &testError{msg: "network timeout occurred"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifyError(err)
	}
}

// Example test for documentation
func ExampleMetrics_DiscoveryRequest() {
	metrics := GetMetrics()
	
	// Track a DNS discovery request
	metrics.DiscoveryRequest("dns", "example.com")
	
	// Track successful discovery
	metrics.DiscoverySuccess("dns", "example.com", "oidc", 100*time.Millisecond)
}