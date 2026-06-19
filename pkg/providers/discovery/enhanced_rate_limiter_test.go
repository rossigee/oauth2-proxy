package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestEnhancedRateLimiterBasicLimits(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond: 100, // High enough not to interfere with specific tests
		DomainPerMinute: 100, // High enough for IP testing
		IPPerMinute:     4,
		UserPerMinute:   5,
		GlobalBurst:     100,
		DomainBurst:     10, // High enough for IP testing
		IPBurst:         2,
		UserBurst:       2,
		CleanupInterval: time.Hour, // Disable cleanup for testing
		LimiterTTL:      time.Hour,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	// Skip global rate limit test since we set it high for other tests
	// Global rate limiting will be tested separately

	// Domain testing moved to separate test due to higher domain limits needed for IP testing

	t.Run("IPSpecificLimit", func(t *testing.T) {

		req := RateLimitRequest{
			Domain:    "unique-ip-test.com", // Use unique domain
			IPAddress: "10.0.0.1",
			UserID:    "user3",
			Priority:  PriorityNormal,
			Operation: "test",
			Context:   context.Background(),
		}

		// Should allow initial requests up to IP burst
		for i := 0; i < config.IPBurst; i++ {
			result := rl.CheckRateLimit(req)
			assert.True(t, result.Allowed, "IP request %d should be allowed", i+1)
		}

		// Should reject additional requests from this IP
		result := rl.CheckRateLimit(req)
		assert.False(t, result.Allowed)
		assert.Contains(t, result.Reason, "ip")

		// But should allow requests from a different IP
		req.IPAddress = "10.0.0.2"
		req.Domain = "another-unique-ip-test.com" // Also change domain to avoid domain limit
		req.UserID = "different-user"             // Also change user to avoid user limit
		result = rl.CheckRateLimit(req)
		if !result.Allowed {
			t.Logf("Different IP rejection reason: %s", result.Reason)
		}
		assert.True(t, result.Allowed, "Different IP should be allowed")
	})
}

func TestEnhancedRateLimiterDomainLimits(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond: 100, // High enough not to interfere
		DomainPerMinute: 100, // High per minute rate
		IPPerMinute:     100,
		UserPerMinute:   100,
		GlobalBurst:     100,
		DomainBurst:     1, // Low burst to test domain limiting
		IPBurst:         10,
		UserBurst:       10,
		CleanupInterval: time.Hour,
		LimiterTTL:      time.Hour,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	req := RateLimitRequest{
		Domain:    "test.com",
		IPAddress: "192.168.1.2",
		UserID:    "user2",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	// Should allow initial requests up to domain burst
	for i := 0; i < config.DomainBurst; i++ {
		result := rl.CheckRateLimit(req)
		assert.True(t, result.Allowed, "Domain request %d should be allowed", i+1)
	}

	// Should reject additional requests for this domain
	result := rl.CheckRateLimit(req)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "domain")

	// But should allow requests for a different domain
	req.Domain = "other.com"
	result = rl.CheckRateLimit(req)
	assert.True(t, result.Allowed, "Different domain should be allowed")
}

func TestEnhancedRateLimiterGlobalLimits(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond: 1000, // Very high rate
		GlobalBurst:     2,    // But low burst
		DomainPerMinute: 100,  // High enough not to interfere
		DomainBurst:     10,   // High enough not to interfere
		IPPerMinute:     100,
		IPBurst:         10, // High enough not to interfere
		UserPerMinute:   100,
		UserBurst:       10, // High enough not to interfere
		CleanupInterval: time.Hour,
		LimiterTTL:      time.Hour,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	req := RateLimitRequest{
		Domain:    "example.com",
		IPAddress: "192.168.1.1",
		UserID:    "user1",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	// Should allow initial requests up to burst
	for i := 0; i < config.GlobalBurst; i++ {
		result := rl.CheckRateLimit(req)
		assert.True(t, result.Allowed, "Request %d should be allowed", i+1)
	}

	// Should reject additional requests beyond burst
	result := rl.CheckRateLimit(req)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "global")
}

func TestEnhancedRateLimiterPriority(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond:   1,
		GlobalBurst:       3,
		DomainPerMinute:   100, // Add domain limits to avoid divide by zero
		DomainBurst:       10,  // High enough not to interfere
		IPPerMinute:       100,
		IPBurst:           10, // High enough not to interfere
		UserPerMinute:     100,
		UserBurst:         10, // High enough not to interfere
		EnablePriority:    true,
		HighPriorityRatio: 0.5, // Reserve 50% for high priority
		CleanupInterval:   time.Hour,
		LimiterTTL:        time.Hour,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	// Exhaust most of the burst capacity with normal priority
	normalReq := RateLimitRequest{
		Domain:    "example.com",
		IPAddress: "192.168.1.1",
		UserID:    "user1",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	result := rl.CheckRateLimit(normalReq)
	assert.True(t, result.Allowed, "First normal request should be allowed")

	// High priority request should still be allowed due to reserved capacity
	highReq := normalReq
	highReq.Priority = PriorityHigh

	result = rl.CheckRateLimit(highReq)
	assert.True(t, result.Allowed, "High priority request should be allowed")

	// Critical priority should always be allowed if any tokens exist
	criticalReq := normalReq
	criticalReq.Priority = PriorityCritical

	result = rl.CheckRateLimit(criticalReq)
	assert.True(t, result.Allowed, "Critical priority request should be allowed")
}

func TestEnhancedRateLimiterExponentialBackoff(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond:          10,  // High enough to not interfere
		GlobalBurst:              10,  // High enough not to interfere
		DomainPerMinute:          600, // 10 per second, fast enough to refill during test
		DomainBurst:              1,   // Very restrictive to trigger backoff
		IPPerMinute:              100, // High enough not to interfere
		IPBurst:                  10,  // High enough not to interfere
		UserPerMinute:            100, // High enough not to interfere
		UserBurst:                10,  // High enough not to interfere
		EnableExponentialBackoff: true,
		InitialBackoff:           50 * time.Millisecond,
		MaxBackoff:               200 * time.Millisecond,
		BackoffMultiplier:        2.0,
		CleanupInterval:          time.Hour,
		LimiterTTL:               time.Hour,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	req := RateLimitRequest{
		Domain:    "example.com",
		IPAddress: "192.168.1.1",
		UserID:    "user1",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	// First request should be allowed
	result := rl.CheckRateLimit(req)
	assert.True(t, result.Allowed)

	// Second request should be rate limited
	result = rl.CheckRateLimit(req)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "domain")

	// Subsequent requests should be in backoff
	result = rl.CheckRateLimit(req)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "backoff")
	assert.True(t, result.BackoffTime > 0)

	// Wait for backoff to expire AND for rate limiter to refill
	time.Sleep(result.BackoffTime + 200*time.Millisecond) // Extra time for rate limiter refill

	// Request should be allowed again after backoff expires
	result = rl.CheckRateLimit(req)
	assert.True(t, result.Allowed)
}

func TestEnhancedRateLimiterCleanup(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond: 10,
		GlobalBurst:     10, // High enough not to interfere
		DomainPerMinute: 10,
		DomainBurst:     10,  // High enough not to interfere
		IPPerMinute:     100, // High enough not to interfere
		IPBurst:         10,  // High enough not to interfere
		CleanupInterval: 100 * time.Millisecond,
		LimiterTTL:      200 * time.Millisecond,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	// Create a domain limiter
	req := RateLimitRequest{
		Domain:    "example.com",
		IPAddress: "192.168.1.1",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	result := rl.CheckRateLimit(req)
	assert.True(t, result.Allowed)

	// Check that limiter exists
	stats := rl.GetStats()
	assert.Equal(t, 1, stats.DomainLimiters)

	// Wait for TTL to expire and cleanup to run
	time.Sleep(config.LimiterTTL + config.CleanupInterval + 50*time.Millisecond)

	// Check that limiter was cleaned up
	stats = rl.GetStats()
	assert.Equal(t, 0, stats.DomainLimiters)
}

func TestEnhancedRateLimiterStats(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := GetDefaultEnhancedRateLimitConfig()

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	// Initial stats
	stats := rl.GetStats()
	assert.Equal(t, 0, stats.DomainLimiters)
	assert.Equal(t, 0, stats.IPLimiters)
	assert.Equal(t, 0, stats.UserLimiters)
	assert.True(t, stats.GlobalTokens > 0)

	// Create some limiters
	req1 := RateLimitRequest{
		Domain:    "example.com",
		IPAddress: "192.168.1.1",
		UserID:    "user1",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	req2 := RateLimitRequest{
		Domain:    "test.com",
		IPAddress: "192.168.1.2",
		UserID:    "user2",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	rl.CheckRateLimit(req1)
	rl.CheckRateLimit(req2)

	stats = rl.GetStats()
	assert.Equal(t, 2, stats.DomainLimiters)
	assert.Equal(t, 2, stats.IPLimiters)
	assert.Equal(t, 2, stats.UserLimiters)
}

func TestRateLimitRequestPriority(t *testing.T) {
	tests := []struct {
		priority RequestPriority
		expected string
	}{
		{PriorityLow, "low"},
		{PriorityNormal, "normal"},
		{PriorityHigh, "high"},
		{PriorityCritical, "critical"},
		{RequestPriority(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.priority.String())
		})
	}
}

func TestEnhancedRateLimiterUserLimits(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond: 100, // High enough to not interfere
		GlobalBurst:     10,  // High enough not to interfere
		DomainPerMinute: 100, // High enough not to interfere
		DomainBurst:     10,  // High enough not to interfere
		IPPerMinute:     100, // High enough not to interfere
		IPBurst:         10,  // High enough not to interfere
		UserPerMinute:   2,
		UserBurst:       1,
		CleanupInterval: time.Hour,
		LimiterTTL:      time.Hour,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	req := RateLimitRequest{
		Domain:    "example.com",
		IPAddress: "192.168.1.1",
		UserID:    "testuser",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	// First request should be allowed
	result := rl.CheckRateLimit(req)
	assert.True(t, result.Allowed)

	// Second request should be rate limited
	result = rl.CheckRateLimit(req)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "user")

	// Different user should still be allowed
	req.UserID = "otheruser"
	result = rl.CheckRateLimit(req)
	assert.True(t, result.Allowed)
}

func TestEnhancedRateLimiterBackoffCalculation(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		EnableExponentialBackoff: true,
		InitialBackoff:           100 * time.Millisecond,
		MaxBackoff:               1 * time.Second,
		BackoffMultiplier:        2.0,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	tests := []struct {
		violations int
		expected   time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1 * time.Second},  // Should cap at MaxBackoff
		{10, 1 * time.Second}, // Should still cap at MaxBackoff
	}

	for _, tt := range tests {
		t.Run("Violations"+string(rune(tt.violations)), func(t *testing.T) {
			backoff := rl.calculateBackoffDuration(tt.violations)
			assert.Equal(t, tt.expected, backoff)
		})
	}
}

func TestEnhancedRateLimiterRetryAfter(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)

	config := EnhancedRateLimitConfig{
		GlobalPerSecond: 10,
		DomainPerMinute: 60,
		IPPerMinute:     120,
		UserPerMinute:   30,
	}

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	tests := []struct {
		limiterType string
		expected    time.Duration
	}{
		{"global", 100 * time.Millisecond}, // 1/10 second
		{"domain", 1 * time.Second},        // 60/60 = 1 second
		{"ip", 500 * time.Millisecond},     // 60/120 = 0.5 second
		{"user", 2 * time.Second},          // 60/30 = 2 seconds
		{"unknown", 1 * time.Second},       // Default
	}

	for _, tt := range tests {
		t.Run(tt.limiterType, func(t *testing.T) {
			retryAfter := rl.calculateRetryAfter(tt.limiterType)
			assert.Equal(t, tt.expected, retryAfter)
		})
	}
}

// Benchmark tests
func BenchmarkEnhancedRateLimiter(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := GetDefaultEnhancedRateLimitConfig()
	config.CleanupInterval = time.Hour // Disable cleanup for benchmarking

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	req := RateLimitRequest{
		Domain:    "example.com",
		IPAddress: "192.168.1.1",
		UserID:    "user1",
		Priority:  PriorityNormal,
		Operation: "test",
		Context:   context.Background(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.CheckRateLimit(req)
	}
}

func BenchmarkEnhancedRateLimiterConcurrent(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := GetDefaultEnhancedRateLimitConfig()
	config.CleanupInterval = time.Hour

	rl := NewEnhancedRateLimiter(config, metrics)
	defer rl.Stop()

	b.RunParallel(func(pb *testing.PB) {
		req := RateLimitRequest{
			Domain:    "example.com",
			IPAddress: "192.168.1.1",
			UserID:    "user1",
			Priority:  PriorityNormal,
			Operation: "test",
			Context:   context.Background(),
		}

		for pb.Next() {
			rl.CheckRateLimit(req)
		}
	})
}
