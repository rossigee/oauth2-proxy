package discovery

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// EnhancedRateLimitConfig defines comprehensive rate limiting configuration
type EnhancedRateLimitConfig struct {
	// Basic rate limits
	GlobalPerSecond    int           `yaml:"global_per_second" json:"global_per_second"`
	DomainPerMinute    int           `yaml:"domain_per_minute" json:"domain_per_minute"`
	IPPerMinute        int           `yaml:"ip_per_minute" json:"ip_per_minute"`
	UserPerMinute      int           `yaml:"user_per_minute" json:"user_per_minute"`
	
	// Burst allowances
	GlobalBurst        int           `yaml:"global_burst" json:"global_burst"`
	DomainBurst        int           `yaml:"domain_burst" json:"domain_burst"`
	IPBurst           int           `yaml:"ip_burst" json:"ip_burst"`
	UserBurst         int           `yaml:"user_burst" json:"user_burst"`
	
	// Advanced features
	EnableAdaptive     bool          `yaml:"enable_adaptive" json:"enable_adaptive"`
	EnableBackpressure bool          `yaml:"enable_backpressure" json:"enable_backpressure"`
	BurstMultiplier    float64       `yaml:"burst_multiplier" json:"burst_multiplier"`
	
	// Window settings
	CleanupInterval    time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
	LimiterTTL         time.Duration `yaml:"limiter_ttl" json:"limiter_ttl"`
	
	// Priority settings
	EnablePriority     bool          `yaml:"enable_priority" json:"enable_priority"`
	HighPriorityRatio  float64       `yaml:"high_priority_ratio" json:"high_priority_ratio"`
	
	// Backoff settings
	EnableExponentialBackoff bool          `yaml:"enable_exponential_backoff" json:"enable_exponential_backoff"`
	InitialBackoff          time.Duration `yaml:"initial_backoff" json:"initial_backoff"`
	MaxBackoff              time.Duration `yaml:"max_backoff" json:"max_backoff"`
	BackoffMultiplier       float64       `yaml:"backoff_multiplier" json:"backoff_multiplier"`
}

// GetDefaultEnhancedRateLimitConfig returns a secure default configuration
func GetDefaultEnhancedRateLimitConfig() EnhancedRateLimitConfig {
	return EnhancedRateLimitConfig{
		// Basic limits - more restrictive for security
		GlobalPerSecond: 50,   // 50 requests per second globally
		DomainPerMinute: 10,   // 10 requests per minute per domain
		IPPerMinute:     30,   // 30 requests per minute per IP
		UserPerMinute:   20,   // 20 requests per minute per user
		
		// Burst allowances - allow some spikes
		GlobalBurst: 100,      // Allow burst of 100 globally
		DomainBurst: 3,        // Allow burst of 3 per domain
		IPBurst:     10,       // Allow burst of 10 per IP
		UserBurst:   5,        // Allow burst of 5 per user
		
		// Advanced features
		EnableAdaptive:     true,
		EnableBackpressure: true,
		BurstMultiplier:    1.5,
		
		// Cleanup settings
		CleanupInterval: 5 * time.Minute,
		LimiterTTL:      30 * time.Minute,
		
		// Priority settings
		EnablePriority:    true,
		HighPriorityRatio: 0.3, // 30% of capacity reserved for high priority
		
		// Backoff settings
		EnableExponentialBackoff: true,
		InitialBackoff:          100 * time.Millisecond,
		MaxBackoff:              30 * time.Second,
		BackoffMultiplier:       2.0,
	}
}

// RequestPriority defines the priority level of a request
type RequestPriority int

const (
	PriorityLow RequestPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

func (p RequestPriority) String() string {
	switch p {
	case PriorityLow:
		return "low"
	case PriorityNormal:
		return "normal"
	case PriorityHigh:
		return "high"
	case PriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// RateLimitRequest represents a rate limit check request
type RateLimitRequest struct {
	Domain     string
	IPAddress  string
	UserID     string
	Priority   RequestPriority
	Operation  string
	Context    context.Context
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed      bool
	Reason       string
	BackoffTime  time.Duration
	RetryAfter   time.Duration
	QueuePosition int
}

// limiterEntry tracks a rate limiter with metadata
type limiterEntry struct {
	limiter    *rate.Limiter
	lastUsed   time.Time
	violations int
	backoffUntil time.Time
}

// EnhancedRateLimiter provides comprehensive rate limiting with advanced features
type EnhancedRateLimiter struct {
	config           EnhancedRateLimitConfig
	globalLimiter    *rate.Limiter
	domainLimiters   map[string]*limiterEntry
	ipLimiters       map[string]*limiterEntry
	userLimiters     map[string]*limiterEntry
	metrics          *Metrics
	mutex            sync.RWMutex
	cleanupTicker    *time.Ticker
	stopCleanup      chan struct{}
}

// NewEnhancedRateLimiter creates a new enhanced rate limiter
func NewEnhancedRateLimiter(config EnhancedRateLimitConfig, metrics *Metrics) *EnhancedRateLimiter {
	rl := &EnhancedRateLimiter{
		config:         config,
		globalLimiter:  rate.NewLimiter(rate.Limit(config.GlobalPerSecond), config.GlobalBurst),
		domainLimiters: make(map[string]*limiterEntry),
		ipLimiters:     make(map[string]*limiterEntry),
		userLimiters:   make(map[string]*limiterEntry),
		metrics:        metrics,
		stopCleanup:    make(chan struct{}),
	}

	// Start cleanup goroutine
	if config.CleanupInterval > 0 {
		rl.cleanupTicker = time.NewTicker(config.CleanupInterval)
		go rl.cleanupLoop()
	}

	return rl
}

// CheckRateLimit performs comprehensive rate limit checking
func (rl *EnhancedRateLimiter) CheckRateLimit(req RateLimitRequest) RateLimitResult {
	now := time.Now()
	
	// Check global rate limit first
	if !rl.checkGlobalLimit(req, now) {
		rl.metrics.RateLimiterReject("global", "all", "global_limit_exceeded")
		return RateLimitResult{
			Allowed:    false,
			Reason:     "global rate limit exceeded",
			RetryAfter: rl.calculateRetryAfter("global"),
		}
	}

	// Check domain-specific rate limit
	if req.Domain != "" {
		if result := rl.checkDomainLimit(req, now); !result.Allowed {
			rl.metrics.RateLimiterReject("domain", req.Domain, result.Reason)
			return result
		}
	}

	// Check IP-specific rate limit
	if req.IPAddress != "" {
		if result := rl.checkIPLimit(req, now); !result.Allowed {
			rl.metrics.RateLimiterReject("ip", req.IPAddress, result.Reason)
			return result
		}
	}

	// Check user-specific rate limit
	if req.UserID != "" {
		if result := rl.checkUserLimit(req, now); !result.Allowed {
			rl.metrics.RateLimiterReject("user", req.UserID, result.Reason)
			return result
		}
	}

	// All checks passed
	rl.metrics.RateLimiterHit("global", "allowed")
	return RateLimitResult{
		Allowed: true,
		Reason:  "rate_limit_passed",
	}
}

// checkGlobalLimit checks the global rate limit with priority handling
func (rl *EnhancedRateLimiter) checkGlobalLimit(req RateLimitRequest, now time.Time) bool {
	// For critical priority, allow some additional capacity
	if req.Priority == PriorityCritical {
		// Always allow critical requests if we have any tokens
		if rl.globalLimiter.Tokens() > 0 {
			return rl.globalLimiter.Allow()
		}
	}

	// For high priority, reserve some capacity
	if rl.config.EnablePriority && req.Priority >= PriorityHigh {
		reservedCapacity := float64(rl.config.GlobalBurst) * rl.config.HighPriorityRatio
		if rl.globalLimiter.Tokens() > reservedCapacity {
			return rl.globalLimiter.Allow()
		}
	}

	return rl.globalLimiter.Allow()
}

// checkDomainLimit checks domain-specific rate limit
func (rl *EnhancedRateLimiter) checkDomainLimit(req RateLimitRequest, now time.Time) RateLimitResult {
	entry := rl.getDomainLimiter(req.Domain, now)
	
	// Check if domain is in backoff period
	if rl.config.EnableExponentialBackoff && now.Before(entry.backoffUntil) {
		backoffRemaining := entry.backoffUntil.Sub(now)
		return RateLimitResult{
			Allowed:     false,
			Reason:      "domain_in_backoff",
			BackoffTime: backoffRemaining,
			RetryAfter:  backoffRemaining,
		}
	}

	// Check rate limit
	if !entry.limiter.Allow() {
		entry.violations++
		
		// Apply exponential backoff if enabled
		if rl.config.EnableExponentialBackoff {
			backoffDuration := rl.calculateBackoffDuration(entry.violations)
			entry.backoffUntil = now.Add(backoffDuration)
		}
		
		return RateLimitResult{
			Allowed:    false,
			Reason:     "domain_rate_limit_exceeded",
			RetryAfter: rl.calculateRetryAfter("domain"),
		}
	}

	// Reset violations on successful request
	entry.violations = 0
	entry.backoffUntil = time.Time{}
	
	return RateLimitResult{Allowed: true}
}

// checkIPLimit checks IP-specific rate limit
func (rl *EnhancedRateLimiter) checkIPLimit(req RateLimitRequest, now time.Time) RateLimitResult {
	entry := rl.getIPLimiter(req.IPAddress, now)
	
	// Check if IP is in backoff period
	if rl.config.EnableExponentialBackoff && now.Before(entry.backoffUntil) {
		backoffRemaining := entry.backoffUntil.Sub(now)
		return RateLimitResult{
			Allowed:     false,
			Reason:      "ip_in_backoff",
			BackoffTime: backoffRemaining,
			RetryAfter:  backoffRemaining,
		}
	}

	// Check rate limit
	if !entry.limiter.Allow() {
		entry.violations++
		
		// Apply exponential backoff if enabled
		if rl.config.EnableExponentialBackoff {
			backoffDuration := rl.calculateBackoffDuration(entry.violations)
			entry.backoffUntil = now.Add(backoffDuration)
		}
		
		return RateLimitResult{
			Allowed:    false,
			Reason:     "ip_rate_limit_exceeded",
			RetryAfter: rl.calculateRetryAfter("ip"),
		}
	}

	// Reset violations on successful request
	entry.violations = 0
	entry.backoffUntil = time.Time{}
	
	return RateLimitResult{Allowed: true}
}

// checkUserLimit checks user-specific rate limit
func (rl *EnhancedRateLimiter) checkUserLimit(req RateLimitRequest, now time.Time) RateLimitResult {
	entry := rl.getUserLimiter(req.UserID, now)
	
	// Check if user is in backoff period
	if rl.config.EnableExponentialBackoff && now.Before(entry.backoffUntil) {
		backoffRemaining := entry.backoffUntil.Sub(now)
		return RateLimitResult{
			Allowed:     false,
			Reason:      "user_in_backoff",
			BackoffTime: backoffRemaining,
			RetryAfter:  backoffRemaining,
		}
	}

	// Check rate limit
	if !entry.limiter.Allow() {
		entry.violations++
		
		// Apply exponential backoff if enabled
		if rl.config.EnableExponentialBackoff {
			backoffDuration := rl.calculateBackoffDuration(entry.violations)
			entry.backoffUntil = now.Add(backoffDuration)
		}
		
		return RateLimitResult{
			Allowed:    false,
			Reason:     "user_rate_limit_exceeded",
			RetryAfter: rl.calculateRetryAfter("user"),
		}
	}

	// Reset violations on successful request
	entry.violations = 0
	entry.backoffUntil = time.Time{}
	
	return RateLimitResult{Allowed: true}
}

// getDomainLimiter gets or creates a domain-specific rate limiter
func (rl *EnhancedRateLimiter) getDomainLimiter(domain string, now time.Time) *limiterEntry {
	rl.mutex.RLock()
	if entry, exists := rl.domainLimiters[domain]; exists {
		entry.lastUsed = now
		rl.mutex.RUnlock()
		return entry
	}
	rl.mutex.RUnlock()

	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if entry, exists := rl.domainLimiters[domain]; exists {
		entry.lastUsed = now
		return entry
	}

	// Create new limiter
	domainRate := rl.config.DomainPerMinute
	if domainRate == 0 {
		domainRate = 1 // Prevent divide by zero
	}
	perMinute := rate.Every(time.Minute / time.Duration(domainRate))
	entry := &limiterEntry{
		limiter:  rate.NewLimiter(perMinute, rl.config.DomainBurst),
		lastUsed: now,
	}
	
	rl.domainLimiters[domain] = entry
	rl.metrics.RateLimiterBacklog("domain", domain, float64(len(rl.domainLimiters)))
	
	return entry
}

// getIPLimiter gets or creates an IP-specific rate limiter
func (rl *EnhancedRateLimiter) getIPLimiter(ip string, now time.Time) *limiterEntry {
	rl.mutex.RLock()
	if entry, exists := rl.ipLimiters[ip]; exists {
		entry.lastUsed = now
		rl.mutex.RUnlock()
		return entry
	}
	rl.mutex.RUnlock()

	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if entry, exists := rl.ipLimiters[ip]; exists {
		entry.lastUsed = now
		return entry
	}

	// Create new limiter
	ipRate := rl.config.IPPerMinute
	if ipRate == 0 {
		ipRate = 1 // Prevent divide by zero
	}
	perMinute := rate.Every(time.Minute / time.Duration(ipRate))
	entry := &limiterEntry{
		limiter:  rate.NewLimiter(perMinute, rl.config.IPBurst),
		lastUsed: now,
	}
	
	rl.ipLimiters[ip] = entry
	rl.metrics.RateLimiterBacklog("ip", ip, float64(len(rl.ipLimiters)))
	
	return entry
}

// getUserLimiter gets or creates a user-specific rate limiter
func (rl *EnhancedRateLimiter) getUserLimiter(userID string, now time.Time) *limiterEntry {
	rl.mutex.RLock()
	if entry, exists := rl.userLimiters[userID]; exists {
		entry.lastUsed = now
		rl.mutex.RUnlock()
		return entry
	}
	rl.mutex.RUnlock()

	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if entry, exists := rl.userLimiters[userID]; exists {
		entry.lastUsed = now
		return entry
	}

	// Create new limiter
	userRate := rl.config.UserPerMinute
	if userRate == 0 {
		userRate = 1 // Prevent divide by zero
	}
	perMinute := rate.Every(time.Minute / time.Duration(userRate))
	entry := &limiterEntry{
		limiter:  rate.NewLimiter(perMinute, rl.config.UserBurst),
		lastUsed: now,
	}
	
	rl.userLimiters[userID] = entry
	rl.metrics.RateLimiterBacklog("user", userID, float64(len(rl.userLimiters)))
	
	return entry
}

// calculateBackoffDuration calculates exponential backoff duration
func (rl *EnhancedRateLimiter) calculateBackoffDuration(violations int) time.Duration {
	if !rl.config.EnableExponentialBackoff {
		return 0
	}

	backoff := rl.config.InitialBackoff
	for i := 1; i < violations; i++ {
		backoff = time.Duration(float64(backoff) * rl.config.BackoffMultiplier)
		if backoff > rl.config.MaxBackoff {
			backoff = rl.config.MaxBackoff
			break
		}
	}
	
	return backoff
}

// calculateRetryAfter calculates when a client should retry
func (rl *EnhancedRateLimiter) calculateRetryAfter(limiterType string) time.Duration {
	switch limiterType {
	case "global":
		return time.Second / time.Duration(rl.config.GlobalPerSecond)
	case "domain":
		return time.Minute / time.Duration(rl.config.DomainPerMinute)
	case "ip":
		return time.Minute / time.Duration(rl.config.IPPerMinute)
	case "user":
		return time.Minute / time.Duration(rl.config.UserPerMinute)
	default:
		return time.Second
	}
}

// cleanupLoop periodically removes expired limiters
func (rl *EnhancedRateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// cleanup removes expired limiters to prevent memory leaks
func (rl *EnhancedRateLimiter) cleanup() {
	now := time.Now()
	cutoff := now.Add(-rl.config.LimiterTTL)

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	// Clean up domain limiters
	for domain, entry := range rl.domainLimiters {
		if entry.lastUsed.Before(cutoff) {
			delete(rl.domainLimiters, domain)
		}
	}

	// Clean up IP limiters
	for ip, entry := range rl.ipLimiters {
		if entry.lastUsed.Before(cutoff) {
			delete(rl.ipLimiters, ip)
		}
	}

	// Clean up user limiters
	for userID, entry := range rl.userLimiters {
		if entry.lastUsed.Before(cutoff) {
			delete(rl.userLimiters, userID)
		}
	}

	// Update metrics
	rl.metrics.RateLimiterBacklog("domain", "total", float64(len(rl.domainLimiters)))
	rl.metrics.RateLimiterBacklog("ip", "total", float64(len(rl.ipLimiters)))
	rl.metrics.RateLimiterBacklog("user", "total", float64(len(rl.userLimiters)))
}

// Stop stops the cleanup goroutine
func (rl *EnhancedRateLimiter) Stop() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
		close(rl.stopCleanup)
	}
}

// GetStats returns current rate limiter statistics
func (rl *EnhancedRateLimiter) GetStats() EnhancedRateLimiterStats {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	return EnhancedRateLimiterStats{
		GlobalTokens:     rl.globalLimiter.Tokens(),
		DomainLimiters:   len(rl.domainLimiters),
		IPLimiters:       len(rl.ipLimiters),
		UserLimiters:     len(rl.userLimiters),
		Config:           rl.config,
	}
}

// EnhancedRateLimiterStats represents statistics for the enhanced rate limiter
type EnhancedRateLimiterStats struct {
	GlobalTokens   float64                     `json:"global_tokens"`
	DomainLimiters int                         `json:"domain_limiters"`
	IPLimiters     int                         `json:"ip_limiters"`
	UserLimiters   int                         `json:"user_limiters"`
	Config         EnhancedRateLimitConfig     `json:"config"`
}