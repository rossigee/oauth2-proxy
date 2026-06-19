package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ReliabilityConfig defines comprehensive reliability settings
type ReliabilityConfig struct {
	// Rate limiting configuration
	RateLimit EnhancedRateLimitConfig `yaml:"rate_limit" json:"rate_limit"`

	// Circuit breaker configuration
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`

	// Timeout settings
	DefaultTimeout   time.Duration `yaml:"default_timeout" json:"default_timeout"`
	DiscoveryTimeout time.Duration `yaml:"discovery_timeout" json:"discovery_timeout"`
	DNSTimeout       time.Duration `yaml:"dns_timeout" json:"dns_timeout"`
	HTTPTimeout      time.Duration `yaml:"http_timeout" json:"http_timeout"`

	// Retry settings
	EnableRetry  bool          `yaml:"enable_retry" json:"enable_retry"`
	MaxRetries   int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay   time.Duration `yaml:"retry_delay" json:"retry_delay"`
	RetryBackoff float64       `yaml:"retry_backoff" json:"retry_backoff"`

	// Health check settings
	EnableHealthCheck   bool          `yaml:"enable_health_check" json:"enable_health_check"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	HealthThreshold     int           `yaml:"health_threshold" json:"health_threshold"`

	// Monitoring settings
	EnableMonitoring bool          `yaml:"enable_monitoring" json:"enable_monitoring"`
	MetricsInterval  time.Duration `yaml:"metrics_interval" json:"metrics_interval"`
}

// GetDefaultReliabilityConfig returns a secure default configuration
func GetDefaultReliabilityConfig() ReliabilityConfig {
	return ReliabilityConfig{
		RateLimit:      GetDefaultEnhancedRateLimitConfig(),
		CircuitBreaker: GetDefaultCircuitBreakerConfig(),

		// Timeout settings
		DefaultTimeout:   30 * time.Second,
		DiscoveryTimeout: 10 * time.Second,
		DNSTimeout:       5 * time.Second,
		HTTPTimeout:      10 * time.Second,

		// Retry settings
		EnableRetry:  true,
		MaxRetries:   3,
		RetryDelay:   1 * time.Second,
		RetryBackoff: 2.0,

		// Health check settings
		EnableHealthCheck:   true,
		HealthCheckInterval: 60 * time.Second,
		HealthThreshold:     5,

		// Monitoring settings
		EnableMonitoring: true,
		MetricsInterval:  30 * time.Second,
	}
}

// ReliabilityManager provides comprehensive reliability features
type ReliabilityManager struct {
	config            ReliabilityConfig
	rateLimiter       *EnhancedRateLimiter
	circuitBreakerMgr *CircuitBreakerManager
	metrics           *Metrics
	healthStatus      map[string]*HealthStatus
	healthMutex       sync.RWMutex
	stopHealthCheck   chan struct{}
	stopMonitoring    chan struct{}
}

// HealthStatus tracks the health of a service endpoint
type HealthStatus struct {
	Service      string        `json:"service"`
	Healthy      bool          `json:"healthy"`
	LastCheck    time.Time     `json:"last_check"`
	FailureCount int           `json:"failure_count"`
	SuccessCount int           `json:"success_count"`
	LastError    string        `json:"last_error,omitempty"`
	ResponseTime time.Duration `json:"response_time"`
	HealthScore  float64       `json:"health_score"`
}

// NewReliabilityManager creates a new reliability manager
func NewReliabilityManager(config ReliabilityConfig, metrics *Metrics) *ReliabilityManager {
	rm := &ReliabilityManager{
		config:            config,
		rateLimiter:       NewEnhancedRateLimiter(config.RateLimit, metrics),
		circuitBreakerMgr: NewCircuitBreakerManager(config.CircuitBreaker, metrics),
		metrics:           metrics,
		healthStatus:      make(map[string]*HealthStatus),
		stopHealthCheck:   make(chan struct{}),
		stopMonitoring:    make(chan struct{}),
	}

	// Start health checking if enabled
	if config.EnableHealthCheck {
		go rm.healthCheckLoop()
	}

	// Start monitoring if enabled
	if config.EnableMonitoring {
		go rm.monitoringLoop()
	}

	return rm
}

// ExecuteWithProtection executes a function with comprehensive protection
func (rm *ReliabilityManager) ExecuteWithProtection(
	ctx context.Context,
	operation string,
	domain string,
	ipAddress string,
	userID string,
	priority RequestPriority,
	fn func(context.Context) error,
) error {
	// Step 1: Rate limiting check
	rateLimitReq := RateLimitRequest{
		Domain:    domain,
		IPAddress: ipAddress,
		UserID:    userID,
		Priority:  priority,
		Operation: operation,
		Context:   ctx,
	}

	rateLimitResult := rm.rateLimiter.CheckRateLimit(rateLimitReq)
	if !rateLimitResult.Allowed {
		rm.metrics.ReliabilityEvent("rate_limit_rejected", operation, rateLimitResult.Reason)
		return fmt.Errorf("rate limit exceeded: %s", rateLimitResult.Reason)
	}

	// Step 2: Circuit breaker protection
	circuitBreaker := rm.circuitBreakerMgr.GetCircuitBreaker(operation)

	// Step 3: Execute with timeout and circuit breaker
	return rm.executeWithTimeout(ctx, operation, circuitBreaker, fn)
}

// executeWithTimeout executes a function with timeout and circuit breaker protection
func (rm *ReliabilityManager) executeWithTimeout(
	ctx context.Context,
	operation string,
	circuitBreaker *CircuitBreaker,
	fn func(context.Context) error,
) error {
	// Create timeout context
	timeout := rm.getTimeoutForOperation(operation)
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute with circuit breaker protection
	return circuitBreaker.Execute(timeoutCtx, func() error {
		return fn(timeoutCtx)
	})
}

// ExecuteWithRetry executes a function with retry logic
func (rm *ReliabilityManager) ExecuteWithRetry(
	ctx context.Context,
	operation string,
	domain string,
	ipAddress string,
	userID string,
	priority RequestPriority,
	fn func(context.Context) error,
) error {
	if !rm.config.EnableRetry {
		return rm.ExecuteWithProtection(ctx, operation, domain, ipAddress, userID, priority, fn)
	}

	var lastErr error
	for attempt := 0; attempt <= rm.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Calculate backoff delay
			delay := time.Duration(float64(rm.config.RetryDelay) *
				(rm.config.RetryBackoff * float64(attempt-1)))

			rm.metrics.ReliabilityEvent("retry_attempt", operation, fmt.Sprintf("attempt_%d", attempt))

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := rm.ExecuteWithProtection(ctx, operation, domain, ipAddress, userID, priority, fn)
		if err == nil {
			if attempt > 0 {
				rm.metrics.ReliabilityEvent("retry_success", operation, fmt.Sprintf("attempt_%d", attempt))
			}
			return nil
		}

		lastErr = err

		// Don't retry on rate limit errors or circuit breaker errors
		if isNonRetryableError(err) {
			break
		}
	}

	rm.metrics.ReliabilityEvent("retry_failed", operation, "max_retries_exceeded")
	return lastErr
}

// DiscoverWithReliability performs provider discovery with full reliability protection
func (rm *ReliabilityManager) DiscoverWithReliability(
	ctx context.Context,
	domain string,
	ipAddress string,
	userID string,
	discoveryFn func(context.Context, string) (*ProviderInfo, error),
) (*ProviderInfo, error) {
	var result *ProviderInfo

	err := rm.ExecuteWithRetry(
		ctx,
		"discovery",
		domain,
		ipAddress,
		userID,
		PriorityNormal,
		func(ctx context.Context) error {
			info, err := discoveryFn(ctx, domain)
			if err != nil {
				rm.updateHealthStatus("discovery", false, err.Error(), 0)
				return err
			}

			result = info
			rm.updateHealthStatus("discovery", true, "", 0)
			return nil
		},
	)

	return result, err
}

// DNSQueryWithReliability performs DNS queries with reliability protection
func (rm *ReliabilityManager) DNSQueryWithReliability(
	ctx context.Context,
	domain string,
	ipAddress string,
	queryFn func(context.Context, string) ([]string, error),
) ([]string, error) {
	var result []string

	err := rm.ExecuteWithRetry(
		ctx,
		"dns_query",
		domain,
		ipAddress,
		"",
		PriorityNormal,
		func(ctx context.Context) error {
			start := time.Now()
			records, err := queryFn(ctx, domain)
			duration := time.Since(start)

			if err != nil {
				rm.updateHealthStatus("dns", false, err.Error(), duration)
				return err
			}

			result = records
			rm.updateHealthStatus("dns", true, "", duration)
			return nil
		},
	)

	return result, err
}

// HTTPRequestWithReliability performs HTTP requests with reliability protection
func (rm *ReliabilityManager) HTTPRequestWithReliability(
	ctx context.Context,
	domain string,
	ipAddress string,
	requestFn func(context.Context, string) (*ProviderInfo, error),
) (*ProviderInfo, error) {
	var result *ProviderInfo

	err := rm.ExecuteWithRetry(
		ctx,
		"http_request",
		domain,
		ipAddress,
		"",
		PriorityNormal,
		func(ctx context.Context) error {
			start := time.Now()
			info, err := requestFn(ctx, domain)
			duration := time.Since(start)

			if err != nil {
				rm.updateHealthStatus("http", false, err.Error(), duration)
				return err
			}

			result = info
			rm.updateHealthStatus("http", true, "", duration)
			return nil
		},
	)

	return result, err
}

// getTimeoutForOperation returns the appropriate timeout for an operation
func (rm *ReliabilityManager) getTimeoutForOperation(operation string) time.Duration {
	switch operation {
	case "discovery":
		return rm.config.DiscoveryTimeout
	case "dns_query":
		return rm.config.DNSTimeout
	case "http_request":
		return rm.config.HTTPTimeout
	default:
		return rm.config.DefaultTimeout
	}
}

// updateHealthStatus updates the health status of a service
func (rm *ReliabilityManager) updateHealthStatus(service string, healthy bool, errorMsg string, responseTime time.Duration) {
	rm.healthMutex.Lock()
	defer rm.healthMutex.Unlock()

	status, exists := rm.healthStatus[service]
	if !exists {
		status = &HealthStatus{
			Service: service,
			Healthy: true,
		}
		rm.healthStatus[service] = status
	}

	status.LastCheck = time.Now()
	status.ResponseTime = responseTime

	if healthy {
		status.SuccessCount++
		status.LastError = ""

		// Improve health score
		status.HealthScore = calculateHealthScore(status.SuccessCount, status.FailureCount)

		// Mark as healthy if enough successes
		if status.SuccessCount >= rm.config.HealthThreshold {
			status.Healthy = true
		}
	} else {
		status.FailureCount++
		status.LastError = errorMsg

		// Decrease health score
		status.HealthScore = calculateHealthScore(status.SuccessCount, status.FailureCount)

		// Mark as unhealthy if enough failures
		if status.FailureCount >= rm.config.HealthThreshold {
			status.Healthy = false
		}
	}

	// Report health metrics
	healthValue := 0.0
	if status.Healthy {
		healthValue = 1.0
	}
	rm.metrics.ServiceHealth(service, healthValue, status.HealthScore)
}

// calculateHealthScore calculates a health score based on success/failure ratio
func calculateHealthScore(successCount, failureCount int) float64 {
	total := successCount + failureCount
	if total == 0 {
		return 1.0
	}

	score := float64(successCount) / float64(total)

	// Apply decay factor for recent failures
	if failureCount > 0 {
		decayFactor := 1.0 - (float64(failureCount) / float64(total+10))
		score *= decayFactor
	}

	return score
}

// healthCheckLoop periodically checks service health
func (rm *ReliabilityManager) healthCheckLoop() {
	ticker := time.NewTicker(rm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.performHealthChecks()
		case <-rm.stopHealthCheck:
			return
		}
	}
}

// performHealthChecks performs health checks on all services
func (rm *ReliabilityManager) performHealthChecks() {
	rm.healthMutex.RLock()
	services := make([]string, 0, len(rm.healthStatus))
	for service := range rm.healthStatus {
		services = append(services, service)
	}
	rm.healthMutex.RUnlock()

	for _, service := range services {
		rm.performServiceHealthCheck(service)
	}
}

// performServiceHealthCheck performs a health check for a specific service
func (rm *ReliabilityManager) performServiceHealthCheck(service string) {
	// This is a basic health check - in practice, you might want to implement
	// specific health check logic for each service type

	rm.healthMutex.RLock()
	status, exists := rm.healthStatus[service]
	if !exists {
		rm.healthMutex.RUnlock()
		return
	}

	// Simple health check: if no recent activity, mark as unknown
	lastActivity := status.LastCheck
	rm.healthMutex.RUnlock()

	if time.Since(lastActivity) > rm.config.HealthCheckInterval*2 {
		rm.updateHealthStatus(service, false, "no_recent_activity", 0)
	}
}

// monitoringLoop periodically reports metrics
func (rm *ReliabilityManager) monitoringLoop() {
	ticker := time.NewTicker(rm.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.reportMetrics()
		case <-rm.stopMonitoring:
			return
		}
	}
}

// reportMetrics reports current system metrics
func (rm *ReliabilityManager) reportMetrics() {
	// Report rate limiter stats
	rateLimiterStats := rm.rateLimiter.GetStats()
	rm.metrics.ReliabilityMetric("rate_limiter_global_tokens", rateLimiterStats.GlobalTokens)
	rm.metrics.ReliabilityMetric("rate_limiter_domain_count", float64(rateLimiterStats.DomainLimiters))
	rm.metrics.ReliabilityMetric("rate_limiter_ip_count", float64(rateLimiterStats.IPLimiters))
	rm.metrics.ReliabilityMetric("rate_limiter_user_count", float64(rateLimiterStats.UserLimiters))

	// Report circuit breaker stats
	circuitBreakerStats := rm.circuitBreakerMgr.GetAllStats()
	for name, stats := range circuitBreakerStats {
		rm.metrics.CircuitBreakerState(name, "current", stats.State.String())
		rm.metrics.ReliabilityMetric("circuit_breaker_failure_count", float64(stats.FailureCount))
		rm.metrics.ReliabilityMetric("circuit_breaker_success_count", float64(stats.SuccessCount))
	}

	// Report health status
	rm.healthMutex.RLock()
	for service, status := range rm.healthStatus {
		healthValue := 0.0
		if status.Healthy {
			healthValue = 1.0
		}
		rm.metrics.ServiceHealth(service, healthValue, status.HealthScore)
	}
	rm.healthMutex.RUnlock()
}

// GetHealthStatus returns current health status for all services
func (rm *ReliabilityManager) GetHealthStatus() map[string]*HealthStatus {
	rm.healthMutex.RLock()
	defer rm.healthMutex.RUnlock()

	result := make(map[string]*HealthStatus)
	for service, status := range rm.healthStatus {
		// Create a copy to avoid race conditions
		statusCopy := *status
		result[service] = &statusCopy
	}

	return result
}

// GetStats returns comprehensive reliability statistics
func (rm *ReliabilityManager) GetStats() ReliabilityStats {
	return ReliabilityStats{
		RateLimiter:     rm.rateLimiter.GetStats(),
		CircuitBreakers: rm.circuitBreakerMgr.GetAllStats(),
		HealthStatus:    rm.GetHealthStatus(),
		Config:          rm.config,
	}
}

// Stop stops all background processes
func (rm *ReliabilityManager) Stop() {
	rm.rateLimiter.Stop()

	if rm.config.EnableHealthCheck {
		close(rm.stopHealthCheck)
	}

	if rm.config.EnableMonitoring {
		close(rm.stopMonitoring)
	}
}

// ReliabilityStats represents comprehensive reliability statistics
type ReliabilityStats struct {
	RateLimiter     EnhancedRateLimiterStats       `json:"rate_limiter"`
	CircuitBreakers map[string]CircuitBreakerStats `json:"circuit_breakers"`
	HealthStatus    map[string]*HealthStatus       `json:"health_status"`
	Config          ReliabilityConfig              `json:"config"`
}

// isNonRetryableError checks if an error should not be retried
func isNonRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return contains(errStr, "rate limit") ||
		contains(errStr, "circuit breaker") ||
		contains(errStr, "validation") ||
		contains(errStr, "forbidden") ||
		contains(errStr, "unauthorized")
}
