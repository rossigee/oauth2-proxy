package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CircuitState represents the current state of a circuit breaker
type CircuitState int

const (
	// StateClosed - circuit is closed, requests are allowed
	StateClosed CircuitState = iota
	// StateOpen - circuit is open, requests are rejected
	StateOpen
	// StateHalfOpen - circuit is half-open, limited requests are allowed for testing
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig defines configuration for circuit breakers
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening
	FailureThreshold int `yaml:"failure_threshold" json:"failure_threshold"`
	
	// SuccessThreshold is the number of consecutive successes needed to close from half-open
	SuccessThreshold int `yaml:"success_threshold" json:"success_threshold"`
	
	// Timeout is how long to wait before transitioning from open to half-open
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	
	// MaxRequests is the maximum number of requests allowed in half-open state
	MaxRequests int `yaml:"max_requests" json:"max_requests"`
	
	// ResetTimeout is how long to wait before resetting failure counts
	ResetTimeout time.Duration `yaml:"reset_timeout" json:"reset_timeout"`
}

// GetDefaultCircuitBreakerConfig returns a secure default configuration
func GetDefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,                // Open after 5 consecutive failures
		SuccessThreshold: 3,                // Close after 3 consecutive successes in half-open
		Timeout:          30 * time.Second, // Wait 30s before trying half-open
		MaxRequests:      3,                // Allow only 3 requests in half-open state
		ResetTimeout:     60 * time.Second, // Reset failure count after 60s of no activity
	}
}

// CircuitBreaker implements the circuit breaker pattern for reliability
type CircuitBreaker struct {
	config           CircuitBreakerConfig
	state            CircuitState
	failureCount     int
	successCount     int
	lastFailureTime  time.Time
	lastSuccessTime  time.Time
	lastStateChange  time.Time
	halfOpenRequests int
	mutex           sync.RWMutex
	metrics         *Metrics
	name            string
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(name string, config CircuitBreakerConfig, metrics *Metrics) *CircuitBreaker {
	return &CircuitBreaker{
		config:          config,
		state:           StateClosed,
		lastStateChange: time.Now(),
		metrics:         metrics,
		name:           name,
	}
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	// Check if we can execute the request
	if !cb.allowRequest() {
		cb.metrics.CircuitBreakerState(cb.name, "rejected", cb.state.String())
		return fmt.Errorf("circuit breaker %s is open", cb.name)
	}

	// Execute the function and handle the result
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	if err != nil {
		cb.onFailure(duration)
		return err
	}

	cb.onSuccess(duration)
	return nil
}

// allowRequest checks if a request should be allowed based on current state
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()

	// Reset failure count if enough time has passed since last failure
	if cb.failureCount > 0 && now.Sub(cb.lastFailureTime) > cb.config.ResetTimeout {
		cb.failureCount = 0
		cb.metrics.CircuitBreakerEvent(cb.name, "failure_count_reset")
	}

	switch cb.state {
	case StateClosed:
		return true

	case StateOpen:
		// Check if we should transition to half-open
		if now.Sub(cb.lastStateChange) >= cb.config.Timeout {
			cb.toHalfOpen()
			return true
		}
		return false

	case StateHalfOpen:
		// Allow limited requests in half-open state
		if cb.halfOpenRequests < cb.config.MaxRequests {
			cb.halfOpenRequests++
			return true
		}
		return false

	default:
		return false
	}
}

// onSuccess handles successful execution
func (cb *CircuitBreaker) onSuccess(duration time.Duration) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.lastSuccessTime = time.Now()
	cb.metrics.CircuitBreakerOperation(cb.name, "success", duration)

	switch cb.state {
	case StateClosed:
		// Reset failure count on success
		if cb.failureCount > 0 {
			cb.failureCount = 0
			cb.metrics.CircuitBreakerEvent(cb.name, "failure_count_reset")
		}

	case StateHalfOpen:
		cb.successCount++
		cb.metrics.CircuitBreakerEvent(cb.name, "half_open_success")
		
		// Check if we should close the circuit
		if cb.successCount >= cb.config.SuccessThreshold {
			cb.toClosed()
		}
	}
}

// onFailure handles failed execution
func (cb *CircuitBreaker) onFailure(duration time.Duration) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount++
	cb.lastFailureTime = time.Now()
	cb.metrics.CircuitBreakerOperation(cb.name, "failure", duration)

	switch cb.state {
	case StateClosed:
		cb.metrics.CircuitBreakerEvent(cb.name, "failure_in_closed")
		
		// Check if we should open the circuit
		if cb.failureCount >= cb.config.FailureThreshold {
			cb.toOpen()
		}

	case StateHalfOpen:
		cb.metrics.CircuitBreakerEvent(cb.name, "failure_in_half_open")
		
		// Any failure in half-open state should open the circuit
		cb.toOpen()
	}
}

// toOpen transitions the circuit breaker to open state
func (cb *CircuitBreaker) toOpen() {
	cb.state = StateOpen
	cb.lastStateChange = time.Now()
	cb.successCount = 0
	cb.halfOpenRequests = 0
	cb.metrics.CircuitBreakerState(cb.name, "opened", "failure_threshold_exceeded")
}

// toHalfOpen transitions the circuit breaker to half-open state
func (cb *CircuitBreaker) toHalfOpen() {
	cb.state = StateHalfOpen
	cb.lastStateChange = time.Now()
	cb.successCount = 0
	cb.halfOpenRequests = 0
	cb.metrics.CircuitBreakerState(cb.name, "half_opened", "timeout_elapsed")
}

// toClosed transitions the circuit breaker to closed state
func (cb *CircuitBreaker) toClosed() {
	cb.state = StateClosed
	cb.lastStateChange = time.Now()
	cb.failureCount = 0
	cb.successCount = 0
	cb.halfOpenRequests = 0
	cb.metrics.CircuitBreakerState(cb.name, "closed", "success_threshold_met")
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetStats returns current statistics about the circuit breaker
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	return CircuitBreakerStats{
		Name:             cb.name,
		State:            cb.state,
		FailureCount:     cb.failureCount,
		SuccessCount:     cb.successCount,
		LastFailureTime:  cb.lastFailureTime,
		LastSuccessTime:  cb.lastSuccessTime,
		LastStateChange:  cb.lastStateChange,
		HalfOpenRequests: cb.halfOpenRequests,
	}
}

// CircuitBreakerStats represents circuit breaker statistics
type CircuitBreakerStats struct {
	Name             string        `json:"name"`
	State            CircuitState  `json:"state"`
	FailureCount     int          `json:"failure_count"`
	SuccessCount     int          `json:"success_count"`
	LastFailureTime  time.Time    `json:"last_failure_time"`
	LastSuccessTime  time.Time    `json:"last_success_time"`
	LastStateChange  time.Time    `json:"last_state_change"`
	HalfOpenRequests int          `json:"half_open_requests"`
}

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	config   CircuitBreakerConfig
	metrics  *Metrics
	mutex    sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager(config CircuitBreakerConfig, metrics *Metrics) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
		config:   config,
		metrics:  metrics,
	}
}

// GetCircuitBreaker gets or creates a circuit breaker for the given name
func (cbm *CircuitBreakerManager) GetCircuitBreaker(name string) *CircuitBreaker {
	cbm.mutex.RLock()
	if breaker, exists := cbm.breakers[name]; exists {
		cbm.mutex.RUnlock()
		return breaker
	}
	cbm.mutex.RUnlock()

	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if breaker, exists := cbm.breakers[name]; exists {
		return breaker
	}

	// Create new circuit breaker
	breaker := NewCircuitBreaker(name, cbm.config, cbm.metrics)
	cbm.breakers[name] = breaker
	cbm.metrics.CircuitBreakerEvent(name, "created")
	
	return breaker
}

// GetAllStats returns statistics for all circuit breakers
func (cbm *CircuitBreakerManager) GetAllStats() map[string]CircuitBreakerStats {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()
	
	stats := make(map[string]CircuitBreakerStats)
	for name, breaker := range cbm.breakers {
		stats[name] = breaker.GetStats()
	}
	
	return stats
}

// ResetAll resets all circuit breakers to closed state
func (cbm *CircuitBreakerManager) ResetAll() {
	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()
	
	for name, breaker := range cbm.breakers {
		breaker.mutex.Lock()
		breaker.toClosed()
		breaker.mutex.Unlock()
		cbm.metrics.CircuitBreakerEvent(name, "manual_reset")
	}
}

// Remove removes a circuit breaker
func (cbm *CircuitBreakerManager) Remove(name string) {
	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()
	
	if _, exists := cbm.breakers[name]; exists {
		delete(cbm.breakers, name)
		cbm.metrics.CircuitBreakerEvent(name, "removed")
	}
}