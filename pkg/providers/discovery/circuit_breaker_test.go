package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestCircuitBreakerStates(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		MaxRequests:      2,
		ResetTimeout:     500 * time.Millisecond,
	}

	cb := NewCircuitBreaker("test", config, metrics)

	// Initially should be closed
	assert.Equal(t, StateClosed, cb.GetState())

	t.Run("ClosedToOpen", func(t *testing.T) {
		// Trigger enough failures to open the circuit
		for i := 0; i < config.FailureThreshold; i++ {
			err := cb.Execute(context.Background(), func() error {
				return errors.New("test failure")
			})
			assert.Error(t, err)
		}

		// Circuit should now be open
		assert.Equal(t, StateOpen, cb.GetState())
	})

	t.Run("OpenRejectsRequests", func(t *testing.T) {
		// Requests should be rejected when circuit is open
		err := cb.Execute(context.Background(), func() error {
			return nil
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circuit breaker")
	})

	t.Run("OpenToHalfOpen", func(t *testing.T) {
		// Wait for timeout to transition to half-open
		time.Sleep(config.Timeout + 10*time.Millisecond)

		// First request should be allowed (transitioning to half-open)
		err := cb.Execute(context.Background(), func() error {
			return nil
		})
		assert.NoError(t, err)

		assert.Equal(t, StateHalfOpen, cb.GetState())
	})

	t.Run("HalfOpenToClosed", func(t *testing.T) {
		// Execute enough successful requests to close the circuit
		for i := 0; i < config.SuccessThreshold-1; i++ {
			err := cb.Execute(context.Background(), func() error {
				return nil
			})
			assert.NoError(t, err)
		}

		// Circuit should now be closed
		assert.Equal(t, StateClosed, cb.GetState())
	})

	t.Run("HalfOpenToOpen", func(t *testing.T) {
		// First, open the circuit again
		for i := 0; i < config.FailureThreshold; i++ {
			cb.Execute(context.Background(), func() error {
				return errors.New("test failure")
			})
		}

		// Wait for timeout and transition to half-open
		time.Sleep(config.Timeout + 10*time.Millisecond)
		
		// First request should succeed (to half-open)
		err := cb.Execute(context.Background(), func() error {
			return nil
		})
		assert.NoError(t, err)
		assert.Equal(t, StateHalfOpen, cb.GetState())

		// Now fail a request in half-open state
		err = cb.Execute(context.Background(), func() error {
			return errors.New("test failure")
		})
		assert.Error(t, err)

		// Circuit should immediately open again
		assert.Equal(t, StateOpen, cb.GetState())
	})
}

func TestCircuitBreakerLimitsInHalfOpen(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 3,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      2,
		ResetTimeout:     200 * time.Millisecond,
	}

	cb := NewCircuitBreaker("test", config, metrics)

	// Open the circuit
	for i := 0; i < config.FailureThreshold; i++ {
		cb.Execute(context.Background(), func() error {
			return errors.New("test failure")
		})
	}

	// Wait for timeout and transition to half-open
	time.Sleep(config.Timeout + 10*time.Millisecond)

	// Execute max allowed requests in half-open state
	for i := 0; i < config.MaxRequests; i++ {
		err := cb.Execute(context.Background(), func() error {
			return nil
		})
		assert.NoError(t, err)
	}

	// Additional requests should be rejected
	err := cb.Execute(context.Background(), func() error {
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker")
}

func TestCircuitBreakerManager(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := GetDefaultCircuitBreakerConfig()

	mgr := NewCircuitBreakerManager(config, metrics)

	t.Run("CreateCircuitBreakers", func(t *testing.T) {
		cb1 := mgr.GetCircuitBreaker("service1")
		cb2 := mgr.GetCircuitBreaker("service2")
		cb1Again := mgr.GetCircuitBreaker("service1")

		assert.NotNil(t, cb1)
		assert.NotNil(t, cb2)
		assert.Same(t, cb1, cb1Again)
		assert.NotSame(t, cb1, cb2)
	})

	t.Run("GetAllStats", func(t *testing.T) {
		cb1 := mgr.GetCircuitBreaker("service1")
		mgr.GetCircuitBreaker("service2") // Create service2 but don't need to store

		// Trigger some failures on service1
		for i := 0; i < 3; i++ {
			cb1.Execute(context.Background(), func() error {
				return errors.New("test failure")
			})
		}

		stats := mgr.GetAllStats()
		assert.Len(t, stats, 2)
		assert.Contains(t, stats, "service1")
		assert.Contains(t, stats, "service2")

		service1Stats := stats["service1"]
		assert.Equal(t, 3, service1Stats.FailureCount)
	})

	t.Run("ResetAll", func(t *testing.T) {
		// Open circuits for both services
		cb1 := mgr.GetCircuitBreaker("service1")
		cb2 := mgr.GetCircuitBreaker("service2")

		for i := 0; i < config.FailureThreshold; i++ {
			cb1.Execute(context.Background(), func() error {
				return errors.New("test failure")
			})
			cb2.Execute(context.Background(), func() error {
				return errors.New("test failure")
			})
		}

		assert.Equal(t, StateOpen, cb1.GetState())
		assert.Equal(t, StateOpen, cb2.GetState())

		// Reset all circuits
		mgr.ResetAll()

		assert.Equal(t, StateClosed, cb1.GetState())
		assert.Equal(t, StateClosed, cb2.GetState())
	})
}

func TestCircuitBreakerStats(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		MaxRequests:      5,
		ResetTimeout:     500 * time.Millisecond,
	}

	cb := NewCircuitBreaker("test", config, metrics)

	// Initial stats
	stats := cb.GetStats()
	assert.Equal(t, "test", stats.Name)
	assert.Equal(t, StateClosed, stats.State)
	assert.Equal(t, 0, stats.FailureCount)
	assert.Equal(t, 0, stats.SuccessCount)

	// Execute some operations
	cb.Execute(context.Background(), func() error {
		return nil // success
	})
	cb.Execute(context.Background(), func() error {
		return errors.New("failure")
	})

	stats = cb.GetStats()
	assert.Equal(t, StateClosed, stats.State)
	assert.Equal(t, 1, stats.FailureCount)
	assert.True(t, stats.LastSuccessTime.After(time.Time{}))
	assert.True(t, stats.LastFailureTime.After(time.Time{}))
}

func TestCircuitBreakerWithContext(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := GetDefaultCircuitBreakerConfig()

	cb := NewCircuitBreaker("test", config, metrics)

	t.Run("ContextCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := cb.Execute(ctx, func() error {
			time.Sleep(100 * time.Millisecond)
			return nil
		})

		assert.Error(t, err)
		// The function should still be executed and might complete or be cancelled
	})

	t.Run("ContextTimeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err := cb.Execute(ctx, func() error {
			time.Sleep(100 * time.Millisecond)
			return nil
		})

		// The circuit breaker Execute method doesn't directly handle context timeout
		// That's handled at a higher level in the reliability manager
		assert.NoError(t, err) // Function completes successfully
	})
}

func TestCircuitBreakerFailureClassification(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		MaxRequests:      5,
		ResetTimeout:     500 * time.Millisecond,
	}

	cb := NewCircuitBreaker("test", config, metrics)

	tests := []struct {
		name     string
		err      error
		isFailure bool
	}{
		{"Success", nil, false},
		{"Timeout", errors.New("timeout"), true},
		{"Network", errors.New("network error"), true},
		{"DNS", errors.New("dns lookup failed"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cb.Execute(context.Background(), func() error {
				return tt.err
			})

			if tt.isFailure {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCircuitBreakerResetTimeout(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      5,
		ResetTimeout:     100 * time.Millisecond,
	}

	cb := NewCircuitBreaker("test", config, metrics)

	// Record one failure
	cb.Execute(context.Background(), func() error {
		return errors.New("test failure")
	})

	stats := cb.GetStats()
	assert.Equal(t, 1, stats.FailureCount)

	// Wait for reset timeout
	time.Sleep(config.ResetTimeout + 10*time.Millisecond)

	// Execute a successful request - this should reset failure count
	err := cb.Execute(context.Background(), func() error {
		return nil
	})
	assert.NoError(t, err)

	// The failure count should be reset after the successful request
	stats = cb.GetStats()
	assert.Equal(t, 0, stats.FailureCount)
}

// Benchmark tests
func BenchmarkCircuitBreakerExecute(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := GetDefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker("test", config, metrics)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Execute(context.Background(), func() error {
			return nil
		})
	}
}

func BenchmarkCircuitBreakerManager(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	config := GetDefaultCircuitBreakerConfig()
	mgr := NewCircuitBreakerManager(config, metrics)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		circuitBreaker := mgr.GetCircuitBreaker("test_service")
		circuitBreaker.Execute(context.Background(), func() error {
			return nil
		})
	}
}