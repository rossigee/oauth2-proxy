# Rate Limiting and Circuit Breakers

This document describes the comprehensive rate limiting and circuit breaker implementation for the oauth2-proxy email discovery system.

## Overview

The email discovery system includes enterprise-grade reliability features:

- **Enhanced Rate Limiting**: Multi-dimensional rate limiting with priority support
- **Circuit Breakers**: Automatic failure detection and recovery
- **Reliability Manager**: Coordinated resilience with health monitoring
- **Comprehensive Metrics**: Full observability via Prometheus

## Rate Limiting System

### Multi-Dimensional Rate Limiting

The system provides rate limiting across multiple dimensions:

1. **Global Rate Limiting**: Overall system protection
2. **Domain-Specific Limiting**: Per-domain request controls  
3. **IP-Based Limiting**: Per-client IP protection
4. **User-Based Limiting**: Per-user account controls

### Priority-Based Requests

Request priorities allow preferential treatment:

- **Critical**: Always allowed if any tokens available
- **High**: Reserved capacity (configurable percentage)
- **Normal**: Standard processing
- **Low**: Lowest priority

### Exponential Backoff

When rate limits are exceeded, the system applies exponential backoff:

- **Initial Backoff**: Starting delay (default: 100ms)
- **Multiplier**: Backoff growth factor (default: 2.0)
- **Maximum Backoff**: Cap on backoff time (default: 30s)
- **Reset Period**: Time before violations reset (default: 60s)

### Configuration

```yaml
rate_limit:
  # Basic rate limits
  global_per_second: 50    # Global requests per second
  domain_per_minute: 10    # Per-domain requests per minute
  ip_per_minute: 30        # Per-IP requests per minute
  user_per_minute: 20      # Per-user requests per minute
  
  # Burst allowances
  global_burst: 100        # Global burst capacity
  domain_burst: 3          # Per-domain burst
  ip_burst: 10             # Per-IP burst
  user_burst: 5            # Per-user burst
  
  # Advanced features
  enable_adaptive: true    # Adaptive rate limiting
  enable_backpressure: true # Backpressure detection
  burst_multiplier: 1.5    # Dynamic burst adjustment
  
  # Priority settings
  enable_priority: true    # Priority-based processing
  high_priority_ratio: 0.3 # Reserved capacity for high priority
  
  # Backoff settings
  enable_exponential_backoff: true
  initial_backoff: "100ms"
  max_backoff: "30s"
  backoff_multiplier: 2.0
  
  # Cleanup settings
  cleanup_interval: "5m"   # Limiter cleanup interval
  limiter_ttl: "30m"       # Unused limiter TTL
```

## Circuit Breaker System

### Circuit Breaker States

Circuit breakers have three states:

1. **Closed**: Normal operation, requests allowed
2. **Open**: Failures detected, requests rejected
3. **Half-Open**: Testing recovery, limited requests allowed

### State Transitions

- **Closed → Open**: After configured failure threshold
- **Open → Half-Open**: After timeout period
- **Half-Open → Closed**: After success threshold
- **Half-Open → Open**: On any failure

### Configuration

```yaml
circuit_breaker:
  failure_threshold: 5     # Failures before opening
  success_threshold: 3     # Successes to close from half-open
  timeout: "30s"          # Time before trying half-open
  max_requests: 3         # Max requests in half-open
  reset_timeout: "60s"    # Failure count reset period
```

### Per-Service Circuit Breakers

The system automatically creates circuit breakers for different operations:

- **discovery**: Overall provider discovery
- **dns_query**: DNS-based discovery
- **http_request**: HTTP well-known discovery

## Reliability Manager

The `ReliabilityManager` coordinates all reliability features:

### Features

1. **Integrated Protection**: Combines rate limiting and circuit breakers
2. **Timeout Management**: Operation-specific timeouts
3. **Retry Logic**: Configurable retry with backoff
4. **Health Monitoring**: Service health tracking
5. **Metrics Collection**: Comprehensive observability

### Configuration

```yaml
reliability:
  # Timeout settings
  default_timeout: "30s"
  discovery_timeout: "10s"
  dns_timeout: "5s"
  http_timeout: "10s"
  
  # Retry settings
  enable_retry: true
  max_retries: 3
  retry_delay: "1s"
  retry_backoff: 2.0
  
  # Health check settings
  enable_health_check: true
  health_check_interval: "60s"
  health_threshold: 5
  
  # Monitoring settings
  enable_monitoring: true
  metrics_interval: "30s"
```

## Usage Examples

### Basic Usage

```go
// Create reliability manager
config := discovery.GetDefaultReliabilityConfig()
metrics := discovery.GetMetrics()
manager := discovery.NewReliabilityManager(config, metrics)

// Execute with protection
err := manager.ExecuteWithProtection(
    ctx,
    "discovery",     // operation name
    "example.com",   // domain
    "192.168.1.1",   // IP address
    "user123",       // user ID
    discovery.PriorityNormal, // priority
    func(ctx context.Context) error {
        // Your operation here
        return performDiscovery(ctx)
    },
)
```

### Retry with Backoff

```go
info, err := manager.DiscoverWithReliability(
    ctx,
    "example.com",
    "192.168.1.1", 
    "user123",
    func(ctx context.Context, domain string) (*discovery.ProviderInfo, error) {
        return discovery.PerformDiscovery(ctx, domain)
    },
)
```

### Direct Rate Limiting

```go
// Create enhanced rate limiter
config := discovery.GetDefaultEnhancedRateLimitConfig()
rateLimiter := discovery.NewEnhancedRateLimiter(config, metrics)

// Check rate limit
req := discovery.RateLimitRequest{
    Domain:    "example.com",
    IPAddress: "192.168.1.1",
    UserID:    "user123",
    Priority:  discovery.PriorityNormal,
    Operation: "discovery",
    Context:   ctx,
}

result := rateLimiter.CheckRateLimit(req)
if !result.Allowed {
    return fmt.Errorf("rate limited: %s", result.Reason)
}
```

### Direct Circuit Breaker

```go
// Create circuit breaker manager
config := discovery.GetDefaultCircuitBreakerConfig()
cbManager := discovery.NewCircuitBreakerManager(config, metrics)

// Get circuit breaker for operation
cb := cbManager.GetCircuitBreaker("discovery")

// Execute with circuit breaker
err := cb.Execute(ctx, func() error {
    return performOperation()
})
```

## Monitoring and Observability

### Prometheus Metrics

The system exports comprehensive metrics:

#### Rate Limiter Metrics
- `oauth2_proxy_email_discovery_rate_limiter_hits_total`
- `oauth2_proxy_email_discovery_rate_limiter_rejects_total`
- `oauth2_proxy_email_discovery_rate_limiter_backlog`

#### Circuit Breaker Metrics
- `oauth2_proxy_email_discovery_circuit_breaker_state`
- `oauth2_proxy_email_discovery_circuit_breaker_operations_total`
- `oauth2_proxy_email_discovery_circuit_breaker_events_total`
- `oauth2_proxy_email_discovery_circuit_breaker_operation_duration_seconds`

#### Health Metrics
- `oauth2_proxy_email_discovery_active_providers` (used for health status)
- `oauth2_proxy_email_discovery_validation_errors_total` (used for reliability events)

### Health Status

The reliability manager tracks health for all services:

```go
// Get health status
healthStatus := manager.GetHealthStatus()
for service, status := range healthStatus {
    fmt.Printf("Service: %s, Healthy: %v, Score: %.2f\n", 
        status.Service, status.Healthy, status.HealthScore)
}
```

### Statistics

```go
// Get comprehensive statistics
stats := manager.GetStats()
fmt.Printf("Rate Limiter: %+v\n", stats.RateLimiter)
fmt.Printf("Circuit Breakers: %+v\n", stats.CircuitBreakers)
fmt.Printf("Health Status: %+v\n", stats.HealthStatus)
```

## Best Practices

### Configuration

1. **Start Conservative**: Begin with stricter limits and relax as needed
2. **Monitor Closely**: Watch metrics to understand usage patterns
3. **Test Thoroughly**: Verify behavior under load and failure conditions
4. **Document Changes**: Track configuration changes and their impact

### Rate Limiting

1. **Use Priority Levels**: Implement priority-based request handling
2. **Monitor Backlog**: Watch limiter backlog sizes for capacity planning
3. **Adjust Burst Sizes**: Balance responsiveness with protection
4. **Regular Cleanup**: Ensure proper cleanup intervals to prevent memory leaks

### Circuit Breakers

1. **Operation-Specific**: Use separate circuit breakers for different operations
2. **Appropriate Thresholds**: Set failure thresholds based on operation criticality
3. **Monitor State Changes**: Track circuit breaker state transitions
4. **Test Recovery**: Verify proper recovery after failures

### Health Monitoring

1. **Define Health Checks**: Implement meaningful health checks for each service
2. **Set Thresholds**: Configure appropriate health thresholds
3. **Monitor Trends**: Track health scores over time
4. **Alerting**: Set up alerts for health degradation

## Integration with Email Discovery

The reliability features are integrated throughout the email discovery system:

### DNS Discovery
- Rate limiting per domain
- Circuit breaker for DNS queries
- Timeout protection
- Retry with exponential backoff

### HTTP Discovery
- Rate limiting per domain and IP
- Circuit breaker for HTTP requests
- TLS and security validation
- Response size limiting

### Provider Management
- Rate limiting per provider type
- Circuit breaker for provider creation
- Health monitoring for active providers
- Metrics for provider operations

## Troubleshooting

### Common Issues

1. **High Rate Limit Rejections**
   - Check rate limit configuration
   - Monitor client request patterns
   - Consider adjusting burst sizes
   - Review priority settings

2. **Circuit Breakers Always Open**
   - Check failure thresholds
   - Verify underlying service health
   - Review timeout settings
   - Monitor error patterns

3. **Poor Performance**
   - Check timeout settings
   - Review retry configuration
   - Monitor health check overhead
   - Optimize cleanup intervals

### Debugging

Enable debug logging and monitor metrics:

```bash
# Check rate limiter metrics
curl -s http://localhost:9090/metrics | grep rate_limiter

# Check circuit breaker metrics  
curl -s http://localhost:9090/metrics | grep circuit_breaker

# Check health metrics
curl -s http://localhost:9090/metrics | grep active_providers
```

## Security Considerations

1. **DoS Protection**: Rate limiting provides primary DoS protection
2. **Resource Limits**: Circuit breakers prevent resource exhaustion
3. **Input Validation**: All inputs are validated before processing
4. **Audit Logging**: All rate limit and circuit breaker events are logged
5. **Secure Defaults**: Default configurations prioritize security over performance

## Performance Impact

The reliability features are designed for minimal overhead:

- **Rate Limiting**: ~1-2μs per check
- **Circuit Breakers**: ~500ns per check when closed
- **Health Monitoring**: Background goroutines, minimal impact
- **Metrics Collection**: Asynchronous with buffering

## Future Enhancements

Planned improvements include:

1. **Adaptive Rate Limiting**: Machine learning-based rate adjustment
2. **Distributed Rate Limiting**: Coordination across multiple instances
3. **Advanced Circuit Breakers**: Dependency-aware circuit breaking
4. **Predictive Health**: Predictive health degradation detection
5. **Custom Policies**: User-defined rate limiting and circuit breaker policies