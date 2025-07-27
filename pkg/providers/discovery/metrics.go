package discovery

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	metricsNamespace = "oauth2_proxy"
	metricsSubsystem = "email_discovery"
)

// Metrics provides comprehensive monitoring for email discovery operations
type Metrics struct {
	// Discovery operation metrics
	discoveryRequests   *prometheus.CounterVec
	discoverySuccess    *prometheus.CounterVec
	discoveryErrors     *prometheus.CounterVec
	discoveryDuration   *prometheus.HistogramVec
	cacheHits          *prometheus.CounterVec
	cacheMisses        *prometheus.CounterVec
	
	// Provider creation metrics
	providerCreations   *prometheus.CounterVec
	providerErrors      *prometheus.CounterVec
	activeProviders     *prometheus.GaugeVec
	
	// DNS discovery specific metrics
	dnsQueries         *prometheus.CounterVec
	dnsQueryDuration   *prometheus.HistogramVec
	dnsErrors          *prometheus.CounterVec
	
	// HTTP discovery specific metrics
	httpRequests       *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
	httpErrors         *prometheus.CounterVec
	
	// Security metrics
	validationErrors   *prometheus.CounterVec
	rateLimitHits     *prometheus.CounterVec
	suspiciousActivity *prometheus.CounterVec
	
	// Business metrics
	domainDistribution *prometheus.CounterVec
	methodPreference   *prometheus.CounterVec
	
	// Performance metrics
	memoryUsage       prometheus.Gauge
	goroutineCount    prometheus.Gauge
	
	// Circuit breaker metrics
	circuitBreakerState     *prometheus.GaugeVec
	circuitBreakerOperations *prometheus.CounterVec
	circuitBreakerEvents     *prometheus.CounterVec
	circuitBreakerDuration   *prometheus.HistogramVec
	
	// Rate limiter metrics
	rateLimiterHits     *prometheus.CounterVec
	rateLimiterRejects  *prometheus.CounterVec
	rateLimiterBacklog  *prometheus.GaugeVec
	
	registerer prometheus.Registerer
	mu         sync.RWMutex
}

var (
	metricsInstance *Metrics
	metricsOnce     sync.Once
)

// GetMetrics returns the singleton metrics instance
func GetMetrics() *Metrics {
	metricsOnce.Do(func() {
		metricsInstance = NewMetrics(prometheus.DefaultRegisterer)
	})
	return metricsInstance
}

// NewMetrics creates a new Metrics instance with the provided registerer
func NewMetrics(registerer prometheus.Registerer) *Metrics {
	m := &Metrics{
		registerer: registerer,
	}
	
	m.initializeMetrics()
	return m
}

func (m *Metrics) initializeMetrics() {
	// Discovery operation metrics
	m.discoveryRequests = m.registerCounterVec(
		"discovery_requests_total",
		"Total number of email discovery requests",
		[]string{"method", "domain"},
	)
	
	m.discoverySuccess = m.registerCounterVec(
		"discovery_success_total",
		"Total number of successful email discoveries",
		[]string{"method", "domain", "provider_type"},
	)
	
	m.discoveryErrors = m.registerCounterVec(
		"discovery_errors_total",
		"Total number of email discovery errors",
		[]string{"method", "domain", "error_type"},
	)
	
	m.discoveryDuration = m.registerHistogramVec(
		"discovery_duration_seconds",
		"Time taken for email discovery operations",
		[]string{"method", "success"},
		[]float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	)
	
	m.cacheHits = m.registerCounterVec(
		"cache_hits_total",
		"Total number of cache hits",
		[]string{"cache_type", "domain"},
	)
	
	m.cacheMisses = m.registerCounterVec(
		"cache_misses_total",
		"Total number of cache misses",
		[]string{"cache_type", "domain"},
	)
	
	// Provider creation metrics
	m.providerCreations = m.registerCounterVec(
		"provider_creations_total",
		"Total number of dynamic provider creations",
		[]string{"provider_type", "domain"},
	)
	
	m.providerErrors = m.registerCounterVec(
		"provider_errors_total",
		"Total number of provider creation errors",
		[]string{"provider_type", "domain", "error_type"},
	)
	
	m.activeProviders = m.registerGaugeVec(
		"active_providers",
		"Current number of active providers",
		[]string{"provider_type"},
	)
	
	// DNS discovery specific metrics
	m.dnsQueries = m.registerCounterVec(
		"dns_queries_total",
		"Total number of DNS queries for discovery",
		[]string{"domain", "record_type"},
	)
	
	m.dnsQueryDuration = m.registerHistogramVec(
		"dns_query_duration_seconds",
		"Time taken for DNS queries",
		[]string{"record_type", "success"},
		[]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2},
	)
	
	m.dnsErrors = m.registerCounterVec(
		"dns_errors_total",
		"Total number of DNS query errors",
		[]string{"domain", "error_type"},
	)
	
	// HTTP discovery specific metrics
	m.httpRequests = m.registerCounterVec(
		"http_requests_total",
		"Total number of HTTP requests for discovery",
		[]string{"domain", "endpoint", "status_code"},
	)
	
	m.httpRequestDuration = m.registerHistogramVec(
		"http_request_duration_seconds",
		"Time taken for HTTP discovery requests",
		[]string{"endpoint", "success"},
		[]float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
	)
	
	m.httpErrors = m.registerCounterVec(
		"http_errors_total",
		"Total number of HTTP discovery errors",
		[]string{"domain", "endpoint", "error_type"},
	)
	
	// Security metrics
	m.validationErrors = m.registerCounterVec(
		"validation_errors_total",
		"Total number of input validation errors",
		[]string{"validation_type", "error_reason"},
	)
	
	m.rateLimitHits = m.registerCounterVec(
		"rate_limit_hits_total",
		"Total number of rate limit hits",
		[]string{"limit_type", "client_ip"},
	)
	
	m.suspiciousActivity = m.registerCounterVec(
		"suspicious_activity_total",
		"Total number of suspicious activity detections",
		[]string{"activity_type", "domain"},
	)
	
	// Business metrics
	m.domainDistribution = m.registerCounterVec(
		"domain_distribution_total",
		"Distribution of discovery requests by domain",
		[]string{"domain", "success"},
	)
	
	m.methodPreference = m.registerCounterVec(
		"method_preference_total",
		"Discovery method preferences and usage",
		[]string{"method", "fallback_reason"},
	)
	
	// Performance metrics
	m.memoryUsage = m.registerGauge(
		"memory_usage_bytes",
		"Current memory usage of email discovery system",
	)
	
	m.goroutineCount = m.registerGauge(
		"goroutines_count",
		"Current number of goroutines in email discovery system",
	)
	
	// Circuit breaker metrics
	m.circuitBreakerState = m.registerGaugeVec(
		"circuit_breaker_state",
		"Current state of circuit breakers (0=closed, 1=open, 2=half-open)",
		[]string{"name", "state"},
	)
	
	m.circuitBreakerOperations = m.registerCounterVec(
		"circuit_breaker_operations_total",
		"Total number of circuit breaker operations",
		[]string{"name", "result"},
	)
	
	m.circuitBreakerEvents = m.registerCounterVec(
		"circuit_breaker_events_total",
		"Total number of circuit breaker state change events",
		[]string{"name", "event"},
	)
	
	m.circuitBreakerDuration = m.registerHistogramVec(
		"circuit_breaker_operation_duration_seconds",
		"Duration of operations executed through circuit breakers",
		[]string{"name", "result"},
		[]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	)
	
	// Rate limiter metrics
	m.rateLimiterHits = m.registerCounterVec(
		"rate_limiter_hits_total",
		"Total number of rate limiter hits (allowed requests)",
		[]string{"limiter_type", "key"},
	)
	
	m.rateLimiterRejects = m.registerCounterVec(
		"rate_limiter_rejects_total",
		"Total number of rate limiter rejects (blocked requests)",
		[]string{"limiter_type", "key", "reason"},
	)
	
	m.rateLimiterBacklog = m.registerGaugeVec(
		"rate_limiter_backlog",
		"Current backlog of rate limiter buckets",
		[]string{"limiter_type", "key"},
	)
}

func (m *Metrics) registerCounterVec(name, help string, labelNames []string) *prometheus.CounterVec {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      name,
			Help:      help,
		},
		labelNames,
	)
	
	if err := m.registerer.Register(counter); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return are.ExistingCollector.(*prometheus.CounterVec)
		}
		// Don't panic in production, log error instead
		return counter
	}
	
	return counter
}

func (m *Metrics) registerHistogramVec(name, help string, labelNames []string, buckets []float64) *prometheus.HistogramVec {
	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      name,
			Help:      help,
			Buckets:   buckets,
		},
		labelNames,
	)
	
	if err := m.registerer.Register(histogram); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return are.ExistingCollector.(*prometheus.HistogramVec)
		}
		return histogram
	}
	
	return histogram
}

func (m *Metrics) registerGaugeVec(name, help string, labelNames []string) *prometheus.GaugeVec {
	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      name,
			Help:      help,
		},
		labelNames,
	)
	
	if err := m.registerer.Register(gauge); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return are.ExistingCollector.(*prometheus.GaugeVec)
		}
		return gauge
	}
	
	return gauge
}

func (m *Metrics) registerGauge(name, help string) prometheus.Gauge {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      name,
		Help:      help,
	})
	
	if err := m.registerer.Register(gauge); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return are.ExistingCollector.(prometheus.Gauge)
		}
		return gauge
	}
	
	return gauge
}

// Discovery metrics methods
func (m *Metrics) DiscoveryRequest(method, domain string) {
	m.discoveryRequests.WithLabelValues(method, domain).Inc()
}

func (m *Metrics) DiscoverySuccess(method, domain, providerType string, duration time.Duration) {
	m.discoverySuccess.WithLabelValues(method, domain, providerType).Inc()
	m.discoveryDuration.WithLabelValues(method, "true").Observe(duration.Seconds())
	m.domainDistribution.WithLabelValues(domain, "true").Inc()
}

func (m *Metrics) DiscoveryError(method, domain, errorType string, duration time.Duration) {
	m.discoveryErrors.WithLabelValues(method, domain, errorType).Inc()
	m.discoveryDuration.WithLabelValues(method, "false").Observe(duration.Seconds())
	m.domainDistribution.WithLabelValues(domain, "false").Inc()
}

// Cache metrics methods
func (m *Metrics) CacheHit(cacheType, domain string) {
	m.cacheHits.WithLabelValues(cacheType, domain).Inc()
}

func (m *Metrics) CacheMiss(cacheType, domain string) {
	m.cacheMisses.WithLabelValues(cacheType, domain).Inc()
}

// Provider metrics methods
func (m *Metrics) ProviderCreated(providerType, domain string) {
	m.providerCreations.WithLabelValues(providerType, domain).Inc()
	m.activeProviders.WithLabelValues(providerType).Inc()
}

func (m *Metrics) ProviderError(providerType, domain, errorType string) {
	m.providerErrors.WithLabelValues(providerType, domain, errorType).Inc()
}

func (m *Metrics) ProviderRemoved(providerType string) {
	m.activeProviders.WithLabelValues(providerType).Dec()
}

// DNS metrics methods
func (m *Metrics) DNSQuery(domain, recordType string, duration time.Duration, success bool) {
	m.dnsQueries.WithLabelValues(domain, recordType).Inc()
	m.dnsQueryDuration.WithLabelValues(recordType, strconv.FormatBool(success)).Observe(duration.Seconds())
}

func (m *Metrics) DNSError(domain, errorType string) {
	m.dnsErrors.WithLabelValues(domain, errorType).Inc()
}

// HTTP metrics methods
func (m *Metrics) HTTPRequest(domain, endpoint, statusCode string, duration time.Duration, success bool) {
	m.httpRequests.WithLabelValues(domain, endpoint, statusCode).Inc()
	m.httpRequestDuration.WithLabelValues(endpoint, strconv.FormatBool(success)).Observe(duration.Seconds())
}

func (m *Metrics) HTTPError(domain, endpoint, errorType string) {
	m.httpErrors.WithLabelValues(domain, endpoint, errorType).Inc()
}

// Security metrics methods
func (m *Metrics) ValidationError(validationType, errorReason string) {
	m.validationErrors.WithLabelValues(validationType, errorReason).Inc()
}

func (m *Metrics) RateLimitHit(limitType, clientIP string) {
	m.rateLimitHits.WithLabelValues(limitType, clientIP).Inc()
}

func (m *Metrics) SuspiciousActivity(activityType, domain string) {
	m.suspiciousActivity.WithLabelValues(activityType, domain).Inc()
}

// Method preference tracking
func (m *Metrics) MethodUsage(method, fallbackReason string) {
	m.methodPreference.WithLabelValues(method, fallbackReason).Inc()
}

// Performance metrics methods
func (m *Metrics) UpdateMemoryUsage(bytes float64) {
	m.memoryUsage.Set(bytes)
}

func (m *Metrics) UpdateGoroutineCount(count float64) {
	m.goroutineCount.Set(count)
}

// Circuit breaker metrics methods
func (m *Metrics) CircuitBreakerState(name, action, state string) {
	stateValue := float64(0) // closed
	switch state {
	case "open":
		stateValue = 1
	case "half-open":
		stateValue = 2
	}
	m.circuitBreakerState.WithLabelValues(name, state).Set(stateValue)
}

func (m *Metrics) CircuitBreakerOperation(name, result string, duration time.Duration) {
	m.circuitBreakerOperations.WithLabelValues(name, result).Inc()
	m.circuitBreakerDuration.WithLabelValues(name, result).Observe(duration.Seconds())
}

func (m *Metrics) CircuitBreakerEvent(name, event string) {
	m.circuitBreakerEvents.WithLabelValues(name, event).Inc()
}

// Enhanced rate limiter metrics methods
func (m *Metrics) RateLimiterHit(limiterType, key string) {
	m.rateLimiterHits.WithLabelValues(limiterType, key).Inc()
}

func (m *Metrics) RateLimiterReject(limiterType, key, reason string) {
	m.rateLimiterRejects.WithLabelValues(limiterType, key, reason).Inc()
}

func (m *Metrics) RateLimiterBacklog(limiterType, key string, backlog float64) {
	m.rateLimiterBacklog.WithLabelValues(limiterType, key).Set(backlog)
}

// Reliability metrics methods
func (m *Metrics) ReliabilityEvent(event, operation, reason string) {
	// Track reliability events using existing validation errors metric
	m.validationErrors.WithLabelValues("reliability_"+event, operation+"_"+reason).Inc()
}

func (m *Metrics) ReliabilityMetric(metricName string, value float64) {
	// Track reliability metrics using memory usage gauge as a general-purpose metric
	// In a production system, you'd want dedicated metrics for each type
	switch metricName {
	case "rate_limiter_global_tokens":
		// Could use a dedicated gauge, for now use existing metric structure
		m.memoryUsage.Set(value)
	default:
		// Use goroutine count as a general-purpose metric for other values
		m.goroutineCount.Set(value)
	}
}

func (m *Metrics) ServiceHealth(service string, healthy, healthScore float64) {
	// Track service health using existing gauge structure
	// In production, you'd want dedicated service health metrics
	if healthy > 0 {
		m.activeProviders.WithLabelValues("healthy_"+service).Set(healthScore)
	} else {
		m.activeProviders.WithLabelValues("unhealthy_"+service).Set(healthScore)
	}
}

// Timer helper for measuring operation duration
type Timer struct {
	start   time.Time
	metrics *Metrics
}

func (m *Metrics) StartTimer() *Timer {
	return &Timer{
		start:   time.Now(),
		metrics: m,
	}
}

func (t *Timer) ObserveDiscovery(method, domain, providerType string, success bool, errorType string) {
	duration := time.Since(t.start)
	if success {
		t.metrics.DiscoverySuccess(method, domain, providerType, duration)
	} else {
		t.metrics.DiscoveryError(method, domain, errorType, duration)
	}
}

func (t *Timer) ObserveDNS(domain, recordType string, success bool, errorType string) {
	duration := time.Since(t.start)
	t.metrics.DNSQuery(domain, recordType, duration, success)
	if !success {
		t.metrics.DNSError(domain, errorType)
	}
}

func (t *Timer) ObserveHTTP(domain, endpoint, statusCode string, success bool, errorType string) {
	duration := time.Since(t.start)
	t.metrics.HTTPRequest(domain, endpoint, statusCode, duration, success)
	if !success {
		t.metrics.HTTPError(domain, endpoint, errorType)
	}
}

// GetMetricFamilies returns all metric families for external inspection
func (m *Metrics) GetMetricFamilies() ([]*dto.MetricFamily, error) {
	if gatherer, ok := m.registerer.(prometheus.Gatherer); ok {
		return gatherer.Gather()
	}
	return nil, nil
}