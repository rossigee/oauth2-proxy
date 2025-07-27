# Email Discovery Monitoring and Metrics

This document describes the comprehensive monitoring and metrics system for the oauth2-proxy email discovery feature.

## Overview

The email discovery system provides extensive metrics for monitoring performance, security, and business analytics. All metrics follow Prometheus naming conventions and integrate seamlessly with existing oauth2-proxy metrics infrastructure.

## Metrics Categories

### 1. Discovery Operation Metrics

These metrics track the core email discovery functionality:

#### Discovery Requests
```
oauth2_proxy_email_discovery_discovery_requests_total{method, domain}
```
- **Type**: Counter
- **Labels**: 
  - `method`: Discovery method used (dns, config, wellknown, unified, email_discovery)
  - `domain`: Target domain
- **Description**: Total number of discovery requests by method and domain

#### Discovery Success
```
oauth2_proxy_email_discovery_discovery_success_total{method, domain, provider_type}
```
- **Type**: Counter
- **Labels**:
  - `method`: Discovery method used
  - `domain`: Target domain
  - `provider_type`: Type of provider discovered (oidc, google, github, etc.)
- **Description**: Successful discovery operations

#### Discovery Errors
```
oauth2_proxy_email_discovery_discovery_errors_total{method, domain, error_type}
```
- **Type**: Counter
- **Labels**:
  - `method`: Discovery method used
  - `domain`: Target domain
  - `error_type`: Error classification (timeout, dns_error, network_error, etc.)
- **Description**: Failed discovery operations by error type

#### Discovery Duration
```
oauth2_proxy_email_discovery_discovery_duration_seconds{method, success}
```
- **Type**: Histogram
- **Labels**:
  - `method`: Discovery method used
  - `success`: Whether operation succeeded (true/false)
- **Buckets**: [.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10]
- **Description**: Time taken for discovery operations

### 2. Cache Performance Metrics

#### Cache Hits
```
oauth2_proxy_email_discovery_cache_hits_total{cache_type, domain}
```
- **Type**: Counter
- **Labels**:
  - `cache_type`: Type of cache (provider, discovery)
  - `domain`: Target domain
- **Description**: Cache hit operations

#### Cache Misses
```
oauth2_proxy_email_discovery_cache_misses_total{cache_type, domain}
```
- **Type**: Counter
- **Labels**:
  - `cache_type`: Type of cache (provider, discovery)
  - `domain`: Target domain
- **Description**: Cache miss operations

### 3. Provider Management Metrics

#### Provider Creations
```
oauth2_proxy_email_discovery_provider_creations_total{provider_type, domain}
```
- **Type**: Counter
- **Labels**:
  - `provider_type`: Type of provider created
  - `domain`: Target domain
- **Description**: Dynamic provider creation events

#### Provider Errors
```
oauth2_proxy_email_discovery_provider_errors_total{provider_type, domain, error_type}
```
- **Type**: Counter
- **Labels**:
  - `provider_type`: Type of provider
  - `domain`: Target domain
  - `error_type`: Error classification
- **Description**: Provider creation/management errors

#### Active Providers
```
oauth2_proxy_email_discovery_active_providers{provider_type}
```
- **Type**: Gauge
- **Labels**:
  - `provider_type`: Type of provider
- **Description**: Current number of active providers by type

### 4. DNS Discovery Metrics

#### DNS Queries
```
oauth2_proxy_email_discovery_dns_queries_total{domain, record_type}
```
- **Type**: Counter
- **Labels**:
  - `domain`: Queried domain
  - `record_type`: DNS record type (TXT, CNAME, etc.)
- **Description**: DNS queries made for discovery

#### DNS Query Duration
```
oauth2_proxy_email_discovery_dns_query_duration_seconds{record_type, success}
```
- **Type**: Histogram
- **Labels**:
  - `record_type`: DNS record type
  - `success`: Whether query succeeded
- **Buckets**: [.001, .005, .01, .025, .05, .1, .25, .5, 1, 2]
- **Description**: DNS query latency

#### DNS Errors
```
oauth2_proxy_email_discovery_dns_errors_total{domain, error_type}
```
- **Type**: Counter
- **Labels**:
  - `domain`: Queried domain
  - `error_type`: Error classification
- **Description**: DNS query failures

### 5. HTTP Discovery Metrics

#### HTTP Requests
```
oauth2_proxy_email_discovery_http_requests_total{domain, endpoint, status_code}
```
- **Type**: Counter
- **Labels**:
  - `domain`: Target domain
  - `endpoint`: Endpoint path (well-known, etc.)
  - `status_code`: HTTP response code
- **Description**: HTTP requests for discovery

#### HTTP Request Duration
```
oauth2_proxy_email_discovery_http_request_duration_seconds{endpoint, success}
```
- **Type**: Histogram
- **Labels**:
  - `endpoint`: Endpoint path
  - `success`: Whether request succeeded
- **Buckets**: [.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30]
- **Description**: HTTP request latency

#### HTTP Errors
```
oauth2_proxy_email_discovery_http_errors_total{domain, endpoint, error_type}
```
- **Type**: Counter
- **Labels**:
  - `domain`: Target domain
  - `endpoint`: Endpoint path
  - `error_type`: Error classification
- **Description**: HTTP request failures

### 6. Security Metrics

#### Validation Errors
```
oauth2_proxy_email_discovery_validation_errors_total{validation_type, error_reason}
```
- **Type**: Counter
- **Labels**:
  - `validation_type`: Type of validation (email_format, domain_extraction, etc.)
  - `error_reason`: Specific error reason
- **Description**: Input validation failures

#### Rate Limit Hits
```
oauth2_proxy_email_discovery_rate_limit_hits_total{limit_type, client_ip}
```
- **Type**: Counter
- **Labels**:
  - `limit_type`: Type of rate limit (discovery, dns, http)
  - `client_ip`: Client IP address
- **Description**: Rate limiting activations

#### Suspicious Activity
```
oauth2_proxy_email_discovery_suspicious_activity_total{activity_type, domain}
```
- **Type**: Counter
- **Labels**:
  - `activity_type`: Type of suspicious activity
  - `domain`: Target domain
- **Description**: Security anomalies detected

### 7. Business Metrics

#### Domain Distribution
```
oauth2_proxy_email_discovery_domain_distribution_total{domain, success}
```
- **Type**: Counter
- **Labels**:
  - `domain`: Target domain
  - `success`: Whether discovery succeeded
- **Description**: Distribution of domains being discovered

#### Method Preference
```
oauth2_proxy_email_discovery_method_preference_total{method, fallback_reason}
```
- **Type**: Counter
- **Labels**:
  - `method`: Discovery method
  - `fallback_reason`: Why this method was chosen
- **Description**: Discovery method usage patterns

### 8. Performance Metrics

#### Memory Usage
```
oauth2_proxy_email_discovery_memory_usage_bytes
```
- **Type**: Gauge
- **Description**: Current memory usage of email discovery system

#### Goroutine Count
```
oauth2_proxy_email_discovery_goroutines_count
```
- **Type**: Gauge
- **Description**: Current number of goroutines in email discovery system

## Prometheus Configuration

### Scraping Configuration

```yaml
scrape_configs:
  - job_name: 'oauth2-proxy'
    static_configs:
      - targets: ['oauth2-proxy:4180']
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Recording Rules

```yaml
groups:
  - name: oauth2_proxy_email_discovery
    rules:
      # Discovery success rate
      - record: oauth2_proxy:email_discovery_success_rate
        expr: |
          rate(oauth2_proxy_email_discovery_discovery_success_total[5m]) /
          rate(oauth2_proxy_email_discovery_discovery_requests_total[5m])
      
      # Cache hit rate
      - record: oauth2_proxy:email_discovery_cache_hit_rate
        expr: |
          rate(oauth2_proxy_email_discovery_cache_hits_total[5m]) /
          (rate(oauth2_proxy_email_discovery_cache_hits_total[5m]) +
           rate(oauth2_proxy_email_discovery_cache_misses_total[5m]))
      
      # DNS success rate
      - record: oauth2_proxy:dns_discovery_success_rate
        expr: |
          rate(oauth2_proxy_email_discovery_dns_queries_total{record_type="TXT"}[5m]) /
          (rate(oauth2_proxy_email_discovery_dns_queries_total{record_type="TXT"}[5m]) +
           rate(oauth2_proxy_email_discovery_dns_errors_total[5m]))
      
      # Average discovery latency
      - record: oauth2_proxy:email_discovery_latency_avg
        expr: |
          rate(oauth2_proxy_email_discovery_discovery_duration_seconds_sum[5m]) /
          rate(oauth2_proxy_email_discovery_discovery_duration_seconds_count[5m])
```

## Alerting Rules

### Critical Alerts

```yaml
groups:
  - name: oauth2_proxy_email_discovery_critical
    rules:
      # High error rate
      - alert: EmailDiscoveryHighErrorRate
        expr: |
          (
            rate(oauth2_proxy_email_discovery_discovery_errors_total[5m]) /
            rate(oauth2_proxy_email_discovery_discovery_requests_total[5m])
          ) > 0.1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High email discovery error rate"
          description: "Email discovery error rate is {{ $value | humanizePercentage }} for the last 5 minutes"
      
      # DNS discovery failures
      - alert: DNSDiscoveryFailures
        expr: rate(oauth2_proxy_email_discovery_dns_errors_total[5m]) > 5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "High DNS discovery failure rate"
          description: "DNS discovery failures: {{ $value }} errors/second"
      
      # Provider creation failures
      - alert: ProviderCreationFailures
        expr: rate(oauth2_proxy_email_discovery_provider_errors_total[5m]) > 2
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High provider creation failure rate"
          description: "Provider creation failures: {{ $value }} errors/second"

### Warning Alerts

```yaml
  - name: oauth2_proxy_email_discovery_warning
    rules:
      # High latency
      - alert: EmailDiscoveryHighLatency
        expr: |
          histogram_quantile(0.95,
            rate(oauth2_proxy_email_discovery_discovery_duration_seconds_bucket[5m])
          ) > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High email discovery latency"
          description: "95th percentile latency is {{ $value }}s"
      
      # Low cache hit rate
      - alert: EmailDiscoveryLowCacheHitRate
        expr: oauth2_proxy:email_discovery_cache_hit_rate < 0.7
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Low email discovery cache hit rate"
          description: "Cache hit rate is {{ $value | humanizePercentage }}"
      
      # Suspicious activity
      - alert: EmailDiscoverySuspiciousActivity
        expr: rate(oauth2_proxy_email_discovery_suspicious_activity_total[5m]) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Suspicious email discovery activity detected"
          description: "Suspicious activity rate: {{ $value }} events/second"
```

## Grafana Dashboard

### Dashboard JSON Configuration

```json
{
  "dashboard": {
    "title": "OAuth2 Proxy - Email Discovery",
    "panels": [
      {
        "title": "Discovery Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "oauth2_proxy:email_discovery_success_rate",
            "legendFormat": "Success Rate"
          }
        ]
      },
      {
        "title": "Discovery Requests per Second",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(oauth2_proxy_email_discovery_discovery_requests_total[5m])",
            "legendFormat": "{{method}} - {{domain}}"
          }
        ]
      },
      {
        "title": "Discovery Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(oauth2_proxy_email_discovery_discovery_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(oauth2_proxy_email_discovery_discovery_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Cache Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(oauth2_proxy_email_discovery_cache_hits_total[5m])",
            "legendFormat": "Cache Hits"
          },
          {
            "expr": "rate(oauth2_proxy_email_discovery_cache_misses_total[5m])",
            "legendFormat": "Cache Misses"
          }
        ]
      },
      {
        "title": "Error Distribution",
        "type": "piechart",
        "targets": [
          {
            "expr": "increase(oauth2_proxy_email_discovery_discovery_errors_total[1h])",
            "legendFormat": "{{error_type}}"
          }
        ]
      }
    ]
  }
}
```

## Monitoring Best Practices

### 1. Metric Collection

- **Collection Interval**: 15-30 seconds for most metrics
- **Retention**: 15 days for detailed metrics, 1 year for aggregated data
- **Cardinality**: Monitor label cardinality to avoid high-cardinality issues

### 2. Alerting Strategy

- **Error Rate Thresholds**: >10% error rate for critical, >5% for warning
- **Latency Thresholds**: >2s for P95 critical, >1s for warning
- **Rate Limits**: Alert on any rate limiting to identify capacity issues

### 3. Performance Monitoring

- **Key Metrics to Watch**:
  - Discovery success rate (target: >95%)
  - Cache hit rate (target: >80%)
  - P95 latency (target: <500ms)
  - DNS query success rate (target: >98%)

### 4. Security Monitoring

- **Security Metrics**:
  - Monitor validation errors for attack patterns
  - Track rate limit hits by IP
  - Alert on suspicious activity patterns

### 5. Business Intelligence

- **Domain Analysis**: Track most popular domains for capacity planning
- **Method Effectiveness**: Monitor which discovery methods are most successful
- **Geographic Patterns**: Consider geographic distribution of requests

## Integration Examples

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: Service
metadata:
  name: oauth2-proxy-metrics
  labels:
    app: oauth2-proxy
spec:
  ports:
  - name: metrics
    port: 4180
    targetPort: 4180
  selector:
    app: oauth2-proxy
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: oauth2-proxy
spec:
  selector:
    matchLabels:
      app: oauth2-proxy
  endpoints:
  - port: metrics
    path: /metrics
    interval: 15s
```

### Docker Compose

```yaml
version: '3.8'
services:
  oauth2-proxy:
    image: rossigee/oauth-proxy:latest
    ports:
      - "4180:4180"
    environment:
      - OAUTH2_PROXY_METRICS_ADDRESS=0.0.0.0:4180
    labels:
      - "prometheus.io/scrape=true"
      - "prometheus.io/port=4180"
      - "prometheus.io/path=/metrics"
```

## Troubleshooting

### Common Issues

1. **High Error Rates**
   - Check DNS resolver configuration
   - Verify network connectivity
   - Review rate limiting settings

2. **High Latency**
   - Monitor DNS resolution times
   - Check HTTP timeout settings
   - Review cache configuration

3. **Memory Usage**
   - Monitor provider cache size
   - Check for memory leaks
   - Review cache eviction policies

### Debugging Queries

```promql
# Error rate by method
rate(oauth2_proxy_email_discovery_discovery_errors_total[5m]) by (method, error_type)

# Slowest domains
topk(10, 
  rate(oauth2_proxy_email_discovery_discovery_duration_seconds_sum[5m]) by (domain) /
  rate(oauth2_proxy_email_discovery_discovery_duration_seconds_count[5m]) by (domain)
)

# Most active domains
topk(10, rate(oauth2_proxy_email_discovery_discovery_requests_total[5m]) by (domain))
```

This monitoring system provides comprehensive visibility into the email discovery feature, enabling proactive issue detection and performance optimization.