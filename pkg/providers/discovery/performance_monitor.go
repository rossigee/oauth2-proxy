package discovery

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// PerformanceMonitor tracks system resources and performance metrics
type PerformanceMonitor struct {
	metrics      *Metrics
	ctx          context.Context
	cancel       context.CancelFunc
	interval     time.Duration
	mu           sync.RWMutex
	running      bool
	lastMemStats runtime.MemStats
}

// PerformanceConfig configures the performance monitor
type PerformanceConfig struct {
	// MonitoringInterval is how often to collect performance metrics
	MonitoringInterval time.Duration
	// Enabled controls whether performance monitoring is active
	Enabled bool
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(config PerformanceConfig) *PerformanceMonitor {
	if config.MonitoringInterval == 0 {
		config.MonitoringInterval = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &PerformanceMonitor{
		metrics:  GetMetrics(),
		ctx:      ctx,
		cancel:   cancel,
		interval: config.MonitoringInterval,
	}
}

// Start begins performance monitoring
func (pm *PerformanceMonitor) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		return nil
	}

	pm.running = true
	go pm.monitorLoop()

	logger.Printf("Performance monitor started with interval %v", pm.interval)
	return nil
}

// Stop stops performance monitoring
func (pm *PerformanceMonitor) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.running {
		return nil
	}

	pm.cancel()
	pm.running = false

	logger.Printf("Performance monitor stopped")
	return nil
}

// IsRunning returns whether the monitor is currently running
func (pm *PerformanceMonitor) IsRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.running
}

// monitorLoop is the main monitoring loop
func (pm *PerformanceMonitor) monitorLoop() {
	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()

	// Collect initial baseline
	pm.collectMetrics()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.collectMetrics()
		}
	}
}

// collectMetrics collects and reports performance metrics
func (pm *PerformanceMonitor) collectMetrics() {
	// Collect memory statistics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Update memory usage metrics
	pm.metrics.UpdateMemoryUsage(float64(memStats.Alloc))

	// Update goroutine count
	pm.metrics.UpdateGoroutineCount(float64(runtime.NumGoroutine()))

	// Log performance metrics periodically (every 5 minutes)
	if pm.shouldLogMetrics() {
		pm.logPerformanceMetrics(&memStats)
	}

	pm.lastMemStats = memStats
}

// shouldLogMetrics determines if we should log performance metrics
func (pm *PerformanceMonitor) shouldLogMetrics() bool {
	// Log every 10 collection cycles (5 minutes with 30s interval)
	return time.Now().Unix()%(10*int64(pm.interval.Seconds())) < int64(pm.interval.Seconds())
}

// logPerformanceMetrics logs current performance state
func (pm *PerformanceMonitor) logPerformanceMetrics(memStats *runtime.MemStats) {
	logger.Printf("Email Discovery Performance Metrics:")
	logger.Printf("  Memory Allocated: %d bytes (%.2f MB)",
		memStats.Alloc, float64(memStats.Alloc)/1024/1024)
	logger.Printf("  Heap Objects: %d", memStats.HeapObjects)
	logger.Printf("  Goroutines: %d", runtime.NumGoroutine())
	logger.Printf("  GC Cycles: %d", memStats.NumGC)

	if pm.lastMemStats.NumGC > 0 {
		logger.Printf("  GC Pause (last): %v",
			//nolint:gosec // Safe bounded conversion
			time.Duration(int64(memStats.PauseNs[(memStats.NumGC+255)%256]&0x7FFFFFFFFFFFFFFF)))
	}
}

// GetStats returns current performance statistics
func (pm *PerformanceMonitor) GetStats() PerformanceStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return PerformanceStats{
		MemoryAllocated: memStats.Alloc,
		HeapObjects:     memStats.HeapObjects,
		//nolint:gosec // Safe bounded conversion
		Goroutines: uint64(max(0, min(runtime.NumGoroutine(), 1000000))),
		GCCycles:   memStats.NumGC,
		//nolint:gosec // Safe bounded conversion
		LastGCPause: time.Duration(int64(memStats.PauseNs[(memStats.NumGC+255)%256] & 0x7FFFFFFFFFFFFFFF)),
		Timestamp:   time.Now(),
	}
}

// PerformanceStats contains performance statistics
type PerformanceStats struct {
	MemoryAllocated uint64        `json:"memory_allocated"`
	HeapObjects     uint64        `json:"heap_objects"`
	Goroutines      uint64        `json:"goroutines"`
	GCCycles        uint32        `json:"gc_cycles"`
	LastGCPause     time.Duration `json:"last_gc_pause"`
	Timestamp       time.Time     `json:"timestamp"`
}

// PerformanceThresholds defines performance alert thresholds
type PerformanceThresholds struct {
	// MaxMemoryMB is the maximum memory usage in MB before alerting
	MaxMemoryMB float64
	// MaxGoroutines is the maximum number of goroutines before alerting
	MaxGoroutines int
	// MaxGCPause is the maximum GC pause duration before alerting
	MaxGCPause time.Duration
}

// DefaultPerformanceThresholds returns sensible default thresholds
func DefaultPerformanceThresholds() PerformanceThresholds {
	return PerformanceThresholds{
		MaxMemoryMB:   100,                   // 100MB
		MaxGoroutines: 1000,                  // 1000 goroutines
		MaxGCPause:    10 * time.Millisecond, // 10ms GC pause
	}
}

// CheckThresholds checks current performance against thresholds
func (pm *PerformanceMonitor) CheckThresholds(thresholds PerformanceThresholds) []string {
	stats := pm.GetStats()
	var alerts []string

	// Check memory usage
	memoryMB := float64(stats.MemoryAllocated) / 1024 / 1024
	if memoryMB > thresholds.MaxMemoryMB {
		alerts = append(alerts,
			"High memory usage: %.2f MB (threshold: %.2f MB)")
	}

	// Check goroutine count
	if thresholds.MaxGoroutines > 0 && stats.Goroutines > uint64(thresholds.MaxGoroutines) {
		alerts = append(alerts,
			"High goroutine count: %d (threshold: %d)")
	}

	// Check GC pause time
	if stats.LastGCPause > thresholds.MaxGCPause {
		alerts = append(alerts,
			"High GC pause: %v (threshold: %v)")
	}

	return alerts
}

// ResourceUsage tracks resource usage over time
type ResourceUsage struct {
	mu       sync.RWMutex
	samples  []PerformanceStats
	maxAge   time.Duration
	maxCount int
}

// NewResourceUsage creates a new resource usage tracker
func NewResourceUsage(maxAge time.Duration, maxCount int) *ResourceUsage {
	return &ResourceUsage{
		samples:  make([]PerformanceStats, 0, maxCount),
		maxAge:   maxAge,
		maxCount: maxCount,
	}
}

// AddSample adds a performance sample
func (ru *ResourceUsage) AddSample(stats PerformanceStats) {
	ru.mu.Lock()
	defer ru.mu.Unlock()

	// Add new sample
	ru.samples = append(ru.samples, stats)

	// Remove old samples
	cutoff := time.Now().Add(-ru.maxAge)
	for i, sample := range ru.samples {
		if sample.Timestamp.After(cutoff) {
			ru.samples = ru.samples[i:]
			break
		}
	}

	// Limit total count
	if len(ru.samples) > ru.maxCount {
		ru.samples = ru.samples[len(ru.samples)-ru.maxCount:]
	}
}

// GetAverages returns average resource usage over the tracked period
func (ru *ResourceUsage) GetAverages() PerformanceStats {
	ru.mu.RLock()
	defer ru.mu.RUnlock()

	if len(ru.samples) == 0 {
		return PerformanceStats{}
	}

	var totalMem, totalObjects, totalGoroutines uint64
	var totalGCCycles uint32
	var totalGCPause time.Duration

	for _, sample := range ru.samples {
		totalMem += sample.MemoryAllocated
		totalObjects += sample.HeapObjects
		totalGoroutines += sample.Goroutines
		totalGCCycles += sample.GCCycles
		totalGCPause += sample.LastGCPause
	}

	count := uint64(len(ru.samples))
	return PerformanceStats{
		MemoryAllocated: totalMem / count,
		HeapObjects:     totalObjects / count,
		Goroutines:      totalGoroutines / count,
		//nolint:gosec // Safe bounded conversion
		GCCycles: uint32(min(uint64(totalGCCycles), 4294967295) / max(count, 1)),
		//nolint:gosec // Safe bounded conversion
		LastGCPause: totalGCPause / time.Duration(max(int64(count), 1)),
		Timestamp:   time.Now(),
	}
}

// GetPeaks returns peak resource usage over the tracked period
func (ru *ResourceUsage) GetPeaks() PerformanceStats {
	ru.mu.RLock()
	defer ru.mu.RUnlock()

	if len(ru.samples) == 0 {
		return PerformanceStats{}
	}

	var maxMem, maxObjects, maxGoroutines uint64
	var maxGCCycles uint32
	var maxGCPause time.Duration

	for _, sample := range ru.samples {
		if sample.MemoryAllocated > maxMem {
			maxMem = sample.MemoryAllocated
		}
		if sample.HeapObjects > maxObjects {
			maxObjects = sample.HeapObjects
		}
		if sample.Goroutines > maxGoroutines {
			maxGoroutines = sample.Goroutines
		}
		if sample.GCCycles > maxGCCycles {
			maxGCCycles = sample.GCCycles
		}
		if sample.LastGCPause > maxGCPause {
			maxGCPause = sample.LastGCPause
		}
	}

	return PerformanceStats{
		MemoryAllocated: maxMem,
		HeapObjects:     maxObjects,
		Goroutines:      maxGoroutines,
		GCCycles:        maxGCCycles,
		LastGCPause:     maxGCPause,
		Timestamp:       time.Now(),
	}
}

// Global performance monitor instance
var globalPerformanceMonitor *PerformanceMonitor
var performanceMonitorOnce sync.Once

// StartGlobalPerformanceMonitor starts the global performance monitor
func StartGlobalPerformanceMonitor(config PerformanceConfig) error {
	var err error
	performanceMonitorOnce.Do(func() {
		globalPerformanceMonitor = NewPerformanceMonitor(config)
		if config.Enabled {
			err = globalPerformanceMonitor.Start()
		}
	})
	return err
}

// GetGlobalPerformanceMonitor returns the global performance monitor
func GetGlobalPerformanceMonitor() *PerformanceMonitor {
	return globalPerformanceMonitor
}

// StopGlobalPerformanceMonitor stops the global performance monitor
func StopGlobalPerformanceMonitor() error {
	if globalPerformanceMonitor != nil {
		return globalPerformanceMonitor.Stop()
	}
	return nil
}
