// Package metrics registers Prometheus metrics for the scanconverter library.
package metrics

import (
 "github.com/prometheus/client_golang/prometheus"
 "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
 // FindingsTotal counts normalized findings by tool and severity.
 FindingsTotal = promauto.NewCounterVec(
 prometheus.CounterOpts{
 Namespace: "scanconverter",
 Name: "findings_total",
 Help: "Total number of normalized findings.",
 },
 []string{"tool", "severity"},
 )

 // ParseDuration measures how long Convert takes per tool.
 ParseDuration = promauto.NewHistogramVec(
 prometheus.HistogramOpts{
 Namespace: "scanconverter",
 Name: "parse_duration_seconds",
 Help: "Time spent parsing tool output.",
 Buckets: prometheus.DefBuckets,
 },
 []string{"tool"},
 )

 // DeduplicationRate tracks the fraction of findings removed as duplicates.
 DeduplicationRate = promauto.NewGauge(
 prometheus.GaugeOpts{
 Namespace: "scanconverter",
 Name: "deduplication_rate",
 Help: "Fraction of findings removed by deduplication (0.0–1.0).",
 },
 )

 // PipelineStepDuration measures time per pipeline step.
 PipelineStepDuration = promauto.NewHistogramVec(
 prometheus.HistogramOpts{
 Namespace: "scanconverter",
 Name: "pipeline_step_duration_seconds",
 Help: "Time spent executing each pipeline step.",
 Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600},
 },
 []string{"pipeline", "step"},
 )

 // EnrichmentErrors counts enricher failures by enricher name.
 EnrichmentErrors = promauto.NewCounterVec(
 prometheus.CounterOpts{
 Namespace: "scanconverter",
 Name: "enrichment_errors_total",
 Help: "Total enrichment failures.",
 },
 []string{"enricher"},
 )

 // CacheHits and CacheMisses track multi-level cache performance.
 CacheHits = promauto.NewCounterVec(
 prometheus.CounterOpts{
 Namespace: "scanconverter",
 Name: "cache_hits_total",
 Help: "Cache hits by level (l1, l2).",
 },
 []string{"level"},
 )

 CacheMisses = promauto.NewCounterVec(
 prometheus.CounterOpts{
 Namespace: "scanconverter",
 Name: "cache_misses_total",
 Help: "Cache misses by level (l1, l2).",
 },
 []string{"level"},
 )
)

// RegisterAll is a no-op when using promauto (auto-registers on package init).
// Call it explicitly to ensure the package is imported and metrics are registered.
func RegisterAll() {
	// promauto registers metrics at init time; this function exists for
	// explicit import forcing and documentation purposes.
}