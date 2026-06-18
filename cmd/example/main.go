// Command example demonstrates the full scanconverter pipeline.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/Ammar777782439/scanconverter/pkg/cache"
	"github.com/Ammar777782439/scanconverter/pkg/converter"
	"github.com/Ammar777782439/scanconverter/pkg/dedup"
	"github.com/Ammar777782439/scanconverter/pkg/enrich"
	"github.com/Ammar777782439/scanconverter/pkg/export"
	"github.com/Ammar777782439/scanconverter/pkg/filter"
	"github.com/Ammar777782439/scanconverter/pkg/metrics"
	"github.com/Ammar777782439/scanconverter/pkg/models"
	"github.com/Ammar777782439/scanconverter/pkg/pipeline"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

func main() {
	// ─── 1. Logger ────────────────────────────────────────────────────────────
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("logger init: %v", err)
	}
	defer logger.Sync() //nolint:errcheck

	// ─── 2. Schema registry with hot-reload ───────────────────────────────────
	reg := schema.NewRegistry(logger)
	if err := reg.LoadDir("./schemas"); err != nil {
		logger.Fatal("load schemas", zap.Error(err))
	}
	// Hot-reload: any schema file change reloads automatically.
	if err := reg.Watch("./schemas"); err != nil {
		logger.Warn("schema watch failed (hot-reload disabled)", zap.Error(err))
	}
	defer reg.Close() //nolint:errcheck

	logger.Info("schemas loaded", zap.Any("stats", reg.Stats()))

	// ─── 3. Converter ─────────────────────────────────────────────────────────
	conv := converter.NewConverter(reg, converter.WithLogger(logger))

	// ─── 4. Multi-level cache (L1=LRU, no Redis in this example) ─────────────
	mlCache := cache.NewMultiLevel(
		cache.WithLRU(1000),
		cache.WithTTL(5*time.Minute),
	)

	// ─── 5. DAG Pipeline: masscan → httpx → nuclei ────────────────────────────
	dag := pipeline.NewDAG("recon-pipeline", reg, logger).
		AddStep("masscan", pipeline.Step{
			Tool:    "masscan",
			Command: []string{"masscan", "-iL", "targets.txt", "-p80,443,8080,8443", "-oJ", "/tmp/masscan.json"},
			Outputs: []string{"/tmp/masscan.json"},
			Timeout: 30 * time.Minute,
			Retries: 1,
		}).
		AddStep("httpx", pipeline.Step{
			Tool:      "httpx",
			Command:   []string{"httpx", "-l", "/tmp/ports.txt", "-json", "-o", "/tmp/httpx.jsonl"},
			DependsOn: []string{"masscan"},
			Outputs:   []string{"/tmp/httpx.jsonl"},
			Timeout:   20 * time.Minute,
		}).
		AddStep("nuclei", pipeline.Step{
			Tool:      "nuclei",
			Command:   []string{"nuclei", "-l", "/tmp/urls.txt", "-json", "-o", "/tmp/nuclei.jsonl", "-severity", "medium,high,critical"},
			DependsOn: []string{"httpx"},
			Outputs:   []string{"/tmp/nuclei.jsonl"},
			Timeout:   60 * time.Minute,
			Retries:   2,
		})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
	defer cancel()

	pipelineResults, err := dag.Execute(ctx)
	if err != nil {
		logger.Error("pipeline error", zap.Error(err))
	}
	logger.Info("pipeline complete", zap.Int("step_results", len(pipelineResults)))

	// ─── 6. Also parse local files for demo purposes ──────────────────────────
	var allResults []*models.ScanResult

	// Parse a local nuclei output file if present
	if raw, err := os.ReadFile("./testdata/nuclei_sample.jsonl"); err == nil {
		start := time.Now()
		result, err := conv.Convert("nuclei", raw, "example.com", "demo-job")
		metrics.ParseDuration.WithLabelValues("nuclei").Observe(time.Since(start).Seconds())
		if err != nil {
			logger.Warn("nuclei parse warning", zap.Error(err))
		}
		for _, f := range result.Findings {
			metrics.FindingsTotal.WithLabelValues("nuclei", string(f.Severity)).Inc()
		}
		allResults = append(allResults, result)
	}

	// Append pipeline results
	allResults = append(allResults, pipelineResults...)

	if len(allResults) == 0 {
		logger.Warn("no results to process; exiting demo")
		return
	}

	// ─── 7. Deduplication ─────────────────────────────────────────────────────
	deduplicator := dedup.NewDeduplicator(dedup.DefaultConfig())
	var dedupedResults []*models.ScanResult
	for _, r := range allResults {
		dedupedResults = append(dedupedResults, deduplicator.Process(r))
	}
	dedupStats := deduplicator.Stats()
	logger.Info("deduplication complete",
		zap.Int("total_in", dedupStats.TotalIn),
		zap.Int("total_out", dedupStats.TotalOut),
		zap.Int("duplicates", dedupStats.Duplicates),
	)
	if dedupStats.TotalIn > 0 {
		rate := float64(dedupStats.Duplicates) / float64(dedupStats.TotalIn)
		metrics.DeduplicationRate.Set(rate)
	}

	// ─── 8. Enrichment ────────────────────────────────────────────────────────
	enrichPipeline := enrich.NewPipeline(logger).
		Add(enrich.CVEEnricher(enrich.DefaultCVEConfig(), logger)).
		Add(enrich.GeoIPEnricher(logger)).
		Add(enrich.TechEnricher())

	for _, r := range dedupedResults {
		enrichPipeline.Enrich(ctx, r)
	}

	// ─── 9. Filtering with expression language ────────────────────────────────
	// Keep only high/critical vulns with CVSS ≥ 7.0, excluding test/demo hosts.
	chain, err := filter.FromConfig(filter.FilterConfig{
		Severities:  []string{"high", "critical"},
		MinCVSS:     7.0,
		Exclude:     []string{"test", "demo", "staging", "dev"},
		Expressions: []string{`type != "raw"`},
	})
	if err != nil {
		logger.Fatal("filter config", zap.Error(err))
	}

	// Also add a custom expression rule
	if err := chain.AddExpressionRule(`cvss_score >= 7.5 || severity == "critical"`); err != nil {
		logger.Warn("expression rule compile failed", zap.Error(err))
	}

	var filteredResults []*models.ScanResult
	for _, r := range dedupedResults {
		filtered := chain.Apply(r)
		filteredResults = append(filteredResults, filtered)
	}
	filterStats := chain.Stats()
	logger.Info("filter complete", zap.Any("stats", filterStats))

	// ─── 10. Export to SARIF + JSON + CSV ─────────────────────────────────────
	sarifExporter := export.NewSARIFExporter()

	// SARIF 2.1.0
	sarifBytes, err := sarifExporter.Export(filteredResults...)
	if err != nil {
		logger.Error("sarif export", zap.Error(err))
	} else {
		if err := os.WriteFile("output.sarif.json", sarifBytes, 0600); err != nil {
			logger.Error("write sarif", zap.Error(err))
		}
		logger.Info("SARIF exported", zap.String("file", "output.sarif.json"))
	}

	// JSON (one file per result)
	for i, r := range filteredResults {
		jsonBytes, err := r.ToJSON()
		if err != nil {
			logger.Error("json export", zap.Error(err))
			continue
		}
		fname := fmt.Sprintf("output_%s_%d.json", r.Tool, i)
		if err := os.WriteFile(fname, jsonBytes, 0600); err != nil {
			logger.Error("write json", zap.Error(err))
		}
	}

	// CSV
	for i, r := range filteredResults {
		csvBytes, err := r.ToCSV()
		if err != nil {
			logger.Error("csv export", zap.Error(err))
			continue
		}
		fname := fmt.Sprintf("output_%s_%d.csv", r.Tool, i)
		if err := os.WriteFile(fname, csvBytes, 0600); err != nil {
			logger.Error("write csv", zap.Error(err))
		}
	}

	// ─── 11. Cache results ────────────────────────────────────────────────────
	for _, r := range filteredResults {
		mlCache.Set(r.ID, r)
	}

	// ─── 12. Summary ──────────────────────────────────────────────────────────
	metrics.RegisterAll()
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Pipeline steps completed: %d\n", len(pipelineResults))
	fmt.Printf("Dedup: %d in → %d out (%d duplicates)\n",
		dedupStats.TotalIn, dedupStats.TotalOut, dedupStats.Duplicates)
	fmt.Printf("Filter rejections: %+v\n", filterStats.RuleRejections)
	totalFiltered := 0
	for _, r := range filteredResults {
		totalFiltered += len(r.Findings)
		if r.Summary != nil {
			fmt.Printf("  [%s] findings=%d vulns=%d ports=%d\n",
				r.Tool, r.Summary.TotalFindings,
				r.Summary.Vulnerabilities, r.Summary.PortsOpen)
		}
	}
	fmt.Printf("Total actionable findings: %d\n", totalFiltered)
	fmt.Println("Schema stats:", reg.Stats())
}
