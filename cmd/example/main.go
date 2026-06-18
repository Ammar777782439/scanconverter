// Command example demonstrates the full scanconverter library.
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

	// ─── 5. Parse local scan files ────────────────────────────────────────────
	var allResults []*models.ScanResult

	// Define which files to parse: (tool_name, file_path)
	scanFiles := []struct {
		Tool string
		File string
	}{
		{"nuclei", "real_nuclei.jsonl"},
		{"nmap", "real_nmap.xml"},
	}

	for _, sf := range scanFiles {
		raw, err := os.ReadFile(sf.File)
		if err != nil {
			logger.Warn("file not found, skipping", zap.String("tool", sf.Tool), zap.String("file", sf.File))
			continue
		}
		start := time.Now()
		result, err := conv.Convert(sf.Tool, raw, "example-target.com", "demo-job")
		metrics.ParseDuration.WithLabelValues(sf.Tool).Observe(time.Since(start).Seconds())
		if err != nil {
			logger.Warn("parse warning", zap.String("tool", sf.Tool), zap.Error(err))
			continue
		}
		for _, f := range result.Findings {
			metrics.FindingsTotal.WithLabelValues(sf.Tool, string(f.Severity)).Inc()
		}
		logger.Info("parsed file",
			zap.String("tool", sf.Tool),
			zap.Int("findings", len(result.Findings)),
		)
		allResults = append(allResults, result)
	}

	if len(allResults) == 0 {
		logger.Warn("no results to process; exiting demo")
		return
	}

	// ─── 6. Deduplication ─────────────────────────────────────────────────────
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

	// ─── 7. Enrichment ────────────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	enrichPipeline := enrich.NewPipeline(logger).
		Add(enrich.CVEEnricher(enrich.DefaultCVEConfig(), logger)).
		Add(enrich.GeoIPEnricher(logger)).
		Add(enrich.TechEnricher())

	for _, r := range dedupedResults {
		enrichPipeline.Enrich(ctx, r)
	}

	// ─── 8. Filtering with expression language ────────────────────────────────
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

	// ─── 9. Export to SARIF + JSON + CSV ──────────────────────────────────────
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

	// ─── 10. Cache results ────────────────────────────────────────────────────
	for _, r := range filteredResults {
		mlCache.Set(r.ID, r)
	}

	// ─── 11. Summary ──────────────────────────────────────────────────────────
	metrics.RegisterAll()
	fmt.Println("\n=== Summary ===")
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
