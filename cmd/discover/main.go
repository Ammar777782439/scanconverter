// Command discover demonstrates the Auto-Discovery engine.
// Usage: go run ./cmd/discover/main.go -file <scan_output_file> [-tool <hint>]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Ammar777782439/scanconverter/pkg/discovery"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

func main() {
	filePath := flag.String("file", "", "Path to the scan output file to analyze")
	toolHint := flag.String("tool", "", "Optional: known tool name (skip auto-detection)")
	save := flag.Bool("save", false, "Save the generated schema to ./schemas/<tool>.json")
	flag.Parse()

	if *filePath == "" {
		fmt.Println("Usage: go run ./cmd/discover/main.go -file <path> [-tool <name>] [-save]")
		os.Exit(1)
	}

	// Read the file
	raw, err := os.ReadFile(*filePath)
	if err != nil {
		log.Fatalf("read file: %v", err)
	}

	// Load existing schemas for dynamic tool detection
	reg := schema.NewRegistry(nil)
	if err := reg.LoadDir("schemas"); err != nil {
		log.Printf("warning: could not load schemas: %v", err)
	}
	var schemas []*schema.ToolSchema
	for _, name := range reg.ListNames() {
		if s, ok := reg.Get(name); ok {
			schemas = append(schemas, s)
		}
	}

	// Run the Auto-Discovery engine
	engine := discovery.New(schemas)
	result, err := engine.Discover(raw, *toolHint)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}

	// ─── Print results ────────────────────────────────────────────────────────
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║          Auto-Discovery Engine — Results             ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("\n🔍 Detected Tool    : %s\n", result.DetectedTool)
	fmt.Printf("📄 Format           : %s\n", result.DetectedFormat)
	fmt.Printf("🎯 Overall Confidence: %.0f%%\n\n", float64(result.OverallConfidence))

	// ─── Field mappings ───────────────────────────────────────────────────────
	fmt.Println("┌─────────────────────────┬───────────────────┬────────────┬──────────────────────────────┐")
	fmt.Printf("│ %-23s │ %-17s │ %-10s │ %-28s │\n", "Original Tool Key", "Library Field", "Confidence", "Sample Value")
	fmt.Println("├─────────────────────────┼───────────────────┼────────────┼──────────────────────────────┤")

	for _, df := range result.DiscoveredFields {
		confidence := fmt.Sprintf("%.0f%%", float64(df.Confidence))
		sample := df.SampleValue
		if len(sample) > 28 {
			sample = sample[:25] + "..."
		}
		fmt.Printf("│ %-23s │ %-17s │ %-10s │ %-28s │\n",
			truncate(df.RawKey, 23),
			truncate(df.TargetField, 17),
			confidence,
			truncate(sample, 28),
		)
	}
	fmt.Println("└─────────────────────────┴───────────────────┴────────────┴──────────────────────────────┘")

	// ─── Unmapped keys ────────────────────────────────────────────────────────
	if len(result.UnmappedKeys) > 0 {
		fmt.Printf("\n⚠️  Unmapped Keys (%d):\n", len(result.UnmappedKeys))
		for _, k := range result.UnmappedKeys {
			fmt.Printf("   • %s\n", k)
		}
	}

	// ─── Warnings ─────────────────────────────────────────────────────────────
	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, w := range result.Warnings {
			fmt.Printf("   • %s\n", w)
		}
	}

	// ─── Generated Schema ─────────────────────────────────────────────────────
	fmt.Println("\n📋 Auto-Generated Schema:")
	schemaBytes, _ := json.MarshalIndent(result.Schema, "", "  ")
	fmt.Println(string(schemaBytes))

	// ─── Save if requested ────────────────────────────────────────────────────
	if *save && result.Schema != nil {
		fname := fmt.Sprintf("schemas/%s.json", result.Schema.Name)
		if err := os.WriteFile(fname, schemaBytes, 0644); err != nil {
			log.Printf("⚠️  Failed to save Schema: %v", err)
		} else {
			fmt.Printf("\n✅ Saved Schema to: %s\n", fname)
		}
	}

	fmt.Printf("\n💡 Tip: Add -save flag to save the generated Schema\n")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
