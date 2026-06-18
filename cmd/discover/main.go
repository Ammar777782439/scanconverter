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

	// Run the Auto-Discovery engine
	engine := discovery.New()
	result, err := engine.Discover(raw, *toolHint)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}

	// ─── Print results ────────────────────────────────────────────────────────
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║          Auto-Discovery Engine — Results             ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("\n🔍 الأداة المكتشفة  : %s\n", result.DetectedTool)
	fmt.Printf("📄 الصيغة           : %s\n", result.DetectedFormat)
	fmt.Printf("🎯 الثقة الإجمالية  : %.0f%%\n\n", float64(result.OverallConfidence))

	// ─── Field mappings ───────────────────────────────────────────────────────
	fmt.Println("┌─────────────────────────┬───────────────────┬────────────┬──────────────────────────────┐")
	fmt.Printf("│ %-23s │ %-17s │ %-10s │ %-28s │\n", "مفتاح الأداة الأصلي", "حقل المكتبة", "الثقة", "قيمة مثال")
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
		fmt.Printf("\n⚠️  مفاتيح لم يتم تعيينها (%d):\n", len(result.UnmappedKeys))
		for _, k := range result.UnmappedKeys {
			fmt.Printf("   • %s\n", k)
		}
	}

	// ─── Warnings ─────────────────────────────────────────────────────────────
	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  تحذيرات:")
		for _, w := range result.Warnings {
			fmt.Printf("   • %s\n", w)
		}
	}

	// ─── Generated Schema ─────────────────────────────────────────────────────
	fmt.Println("\n📋 الـ Schema المولّدة تلقائياً:")
	schemaBytes, _ := json.MarshalIndent(result.Schema, "", "  ")
	fmt.Println(string(schemaBytes))

	// ─── Save if requested ────────────────────────────────────────────────────
	if *save && result.Schema != nil {
		fname := fmt.Sprintf("schemas/%s.json", result.Schema.Name)
		if err := os.WriteFile(fname, schemaBytes, 0644); err != nil {
			log.Printf("⚠️  فشل حفظ الـ Schema: %v", err)
		} else {
			fmt.Printf("\n✅ تم حفظ الـ Schema في: %s\n", fname)
		}
	}

	fmt.Printf("\n💡 نصيحة: إذا أردت حفظ الـ Schema أضف -save للأمر\n")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
