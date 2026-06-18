package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Ammar777782439/scanconverter/pkg/converter"
	"github.com/Ammar777782439/scanconverter/pkg/discovery"
	"github.com/Ammar777782439/scanconverter/pkg/export"
	"github.com/Ammar777782439/scanconverter/pkg/models"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

func main() {
	htmlOut := flag.String("html", "", "Output path for the Premium HTML Report")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		files = []string{"./rich_nmap.xml"}
	}

	// 1) Load schemas & init engines
	reg := schema.NewRegistry(nil)
	if err := reg.LoadDir("./schemas"); err != nil {
		log.Fatal("load schemas:", err)
	}

	conv := converter.NewConverter(reg)

	var schemas []*schema.ToolSchema
	for _, name := range reg.ListNames() {
		if s, ok := reg.Get(name); ok {
			schemas = append(schemas, s)
		}
	}
	discEngine := discovery.New(schemas)

	// Master result to combine all findings
	masterResult := models.NewScanResult("combined", "multiple", "job-all")

	// Process all files
	for _, inputFile := range files {
		raw, err := os.ReadFile(inputFile)
		if err != nil {
			log.Printf("[-] Failed to read %s: %v", inputFile, err)
			continue
		}

		// Auto-discover the tool
		discRes, err := discEngine.Discover(raw, "")
		if err != nil || discRes.OverallConfidence < 10 {
			log.Printf("[-] Could not identify tool for %s", inputFile)
			continue
		}
		toolName := discRes.DetectedTool

		// We assume the toolName matches a schema
		res, err := conv.Convert(toolName, raw, "auto-target", "job-auto")
		if err != nil {
			// fallback to just parsing by format if we have no schema
			log.Printf("[-] Convert error for %s: %v", inputFile, err)
			continue
		}

		masterResult.Findings = append(masterResult.Findings, res.Findings...)
		fmt.Printf("[+] Processed %s (Tool: %s, Findings: %d)\n", inputFile, toolName, len(res.Findings))
	}

	masterResult.BuildSummary()

	// 4) Print each result with its details
	for i, f := range masterResult.Findings {
		fmt.Printf("[%d] ─────────────────────────────────────\n", i+1)
		fmt.Printf("  Type      : %s\n", f.Type)
		fmt.Printf("  IP        : %s\n", f.IP)
		fmt.Printf("  Hostname  : %s\n", f.Hostname)
		if f.Port != 0 {
			fmt.Printf("  Port      : %d/%s  state=%s\n", f.Port, f.Protocol, f.State)
			fmt.Printf("  Service   : %s  (%s)\n", f.Service, f.Version)
		}
		if f.Name != "" {
			fmt.Printf("  Name      : %s\n", f.Name)
		}
		if os_val, ok := f.Extra["os"]; ok {
			fmt.Printf("  OS        : %s\n", os_val)
		}
		if scripts, ok := f.Extra["scripts"]; ok {
			fmt.Printf("  Scripts   :\n")
			if sm, ok := scripts.(map[string]string); ok {
				for name, output := range sm {
					// Trim output to first 80 characters
					out := output
					if len(out) > 80 {
						out = out[:80] + "..."
					}
					fmt.Printf("    [%s]: %s\n", name, out)
				}
			}
		}
		if hs, ok := f.Extra["host_scripts"]; ok {
			fmt.Printf("  Host Scripts:\n")
			if sm, ok := hs.(map[string]string); ok {
				for name, output := range sm {
					out := output
					if len(out) > 80 {
						out = out[:80] + "..."
					}
					fmt.Printf("    [%s]: %s\n", name, out)
				}
			}
		}
	}

	// 5) Print summary
	if masterResult.Summary != nil {
		fmt.Printf("\n=== Summary ===\n")
		fmt.Printf("  Total Targets : %d\n", masterResult.Summary.TotalTargets)
		fmt.Printf("  Total Findings: %d\n", masterResult.Summary.TotalFindings)
		fmt.Printf("  Open Ports    : %d\n", masterResult.Summary.PortsOpen)
		fmt.Printf("  Vulnerabilities: %d\n", masterResult.Summary.Vulnerabilities)
		fmt.Printf("  Findings By Type: %v\n", masterResult.Summary.FindingsByType)
	}

	// 6) Export HTML Report if requested
	if *htmlOut != "" {
		htmlExporter := export.NewHTMLExporter()
		htmlBytes, err := htmlExporter.Export(masterResult)
		if err != nil {
			log.Printf("Failed to generate HTML report: %v", err)
		} else {
			_ = os.WriteFile(*htmlOut, htmlBytes, 0644)
			fmt.Printf("\n✨ Premium HTML Report saved to: %s\n", *htmlOut)
		}
	}

	// 7) Save all as JSON
	out, _ := json.MarshalIndent(masterResult, "", "  ")
	_ = os.WriteFile("combined_all.json", out, 0644)
	fmt.Println("\n[+] Saved all results to: combined_all.json")
}