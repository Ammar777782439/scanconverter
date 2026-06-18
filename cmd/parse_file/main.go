package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Ammar777782439/scanconverter/pkg/converter"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

func main() {
	// 1) Load schemas
	reg := schema.NewRegistry(nil)
	if err := reg.LoadDir("./schemas"); err != nil {
		log.Fatal("load schemas:", err)
	}

	conv := converter.NewConverter(reg)

	// 2) Read Nmap file
	raw, err := os.ReadFile("./rich_nmap.xml")
	if err != nil {
		log.Fatal("read rich_nmap.xml:", err)
	}

	// 3) Convert without any filter
	res, err := conv.Convert("nmap", raw, "example.com", "job-nmap-001")
	if err != nil {
		log.Println("convert warning:", err)
	}

	fmt.Printf("=== Total Results: %d findings ===\n\n", len(res.Findings))

	// 4) Print each result with its details
	for i, f := range res.Findings {
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
	if res.Summary != nil {
		fmt.Printf("\n=== Summary ===\n")
		fmt.Printf("  Total Targets : %d\n", res.Summary.TotalTargets)
		fmt.Printf("  Total Findings: %d\n", res.Summary.TotalFindings)
		fmt.Printf("  Open Ports    : %d\n", res.Summary.PortsOpen)
		fmt.Printf("  Vulnerabilities: %d\n", res.Summary.Vulnerabilities)
		fmt.Printf("  Findings By Type: %v\n", res.Summary.FindingsByType)
	}

	// 6) Save all as JSON
	out, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile("nmap_all.json", out, 0644)
	fmt.Println("\n[+] Saved all results to: nmap_all.json")
}