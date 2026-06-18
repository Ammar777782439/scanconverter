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
	// 1) تحميل السكيمات
	reg := schema.NewRegistry(nil)
	if err := reg.LoadDir("./schemas"); err != nil {
		log.Fatal("load schemas:", err)
	}

	conv := converter.NewConverter(reg)

	// 2) قراءة ملف Nmap
	raw, err := os.ReadFile("./rich_nmap.xml")
	if err != nil {
		log.Fatal("read rich_nmap.xml:", err)
	}

	// 3) تحويل بدون أي فلترة
	res, err := conv.Convert("nmap", raw, "example.com", "job-nmap-001")
	if err != nil {
		log.Println("convert warning:", err)
	}

	fmt.Printf("=== إجمالي النتائج: %d findings ===\n\n", len(res.Findings))

	// 4) طباعة كل نتيجة بتفاصيلها
	for i, f := range res.Findings {
		fmt.Printf("[%d] ─────────────────────────────────────\n", i+1)
		fmt.Printf("  النوع     : %s\n", f.Type)
		fmt.Printf("  الـ IP    : %s\n", f.IP)
		fmt.Printf("  الـ Hostname: %s\n", f.Hostname)
		if f.Port != 0 {
			fmt.Printf("  البورت   : %d/%s  state=%s\n", f.Port, f.Protocol, f.State)
			fmt.Printf("  الخدمة   : %s  (%s)\n", f.Service, f.Version)
		}
		if f.Name != "" {
			fmt.Printf("  الاسم    : %s\n", f.Name)
		}
		if os_val, ok := f.Extra["os"]; ok {
			fmt.Printf("  نظام التشغيل: %s\n", os_val)
		}
		if scripts, ok := f.Extra["scripts"]; ok {
			fmt.Printf("  السكربتات:\n")
			if sm, ok := scripts.(map[string]string); ok {
				for name, output := range sm {
					// نقصر الـ output لأول 80 حرف إذا كانت طويلة
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

	// 5) طباعة الملخص
	if res.Summary != nil {
		fmt.Printf("\n=== الملخص ===\n")
		fmt.Printf("  إجمالي الأهداف : %d\n", res.Summary.TotalTargets)
		fmt.Printf("  إجمالي النتائج : %d\n", res.Summary.TotalFindings)
		fmt.Printf("  المنافذ المفتوحة: %d\n", res.Summary.PortsOpen)
		fmt.Printf("  الثغرات        : %d\n", res.Summary.Vulnerabilities)
		fmt.Printf("  التصنيف حسب النوع: %v\n", res.Summary.FindingsByType)
	}

	// 6) حفظ الكل كـ JSON
	out, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile("nmap_all.json", out, 0644)
	fmt.Println("\n✅ تم حفظ كل النتائج في: nmap_all.json")
}