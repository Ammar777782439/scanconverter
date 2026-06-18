package main

import (
    "encoding/json"
    "fmt"
    "log"
    "os"

    "github.com/Ammar777782439/scanconverter/pkg/converter"
    "github.com/Ammar777782439/scanconverter/pkg/filter"
    "github.com/Ammar777782439/scanconverter/pkg/models"
    "github.com/Ammar777782439/scanconverter/pkg/schema"
)

func main() {
    // 1) تحميل السكيمات
    reg := schema.NewRegistry(nil)
    if err := reg.LoadDir("./schemas"); err != nil {
        log.Fatal("load schemas:", err)
    }

    conv := converter.NewConverter(reg)

    // 2) قراءة nmap XML (الملف اللي أرسلته mock_nmap.xml)
    raw, err := os.ReadFile("././mock_nmap.xml")
    if err != nil {
        log.Fatal("read mock_nmap.xml:", err)
    }

    // 3) تحويل
    res, err := conv.Convert("nmap", raw, "example.com", "job-nmap-001")
    if err != nil {
        log.Println("convert warning:", err)
    }

    fmt.Printf("قبل الفلترة: %d findings\n", len(res.Findings))

    // 4) فلترة – مثال: خذ فقط منافذ 80 و443
    chain := filter.NewFilterChain().
        AddRule(filter.ByTypes(models.TypePort)).   // تأكد إنه نوع port
        AddRule(filter.ByPorts(80, 443))            // فقط البورت 80 و 443

    filtered := chain.Apply(res)

    fmt.Printf("بعد الفلترة: %d findings\n\n", len(filtered.Findings))

    for i, f := range filtered.Findings {
        fmt.Printf("[%d] %s:%d/%s state=%s service=%s version=%s\n",
            i+1, f.IP, f.Port, f.Protocol, f.State, f.Service, f.Version)
    }

    // 5) حفظ الناتج بعد الفلترة
    out, _ := json.MarshalIndent(filtered, "", "  ")
    _ = os.WriteFile("nmap_filtered.json", out, 0644)
    fmt.Println("الناتج المحفوظ: nmap_filtered.json")
}