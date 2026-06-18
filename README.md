<div align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Security-Scanners-red?style=for-the-badge" alt="Security" />
  <h1>🚀 ScanConverter</h1>
  <p><b>The Ultimate Post-Processing Brain for Offensive Security Scans</b></p>
</div>

---

## 📖 Overview

**ScanConverter** is a highly dynamic, schema-driven data normalization, filtering, and auto-discovery engine. 

It is designed to be the central "Brain" for your security workflows. While you use various tools to scan your targets, **ScanConverter** takes those raw, unstructured files, understands them, filters out the noise, enriches the data, and unifies them into a single, perfectly structured JSON format ready to be consumed by your Frontend UI or Database.

### 🌟 Premium HTML Report Exporter
Transform your raw scans into stunning, interactive, standalone HTML reports out-of-the-box. Dark mode, Glassmorphism, and Chart.js analytics included.
![Premium HTML Report Preview](./report_preview.png)

## 📑 Table of Contents
- [Core Capabilities](#-core-capabilities)
- [Supported Tools](#-supported-tools-out-of-the-box)
- [Architecture Workflow](#-architecture-workflow)
- [Installation](#-installation)
- [Usage (CLI & Go Library)](#-usage)
- [The Schema System](#-the-schema-system)
- [Plugin Engine (gRPC)](#-plugin-engine)

---

## ✨ Core Capabilities

ScanConverter is a full-fledged post-processing pipeline:

*   🧠 **Auto-Discovery Engine**: Don't have a schema for a new tool? Just pass the raw output file. The engine will automatically detect the tool, map the fields, and generate a Schema for you.
*   🛠️ **Zero-Code Integration**: Support a new security tool entirely through a JSON/YAML schema file.
*   🎯 **Schema-Based Filtering**: Write dynamic `expr-lang` expressions directly in your schemas (e.g., `"port == 80 || port == 443"`).
*   🧹 **Advanced Deduplication**: Configurable finding deduplication using specific field hashing and smart result merging.
*   ⚡ **Enrichment Pipeline**: 
    *   **CVEEnricher**: Fetches and attaches CVSS scores and CVE details.
    *   **GeoIPEnricher**: Attaches IP geolocation data.
    *   **TechEnricher**: Identifies web technologies automatically.
*   💾 **Multi-Level Caching**: Redis and LRU Memory caching to instantly retrieve previous scan results.
*   🔌 **Plugin System**: Extend the engine using Go interfaces or **gRPC plugins** for complex custom tools.
*   📤 **SARIF Export**: Natively exports normalized results to the industry-standard SARIF format for CI/CD integrations.

---

## 🛠️ Supported Tools (Out of the Box)
Because of the generic schema system, ScanConverter supports almost anything. The following schemas are included by default:
- **Network**: Nmap, Masscan
- **Web Vulns**: Nuclei, Nikto, WPScan, Sqlmap
- **Recon & Assets**: Httpx, Subfinder, Amass
- **Fuzzing**: FFUF, Gobuster
- **Container/Cloud**: Trivy

---

## 🏗️ Architecture Workflow

```mermaid
graph LR
    A[Security Tools] -->|Raw Output| B(Raw JSON/XML/TXT)
    B --> D{ScanConverter}
    
    subgraph Pipeline
    D -->|1. Parse & Discover| E[Normalize]
    E -->|2. Schema Filters| F[Deduplicate]
    F -->|3. GeoIP & CVE| G[Enrich]
    G -->|4. LRU/Redis| H[Cache]
    end
    
    H --> I[(Unified JSON)]
    H --> J[(SARIF Export)]
```

---

## 🚀 Installation

```bash
git clone https://github.com/Ammar777782439/scanconverter.act
cd scanconverter
go mod tidy
go build -o scanconverter ./cmd/parse_file/
go build -o discover ./cmd/discover/
```

---

## 💻 Usage

### As a CLI Tool

Parse a known tool's output to a unified format:
```bash
./scanconverter 
# Outputs: nmap_all.json
```

Use the **Auto-Discovery Engine** on an unknown tool's output:
```bash
./discover -file raw_output.jsonl -save
```

### As a Go Library (The Ultimate Pipeline)

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/Ammar777782439/scanconverter/pkg/converter"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
	"github.com/Ammar777782439/scanconverter/pkg/dedup"
	"github.com/Ammar777782439/scanconverter/pkg/enrich"
	"github.com/Ammar777782439/scanconverter/pkg/export"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()

	// 1. Load schemas
	reg := schema.NewRegistry(logger)
	reg.LoadDir("./schemas")

	// 2. Initialize Converter
	conv := converter.NewConverter(reg, converter.WithLogger(logger))

	// 3. Setup Deduplication
	dedupEngine := dedup.NewDeduplicator(dedup.DefaultConfig())

	// 4. Setup Enrichment Pipeline (CVE + GeoIP + Tech)
	enrichPipeline := enrich.NewPipeline(logger).
		Add(enrich.CVEEnricher(enrich.DefaultCVEConfig(), logger)).
		Add(enrich.GeoIPEnricher(logger)).
		Add(enrich.TechEnricher())

	// -- Execute Pipeline -- //

	raw, _ := os.ReadFile("raw_results.json")
	
	// A. Convert & Filter
	result, _ := conv.Convert("nuclei", raw, "example.com", "job-123")

	// B. Deduplicate
	result = dedupEngine.Process(result)

	// C. Enrich
	result = enrichPipeline.Enrich(context.Background(), result)

	// D. Export to SARIF
	sarifExporter := export.NewSARIFExporter()
	sarifBytes, _ := sarifExporter.Export(result)
	os.WriteFile("results.sarif", sarifBytes, 0644)
}
```

---

## 🛠️ The Schema System

Schemas map complex tool outputs to a unified model dynamically.

### Example Schema (`schemas/httpx.json`)
```json
{
  "name": "httpx",
  "version": "1.0",
  "format": "jsonl",
  "finding_type": "http",
  "fields": [
    { "name": "url", "path": "url" },
    { "name": "ip", "path": "host" },
    { "name": "port", "path": "port" }
  ],
  "filters": {
    "expressions": [
      "status_code == 200 || status_code == 301"
    ]
  }
}
```

### Supported Filter Variables
When writing `expressions`, you have access to the unified finding fields:
`type`, `target`, `ip`, `port`, `protocol`, `state`, `url`, `method`, `status_code`, `title`, `server`, `service`, `version`, `vuln_id`, `name`, `severity`, `cvss_score`, `hostname`.

**Helper Functions:**
- `contains(title, "Admin")`
- `matches(version, "^1\\.2\\.")`
- `in_cidr(ip, "192.168.1.0/24")`

---

## 🔌 Plugin Engine

For tools that generate highly unpredictable outputs that cannot be mapped via a static Schema, ScanConverter supports **gRPC Plugins**. You can write a plugin in any language, and ScanConverter will communicate with it over gRPC to parse the data securely and efficiently!
