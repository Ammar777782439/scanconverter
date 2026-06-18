// Package export writes ScanResults to industry-standard output formats.
package export

import (
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "strings"
 "time"

 "github.com/Ammar777782439/scanconverter/pkg/models"
)

// SARIF 2.1.0 structs — mandatory fields per spec [8].

// SARIFReport is the top-level SARIF document.
type SARIFReport struct {
 Version string `json:"version"` // MUST be "2.1.0" [8]
 Schema string `json:"$schema,omitempty"`
 Runs []SARIFRun `json:"runs"` // REQUIRED array [8]
}

// SARIFRun represents one analysis run.
type SARIFRun struct {
 Tool SARIFTool `json:"tool"`
 Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
 Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool metadata and the rule set.
type SARIFDriver struct {
 Name string `json:"name"`
 Version string `json:"version,omitempty"`
 InformationURI string `json:"informationUri,omitempty"`
 Rules []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule represents one finding type / template.
type SARIFRule struct {
 ID string `json:"id"`
 Name string `json:"name,omitempty"`
 ShortDescription SARIFMessage `json:"shortDescription,omitempty"`
 FullDescription SARIFMessage `json:"fullDescription,omitempty"`
 Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFResult represents one finding instance.
type SARIFResult struct {
 RuleID string `json:"ruleId"` // REQUIRED [8]
 Message SARIFMessage `json:"message"` // REQUIRED [8]
 Level string `json:"level,omitempty"` // error/warning/note
 Locations []SARIFLocation `json:"locations,omitempty"`
 PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
 Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage wraps a text string.
type SARIFMessage struct {
 Text string `json:"text"`
}

// SARIFLocation points to the artifact where the finding was observed.
type SARIFLocation struct {
 PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation holds a URI.
type SARIFPhysicalLocation struct {
 ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation holds the URI of the scanned artifact.
type SARIFArtifactLocation struct {
 URI string `json:"uri"`
}

// severityToLevel maps Finding severity to SARIF level [7].
//
//	critical/high → error
//	medium → warning
//	low/info → note
func severityToLevel(sev models.Severity) string {
 switch sev {
 case models.SeverityCritical, models.SeverityHigh:
 return "error"
 case models.SeverityMedium:
 return "warning"
 default:
 return "note"
 }
}

// generateRuleID produces a stable rule ID from a Finding.
func generateRuleID(f *models.Finding) string {
 if f.VulnID != "" {
 return f.VulnID
 }
 if f.Name != "" {
 return "SC-" + strings.ToUpper(strings.ReplaceAll(f.Name, " ", "-"))
 }
 return fmt.Sprintf("SC-%s-%d", strings.ToUpper(string(f.Type)), f.Port)
}

// generateFingerprint computes a partial fingerprint for SARIF deduplication.
func generateFingerprint(f *models.Finding) string {
 h:= sha256.New()
 fmt.Fprintf(h, "%s|%s|%s|%d|%s",
 f.VulnID, f.URL, string(f.Severity), f.Port, f.IP)
 return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// SARIFExporter converts ScanResults to SARIF 2.1.0 JSON.
type SARIFExporter struct{}

// NewSARIFExporter creates a SARIFExporter.
func NewSARIFExporter() *SARIFExporter { return &SARIFExporter{} }

// Export converts one or more ScanResults into a single SARIF 2.1.0 document [7][8].
// Multiple results are merged into separate runs within the same report.
func (e *SARIFExporter) Export(results...*models.ScanResult) ([]byte, error) {
 report:= SARIFReport{
 Version: "2.1.0",
 Schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
 }

 for _, result:= range results {
 run:= e.buildRun(result)
 report.Runs = append(report.Runs, run)
 }

 return json.MarshalIndent(report, "", " ")
}

func (e *SARIFExporter) buildRun(result *models.ScanResult) SARIFRun {
 ruleMap:= make(map[string]SARIFRule)
 var sarifResults []SARIFResult

 for _, f:= range result.Findings {
 fc:= f
 ruleID:= generateRuleID(&fc)

 if _, exists:= ruleMap[ruleID]; !exists {
 ruleMap[ruleID] = SARIFRule{
 ID: ruleID,
 Name: fc.Name,
 ShortDescription: SARIFMessage{Text: fc.Name},
 Properties: map[string]interface{}{
 "severity": string(fc.Severity),
 "cvss": fc.CVSS,
 "cwe": fc.CWE,
 },
 }
 }

 loc:= ""
 if fc.URL != "" {
 loc = fc.URL
 } else if fc.IP != "" {
 loc = fmt.Sprintf("%s:%d", fc.IP, fc.Port)
 }

 msgText:= fc.Name
 if msgText == "" {
 msgText = fmt.Sprintf("%s finding on %s", string(fc.Type), fc.Target)
 }

 sr:= SARIFResult{
 RuleID: ruleID,
 Message: SARIFMessage{Text: msgText},
 Level: severityToLevel(fc.Severity),
 PartialFingerprints: map[string]string{
 "primaryLocationLineHash": generateFingerprint(&fc),
 },
 Properties: map[string]interface{}{
 "tool": result.Tool,
 "source": fc.Source,
 "first_seen": fc.FirstSeen.Format(time.RFC3339),
 "last_seen": fc.LastSeen.Format(time.RFC3339),
 "cvss_score": fc.CVSS,
 "tags": fc.Tags,
 },
 }

 if loc != "" {
 sr.Locations = []SARIFLocation{
 {PhysicalLocation: SARIFPhysicalLocation{
 ArtifactLocation: SARIFArtifactLocation{URI: loc},
 }},
 }
 }

 sarifResults = append(sarifResults, sr)
 }

 rules:= make([]SARIFRule, 0, len(ruleMap))
 for _, r:= range ruleMap {
 rules = append(rules, r)
 }

 return SARIFRun{
 Tool: SARIFTool{
 Driver: SARIFDriver{
 Name: result.Tool,
 Version: "1.0.0",
 InformationURI: "https://github.com/Ammar777782439/scanconverter",
 Rules: rules,
 },
 },
 Results: sarifResults,
 }
}