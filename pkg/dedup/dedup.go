// Package dedup implements DefectDojo-inspired finding deduplication [3][4].
package dedup

import (
 "crypto/sha256"
 "fmt"
 "strings"
 "sync"
 "time"

 "github.com/Ammar777782439/scanconverter/pkg/models"
)

// Algorithm selects which deduplication strategy to use.
// Mirrors DefectDojo's four algorithms [3].
type Algorithm string

const (
 // AlgoHash computes SHA256 from configurable field sets per tool type [4].
 AlgoHash Algorithm = "hash"
 // AlgoUniqueID uses Finding.VulnID as the unique identifier.
 AlgoUniqueID Algorithm = "unique_id"
 // AlgoUniqueIDOrHash falls back to hash when VulnID is empty.
 AlgoUniqueIDOrHash Algorithm = "unique_id_or_hash"
 // AlgoLegacy uses target+type+name as the key (backward-compatible).
 AlgoLegacy Algorithm = "legacy"
)

// DefaultHashFields specifies which Finding fields to hash per FindingType.
// Mirrors DefectDojo's HASHCODE_FIELDS_PER_SCANNER dictionary [4].
var DefaultHashFields = map[models.FindingType][]string{
 models.TypeVuln: {"vuln_id", "url", "severity"},
 models.TypePort: {"ip", "port", "protocol"},
 models.TypePath: {"url", "status_code"},
 models.TypeSubdomain: {"hostname"},
 models.TypeService: {"url", "server"},
 models.TypeSecret: {"url", "name"},
}

// HashFinding computes a SHA256 fingerprint from the specified fields.
func HashFinding(f *models.Finding, fields []string) string {
 h:= sha256.New()
 for _, field:= range fields {
 val:= f.FieldValue(field)
 fmt.Fprintf(h, "%s=%v|", field, val)
 }
 return fmt.Sprintf("%x", h.Sum(nil))
}

// legacyKey builds a simple composite key for AlgoLegacy.
func legacyKey(f *models.Finding) string {
 return strings.Join([]string{
 f.Target,
 string(f.Type),
 strings.ToLower(f.Name),
 }, "|")
}

// MergeFindings merges a duplicate finding into the existing one.
// It updates LastSeen, increments OccurrenceCount, and keeps the higher severity.
func MergeFindings(existing, incoming *models.Finding) *models.Finding {
 merged:= *existing
 merged.LastSeen = time.Now().UTC()
 merged.OccurrenceCount++

 // Keep higher severity
 severityOrder:= map[models.Severity]int{
 models.SeverityCritical: 5,
 models.SeverityHigh: 4,
 models.SeverityMedium: 3,
 models.SeverityLow: 2,
 models.SeverityInfo: 1,
 models.SeverityUnknown: 0,
 }
 if severityOrder[incoming.Severity] > severityOrder[existing.Severity] {
 merged.Severity = incoming.Severity
 merged.CVSS = incoming.CVSS
 }

 // Merge tags
 tagSet:= make(map[string]struct{})
 for _, t:= range existing.Tags {
 tagSet[t] = struct{}{}
 }
 for _, t:= range incoming.Tags {
 if _, seen:= tagSet[t]; !seen {
 merged.Tags = append(merged.Tags, t)
 tagSet[t] = struct{}{}
 }
 }
 return &merged
}

// DeduplicateByUniqueID removes findings with duplicate VulnIDs, keeping the first seen.
func DeduplicateByUniqueID(findings []models.Finding) []models.Finding {
 seen:= make(map[string]struct{}, len(findings))
 out:= make([]models.Finding, 0, len(findings))
 for _, f:= range findings {
 if f.VulnID == "" {
 out = append(out, f)
 continue
 }
 if _, dup:= seen[f.VulnID]; dup {
 continue
 }
 seen[f.VulnID] = struct{}{}
 out = append(out, f)
 }
 return out
}

// DeduplicationStats tracks deduplication outcomes.
type DeduplicationStats struct {
 TotalIn int `json:"total_in"`
 TotalOut int `json:"total_out"`
 Duplicates int `json:"duplicates"`
 Merges int `json:"merges"`
 Algorithm Algorithm `json:"algorithm"`
 ProcessedAt time.Time `json:"processed_at"`
}

// Config configures a Deduplicator.
type Config struct {
 Algorithm Algorithm `json:"algorithm"`
 CustomFields map[models.FindingType][]string `json:"custom_fields,omitempty"`
}

// DefaultConfig returns a Deduplicator config using hash-based dedup.
func DefaultConfig() Config {
 return Config{Algorithm: AlgoHash}
}

// Deduplicator processes a ScanResult and removes or merges duplicate findings.
type Deduplicator struct {
 cfg Config
 mu sync.Mutex
 index map[string]*models.Finding // fingerprint → canonical finding
 stats DeduplicationStats
}

// NewDeduplicator creates a Deduplicator with the given config.
func NewDeduplicator(cfg Config) *Deduplicator {
 return &Deduplicator{
 cfg: cfg,
 index: make(map[string]*models.Finding),
 }
}

// computeKey returns the deduplication key for a Finding under the configured algorithm.
func (d *Deduplicator) computeKey(f *models.Finding) string {
 switch d.cfg.Algorithm {
 case AlgoUniqueID:
 return f.VulnID
 case AlgoUniqueIDOrHash:
 if f.VulnID != "" {
 return f.VulnID
 }
 fallthrough
 case AlgoHash:
 fields:= d.hashFields(f.Type)
 return HashFinding(f, fields)
 case AlgoLegacy:
 return legacyKey(f)
 default:
 return legacyKey(f)
 }
}

func (d *Deduplicator) hashFields(ft models.FindingType) []string {
 if d.cfg.CustomFields != nil {
 if fields, ok:= d.cfg.CustomFields[ft]; ok {
 return fields
 }
 }
 if fields, ok:= DefaultHashFields[ft]; ok {
 return fields
 }
 return []string{"target", "type", "name"}
}

// Process deduplicates findings in a ScanResult and returns a new result.
func (d *Deduplicator) Process(result *models.ScanResult) *models.ScanResult {
 d.mu.Lock()
 defer d.mu.Unlock()

 out:= models.NewScanResult(result.Tool, result.Target, result.JobID)
 out.Pipeline = result.Pipeline
 d.stats.TotalIn += len(result.Findings)
 d.stats.Algorithm = d.cfg.Algorithm
 d.stats.ProcessedAt = time.Now().UTC()

 for _, f:= range result.Findings {
 fc:= f
 key:= d.computeKey(&fc)
 if key == "" {
 out.AddFinding(fc)
 continue
 }
 if existing, dup:= d.index[key]; dup {
 merged:= MergeFindings(existing, &fc)
 d.index[key] = merged
 d.stats.Duplicates++
 d.stats.Merges++
 continue
 }
 fc.Fingerprint = key
 d.index[key] = &fc
 out.AddFinding(fc)
 }

 d.stats.TotalOut += len(out.Findings)
 out.BuildSummary()
 if out.Summary != nil {
 out.Summary.Duplicates = d.stats.Duplicates
 }
 return out
}

// Stats returns cumulative deduplication statistics.
func (d *Deduplicator) Stats() DeduplicationStats {
 d.mu.Lock()
 defer d.mu.Unlock()
 return d.stats
}

// Reset clears the internal index (use between independent scan sessions).
func (d *Deduplicator) Reset() {
 d.mu.Lock()
 defer d.mu.Unlock()
 d.index = make(map[string]*models.Finding)
}