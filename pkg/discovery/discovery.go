// Package discovery provides automatic schema generation from raw tool output.
// It analyzes unknown file formats and produces a best-guess ToolSchema
// that can be confirmed by the user and saved for future use.
package discovery

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

// ─── Confidence levels ────────────────────────────────────────────────────────

// Confidence represents how certain the engine is about a mapping (0–100).
type Confidence float64

const (
	ConfidenceHigh   Confidence = 90
	ConfidenceMedium Confidence = 60
	ConfidenceLow    Confidence = 30
)

// ─── Field hint database ──────────────────────────────────────────────────────

// fieldHint maps candidate key names (lowercase) → unified Finding field name.
// The engine scores each discovered key against this map using substring matching.
var fieldHints = []struct {
	Keywords []string // substrings to match against the raw key
	Target   string   // unified Finding field name
	Weight   float64  // score contribution per keyword match
}{
	// --- Identity / target ---
	{Keywords: []string{"host", "target", "domain", "fqdn"}, Target: "hostname", Weight: 1.2},
	{Keywords: []string{"ip", "addr", "address"}, Target: "ip", Weight: 1.5},
	{Keywords: []string{"url", "matched", "link", "endpoint", "path"}, Target: "url", Weight: 1.2},

	// --- Port / protocol ---
	{Keywords: []string{"port", "portid"}, Target: "port", Weight: 2.0},
	{Keywords: []string{"proto", "protocol"}, Target: "protocol", Weight: 1.8},
	{Keywords: []string{"state", "status"}, Target: "state", Weight: 1.0},
	{Keywords: []string{"service", "svc", "name"}, Target: "service", Weight: 1.0},
	{Keywords: []string{"version", "ver", "product"}, Target: "version", Weight: 1.0},

	// --- HTTP ---
	{Keywords: []string{"status_code", "statuscode", "status-code", "code"}, Target: "status_code", Weight: 1.5},
	{Keywords: []string{"content_length", "content-length", "length", "size"}, Target: "content_length", Weight: 1.2},
	{Keywords: []string{"title", "page_title"}, Target: "title", Weight: 1.5},
	{Keywords: []string{"server", "webserver", "web_server"}, Target: "server", Weight: 1.2},
	{Keywords: []string{"method", "http_method"}, Target: "method", Weight: 1.5},

	// --- Vulnerability ---
	{Keywords: []string{"severity", "risk", "level", "criticality", "priority"}, Target: "severity", Weight: 2.0},
	{Keywords: []string{"cvss", "score", "cvss_score"}, Target: "cvss_score", Weight: 2.0},
	{Keywords: []string{"cve", "vuln_id", "template-id", "templateid", "finding_id"}, Target: "vuln_id", Weight: 1.8},
	{Keywords: []string{"name", "title", "vuln_name", "finding"}, Target: "name", Weight: 1.0},
	{Keywords: []string{"description", "desc", "details", "info"}, Target: "description", Weight: 0.8},
	{Keywords: []string{"solution", "remediation", "fix", "recommendation"}, Target: "solution", Weight: 1.2},
	{Keywords: []string{"reference", "ref", "link", "resource"}, Target: "reference", Weight: 0.8},

	// --- Subdomain ---
	{Keywords: []string{"subdomain", "sub", "hostname"}, Target: "hostname", Weight: 1.5},

	// --- Meta ---
	{Keywords: []string{"timestamp", "time", "date", "created"}, Target: "timestamp", Weight: 0.5},
	{Keywords: []string{"source", "tool", "scanner"}, Target: "source", Weight: 0.5},
}

// knownToolSignatures maps known key patterns → tool name.
// Used for tool auto-detection before schema generation.
var knownToolSignatures = []struct {
	Keys []string // keys that must ALL be present
	Tool string
	Type string // finding_type
}{
	{Keys: []string{"template-id", "matcher-status", "info"}, Tool: "nuclei", Type: "vulnerability"},
	{Keys: []string{"host", "port", "matched-at"}, Tool: "httpx", Type: "http"},
	{Keys: []string{"host", "input", "a"}, Tool: "subfinder", Type: "subdomain"},
	{Keys: []string{"Vulnerabilities", "Target", "Class"}, Tool: "trivy", Type: "vulnerability"},
	{Keys: []string{"ip", "ports", "mac"}, Tool: "masscan", Type: "port"},
	{Keys: []string{"url", "status", "length", "words"}, Tool: "ffuf", Type: "path"},
	{Keys: []string{"domain", "subdomain", "ip", "sources"}, Tool: "amass", Type: "subdomain"},
}

// severityValues are common severity strings used to detect severity fields.
var severityValues = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
	"info": true, "informational": true, "unknown": true,
	"none": true, "negligible": true,
}

// ─── DiscoveredField ──────────────────────────────────────────────────────────

// DiscoveredField represents a key found in the raw output, mapped to a
// unified Finding field with a confidence score.
type DiscoveredField struct {
	RawKey     string     `json:"raw_key"`     // The original key in the file (e.g. "matched-at")
	TargetField string    `json:"target_field"` // The unified field name (e.g. "url")
	Confidence Confidence `json:"confidence"`   // How sure we are (0–100)
	SampleValue string   `json:"sample_value"` // A sample value to help the user verify
}

// ─── DiscoveryResult ──────────────────────────────────────────────────────────

// DiscoveryResult is the output of the Auto-Discovery engine.
// It contains both the generated Schema and enough metadata for a UI to
// display a "confirm & adjust" screen to the user.
type DiscoveryResult struct {
	// Generated schema (ready to use or save)
	Schema *schema.ToolSchema `json:"schema"`

	// Detected tool name (may be empty if unknown)
	DetectedTool string `json:"detected_tool,omitempty"`

	// Detected format
	DetectedFormat schema.FormatType `json:"detected_format"`

	// Overall confidence in the detection (0–100)
	OverallConfidence Confidence `json:"overall_confidence"`

	// All discovered field mappings with individual confidence scores
	DiscoveredFields []DiscoveredField `json:"discovered_fields"`

	// Fields that were found in the file but couldn't be mapped
	UnmappedKeys []string `json:"unmapped_keys,omitempty"`

	// Warning messages (e.g. "multiple keys mapped to same target")
	Warnings []string `json:"warnings,omitempty"`

	// Sample data extracted for display in the UI
	SampleRecord map[string]interface{} `json:"sample_record,omitempty"`
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine is the Auto-Discovery engine.
type Engine struct{
	schemas []*schema.ToolSchema
}

// New creates a new Auto-Discovery Engine.
// It accepts a list of known schemas to use for dynamic tool detection.
func New(schemas []*schema.ToolSchema) *Engine { return &Engine{schemas: schemas} }

// Discover analyzes raw tool output and returns a DiscoveryResult.
// The toolNameHint is optional — if provided, it overrides auto-detection.
func (e *Engine) Discover(raw []byte, toolNameHint string) (*DiscoveryResult, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("discovery: empty input")
	}

	// 1. Detect format
	format, err := detectFormat(raw)
	if err != nil {
		return nil, err
	}

	// 2. Extract flat key-value map from the first record
	keys, sample, err := extractKeys(raw, format)
	if err != nil {
		return nil, fmt.Errorf("discovery: extract keys: %w", err)
	}

	// 3. Detect tool (if not hinted)
	detectedTool := toolNameHint
	detectedType := "vulnerability" // default
	if detectedTool == "" {
		detectedTool, detectedType = e.detectTool(keys)
	}

	// 4. Map keys → unified fields
	discovered, unmapped, warnings := mapFields(keys, sample)

	// 5. Build ToolSchema from discovered mappings
	sch := buildSchema(detectedTool, format, detectedType, discovered)

	// 6. Compute overall confidence
	overall := computeOverallConfidence(discovered)

	return &DiscoveryResult{
		Schema:            sch,
		DetectedTool:      detectedTool,
		DetectedFormat:    format,
		OverallConfidence: overall,
		DiscoveredFields:  discovered,
		UnmappedKeys:      unmapped,
		Warnings:          warnings,
		SampleRecord:      sample,
	}, nil
}

// ─── Format detection ─────────────────────────────────────────────────────────

func detectFormat(raw []byte) (schema.FormatType, error) {
	// XML: starts with '<'
	if raw[0] == '<' {
		return schema.FormatXML, nil
	}

	// Try JSON object
	if raw[0] == '{' {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) == nil {
			return schema.FormatJSON, nil
		}
	}

	// Try JSON array
	if raw[0] == '[' {
		var arr []interface{}
		if json.Unmarshal(raw, &arr) == nil {
			return schema.FormatJSON, nil
		}
	}

	// JSONL: multiple lines each being a valid JSON object
	lines := bytes.Split(raw, []byte("\n"))
	validJSON := 0
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal(line, &m) == nil {
			validJSON++
		}
		if validJSON >= 2 {
			return schema.FormatJSONL, nil
		}
	}
	if validJSON == 1 {
		return schema.FormatJSONL, nil
	}

	// Fallback: text
	return schema.FormatText, nil
}

// ─── Key extraction ───────────────────────────────────────────────────────────

// extractKeys flattens the first record into a map of dotted-path → sample value.
// e.g. {"info.severity": "medium", "template-id": "CVE-2021-31589", ...}
func extractKeys(raw []byte, format schema.FormatType) ([]string, map[string]interface{}, error) {
	switch format {
	case schema.FormatJSONL:
		lines := bytes.Split(raw, []byte("\n"))
		for _, line := range lines {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			var m map[string]interface{}
			if err := json.Unmarshal(line, &m); err == nil {
				flat := flattenMap(m, "")
				keys := mapKeys(flat)
				return keys, flat, nil
			}
		}
		return nil, nil, fmt.Errorf("no valid JSONL records found")

	case schema.FormatJSON:
		var obj interface{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, nil, err
		}
		// If it's an array, use first element
		if arr, ok := obj.([]interface{}); ok && len(arr) > 0 {
			if m, ok := arr[0].(map[string]interface{}); ok {
				flat := flattenMap(m, "")
				return mapKeys(flat), flat, nil
			}
		}
		if m, ok := obj.(map[string]interface{}); ok {
			flat := flattenMap(m, "")
			return mapKeys(flat), flat, nil
		}
		return nil, nil, fmt.Errorf("unsupported JSON structure")

	case schema.FormatXML:
		// For XML, extract attribute names from the raw content using regex
		attrRe := regexp.MustCompile(`(\w+)=["'][^"']*["']`)
		matches := attrRe.FindAllStringSubmatch(string(raw), -1)
		seen := map[string]bool{}
		var keys []string
		sample := map[string]interface{}{}
		for _, m := range matches {
			k := m[1]
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
				sample[k] = strings.Split(m[0], "=")[1]
			}
		}
		// Also extract element names
		elemRe := regexp.MustCompile(`<(\w+)[\s>]`)
		eMatches := elemRe.FindAllStringSubmatch(string(raw), -1)
		for _, m := range eMatches {
			k := m[1]
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		return keys, sample, nil

	default:
		return nil, nil, fmt.Errorf("text format: manual schema required")
	}
}

// flattenMap recursively flattens a nested map into dot-notation paths.
func flattenMap(m map[string]interface{}, prefix string) map[string]interface{} {
	result := map[string]interface{}{}
	for k, v := range m {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]interface{}:
			for fk, fv := range flattenMap(val, fullKey) {
				result[fk] = fv
			}
		case []interface{}:
			// Store the array itself; don't recurse into arrays
			result[fullKey] = v
		default:
			result[fullKey] = val
		}
	}
	return result
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ─── Tool detection ───────────────────────────────────────────────────────────

func (e *Engine) detectTool(keys []string) (toolName string, findingType string) {
	keySet := map[string]bool{}
	for _, k := range keys {
		// Use only the last segment for signature matching
		parts := strings.Split(k, ".")
		keySet[parts[len(parts)-1]] = true
		keySet[k] = true
	}

	bestScore := 0
	
	// Dynamic detection: score against all provided schemas
	for _, sch := range e.schemas {
		score := 0
		requiredKeys := 0
		
		for _, field := range sch.Fields {
			if field.Required {
				requiredKeys++
			}
			
			// Check both the full path and the last segment
			parts := strings.Split(field.Path, ".")
			lastSeg := parts[len(parts)-1]
			
			if keySet[field.Path] || keySet[lastSeg] {
				score++
			}
		}

		// Tool must match at least 2 keys or all required keys to be considered
		if score > bestScore && (score >= 2 || (requiredKeys > 0 && score >= requiredKeys)) {
			bestScore = score
			toolName = sch.Name
			findingType = sch.FindingType
		}
	}

	if bestScore == 0 {
		return "unknown", "vulnerability"
	}
	return toolName, findingType
}

// ─── Field mapping ────────────────────────────────────────────────────────────

func mapFields(keys []string, sample map[string]interface{}) (
	discovered []DiscoveredField,
	unmapped []string,
	warnings []string,
) {
	// Track which target fields already have a high-confidence mapping
	// to warn about conflicts
	targetClaimed := map[string]string{}

	for _, key := range keys {
		// Normalize the key for matching (lowercase, replace separators)
		normalized := strings.ToLower(key)
		normalized = strings.ReplaceAll(normalized, "-", "_")
		normalized = strings.ReplaceAll(normalized, ".", "_")
		// Use only the last segment for short matching
		segments := strings.Split(normalized, "_")
		lastSeg := segments[len(segments)-1]

		best := scoreKey(normalized, lastSeg, sample[key])
		if best.TargetField == "" {
			unmapped = append(unmapped, key)
			continue
		}

		// Conflict warning
		if prev, exists := targetClaimed[best.TargetField]; exists && best.Confidence >= ConfidenceMedium {
			warnings = append(warnings, fmt.Sprintf(
				"両 '%s' and '%s' map to '%s' — kept highest confidence",
				prev, key, best.TargetField,
			))
		}

		best.RawKey = key
		// Attach sample value
		if v, ok := sample[key]; ok {
			best.SampleValue = fmt.Sprintf("%v", v)
			if len(best.SampleValue) > 80 {
				best.SampleValue = best.SampleValue[:80] + "…"
			}
		}

		// Only keep the highest-confidence mapping per target
		replaced := false
		for i, d := range discovered {
			if d.TargetField == best.TargetField && best.Confidence > d.Confidence {
				discovered[i] = best
				targetClaimed[best.TargetField] = key
				replaced = true
				break
			}
		}
		if !replaced {
			if _, claimed := targetClaimed[best.TargetField]; !claimed {
				discovered = append(discovered, best)
				targetClaimed[best.TargetField] = key
			}
		}
	}
	return
}

// scoreKey returns the best DiscoveredField match for a given key.
func scoreKey(normalized, lastSeg string, sampleVal interface{}) DiscoveredField {
	type candidate struct {
		target string
		score  float64
	}
	var candidates []candidate

	for _, hint := range fieldHints {
		score := 0.0
		for _, kw := range hint.Keywords {
			kwNorm := strings.ReplaceAll(strings.ToLower(kw), "-", "_")
			// Exact match on last segment → very high score
			if lastSeg == kwNorm {
				score += hint.Weight * 3
				continue
			}
			// Substring match on full normalized key
			if strings.Contains(normalized, kwNorm) {
				score += hint.Weight
			}
		}
		if score > 0 {
			candidates = append(candidates, candidate{target: hint.Target, score: score})
		}
	}

	// Bonus: if sample value looks like a known severity → boost severity
	if sv, ok := sampleVal.(string); ok {
		if severityValues[strings.ToLower(sv)] {
			for i, c := range candidates {
				if c.target == "severity" {
					candidates[i].score += 5
				}
			}
		}
		// Bonus: sample value looks like an IP
		if isIP(sv) {
			for i, c := range candidates {
				if c.target == "ip" {
					candidates[i].score += 5
				}
			}
		}
		// Bonus: sample value looks like a URL
		if strings.HasPrefix(sv, "http") {
			for i, c := range candidates {
				if c.target == "url" || c.target == "hostname" {
					candidates[i].score += 3
				}
			}
		}
		// Bonus: sample value is numeric integer → port candidate
		if _, err := strconv.Atoi(sv); err == nil {
			n, _ := strconv.Atoi(sv)
			if n > 0 && n <= 65535 {
				for i, c := range candidates {
					if c.target == "port" {
						candidates[i].score += 4
					}
				}
			}
		}
	}

	if len(candidates) == 0 {
		return DiscoveredField{}
	}

	// Pick best candidate
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.score > best.score {
			best = c
		}
	}

	// Normalize score to 0–100 confidence
	conf := Confidence(math.Min(100, best.score*10))
	if conf < 20 {
		return DiscoveredField{} // too uncertain, treat as unmapped
	}

	return DiscoveredField{
		TargetField: best.target,
		Confidence:  conf,
	}
}

// ─── Schema builder ───────────────────────────────────────────────────────────

func buildSchema(name string, format schema.FormatType, findingType string, fields []DiscoveredField) *schema.ToolSchema {
	if name == "" {
		name = "discovered"
	}
	sch := &schema.ToolSchema{
		Name:        name,
		Version:     "auto-1.0",
		Format:      format,
		FindingType: findingType,
		Description: fmt.Sprintf("Auto-generated schema for %q by scanconverter discovery engine", name),
	}

	for _, df := range fields {
		if df.TargetField == "" {
			continue
		}
		sch.Fields = append(sch.Fields, schema.FieldMapping{
			Name: df.TargetField,
			Path: df.RawKey,
		})
	}
	return sch
}

// ─── Confidence computation ───────────────────────────────────────────────────

func computeOverallConfidence(fields []DiscoveredField) Confidence {
	if len(fields) == 0 {
		return 0
	}
	// Core fields that must be mapped for a useful schema
	coreFields := map[string]bool{
		"ip": true, "hostname": true, "url": true,
		"severity": true, "port": true,
	}
	coreFound := 0
	total := 0.0
	for _, f := range fields {
		total += float64(f.Confidence)
		if coreFields[f.TargetField] {
			coreFound++
		}
	}
	avg := total / float64(len(fields))
	// Bonus for finding core fields
	coreBonus := float64(coreFound) * 5
	return Confidence(math.Min(100, avg+coreBonus))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var ipRe = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

func isIP(s string) bool { return ipRe.MatchString(s) }

// XMLSniffer is used only for XML format detection (compile-time check).
var _ = xml.Unmarshal
