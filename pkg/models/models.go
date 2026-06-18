// Package models defines the unified data structures for all security tool outputs.
package models

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FindingType classifies what a Finding represents.
type FindingType string

const (
	TypePort      FindingType = "port"
	TypeVuln      FindingType = "vulnerability"
	TypePath      FindingType = "path"
	TypeSubdomain FindingType = "subdomain"
	TypeService   FindingType = "service"
	TypeSecret    FindingType = "secret"
	TypeMisconfig FindingType = "misconfiguration"
	TypeRaw       FindingType = "raw"
)

// Severity normalizes severity levels across all tools.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// ScanStatus represents the outcome of a scan run.
type ScanStatus string

const (
	StatusSuccess   ScanStatus = "success"
	StatusFailed    ScanStatus = "failed"
	StatusPartial   ScanStatus = "partial"
	StatusTimeout   ScanStatus = "timeout"
	StatusCancelled ScanStatus = "cancelled"
)

// Finding is the unified representation of one result from any security tool.
// All tool-specific fields map into this struct; unmapped fields go into Extra.
type Finding struct {
	// Identity
	Type   FindingType `json:"type"`
	Target string      `json:"target"`

	// Network
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	State    string `json:"state,omitempty"`

	// HTTP
	URL        string `json:"url,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	ContentLen int    `json:"content_length,omitempty"`
	Title      string `json:"title,omitempty"`
	Server     string `json:"server,omitempty"`

	// Service
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`

	// Vulnerability
	VulnID     string   `json:"vuln_id,omitempty"`
	Name       string   `json:"name,omitempty"`
	Severity   Severity `json:"severity,omitempty"`
	CVSS       float64  `json:"cvss_score,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	References []string `json:"references,omitempty"`
	Matched    string   `json:"matched,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`

	// Subdomain
	Hostname string `json:"hostname,omitempty"`

	// Advanced fields (v2)
	Fingerprint     string    `json:"fingerprint,omitempty"` // SHA256 dedup hash
	Confidence      float64   `json:"confidence,omitempty"`  // 0.0–1.0
	Tags            []string  `json:"tags,omitempty"`
	Remediation     string    `json:"remediation,omitempty"`
	FirstSeen       time.Time `json:"first_seen,omitempty"`
	LastSeen        time.Time `json:"last_seen,omitempty"`
	OccurrenceCount int       `json:"occurrence_count,omitempty"`
	Source          string    `json:"source,omitempty"`   // tool name
	RawLine         string    `json:"raw_line,omitempty"` // original TXT line

	Extra     map[string]interface{} `json:"extra,omitempty"`
	Extracted map[string]interface{} `json:"extracted,omitempty"`
}

// ComputeFingerprint computes a SHA256 fingerprint from the specified fields.
// fields is a list of field names like ["vuln_id", "url", "severity"].
func (f *Finding) ComputeFingerprint(fields []string) string {
	h := sha256.New()
	for _, field := range fields {
		val := f.FieldValue(field)
		fmt.Fprintf(h, "%s=%v|", field, val)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// FieldValue returns the value of a named field as interface{}.
func (f *Finding) FieldValue(name string) interface{} {
	switch strings.ToLower(name) {
	case "type":
		return string(f.Type)
	case "target":
		return f.Target
	case "ip":
		return f.IP
	case "port":
		return f.Port
	case "protocol":
		return f.Protocol
	case "url":
		return f.URL
	case "status_code":
		return f.StatusCode
	case "vuln_id", "template-id", "template_id":
		return f.VulnID
	case "name":
		return f.Name
	case "severity":
		return string(f.Severity)
	case "cvss", "cvss_score":
		return f.CVSS
	case "hostname":
		return f.Hostname
	default:
		if f.Extra != nil {
			return f.Extra[name]
		}
		return nil
	}
}

// ScanSummary holds aggregated statistics for a ScanResult.
type ScanSummary struct {
	TotalTargets       int            `json:"total_targets"`
	TotalFindings      int            `json:"total_findings"`
	FindingsByType     map[string]int `json:"findings_by_type"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	PortsOpen          int            `json:"ports_open,omitempty"`
	Vulnerabilities    int            `json:"vulnerabilities,omitempty"`
	Subdomains         int            `json:"subdomains,omitempty"`
	Paths              int            `json:"paths,omitempty"`
	Duplicates         int            `json:"duplicates,omitempty"`
}

// InstanceInfo describes the compute instance that ran the scan.
type InstanceInfo struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Region   string `json:"region"`
	Provider string `json:"provider"`
}

// ProxyInfo records the proxy used during the scan.
type ProxyInfo struct {
	URL       string    `json:"url"`
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Provider  string    `json:"provider"`
	RotatedAt time.Time `json:"rotated_at,omitempty"`
}

// ScanResult wraps all findings from a single tool run.
type ScanResult struct {
	ID        string        `json:"id"`
	JobID     string        `json:"job_id"`
	Tool      string        `json:"tool"`
	Target    string        `json:"target"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration,omitempty"`
	Status    ScanStatus    `json:"status"`
	Error     string        `json:"error,omitempty"`

	Findings  []Finding    `json:"findings,omitempty"`
	Summary   *ScanSummary `json:"summary,omitempty"`
	RawOutput string       `json:"raw_output,omitempty"`

	// Advanced fields (v2)
	Pipeline string                 `json:"pipeline,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	Instance *InstanceInfo `json:"instance_info,omitempty"`
	Proxy    *ProxyInfo    `json:"proxy_info,omitempty"`
}

// NewScanResult creates a ScanResult with sensible defaults.
func NewScanResult(tool, target, jobID string) *ScanResult {
	return &ScanResult{
		ID:        generateID(),
		JobID:     jobID,
		Tool:      tool,
		Target:    target,
		Timestamp: time.Now().UTC(),
		Status:    StatusSuccess,
		Findings:  make([]Finding, 0),
		Metadata:  make(map[string]interface{}),
	}
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// AddFinding appends a Finding and sets Source if empty.
func (r *ScanResult) AddFinding(f Finding) {
	if f.Source == "" {
		f.Source = r.Tool
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = time.Now().UTC()
	}
	f.LastSeen = time.Now().UTC()
	r.Findings = append(r.Findings, f)
}

// BuildSummary computes ScanSummary from current Findings.
func (r *ScanResult) BuildSummary() {
	s := &ScanSummary{
		TotalTargets:       1,
		TotalFindings:      len(r.Findings),
		FindingsByType:     make(map[string]int),
		FindingsBySeverity: make(map[string]int),
	}
	for _, f := range r.Findings {
		s.FindingsByType[string(f.Type)]++
		if f.Severity != "" {
			s.FindingsBySeverity[string(f.Severity)]++
		}
		switch f.Type {
		case TypePort:
			if f.State == "open" {
				s.PortsOpen++
			}
		case TypeVuln:
			s.Vulnerabilities++
		case TypeSubdomain:
			s.Subdomains++
		case TypePath:
			s.Paths++
		}
	}
	r.Summary = s
}

// ToJSON serializes the ScanResult to JSON bytes.
func (r *ScanResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", " ")
}

// ToCSV serializes Findings to CSV bytes.
func (r *ScanResult) ToCSV() ([]byte, error) {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{
		"type", "target", "ip", "port", "url",
		"status_code", "severity", "vuln_id", "name",
		"cvss", "hostname", "source",
	})
	for _, f := range r.Findings {
		_ = w.Write([]string{
			string(f.Type), f.Target, f.IP,
			fmt.Sprintf("%d", f.Port), f.URL,
			fmt.Sprintf("%d", f.StatusCode),
			string(f.Severity), f.VulnID, f.Name,
			fmt.Sprintf("%.1f", f.CVSS), f.Hostname, f.Source,
		})
	}
	w.Flush()
	return []byte(sb.String()), w.Error()
}

// Merge combines findings from another ScanResult into this one.
// Duplicate fingerprints are skipped; OccurrenceCount is incremented.
func (r *ScanResult) Merge(other *ScanResult) *ScanResult {
	seen := make(map[string]struct{})
	for _, f := range r.Findings {
		if f.Fingerprint != "" {
			seen[f.Fingerprint] = struct{}{}
		}
	}
	for _, f := range other.Findings {
		if f.Fingerprint != "" {
			if _, dup := seen[f.Fingerprint]; dup {
				// update occurrence count on existing
				for i := range r.Findings {
					if r.Findings[i].Fingerprint == f.Fingerprint {
						r.Findings[i].OccurrenceCount++
						r.Findings[i].LastSeen = time.Now().UTC()
					}
				}
				continue
			}
		}
		r.AddFinding(f)
		seen[f.Fingerprint] = struct{}{}
	}
	r.BuildSummary()
	return r
}
