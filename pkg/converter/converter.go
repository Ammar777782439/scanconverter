// Package converter transforms raw tool output into unified ScanResult structures.
package converter

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	"github.com/Ammar777782439/scanconverter/pkg/models"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
	"github.com/Ammar777782439/scanconverter/pkg/filter"
)

// --- Preprocessors ---

var ansiEscape = regexp.MustCompile(`\x1b$$
[0]*[a-zA-Z]`)

// stripANSI removes ANSI escape codes from TXT tool outputs (e.g., gobuster colored output).
func stripANSI(b []byte) []byte {
	return ansiEscape.ReplaceAll(b, nil)
}

// normalizeLineEndings converts \r\n and bare \r to \n.
func normalizeLineEndings(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
	return b
}

// decodeBase64Lines is a no-op placeholder; Nikto request/response fields are
// already base64 strings inside JSON — callers decode them per-field as needed.
func decodeBase64Lines(b []byte) []byte { return b }

// applyPreprocessors runs the named preprocessors in order.
func applyPreprocessors(raw []byte, names []string) []byte {
	for _, name := range names {
		switch name {
		case "trim_ansi":
			raw = stripANSI(raw)
		case "normalize_lines":
			raw = normalizeLineEndings(raw)
		case "base64_decode":
			raw = decodeBase64Lines(raw)
		}
	}
	return raw
}

// --- Nmap XML structs ---

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses   []nmapAddress `xml:"address"`
	Hostnames   nmapHostnames `xml:"hostnames"`
	Ports       nmapPorts     `xml:"ports"`
	HostScripts []nmapScript  `xml:"hostscript>script"`
	Os          nmapOs        `xml:"os"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapOs struct {
	OsMatches []nmapOsMatch `xml:"osmatch"`
}

type nmapOsMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// parseNmapXML parses nmap XML output (nmaprun > host > ports > port) [2].
func parseNmapXML(raw []byte, target, jobID string) (*models.ScanResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return nil, fmt.Errorf("nmap xml unmarshal: %w", err)
	}
	r := models.NewScanResult("nmap", target, jobID)
	for _, host := range run.Hosts {
		ip := ""
		mac := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
			} else if addr.AddrType == "mac" {
				mac = addr.Addr
			}
		}

		var hnames []string
		for _, hn := range host.Hostnames.Hostnames {
			hnames = append(hnames, hn.Name)
		}
		hostnameStr := strings.Join(hnames, ",")

		osName := ""
		if len(host.Os.OsMatches) > 0 {
			osName = host.Os.OsMatches[0].Name
		}

		for _, port := range host.Ports.Ports {
			f := models.Finding{
				Type:     models.TypePort,
				Target:   target,
				IP:       ip,
				Hostname: hostnameStr,
				Port:     port.PortID,
				Protocol: port.Protocol,
				State:    port.State.State,
				Service:  port.Service.Name,
				Version:  strings.TrimSpace(port.Service.Product + " " + port.Service.Version),
				Extra:    make(map[string]interface{}),
			}

			if mac != "" {
				f.Extra["mac"] = mac
			}
			if osName != "" {
				f.Extra["os"] = osName
			}

			if len(port.Scripts) > 0 {
				scriptsMap := make(map[string]string)
				for _, s := range port.Scripts {
					scriptsMap[s.ID] = s.Output
				}
				f.Extra["scripts"] = scriptsMap
			}

			r.AddFinding(f)
		}

		// If there are host scripts (e.g. vulnerability checks running against the host directly)
		if len(host.HostScripts) > 0 {
			f := models.Finding{
				Type:     models.TypeVuln,
				Target:   target,
				IP:       ip,
				Hostname: hostnameStr,
				Extra:    make(map[string]interface{}),
			}
			scriptsMap := make(map[string]string)
			for _, s := range host.HostScripts {
				scriptsMap[s.ID] = s.Output
			}
			f.Extra["host_scripts"] = scriptsMap
			f.Name = "Nmap Host Script Result"
			r.AddFinding(f)
		}
	}
	return r, nil
}

// --- Converter ---

// Converter transforms raw tool output into a unified ScanResult.
type Converter struct {
	registry *schema.Registry
	log      *zap.Logger
}

// Option configures a Converter.
type Option func(*Converter)

// WithLogger sets the logger.
func WithLogger(l *zap.Logger) Option {
	return func(c *Converter) { c.log = l }
}

// NewConverter creates a Converter backed by the given Registry.
func NewConverter(reg *schema.Registry, opts ...Option) *Converter {
	c := &Converter{registry: reg, log: zap.NewNop()}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Convert parses raw tool output into a ScanResult.
// If no schema is found for tool, the output is stored as TypeRaw.
func (c *Converter) Convert(tool string, raw []byte, target, jobID string) (*models.ScanResult, error) {
	// Special case: nmap XML
	if tool == "nmap" {
		r, err := parseNmapXML(raw, target, jobID)
		if r != nil {
			// Apply Schema Filters if present
			if nmapSch, ok := c.registry.Get("nmap"); ok && nmapSch.Filters != nil && len(nmapSch.Filters.Expressions) > 0 {
				chain := filter.NewFilterChain()
				for _, exprStr := range nmapSch.Filters.Expressions {
					chain.AddExpressionRule(exprStr)
				}
				r = chain.Apply(r)
			}
		}
		return r, err
	}

	sch, ok := c.registry.Get(tool)
	if !ok {
		return c.parseGeneric(tool, raw, target, jobID), nil
	}

	raw = applyPreprocessors(raw, sch.Preprocessors)

	var (
		r   *models.ScanResult
		err error
	)
	switch sch.Format {
	case schema.FormatJSON, schema.FormatJSONL:
		r, err = c.parseJSON(tool, raw, target, jobID, sch)
	case schema.FormatXML:
		// Generic XML → JSON fallback (nmap has dedicated parser above)
		r, err = c.parseGenericXML(tool, raw, target, jobID, sch)
	case schema.FormatText:
		r, err = c.parseText(tool, raw, target, jobID, sch)
	default:
		r = c.parseGeneric(tool, raw, target, jobID)
	}
	if r != nil {
		r.RawOutput = string(raw)
		for i := range r.Findings {
			if r.Findings[i].Target == "" {
				r.Findings[i].Target = target
			}
		}
		r.BuildSummary()

		// Apply Schema Filters if present
		if sch != nil && sch.Filters != nil && len(sch.Filters.Expressions) > 0 {
			chain := filter.NewFilterChain()
			for _, exprStr := range sch.Filters.Expressions {
				chain.AddExpressionRule(exprStr)
			}
			filtered := chain.Apply(r)
			r = filtered
		}
	}
	return r, err
}

// ConvertStream reads JSONL from r and emits Findings on the returned channel.
// This avoids loading the entire file into memory for large JSONL outputs.
func (c *Converter) ConvertStream(
	tool string,
	r io.Reader,
	target, jobID string,
) (<-chan models.Finding, <-chan error) {
	findings := make(chan models.Finding, 256)
	errs := make(chan error, 1)

	go func() {
		defer close(findings)
		defer close(errs)

		sch, ok := c.registry.Get(tool)
		if !ok {
			errs <- fmt.Errorf("ConvertStream: no schema for %q", tool)
			return
		}

		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10 MB max line
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			f, err := c.extractFindingFromJSON(line, sch)
			if err != nil {
				c.log.Warn("stream parse line failed", zap.Error(err))
				continue
			}
			if f != nil {
				if f.Target == "" {
					f.Target = target
				}
				findings <- *f
			}
		}
		if err := scanner.Err(); err != nil {
			errs <- fmt.Errorf("ConvertStream scan: %w", err)
		}
	}()
	return findings, errs
}

func (c *Converter) parseGeneric(tool string, raw []byte, target, jobID string) *models.ScanResult {
	r := models.NewScanResult(tool, target, jobID)
	r.Status = models.StatusPartial
	r.AddFinding(models.Finding{
		Type:    models.TypeRaw,
		Target:  target,
		RawLine: string(raw),
		Extra:   map[string]interface{}{"content": string(raw)},
	})
	return r
}

func (c *Converter) parseJSON(
	tool string, raw []byte, target, jobID string, sch *schema.ToolSchema,
) (*models.ScanResult, error) {
	r := models.NewScanResult(tool, target, jobID)

	// Trivy-style nested array: "Results.#.Vulnerabilities"
	if sch.ArrayPath != "" && strings.Contains(sch.ArrayPath, "#") {
		items := gjson.ParseBytes(raw).Get(sch.ArrayPath)
		items.ForEach(func(_, v gjson.Result) bool {
			f, err := c.extractFindingFromJSON([]byte(v.Raw), sch)
			if err != nil {
				c.log.Warn("nested array parse failed", zap.Error(err))
				return true
			}
			if f != nil {
				r.AddFinding(*f)
			}
			return true
		})
		return r, nil
	}

	if sch.Format == schema.FormatJSONL {
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		for _, line := range lines {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			f, err := c.extractFindingFromJSON(line, sch)
			if err != nil {
				c.log.Warn("jsonl line parse failed", zap.Error(err))
				continue
			}
			if f != nil {
				r.AddFinding(*f)
			}
		}
		return r, nil
	}

	// Standard JSON: single object or array
	j := gjson.ParseBytes(raw)

	// Masscan wraps everything in a top-level array; each element has ip + ports[]
	if sch.ArrayPath != "" && !strings.Contains(sch.ArrayPath, "#") {
		j.ForEach(func(_, elem gjson.Result) bool {
			ip := elem.Get("ip").String()
			ts := elem.Get("timestamp").String()
			elem.Get(sch.ArrayPath).ForEach(func(_, portObj gjson.Result) bool {
				f, err := c.extractFindingFromJSON([]byte(portObj.Raw), sch)
				if err != nil {
					return true
				}
				if f != nil {
					f.Target = target
					if ip != "" {
						f.IP = ip
					}
					if ts != "" {
						f.Extra["timestamp"] = ts
					}
					r.AddFinding(*f)
				}
				return true
			})
			return true
		})
		return r, nil
	}

	if j.IsArray() {
		j.ForEach(func(_, v gjson.Result) bool {
			f, err := c.extractFindingFromJSON([]byte(v.Raw), sch)
			if err != nil {
				c.log.Warn("json array item parse failed", zap.Error(err))
				return true
			}
			if f != nil {
				r.AddFinding(*f)
			}
			return true
		})
	} else {
		f, err := c.extractFindingFromJSON(raw, sch)
		if err != nil {
			return r, err
		}
		if f != nil {
			r.AddFinding(*f)
		}
	}
	return r, nil
}

func (c *Converter) extractFindingFromJSON(raw []byte, sch *schema.ToolSchema) (*models.Finding, error) {
	j := gjson.ParseBytes(raw)
	f := &models.Finding{
		Type:  models.FindingType(sch.FindingType),
		Extra: make(map[string]interface{}),
	}

	for _, fld := range sch.Fields {
		v := j.Get(fld.Path)
		if !v.Exists() {
			continue
		}
		c.setFieldValue(f, fld.Name, v)
	}

	for nestedKey, nestedFields := range sch.NestedObjects {
		obj := j.Get(nestedKey)
		if !obj.Exists() {
			continue
		}
		for _, fld := range nestedFields {
			v := obj.Get(fld.Path)
			if !v.Exists() {
				continue
			}
			c.setFieldValue(f, fld.Name, v)
		}
	}

	if sch.SeverityMap != nil && f.Severity != "" {
		if mapped, ok := sch.SeverityMap[strings.ToLower(string(f.Severity))]; ok {
			f.Severity = models.Severity(mapped)
		}
	}

	return f, nil
}

func (c *Converter) setFieldValue(f *models.Finding, name string, v gjson.Result) {
	switch strings.ToLower(name) {
	case "ip":
		f.IP = v.String()
	case "port":
		f.Port = int(v.Int())
	case "protocol":
		f.Protocol = v.String()
	case "state":
		f.State = v.String()
	case "service":
		f.Service = v.String()
	case "version":
		f.Version = v.String()
	case "banner":
		f.Banner = v.String()
	case "url":
		f.URL = v.String()
	case "method":
		f.Method = v.String()
	case "status", "status_code":
		f.StatusCode = int(v.Int())
	case "title":
		f.Title = v.String()
	case "server":
		f.Server = v.String()
	case "length", "size", "content_length":
		f.ContentLen = int(v.Int())
	case "vuln_id", "template-id", "template_id":
		f.VulnID = v.String()
	case "name":
		f.Name = v.String()
	case "severity":
		f.Severity = models.Severity(strings.ToLower(v.String()))
	case "cvss", "cvss_score":
		f.CVSS = v.Float()
	case "cwe", "cwe-id", "cwe_ids":
		if v.IsArray() {
			v.ForEach(func(_, x gjson.Result) bool {
				f.CWE = append(f.CWE, x.String())
				return true
			})
		} else if s := v.String(); s != "" {
			f.CWE = []string{s}
		}
	case "references", "reference":
		if v.IsArray() {
			v.ForEach(func(_, x gjson.Result) bool {
				f.References = append(f.References, x.String())
				return true
			})
		}
	case "hostname", "host":
		if f.Hostname == "" {
			f.Hostname = v.String()
		}
	case "matched", "matched-at":
		f.Matched = v.String()
		if f.URL == "" {
			f.URL = v.String()
		}
	case "source":
		f.Source = v.String()
	case "tags":
		if v.IsArray() {
			v.ForEach(func(_, x gjson.Result) bool {
				f.Tags = append(f.Tags, x.String())
				return true
			})
		}
	default:
		f.Extra[name] = v.Value()
	}
}

func (c *Converter) parseText(
	tool string, raw []byte, target, jobID string, sch *schema.ToolSchema,
) (*models.ScanResult, error) {
	r := models.NewScanResult(tool, target, jobID)
	raw = stripANSI(raw)
	raw = normalizeLineEndings(raw)

	compiledPatterns := make([]*regexp.Regexp, 0, len(sch.LinePatterns))
	for _, lp := range sch.LinePatterns {
		re, err := regexp.Compile(lp.Regex)
		if err != nil {
			c.log.Warn("invalid line pattern", zap.String("regex", lp.Regex), zap.Error(err))
			compiledPatterns = append(compiledPatterns, nil)
			continue
		}
		compiledPatterns = append(compiledPatterns, re)
	}

	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip lines matching any skip prefix
		skip := false
		for _, prefix := range sch.SkipPrefixes {
			if strings.HasPrefix(line, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		matched := false
		for i, re := range compiledPatterns {
			if re == nil {
				continue
			}
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			f := models.Finding{
				Type:    models.FindingType(sch.FindingType),
				Target:  target,
				RawLine: line,
				Extra:   make(map[string]interface{}),
			}
			for fieldName, groupStr := range sch.LinePatterns[i].Fields {
				groupIdx, err := strconv.Atoi(groupStr)
				if err != nil || groupIdx >= len(m) {
					continue
				}
				val := m[groupIdx]
				c.setFieldValueStr(&f, fieldName, val)
			}
			r.AddFinding(f)
			matched = true
			break
		}
		if !matched {
			// Store unmatched lines as raw findings so no data is lost
			r.AddFinding(models.Finding{
				Type:    models.TypeRaw,
				Target:  target,
				RawLine: line,
				Extra:   map[string]interface{}{"line": line},
			})
		}
	}
	return r, nil
}

func (c *Converter) setFieldValueStr(f *models.Finding, name, val string) {
	switch strings.ToLower(name) {
	case "ip":
		f.IP = val
	case "port":
		if n, err := strconv.Atoi(val); err == nil {
			f.Port = n
		}
	case "url", "path":
		f.URL = val
	case "status_code", "status":
		if n, err := strconv.Atoi(val); err == nil {
			f.StatusCode = n
		}
	case "content_length", "length", "size":
		if n, err := strconv.Atoi(val); err == nil {
			f.ContentLen = n
		}
	case "name", "message":
		f.Name = val
	case "vuln_id", "test_id":
		f.VulnID = val
	case "severity":
		f.Severity = models.Severity(strings.ToLower(val))
	case "hostname", "host":
		f.Hostname = val
	case "server":
		f.Server = val
	default:
		f.Extra[name] = val
	}
}

func (c *Converter) parseGenericXML(
	tool string, raw []byte, target, jobID string, sch *schema.ToolSchema,
) (*models.ScanResult, error) {
	// Generic XML: store as raw; specialized tools (nmap) use parseNmapXML.
	r := models.NewScanResult(tool, target, jobID)
	r.Status = models.StatusPartial
	r.AddFinding(models.Finding{
		Type:    models.TypeRaw,
		Target:  target,
		RawLine: string(raw),
	})
	return r, nil
}
