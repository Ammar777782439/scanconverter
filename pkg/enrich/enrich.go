// Package enrich adds CVE, GeoIP, and technology data to Findings.
package enrich

import (
 "context"
 "encoding/json"
 "fmt"
 "net/http"
 "strings"
 "time"

 "github.com/sony/gobreaker"
 "go.uber.org/zap"

 "github.com/Ammar777782439/scanconverter/pkg/models"
)

// Enricher adds data to a Finding in place.
type Enricher interface {
 Enrich(ctx context.Context, f *models.Finding) error
 Name() string
}

// Pipeline runs multiple Enrichers in sequence.
type Pipeline struct {
 enrichers []Enricher
 log *zap.Logger
}

// NewPipeline creates an empty enrichment pipeline.
func NewPipeline(log *zap.Logger) *Pipeline {
 if log == nil {
 log = zap.NewNop()
 }
 return &Pipeline{log: log}
}

// Add appends an Enricher to the pipeline.
func (p *Pipeline) Add(e Enricher) *Pipeline {
 p.enrichers = append(p.enrichers, e)
 return p
}

// Enrich runs all enrichers on every Finding in the ScanResult.
func (p *Pipeline) Enrich(ctx context.Context, result *models.ScanResult) *models.ScanResult {
 for i:= range result.Findings {
 for _, e:= range p.enrichers {
  if err:= e.Enrich(ctx, &result.Findings[i]); err != nil {
  p.log.Warn("enricher failed",
  zap.String("enricher", e.Name()),
  zap.Error(err),
  )
 }
 }
 }
 return result
}

// --- CVE Enricher ---

// nvdCVEResponse is a minimal NVD API v2 response struct.
type nvdCVEResponse struct {
 Vulnerabilities []struct {
 CVE struct {
 ID string `json:"id"`
 Descriptions []struct {
 Lang string `json:"lang"`
 Value string `json:"value"`
 } `json:"descriptions"`
 Metrics struct {
 CVSSMetricV31 []struct {
 CVSSData struct {
 BaseScore float64 `json:"baseScore"`
 } `json:"cvssData"`
 } `json:"cvssMetricV31"`
 } `json:"metrics"`
 Weaknesses []struct {
 Description []struct {
 Value string `json:"value"`
 } `json:"description"`
 } `json:"weaknesses"`
 References []struct {
 URL string `json:"url"`
 } `json:"references"`
 } `json:"cve"`
 } `json:"vulnerabilities"`
}

// CVEEnricherConfig configures the CVE enricher.
type CVEEnricherConfig struct {
 NVDAPIURL string
 APIKey string
 Timeout time.Duration
}

// DefaultCVEConfig returns a config pointing at the NVD API v2.
func DefaultCVEConfig() CVEEnricherConfig {
 return CVEEnricherConfig{
 NVDAPIURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
 Timeout: 10 * time.Second,
 }
}

// cveEnricher fetches CVE details from NVD, protected by a circuit breaker.
type cveEnricher struct {
 cfg CVEEnricherConfig
 cb *gobreaker.CircuitBreaker
 cli *http.Client
 log *zap.Logger
}

// CVEEnricher creates a CVE enricher with circuit breaker protection.
func CVEEnricher(cfg CVEEnricherConfig, log *zap.Logger) Enricher {
 if log == nil {
 log = zap.NewNop()
 }
 cbSettings:= gobreaker.Settings{
 Name: "nvd-api",
 MaxRequests: 3,
 Interval: 60 * time.Second,
 Timeout: 30 * time.Second,
 ReadyToTrip: func(counts gobreaker.Counts) bool {
 return counts.ConsecutiveFailures > 5
 },
 }
 return &cveEnricher{
 cfg: cfg,
 cb: gobreaker.NewCircuitBreaker(cbSettings),
 cli: &http.Client{Timeout: cfg.Timeout},
 log: log,
 }
}

func (e *cveEnricher) Name() string { return "CVEEnricher" }

func (e *cveEnricher) Enrich(ctx context.Context, f *models.Finding) error {
 if f.VulnID == "" || !strings.HasPrefix(strings.ToUpper(f.VulnID), "CVE-") {
 return nil
 }

 result, err:= e.cb.Execute(func() (interface{}, error) {
 url:= fmt.Sprintf("%s?cveId=%s", e.cfg.NVDAPIURL, f.VulnID)
 req, err:= http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
 if err != nil {
 return nil, err
 }
 if e.cfg.APIKey != "" {
 req.Header.Set("apiKey", e.cfg.APIKey)
 }
 resp, err:= e.cli.Do(req)
 if err != nil {
 return nil, err
 }
 defer resp.Body.Close()
 var nvd nvdCVEResponse
 if err:= json.NewDecoder(resp.Body).Decode(&nvd); err != nil {
 return nil, err
 }
 return &nvd, nil
 })
 if err != nil {
 return fmt.Errorf("CVEEnricher %s: %w", f.VulnID, err)
 }

 nvd, ok:= result.(*nvdCVEResponse)
 if !ok || len(nvd.Vulnerabilities) == 0 {
 return nil
 }
 cve:= nvd.Vulnerabilities[0].CVE

 // Fill in CVSS if not already set
 if f.CVSS == 0 && len(cve.Metrics.CVSSMetricV31) > 0 {
 f.CVSS = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
 }

 // Fill description
 for _, d:= range cve.Descriptions {
 if d.Lang == "en" && f.Name == "" {
 f.Name = d.Value
 break
 }
 }

 // Fill CWE
 if len(f.CWE) == 0 {
 for _, w:= range cve.Weaknesses {
 for _, d:= range w.Description {
 if strings.HasPrefix(d.Value, "CWE-") {
 f.CWE = append(f.CWE, d.Value)
 }
 }
 }
 }

 // Fill references
 if len(f.References) == 0 {
 for _, ref:= range cve.References {
 f.References = append(f.References, ref.URL)
 }
 }

 return nil
}

// --- GeoIP Enricher (ip-api.com) ---

type geoIPResponse struct {
 Status string `json:"status"`
 Country string `json:"country"`
 ISP string `json:"isp"`
 Org string `json:"org"`
 AS string `json:"as"`
}

type geoIPEnricher struct {
 cb *gobreaker.CircuitBreaker
 cli *http.Client
 log *zap.Logger
}

// GeoIPEnricher creates a GeoIP enricher using ip-api.com (no API key required for low volume).
func GeoIPEnricher(log *zap.Logger) Enricher {
 if log == nil {
 log = zap.NewNop()
 }
 cbSettings:= gobreaker.Settings{
 Name: "geoip-api",
 MaxRequests: 5,
 Interval: 60 * time.Second,
 Timeout: 30 * time.Second,
 ReadyToTrip: func(counts gobreaker.Counts) bool {
 return counts.ConsecutiveFailures > 3
 },
 }
 return &geoIPEnricher{
 cb: gobreaker.NewCircuitBreaker(cbSettings),
 cli: &http.Client{Timeout: 5 * time.Second},
 log: log,
 }
}

func (e *geoIPEnricher) Name() string { return "GeoIPEnricher" }

func (e *geoIPEnricher) Enrich(ctx context.Context, f *models.Finding) error {
 if f.IP == "" {
 return nil
 }
 result, err:= e.cb.Execute(func() (interface{}, error) {
 url:= fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,isp,org,as", f.IP)
 req, err:= http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
 if err != nil {
 return nil, err
 }
 resp, err:= e.cli.Do(req)
 if err != nil {
 return nil, err
 }
 defer resp.Body.Close()
 var geo geoIPResponse
 if err:= json.NewDecoder(resp.Body).Decode(&geo); err != nil {
 return nil, err
 }
 return &geo, nil
 })
 if err != nil {
 return fmt.Errorf("GeoIPEnricher %s: %w", f.IP, err)
 }
 geo, ok:= result.(*geoIPResponse)
 if !ok || geo.Status != "success" {
 return nil
 }
 if f.Extra == nil {
 f.Extra = make(map[string]interface{})
 }
 f.Extra["geo_country"] = geo.Country
 f.Extra["geo_isp"] = geo.ISP
 f.Extra["geo_org"] = geo.Org
 f.Extra["geo_asn"] = geo.AS
 return nil
}

// --- Technology Enricher ---

type techEnricher struct{}

// TechEnricher identifies technologies from Server header and page title.
func TechEnricher() Enricher { return &techEnricher{} }

func (e *techEnricher) Name() string { return "TechEnricher" }

var techPatterns = map[string][]string{
 "nginx": {"nginx"},
 "apache": {"apache"},
 "iis": {"microsoft-iis", "iis"},
 "nodejs": {"node.js", "nodejs", "express"},
 "php": {"php"},
 "wordpress": {"wordpress", "wp-content"},
 "django": {"django", "csrfmiddlewaretoken"},
 "rails": {"x-powered-by: phusion", "rails"},
}

func (e *techEnricher) Enrich(_ context.Context, f *models.Finding) error {
 haystack:= strings.ToLower(f.Server + " " + f.Title + " " + f.Banner)
 for tech, patterns:= range techPatterns {
 for _, p:= range patterns {
 if strings.Contains(haystack, p) {
 alreadyTagged:= false
 for _, tag:= range f.Tags {
 if tag == "tech:"+tech {
 alreadyTagged = true
 break
 }
 }
 if !alreadyTagged {
 f.Tags = append(f.Tags, "tech:"+tech)
 }
 break
 }
 }
 }
 return nil
}