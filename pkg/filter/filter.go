// Package filter provides composable, expression-based filtering for ScanResults.
package filter

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/Ammar777782439/scanconverter/pkg/models"
)

// --- expr-lang environment ---

// FindingEnv is the evaluation environment exposed to expression strings.
// Every field maps directly to models.Finding fields.
type FindingEnv struct {
	Type       string  `expr:"type"`
	Target     string  `expr:"target"`
	IP         string  `expr:"ip"`
	Port       int     `expr:"port"`
	Protocol   string  `expr:"protocol"`
	State      string  `expr:"state"`
	URL        string  `expr:"url"`
	Method     string  `expr:"method"`
	StatusCode int     `expr:"status_code"`
	ContentLen int     `expr:"content_length"`
	Title      string  `expr:"title"`
	Server     string  `expr:"server"`
	Service    string  `expr:"service"`
	Version    string  `expr:"version"`
	VulnID     string  `expr:"vuln_id"`
	Name       string  `expr:"name"`
	Severity   string  `expr:"severity"`
	CVSS       float64 `expr:"cvss_score"`
	Confidence float64 `expr:"confidence"`
	Hostname   string  `expr:"hostname"`
	Source     string  `expr:"source"`
	OccCount   int     `expr:"occurrence_count"`

	// Helper functions injected into the environment
	Contains func(s, sub string) bool     `expr:"contains"`
	Matches  func(s, pattern string) bool `expr:"matches"`
	InCIDR   func(ip, cidr string) bool   `expr:"in_cidr"`
}

func findingToEnv(f *models.Finding) FindingEnv {
	return FindingEnv{
		Type:       string(f.Type),
		Target:     f.Target,
		IP:         f.IP,
		Port:       f.Port,
		Protocol:   f.Protocol,
		State:      f.State,
		URL:        f.URL,
		Method:     f.Method,
		StatusCode: f.StatusCode,
		ContentLen: f.ContentLen,
		Title:      f.Title,
		Server:     f.Server,
		Service:    f.Service,
		Version:    f.Version,
		VulnID:     f.VulnID,
		Name:       f.Name,
		Severity:   string(f.Severity),
		CVSS:       f.CVSS,
		Confidence: f.Confidence,
		Hostname:   f.Hostname,
		Source:     f.Source,
		OccCount:   f.OccurrenceCount,
		Contains:   strings.Contains,
		Matches:    regexMatch,
		InCIDR:     inCIDR,
	}
}

func regexMatch(s, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func inCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return network.Contains(parsed)
}

// --- CompiledFilter ---

// CompiledFilter holds a pre-compiled expr-lang program for reuse.
// Compiling once and running many times is significantly faster than
// re-parsing the expression string for each Finding.
type CompiledFilter struct {
	program *vm.Program
	source  string
}

// CompileFilter compiles an expression string into a reusable CompiledFilter.
//
// Example expressions:
// severity in ["high", "critical"] && cvss_score >= 7.5
// type == "port" && port in [80][443][8080]
// contains(url, "admin") && status_code == 200
// in_cidr(ip, "10.0.0.0/8")
func CompileFilter(expression string) (*CompiledFilter, error) {
	env := FindingEnv{}
	program, err := expr.Compile(
		expression,
		expr.Env(env),
		expr.AsBool(),
	)
	if err != nil {
		return nil, fmt.Errorf("CompileFilter %q: %w", expression, err)
	}
	return &CompiledFilter{program: program, source: expression}, nil
}

// Match returns true if the Finding satisfies the compiled expression.
func (cf *CompiledFilter) Match(f *models.Finding) bool {
	env := findingToEnv(f)
	out, err := expr.Run(cf.program, env)
	if err != nil {
		return false
	}
	result, _ := out.(bool)
	return result
}

// --- ExpressionFilter (single expression, wraps CompiledFilter) ---

// ExpressionFilter filters a ScanResult using one expression string.
type ExpressionFilter struct {
	compiled *CompiledFilter
}

// NewExpressionFilter creates an ExpressionFilter from an expression string.
func NewExpressionFilter(expression string) (*ExpressionFilter, error) {
	cf, err := CompileFilter(expression)
	if err != nil {
		return nil, err
	}
	return &ExpressionFilter{compiled: cf}, nil
}

// Apply returns a new ScanResult containing only Findings that match the expression.
func (ef *ExpressionFilter) Apply(result *models.ScanResult) *models.ScanResult {
	out := models.NewScanResult(result.Tool, result.Target, result.JobID)
	out.Pipeline = result.Pipeline
	for _, f := range result.Findings {
		fc := f // copy
		if ef.compiled.Match(&fc) {
			out.AddFinding(fc)
		}
	}
	out.BuildSummary()
	return out
}

// --- Rule interface (for FilterChain) ---

// Rule is a single filter condition.
type Rule interface {
	// Apply returns true if the Finding should be kept.
	Apply(*models.Finding) bool
	// Name returns a human-readable rule identifier.
	Name() string
}

// ruleStats tracks how many findings each rule rejected.
type ruleStats struct {
	rejected int64
}

// FilterStats holds per-rule rejection counts.
type FilterStats struct {
	RuleRejections map[string]int64 `json:"rule_rejections"`
	TotalIn        int64            `json:"total_in"`
	TotalOut       int64            `json:"total_out"`
}

// FilterConfig allows building a FilterChain from a configuration struct.
type FilterConfig struct {
	Severities  []string `json:"severities,omitempty"`
	Types       []string `json:"types,omitempty"`
	Ports       []int    `json:"ports,omitempty"`
	StatusCodes []int    `json:"status_codes,omitempty"`
	MinCVSS     float64  `json:"min_cvss,omitempty"`
	Exclude     []string `json:"exclude_keywords,omitempty"`
	Limit       int      `json:"limit,omitempty"`
	Expressions []string `json:"expressions,omitempty"`
}

// FilterChain applies an ordered sequence of Rules to a ScanResult.
type FilterChain struct {
	rules []Rule
	stats []*ruleStats
	mu    sync.Mutex

	totalIn  int64
	totalOut int64
}

// NewFilterChain creates an empty FilterChain.
func NewFilterChain() *FilterChain {
	return &FilterChain{}
}

// FromConfig builds a FilterChain from a FilterConfig.
func FromConfig(cfg FilterConfig) (*FilterChain, error) {
	fc := NewFilterChain()
	if len(cfg.Severities) > 0 {
		sevs := make([]models.Severity, len(cfg.Severities))
		for i, s := range cfg.Severities {
			sevs[i] = models.Severity(s)
		}
		fc.AddRule(BySeverities(sevs...))
	}
	if len(cfg.Types) > 0 {
		types := make([]models.FindingType, len(cfg.Types))
		for i, t := range cfg.Types {
			types[i] = models.FindingType(t)
		}
		fc.AddRule(ByTypes(types...))
	}
	if len(cfg.Ports) > 0 {
		fc.AddRule(ByPorts(cfg.Ports...))
	}
	if len(cfg.StatusCodes) > 0 {
		fc.AddRule(ByStatusCodes(cfg.StatusCodes...))
	}
	if cfg.MinCVSS > 0 {
		fc.AddRule(WithMinCVSS(cfg.MinCVSS))
	}
	if len(cfg.Exclude) > 0 {
		fc.AddRule(ExcludeKeywords(cfg.Exclude...))
	}
	if cfg.Limit > 0 {
		fc.AddRule(LimitFindings(cfg.Limit))
	}
	for _, exprStr := range cfg.Expressions {
		if err := fc.AddExpressionRule(exprStr); err != nil {
			return nil, fmt.Errorf("FromConfig expression %q: %w", exprStr, err)
		}
	}
	return fc, nil
}

// AddRule appends a Rule to the chain.
func (fc *FilterChain) AddRule(r Rule) *FilterChain {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.rules = append(fc.rules, r)
	fc.stats = append(fc.stats, &ruleStats{})
	return fc
}

// AddExpressionRule compiles an expression and adds it as a Rule.
func (fc *FilterChain) AddExpressionRule(expression string) error {
	cf, err := CompileFilter(expression)
	if err != nil {
		return err
	}
	fc.AddRule(&exprRule{cf: cf, name: expression})
	return nil
}

// Apply returns a filtered copy of result.
func (fc *FilterChain) Apply(result *models.ScanResult) *models.ScanResult {
	out := models.NewScanResult(result.Tool, result.Target, result.JobID)
	out.Pipeline = result.Pipeline

	atomic.AddInt64(&fc.totalIn, int64(len(result.Findings)))

	for _, f := range result.Findings {
		findingCopy := f // copy to avoid aliasing
		keep := true
		for i, rule := range fc.rules { //nolint:govet
			if !rule.Apply(&findingCopy) {
				atomic.AddInt64(&fc.stats[i].rejected, 1) //nolint:govet
				keep = false
				break
			}
		}
		if keep {
			out.AddFinding(findingCopy)
		}
	}

	atomic.AddInt64(&fc.totalOut, int64(len(out.Findings)))
	out.BuildSummary()
	return out
}

// Stats returns per-rule rejection counts.
func (fc *FilterChain) Stats() FilterStats {
	fs := FilterStats{
		RuleRejections: make(map[string]int64),
		TotalIn:        atomic.LoadInt64(&fc.totalIn),
		TotalOut:       atomic.LoadInt64(&fc.totalOut),
	}
	for i, rule := range fc.rules {
		fs.RuleRejections[rule.Name()] = atomic.LoadInt64(&fc.stats[i].rejected)
	}
	return fs
}

// --- Built-in Rules ---

type severityRule struct{ allowed map[models.Severity]struct{} }

// BySeverities keeps only Findings with one of the given severity levels.
func BySeverities(sevs ...models.Severity) Rule {
	m := make(map[models.Severity]struct{}, len(sevs))
	for _, s := range sevs {
		m[s] = struct{}{}
	}
	return &severityRule{allowed: m}
}

func (r *severityRule) Apply(f *models.Finding) bool {
	_, ok := r.allowed[f.Severity]
	return ok
}
func (r *severityRule) Name() string { return "BySeverities" }

type typeRule struct {
	allowed map[models.FindingType]struct{}
}

// ByTypes keeps only Findings with one of the given FindingTypes.
func ByTypes(types ...models.FindingType) Rule {
	m := make(map[models.FindingType]struct{}, len(types))
	for _, t := range types {
		m[t] = struct{}{}
	}
	return &typeRule{allowed: m}
}

func (r *typeRule) Apply(f *models.Finding) bool {
	_, ok := r.allowed[f.Type]
	return ok
}
func (r *typeRule) Name() string { return "ByTypes" }

type portRule struct{ allowed map[int]struct{} }

// ByPorts keeps only Findings on one of the given ports.
func ByPorts(ports ...int) Rule {
	m := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	return &portRule{allowed: m}
}

func (r *portRule) Apply(f *models.Finding) bool {
	if f.Port == 0 {
		return true // non-port findings pass through
	}
	_, ok := r.allowed[f.Port]
	return ok
}
func (r *portRule) Name() string { return "ByPorts" }

type statusRule struct{ allowed map[int]struct{} }

// ByStatusCodes keeps only Findings with one of the given HTTP status codes.
func ByStatusCodes(codes ...int) Rule {
	m := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		m[c] = struct{}{}
	}
	return &statusRule{allowed: m}
}

func (r *statusRule) Apply(f *models.Finding) bool {
	if f.StatusCode == 0 {
		return true
	}
	_, ok := r.allowed[f.StatusCode]
	return ok
}
func (r *statusRule) Name() string { return "ByStatusCodes" }

type cvssRule struct{ min float64 }

// WithMinCVSS keeps only Findings with CVSS >= min (0.0 passes all).
func WithMinCVSS(min float64) Rule { return &cvssRule{min: min} }

func (r *cvssRule) Apply(f *models.Finding) bool {
	if f.CVSS == 0 {
		return true // no CVSS data → don't filter out
	}
	return f.CVSS >= r.min
}
func (r *cvssRule) Name() string { return "WithMinCVSS" }

type keywordRule struct{ keywords []string }

// ExcludeKeywords drops Findings whose URL, Name, or VulnID contains any keyword.
func ExcludeKeywords(kws ...string) Rule { return &keywordRule{keywords: kws} }

func (r *keywordRule) Apply(f *models.Finding) bool {
	haystack := strings.ToLower(f.URL + " " + f.Name + " " + f.VulnID + " " + f.Hostname)
	for _, kw := range r.keywords {
		if strings.Contains(haystack, strings.ToLower(kw)) {
			return false
		}
	}
	return true
}
func (r *keywordRule) Name() string { return "ExcludeKeywords" }

type limitRule struct {
	max   int
	count int
}

// LimitFindings caps the result list at max findings.
func LimitFindings(max int) Rule { return &limitRule{max: max} }

func (r *limitRule) Apply(_ *models.Finding) bool {
	r.count++
	return r.count <= r.max
}
func (r *limitRule) Name() string { return "LimitFindings" }

// exprRule wraps a CompiledFilter as a Rule.
type exprRule struct {
	cf   *CompiledFilter
	name string
}

func (r *exprRule) Apply(f *models.Finding) bool { return r.cf.Match(f) }
func (r *exprRule) Name() string                 { return "expr:" + r.name }
