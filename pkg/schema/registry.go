// Package schema loads, validates, and hot-reloads tool schema definitions.
package schema

import (
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "sync"
 "time"

 "github.com/fsnotify/fsnotify"
 "go.uber.org/zap"
 "gopkg.in/yaml.v3"
)

// FormatType represents the output format of a tool.
type FormatType string

const (
 FormatJSON FormatType = "json"
 FormatJSONL FormatType = "jsonl"
 FormatXML FormatType = "xml"
 FormatText FormatType = "text"
)

// FieldMapping maps a tool's JSON path to a unified Finding field.
type FieldMapping struct {
 Name string `json:"name" yaml:"name"`
 Path string `json:"path" yaml:"path"`
 Type string `json:"type" yaml:"type"`
 Required bool `json:"required,omitempty" yaml:"required,omitempty"`
 Default interface{} `json:"default,omitempty" yaml:"default,omitempty"`
}

// LinePattern defines a regex pattern for TXT tool outputs.
type LinePattern struct {
 Regex string `json:"regex" yaml:"regex"`
 Fields map[string]string `json:"fields" yaml:"fields"` // fieldName → capture group number
}

// ValidationRules specifies constraints on parsed output.
type ValidationRules struct {
 RequireFields []string `json:"require_fields,omitempty" yaml:"require_fields,omitempty"`
 MinFindings int `json:"min_findings,omitempty" yaml:"min_findings,omitempty"`
 MaxFindings int `json:"max_findings,omitempty" yaml:"max_findings,omitempty"`
 AllowEmpty bool `json:"allow_empty,omitempty" yaml:"allow_empty,omitempty"`
}

// SchemaFilters defines auto-applied filters for a tool.
type SchemaFilters struct {
	Expressions []string `json:"expressions,omitempty" yaml:"expressions,omitempty"`
}

// ToolSchema defines how a tool's output maps to the unified Finding model.
type ToolSchema struct {
 Name string `json:"name" yaml:"name"`
 Version string `json:"version,omitempty" yaml:"version,omitempty"`
 Author string `json:"author,omitempty" yaml:"author,omitempty"`
 UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
 Format FormatType `json:"format" yaml:"format"`
 FindingType string `json:"finding_type" yaml:"finding_type"`
 Description string `json:"description,omitempty" yaml:"description,omitempty"`

 // For JSON/JSONL tools
 Fields []FieldMapping `json:"fields,omitempty" yaml:"fields,omitempty"`
 NestedObjects map[string][]FieldMapping `json:"nested_objects,omitempty" yaml:"nested_objects,omitempty"`
 SeverityMap map[string]string `json:"severity_map,omitempty" yaml:"severity_map,omitempty"`

 // ArrayPath supports nested arrays like "Results.#.Vulnerabilities" for Trivy [1]
 ArrayPath string `json:"array_path,omitempty" yaml:"array_path,omitempty"`

 // For TXT tools
 LinePatterns []LinePattern `json:"line_patterns,omitempty" yaml:"line_patterns,omitempty"`
 SkipPrefixes []string `json:"skip_prefixes,omitempty" yaml:"skip_prefixes,omitempty"`

 // Pre/post processing hooks
 Preprocessors []string `json:"preprocessors,omitempty" yaml:"preprocessors,omitempty"`
 PostProcessors []string `json:"post_processors,omitempty" yaml:"post_processors,omitempty"`

 // Validation
 Validation *ValidationRules `json:"validation,omitempty" yaml:"validation,omitempty"`

 // Auto-applied filters
 Filters *SchemaFilters `json:"filters,omitempty" yaml:"filters,omitempty"`
}

// Validate checks that required schema fields are present.
func (s *ToolSchema) Validate() error {
 if s.Name == "" {
 return fmt.Errorf("schema: name required")
 }
 if s.Format == "" {
 return fmt.Errorf("schema %q: format required", s.Name)
 }
 if s.FindingType == "" {
 return fmt.Errorf("schema %q: finding_type required", s.Name)
 }
 return nil
}

// SchemaStats tracks usage statistics per schema.
type SchemaStats struct {
 LoadCount int `json:"load_count"`
 UseCount int64 `json:"use_count"`
 LastUsed time.Time `json:"last_used"`
 ErrorCount int64 `json:"error_count"`
}

// Registry stores all loaded ToolSchemas and supports hot-reload.
type Registry struct {
 mu sync.RWMutex
 schemas map[string]*ToolSchema
 stats map[string]*SchemaStats
 log *zap.Logger
 watcher *fsnotify.Watcher
}

// NewRegistry creates an empty Registry.
func NewRegistry(log *zap.Logger) *Registry {
 if log == nil {
 log = zap.NewNop()
 }
 return &Registry{
 schemas: make(map[string]*ToolSchema),
 stats: make(map[string]*SchemaStats),
 log: log,
 }
}

// Register adds or replaces a ToolSchema.
func (r *Registry) Register(s *ToolSchema) error {
 if err:= s.Validate(); err != nil {
 return err
 }
 r.mu.Lock()
 defer r.mu.Unlock()
 r.schemas[s.Name] = s
 if _, ok:= r.stats[s.Name]; !ok {
 r.stats[s.Name] = &SchemaStats{}
 }
 r.stats[s.Name].LoadCount++
 r.log.Info("schema registered", zap.String("name", s.Name), zap.String("format", string(s.Format)))
 return nil
}

// Get retrieves a ToolSchema by tool name.
func (r *Registry) Get(name string) (*ToolSchema, bool) {
 r.mu.RLock()
 defer r.mu.RUnlock()
 s, ok:= r.schemas[name]
 if ok {
 r.stats[name].UseCount++
 r.stats[name].LastUsed = time.Now().UTC()
 }
 return s, ok
}

// ListNames returns a list of all registered schema names.
func (r *Registry) ListNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.schemas))
	for name := range r.schemas {
		names = append(names, name)
	}
	return names
}

// LoadFile loads a single JSON or YAML schema file.
func (r *Registry) LoadFile(path string) error {
 b, err:= os.ReadFile(path)
 if err != nil {
 return fmt.Errorf("schema LoadFile %q: %w", path, err)
 }
 var s ToolSchema
 switch filepath.Ext(path) {
 case ".yaml", ".yml":
 if err:= yaml.Unmarshal(b, &s); err != nil {
 return fmt.Errorf("schema yaml parse %q: %w", path, err)
 }
 default:
 if err:= json.Unmarshal(b, &s); err != nil {
 return fmt.Errorf("schema json parse %q: %w", path, err)
 }
 }
 return r.Register(&s)
}

// LoadDir loads all.json and.yaml schema files from a directory.
func (r *Registry) LoadDir(dir string) error {
 entries, err:= os.ReadDir(dir)
 if err != nil {
 return fmt.Errorf("schema LoadDir %q: %w", dir, err)
 }
 for _, e:= range entries {
 if e.IsDir() {
 continue
 }
 ext:= filepath.Ext(e.Name())
 if ext != ".json" && ext != ".yaml" && ext != ".yml" {
 continue
 }
 if err:= r.LoadFile(filepath.Join(dir, e.Name())); err != nil {
 r.log.Warn("schema load failed", zap.String("file", e.Name()), zap.Error(err))
 }
 }
 return nil
}

// Watch starts a filesystem watcher on dir and reloads schemas on change.
// Call this in a goroutine; it blocks until ctx is cancelled or watcher closes.
func (r *Registry) Watch(dir string) error {
 w, err:= fsnotify.NewWatcher()
 if err != nil {
 return fmt.Errorf("schema Watch: %w", err)
 }
 r.watcher = w
 if err:= w.Add(dir); err != nil {
 return fmt.Errorf("schema Watch add dir: %w", err)
 }
 go func() {
 for {
 select {
 case event, ok:= <-w.Events:
 if !ok {
 return
 }
 if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
 ext:= filepath.Ext(event.Name)
 if ext == ".json" || ext == ".yaml" || ext == ".yml" {
 r.log.Info("hot-reload schema", zap.String("file", event.Name))
 if err:= r.LoadFile(event.Name); err != nil {
 r.log.Error("hot-reload failed", zap.Error(err))
 }
 }
 }
 case err, ok := <-w.Errors:
 if !ok {
 return
 }
 r.log.Error("watcher error", zap.Error(err))
 }
 }
 }()
 return nil
}

// Close shuts down the filesystem watcher.
func (r *Registry) Close() error {
 if r.watcher != nil {
 return r.watcher.Close()
 }
 return nil
}

// Stats returns usage statistics for all loaded schemas.
func (r *Registry) Stats() map[string]SchemaStats {
 r.mu.RLock()
 defer r.mu.RUnlock()
 out:= make(map[string]SchemaStats, len(r.stats))
 for k, v:= range r.stats {
 out[k] = *v
 }
 return out
}

// Validate checks whether sample bytes conform to the named schema's validation rules.
func (r *Registry) Validate(name string, sample []byte) error {
 sch, ok:= r.Get(name)
 if !ok {
 return fmt.Errorf("schema %q not found", name)
 }
 if sch.Validation == nil {
 return nil
 }
 if len(sample) == 0 && !sch.Validation.AllowEmpty {
 return fmt.Errorf("schema %q: empty input not allowed", name)
 }
 return nil
}