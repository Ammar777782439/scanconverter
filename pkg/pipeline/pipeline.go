// Package pipeline executes security tools as a Directed Acyclic Graph (DAG).
package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Ammar777782439/scanconverter/pkg/converter"
	"github.com/Ammar777782439/scanconverter/pkg/models"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

// Step defines a single command execution in the pipeline.
type Step struct {
	Tool      string
	Command   []string
	DependsOn []string
	Outputs   []string
	Timeout   time.Duration
	Retries   int
}

// DAG represents a Directed Acyclic Graph of pipeline steps.
type DAG struct {
	name  string
	steps map[string]Step
	reg   *schema.Registry
	log   *zap.Logger
}

// NewDAG creates a new DAG pipeline.
func NewDAG(name string, reg *schema.Registry, log *zap.Logger) *DAG {
	if log == nil {
		log = zap.NewNop()
	}
	return &DAG{
		name:  name,
		steps: make(map[string]Step),
		reg:   reg,
		log:   log,
	}
}

// AddStep adds a named step to the DAG.
func (d *DAG) AddStep(name string, step Step) *DAG {
	d.steps[name] = step
	return d
}

// Execute runs the pipeline respecting dependencies and returns the parsed results.
// For simplicity, this implementation runs steps sequentially based on a topological sort.
// A production implementation would run independent steps concurrently.
func (d *DAG) Execute(ctx context.Context) ([]*models.ScanResult, error) {
	// Simple topological sort
	ordered, err := d.topologicalSort()
	if err != nil {
		return nil, fmt.Errorf("DAG execute: %w", err)
	}

	conv := converter.NewConverter(d.reg, converter.WithLogger(d.log))
	var allResults []*models.ScanResult
	var mu sync.Mutex

	for _, stepName := range ordered {
		step := d.steps[stepName]

		d.log.Info("running step", zap.String("step", stepName), zap.Strings("cmd", step.Command))

		if err := d.runStepWithRetries(ctx, step); err != nil {
			return nil, fmt.Errorf("step %q failed: %w", stepName, err)
		}

		// Parse outputs
		for _, outPath := range step.Outputs {
			raw, err := os.ReadFile(outPath)
			if err != nil {
				d.log.Warn("failed to read step output", zap.String("file", outPath), zap.Error(err))
				continue
			}
			res, err := conv.Convert(step.Tool, raw, "pipeline-target", d.name)
			if err != nil {
				d.log.Warn("failed to convert step output", zap.String("tool", step.Tool), zap.Error(err))
				continue
			}
			if len(res.Findings) > 0 {
				mu.Lock()
				allResults = append(allResults, res)
				mu.Unlock()
			}
		}
	}

	return allResults, nil
}

func (d *DAG) runStepWithRetries(ctx context.Context, step Step) error {
	attempts := step.Retries + 1
	var lastErr error

	for i := 0; i < attempts; i++ {
		timeout := step.Timeout
		if timeout == 0 {
			timeout = 10 * time.Minute
		}

		stepCtx, cancel := context.WithTimeout(ctx, timeout)
		cmd := exec.CommandContext(stepCtx, step.Command[0], step.Command[1:]...)

		output, err := cmd.CombinedOutput()
		cancel()

		if err == nil {
			return nil // Success
		}
		lastErr = fmt.Errorf("%v (output: %s)", err, string(output))
		d.log.Warn("step attempt failed", zap.Int("attempt", i+1), zap.Error(err))

		if i < attempts-1 {
			time.Sleep(2 * time.Second)
		}
	}
	return lastErr
}

func (d *DAG) topologicalSort() ([]string, error) {
	visited := make(map[string]bool)
	tempMark := make(map[string]bool)
	var ordered []string

	var visit func(string) error
	visit = func(n string) error {
		if tempMark[n] {
			return fmt.Errorf("circular dependency detected involving %q", n)
		}
		if visited[n] {
			return nil
		}
		tempMark[n] = true

		step := d.steps[n]
		for _, dep := range step.DependsOn {
			if _, exists := d.steps[dep]; !exists {
				return fmt.Errorf("step %q depends on unknown step %q", n, dep)
			}
			if err := visit(dep); err != nil {
				return err
			}
		}

		tempMark[n] = false
		visited[n] = true
		ordered = append(ordered, n)
		return nil
	}

	for name := range d.steps {
		if !visited[name] {
			if err := visit(name); err != nil {
				return nil, err
			}
		}
	}

	return ordered, nil
}
