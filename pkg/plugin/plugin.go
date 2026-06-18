// Package plugin enables external tool parsers via hashicorp/go-plugin over gRPC.
package plugin

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"

	goplugin "github.com/hashicorp/go-plugin"
	"go.uber.org/zap"

	"github.com/Ammar777782439/scanconverter/pkg/models"
	"github.com/Ammar777782439/scanconverter/pkg/schema"
)

// ToolPlugin is the interface that every plugin must implement.
// Plugins can be written in any language that supports gRPC.
type ToolPlugin interface {
	// Name returns the tool name this plugin handles.
	Name() string
	// Parse converts raw tool output into a ScanResult.
	Parse(raw []byte, target, jobID string) (*models.ScanResult, error)
	// Schema returns the ToolSchema for this plugin's tool.
	Schema() *schema.ToolSchema
}

// Handshake is the config shared between host and plugin binary.
// Both sides must agree on these values or the connection is rejected.
var Handshake = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SCANCONVERTER_PLUGIN",
	MagicCookieValue: "scanconverter-v1",
}

// pluginEntry tracks a loaded plugin client.
type pluginEntry struct {
	client *goplugin.Client
	plugin ToolPlugin
}

// Manager loads and manages external tool plugins.
type Manager struct {
	dir     string
	mu      sync.RWMutex
	plugins map[string]*pluginEntry
	log     *zap.Logger
}

// NewManager creates a Manager that looks for plugin binaries in dir.
func NewManager(dir string, log *zap.Logger) *Manager {
	if log == nil {
		log = zap.NewNop()
	}
	return &Manager{
		dir:     dir,
		plugins: make(map[string]*pluginEntry),
		log:     log,
	}
}

// Load launches a plugin binary named <name> from the plugins directory.
// The binary must implement the ToolPlugin gRPC interface.
func (m *Manager) Load(name string) error {
	binPath := filepath.Join(m.dir, name)

	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: Handshake,
		Plugins: map[string]goplugin.Plugin{
			"tool_plugin": &ToolPluginGRPC{},
		},
		Cmd:              exec.Command(binPath), //nolint:gosec
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return fmt.Errorf("plugin Load %q: connect: %w", name, err)
	}

	raw, err := rpcClient.Dispense("tool_plugin")
	if err != nil {
		client.Kill()
		return fmt.Errorf("plugin Load %q: dispense: %w", name, err)
	}

	tp, ok := raw.(ToolPlugin)
	if !ok {
		client.Kill()
		return fmt.Errorf("plugin Load %q: type assertion failed", name)
	}

	m.mu.Lock()
	m.plugins[name] = &pluginEntry{client: client, plugin: tp}
	m.mu.Unlock()

	m.log.Info("plugin loaded", zap.String("name", name), zap.String("path", binPath))
	return nil
}

// Parse delegates parsing to the named plugin.
func (m *Manager) Parse(name string, raw []byte, target, jobID string) (*models.ScanResult, error) {
	m.mu.RLock()
	entry, ok := m.plugins[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plugin %q not loaded", name)
	}
	return entry.plugin.Parse(raw, target, jobID)
}

// List returns the names of all currently loaded plugins.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.plugins))
	for name := range m.plugins {
		names = append(names, name)
	}
	return names
}

// Unload kills the plugin subprocess and removes it from the registry.
func (m *Manager) Unload(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.plugins[name]; ok {
		entry.client.Kill()
		delete(m.plugins, name)
		m.log.Info("plugin unloaded", zap.String("name", name))
	}
}

// Close kills all plugin subprocesses.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, entry := range m.plugins {
		entry.client.Kill()
		m.log.Info("plugin killed", zap.String("name", name))
	}
}

// ToolPluginGRPC is the go-plugin interface implementation.
// Actual gRPC proto generation is left to the caller's build step.
type ToolPluginGRPC struct {
	goplugin.Plugin
	Impl ToolPlugin
}
