package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/integration"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

var versionPattern = regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`)

const maxAgentConfigBytes = 8 << 20
const maxAgentVersionBytes = 64 << 10

const agentVersionTimeout = 3 * time.Second
const agentVersionOutputDrainGrace = 25 * time.Millisecond
const maxConcurrentVersionProbes = 4
const maxAgentConfigPathBytes = 4096

var SupportedAgents = []string{"codex", "claude", "hermes", "openclaw", "opencode", "cursor", "zed", "cline"}

type DetectionStatus string

const (
	DetectionVerified       DetectionStatus = "verified"
	DetectionUnverified     DetectionStatus = "unverified"
	DetectionVersionUnknown DetectionStatus = "version_unknown"
)

type Detection struct {
	Agent      string          `json:"agent"`
	Executable string          `json:"executable"`
	Version    string          `json:"version,omitempty"`
	Status     DetectionStatus `json:"status"`
}

type System interface {
	LookPath(string) (string, error)
	Version(context.Context, string) (string, error)
	ReadFile(string) ([]byte, error)
	LookupEnv(string) (string, bool)
	HomeDir() (string, error)
}
type OSSystem struct{}

func (OSSystem) LookPath(name string) (string, error) { return exec.LookPath(name) }
func (OSSystem) Version(ctx context.Context, executable string) (string, error) {
	if ctx == nil {
		return "", domain.NewError(domain.ErrInvalidContract, "read agent version", "context is required")
	}
	bounded, cancel := context.WithTimeout(ctx, agentVersionTimeout)
	defer cancel()
	output := &boundedVersionOutput{limit: maxAgentVersionBytes}
	command := exec.CommandContext(bounded, executable, "--version")
	configureVersionCommand(command)
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", domain.NewError(domain.ErrInvalidContract, "read agent version", "version output pipe is unavailable")
	}
	command.Stdout = writer
	command.Stderr = writer
	if err := command.Start(); err != nil {
		reader.Close()
		writer.Close()
		return "", err
	}
	writer.Close()
	readDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(output, reader)
		close(readDone)
	}()
	err = command.Wait()
	inheritedOutputPipe := false
	select {
	case <-readDone:
	case <-time.After(agentVersionOutputDrainGrace):
		inheritedOutputPipe = true
	}
	cleanupVersionCommand(command)
	if inheritedOutputPipe {
		_ = reader.Close()
		<-readDone
	}
	_ = reader.Close()
	if output.Exceeded() {
		return output.String(), domain.NewError(domain.ErrInvalidContract, "read agent version", "version output exceeds its size limit")
	}
	if bounded.Err() != nil {
		return output.String(), domain.NewError(domain.ErrInvalidContract, "read agent version", "version command timed out or was cancelled")
	}
	if inheritedOutputPipe {
		return output.String(), domain.NewError(domain.ErrInvalidContract, "read agent version", "version command left inherited output pipes open")
	}
	return output.String(), err
}

type boundedVersionOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (w *boundedVersionOutput) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.limit - w.buffer.Len()
	if remaining <= 0 {
		w.exceeded = true
		return len(payload), nil
	}
	if len(payload) > remaining {
		_, _ = w.buffer.Write(payload[:remaining])
		w.exceeded = true
		return len(payload), nil
	}
	_, _ = w.buffer.Write(payload)
	return len(payload), nil
}

func (w *boundedVersionOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func (w *boundedVersionOutput) Exceeded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
}
func (OSSystem) ReadFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxAgentConfigBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "read agent config", "configuration file type or size is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, domain.NewError(domain.ErrInvalidContract, "read agent config", "configuration file changed during validation")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxAgentConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxAgentConfigBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "read agent config", "configuration file is too large")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(content)) || !after.ModTime().Equal(opened.ModTime()) {
		return nil, domain.NewError(domain.ErrInvalidContract, "read agent config", "configuration file changed while it was read")
	}
	return content, nil
}
func (OSSystem) LookupEnv(key string) (string, bool) { return os.LookupEnv(key) }
func (OSSystem) HomeDir() (string, error)            { return os.UserHomeDir() }

type Discoverer struct {
	System   System
	Verified map[string]map[string]struct{}
}

func Default() Discoverer {
	return Discoverer{System: OSSystem{}, Verified: compatibility.VerifiedVersions(runtime.GOOS)}
}

func (d Discoverer) DetectAll(ctx context.Context) []Detection {
	agents := append([]string(nil), SupportedAgents...)
	probes := make([]Detection, len(agents))
	installed := make([]bool, len(agents))
	semaphore := make(chan struct{}, maxConcurrentVersionProbes)
	var wait sync.WaitGroup
	for index, name := range agents {
		executable, err := d.System.LookPath(name)
		if err != nil {
			continue
		}
		installed[index] = true
		probes[index] = Detection{Agent: name, Executable: executable, Status: DetectionVersionUnknown}
		wait.Add(1)
		go func(index int, name, executable string) {
			defer wait.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			detection := probes[index]
			if output, versionErr := d.System.Version(ctx, executable); versionErr == nil {
				detection.Version = versionPattern.FindString(output)
			}
			if detection.Version != "" {
				detection.Status = DetectionUnverified
				if versions := d.Verified[name]; versions != nil {
					if _, ok := versions[detection.Version]; ok {
						detection.Status = DetectionVerified
					}
				}
			}
			probes[index] = detection
		}(index, name, executable)
	}
	wait.Wait()
	result := make([]Detection, 0, len(probes))
	for index, detection := range probes {
		if installed[index] {
			result = append(result, detection)
		}
	}
	return result
}

func (d Discoverer) Inspect(ctx context.Context, name string) (domain.AgentManifest, error) {
	name = strings.ToLower(name)
	executable, err := d.System.LookPath(name)
	if err != nil {
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover agent", "agent executable was not found")
	}
	output, err := d.System.Version(ctx, executable)
	if err != nil {
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover agent", "agent version could not be read")
	}
	version := versionPattern.FindString(output)
	if version == "" {
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover agent", "agent version format is unknown")
	}
	config := integration.Config{AgentID: name + "-local", Kind: name, Version: version, Executable: executable, Mode: domain.ModeLaunch}
	homeValue, homeErr := d.System.HomeDir()
	home, homeOK := safeAgentConfigPath(homeValue)
	if homeErr != nil || !homeOK {
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover agent", "user configuration directory is unavailable or unsafe")
	}
	switch name {
	case "codex":
		config.ConfigSource = filepath.Join(home, ".codex", "config.toml")
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			if containsTOMLKey(content, "model_provider") || containsTOMLKey(content, "base_url") {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover codex", "custom provider configuration requires a versioned adapter")
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover codex", "configuration could not be inspected")
		}
		config.Slots = []integration.Slot{{ID: "primary", Name: "Primary model", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, BaseURL: "https://api.openai.com", Auth: domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:codex-login-or-environment"}, Network: environmentProxyRoute(d.System), Rewritable: true, Required: true}}
	case "claude":
		config.ConfigSource = filepath.Join(home, ".claude", "settings.json")
		baseURL := "https://api.anthropic.com"
		if value, ok := d.System.LookupEnv("ANTHROPIC_BASE_URL"); ok && value != "" {
			baseURL = value
		}
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			var settings struct {
				Env map[string]string `json:"env"`
			}
			if jsonsafe.Validate(content) != nil || json.Unmarshal(content, &settings) != nil {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover claude", "settings JSON is invalid or ambiguous")
			}
			if settings.Env["ANTHROPIC_BASE_URL"] != "" {
				baseURL = settings.Env["ANTHROPIC_BASE_URL"]
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover claude", "configuration could not be inspected")
		}
		auth := domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:claude-login"}
		rewritable := false
		if value, ok := d.System.LookupEnv("ANTHROPIC_API_KEY"); ok && value != "" {
			auth = domain.AuthStrategy{Type: domain.AuthAnthropicKey, Source: "environment:ANTHROPIC_API_KEY"}
			rewritable = true
		}
		config.Slots = []integration.Slot{{ID: "primary", Name: "Primary model", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolAnthropic, BaseURL: baseURL, Auth: auth, Network: environmentProxyRoute(d.System), Rewritable: rewritable, Required: true}}
	case "hermes":
		hermesHome := filepath.Join(home, ".hermes")
		if configuredHome, ok := d.System.LookupEnv("HERMES_HOME"); ok && configuredHome != "" {
			var valid bool
			hermesHome, valid = safeAgentConfigPath(configuredHome)
			if !valid {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover hermes", "HERMES_HOME must be an absolute safe path")
			}
		}
		config.ConfigSource = filepath.Join(hermesHome, "config.yaml")
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			config.Observed, config.LocalMCP, err = integration.ParseHermesConfig(content)
			if err != nil {
				return domain.AgentManifest{}, err
			}
		} else if errors.Is(readErr, os.ErrNotExist) {
			config.Slots = []integration.Slot{{ID: "unknown-egress", Name: "Unresolved agent egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true}}
		} else {
			return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover hermes", "configuration could not be inspected")
		}
	case "openclaw":
		config.Mode = domain.ModeManaged
		config.ConfigSource = filepath.Join(home, ".openclaw", "openclaw.json")
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			config.Observed, err = integration.ParseOpenClawConfig(content)
			if err != nil {
				return domain.AgentManifest{}, err
			}
		} else {
			config.Slots = []integration.Slot{{ID: "unknown-egress", Name: "Unresolved agent egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true}}
		}
	case "opencode":
		config.ConfigSource = filepath.Join(home, ".config", "opencode", "opencode.json")
		if value, ok := d.System.LookupEnv("OPENCODE_CONFIG"); ok && value != "" {
			if config.ConfigSource, ok = safeAgentConfigPath(value); !ok {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover opencode", "OPENCODE_CONFIG must be an absolute safe path")
			}
		}
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			config.Observed, config.LocalMCP, err = integration.ParseOpenCodeConfig(content)
			if err != nil {
				return domain.AgentManifest{}, err
			}
		} else {
			config.Observed = append(config.Observed, openCodeUnknownSlot("configuration-file", "configured file could not be inspected"))
		}
		if _, ok := d.System.LookupEnv("OPENCODE_CONFIG_CONTENT"); ok {
			config.Observed = append(config.Observed, openCodeUnknownSlot("inline-config-overrides", "OPENCODE_CONFIG_CONTENT may override file configuration"))
		}
		config.Observed = append(config.Observed, openCodeUnknownSlot("workspace-config-overrides", "project and managed configuration precedence is not resolved"))
	case "zed":
		config.ConfigSource = filepath.Join(home, ".config", "zed", "settings.json")
		if value, ok := d.System.LookupEnv("XDG_CONFIG_HOME"); ok && value != "" {
			root, valid := safeAgentConfigPath(value)
			if !valid {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover zed", "XDG_CONFIG_HOME must be an absolute safe path")
			}
			config.ConfigSource = filepath.Join(root, "zed", "settings.json")
		}
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			config.Observed, config.LocalMCP, err = integration.ParseZedConfig(content)
			if err != nil {
				return domain.AgentManifest{}, err
			}
		} else {
			config.Observed = append(config.Observed, zedUnknownSlot("configuration-file", "configured file could not be inspected"))
		}
		config.Observed = append(config.Observed, zedUnknownSlot("dynamic-model-selection", "keychain providers and runtime model selection are not statically resolved"))
		config.Observed = append(config.Observed, zedUnknownSlot("workspace-config-overrides", "project .zed/settings.json configuration is not resolved"))
	case "cline":
		dataDir := filepath.Join(home, ".cline", "data")
		if value, ok := d.System.LookupEnv("CLINE_DATA_DIR"); ok && value != "" {
			if dataDir, ok = safeAgentConfigPath(value); !ok {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover cline", "CLINE_DATA_DIR must be an absolute safe path")
			}
		}
		providerPath := filepath.Join(dataDir, "settings", "providers.json")
		if value, ok := d.System.LookupEnv("CLINE_PROVIDER_SETTINGS_PATH"); ok && value != "" {
			if providerPath, ok = safeAgentConfigPath(value); !ok {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover cline", "CLINE_PROVIDER_SETTINGS_PATH must be an absolute safe path")
			}
		}
		mcpPath := filepath.Join(dataDir, "settings", "cline_mcp_settings.json")
		if value, ok := d.System.LookupEnv("CLINE_MCP_SETTINGS_PATH"); ok && value != "" {
			if mcpPath, ok = safeAgentConfigPath(value); !ok {
				return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover cline", "CLINE_MCP_SETTINGS_PATH must be an absolute safe path")
			}
		}
		config.ConfigSource = dataDir
		if content, readErr := d.System.ReadFile(providerPath); readErr == nil {
			config.Observed, err = integration.ParseClineProviders(content)
			if err != nil {
				return domain.AgentManifest{}, err
			}
		} else {
			config.Observed = append(config.Observed, clineUnknownSlot("provider-configuration", "provider settings could not be inspected"))
		}
		if content, readErr := d.System.ReadFile(mcpPath); readErr == nil {
			mcpSlots, localMCP, parseErr := integration.ParseClineMCP(content)
			if parseErr != nil {
				return domain.AgentManifest{}, parseErr
			}
			config.Observed = append(config.Observed, mcpSlots...)
			config.LocalMCP = append(config.LocalMCP, localMCP...)
		} else {
			config.Observed = append(config.Observed, clineUnknownSlot("mcp-configuration", "MCP settings could not be inspected"))
		}
		config.Observed = append(config.Observed, clineUnknownSlot("host-and-workspace-overrides", "IDE host and project configuration are not resolved"))
	case "cursor":
		config.ConfigSource = filepath.Join(home, ".cursor", "mcp.json")
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			config.Observed, config.LocalMCP, err = integration.ParseCursorMCP(content)
			if err != nil {
				return domain.AgentManifest{}, err
			}
		} else {
			config.Observed = append(config.Observed, cursorUnknownSlot("global-mcp-configuration", "global MCP settings could not be inspected"))
		}
		config.Observed = append(config.Observed, cursorUnknownSlot("model-egress", "Cursor model and specialized feature backends are not statically resolved"))
		config.Observed = append(config.Observed, cursorUnknownSlot("workspace-mcp-overrides", "project and nested .cursor/mcp.json configuration is not resolved"))
		config.Observed = append(config.Observed, cursorUnknownSlot("dynamic-mcp-registrations", "extension API MCP registrations are not statically resolved"))
	default:
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover agent", "agent has no integration")
	}
	if versions := d.Verified[name]; versions == nil {
		downgradeUnverifiedConfig(&config)
	} else if _, verified := versions[version]; !verified {
		downgradeUnverifiedConfig(&config)
	}
	return (integration.Inspector{VerifiedVersions: d.Verified}).Inspect(config)
}

func downgradeUnverifiedConfig(config *integration.Config) {
	if config == nil {
		return
	}
	for index := range config.Slots {
		config.Slots[index].Rewritable = false
	}
	for index := range config.Observed {
		config.Observed[index].Rewritable = false
	}
	used := make(map[string]struct{}, len(config.Slots)+len(config.Observed))
	hasRequiredUnknown := false
	for _, slot := range append(append([]integration.Slot(nil), config.Slots...), config.Observed...) {
		used[slot.ID] = struct{}{}
		if (slot.Type == domain.SurfaceUnknown || slot.Protocol == domain.ProtocolUnknown) && slot.Required {
			hasRequiredUnknown = true
		}
	}
	if hasRequiredUnknown {
		return
	}
	id := "version-compatibility"
	for suffix := 2; ; suffix++ {
		if _, exists := used[id]; !exists {
			break
		}
		id = fmt.Sprintf("version-compatibility-%d", suffix)
	}
	config.Observed = append(config.Observed, integration.Slot{ID: id, Name: "Unverified version egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true, Metadata: map[string]string{"reason": "agent version has no verified complete Surface inventory"}})
}

func openCodeUnknownSlot(id, reason string) integration.Slot {
	return integration.Slot{ID: id, Name: "Unresolved OpenCode egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true, Metadata: map[string]string{"reason": reason}}
}

func zedUnknownSlot(id, reason string) integration.Slot {
	return integration.Slot{ID: id, Name: "Unresolved Zed egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true, Metadata: map[string]string{"reason": reason}}
}

func clineUnknownSlot(id, reason string) integration.Slot {
	return integration.Slot{ID: id, Name: "Unresolved Cline egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true, Metadata: map[string]string{"reason": reason}}
}

func cursorUnknownSlot(id, reason string) integration.Slot {
	return integration.Slot{ID: id, Name: "Unresolved Cursor egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true, Metadata: map[string]string{"reason": reason}}
}

func environmentProxyRoute(system System) *domain.NetworkRoute {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy"} {
		if value, ok := system.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
			route := domain.NetworkRoute{Type: domain.NetworkSystemProxy}
			return &route
		}
	}
	return nil
}

func containsTOMLKey(content []byte, key string) bool {
	return regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=`).Match(content)
}

func safeAgentConfigPath(value string) (string, bool) {
	if value == "" || len(value) > maxAgentConfigPathBytes || strings.TrimSpace(value) != value || !filepath.IsAbs(value) {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return filepath.Clean(value), true
}
