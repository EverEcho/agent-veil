package discovery

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/integration"
)

var versionPattern = regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`)

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
	value, err := exec.CommandContext(ctx, executable, "--version").CombinedOutput()
	return string(value), err
}
func (OSSystem) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (OSSystem) LookupEnv(key string) (string, bool)  { return os.LookupEnv(key) }
func (OSSystem) HomeDir() (string, error)             { return os.UserHomeDir() }

type Discoverer struct {
	System   System
	Verified map[string]map[string]struct{}
}

func Default() Discoverer {
	return Discoverer{System: OSSystem{}, Verified: compatibility.VerifiedVersions(runtime.GOOS)}
}

func (d Discoverer) DetectAll(ctx context.Context) []Detection {
	result := make([]Detection, 0, len(SupportedAgents))
	for _, name := range SupportedAgents {
		executable, err := d.System.LookPath(name)
		if err != nil {
			continue
		}
		detection := Detection{Agent: name, Executable: executable, Status: DetectionVersionUnknown}
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
		result = append(result, detection)
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
	home, _ := d.System.HomeDir()
	switch name {
	case "codex":
		config.ConfigSource = filepath.Join(home, ".codex", "config.toml")
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil && (containsTOMLKey(content, "model_provider") || containsTOMLKey(content, "base_url")) {
			return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover codex", "custom provider configuration requires a versioned adapter")
		}
		config.Slots = []integration.Slot{{ID: "primary", Name: "Primary model", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolOpenAIResponses, BaseURL: "https://api.openai.com", Auth: domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:codex-login-or-environment"}, Rewritable: true, Required: true}}
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
			if json.Unmarshal(content, &settings) == nil && settings.Env["ANTHROPIC_BASE_URL"] != "" {
				baseURL = settings.Env["ANTHROPIC_BASE_URL"]
			}
		}
		auth := domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:claude-login"}
		rewritable := false
		if value, ok := d.System.LookupEnv("ANTHROPIC_API_KEY"); ok && value != "" {
			auth = domain.AuthStrategy{Type: domain.AuthAnthropicKey, Source: "environment:ANTHROPIC_API_KEY"}
			rewritable = true
		}
		config.Slots = []integration.Slot{{ID: "primary", Name: "Primary model", Type: domain.SurfaceModelPrimary, Protocol: domain.ProtocolAnthropic, BaseURL: baseURL, Auth: auth, Rewritable: rewritable, Required: true}}
	case "hermes":
		config.ConfigSource = filepath.Join(home, ".hermes", "config.yaml")
		if content, readErr := d.System.ReadFile(config.ConfigSource); readErr == nil {
			config.Observed, config.LocalMCP, err = integration.ParseHermesConfig(content)
			if err != nil {
				return domain.AgentManifest{}, err
			}
		} else {
			config.Slots = []integration.Slot{{ID: "unknown-egress", Name: "Unresolved agent egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true}}
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
		if value, ok := d.System.LookupEnv("OPENCODE_CONFIG"); ok && strings.TrimSpace(value) != "" {
			config.ConfigSource = strings.TrimSpace(value)
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
		if value, ok := d.System.LookupEnv("XDG_CONFIG_HOME"); ok && strings.TrimSpace(value) != "" {
			config.ConfigSource = filepath.Join(strings.TrimSpace(value), "zed", "settings.json")
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
		if value, ok := d.System.LookupEnv("CLINE_DATA_DIR"); ok && strings.TrimSpace(value) != "" {
			dataDir = strings.TrimSpace(value)
		}
		providerPath := filepath.Join(dataDir, "settings", "providers.json")
		if value, ok := d.System.LookupEnv("CLINE_PROVIDER_SETTINGS_PATH"); ok && strings.TrimSpace(value) != "" {
			providerPath = strings.TrimSpace(value)
		}
		mcpPath := filepath.Join(dataDir, "settings", "cline_mcp_settings.json")
		if value, ok := d.System.LookupEnv("CLINE_MCP_SETTINGS_PATH"); ok && strings.TrimSpace(value) != "" {
			mcpPath = strings.TrimSpace(value)
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
		config.ConfigSource = "unsupported-versioned-config"
		config.Slots = []integration.Slot{{ID: "unknown-egress", Name: "Unresolved agent egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true}}
	default:
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover agent", "agent has no integration")
	}
	return (integration.Inspector{VerifiedVersions: d.Verified}).Inspect(config)
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

func containsTOMLKey(content []byte, key string) bool {
	return regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=`).Match(content)
}
