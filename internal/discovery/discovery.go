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
	case "cursor":
		config.ConfigSource = "unsupported-versioned-config"
		config.Slots = []integration.Slot{{ID: "unknown-egress", Name: "Unresolved agent egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true}}
	default:
		return domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "discover agent", "agent has no integration")
	}
	return (integration.Inspector{VerifiedVersions: d.Verified}).Inspect(config)
}

func containsTOMLKey(content []byte, key string) bool {
	return regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=`).Match(content)
}
