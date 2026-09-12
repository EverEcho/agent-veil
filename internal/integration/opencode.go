package integration

import (
	"sort"
	"strings"
	"unicode"

	"github.com/agentveil/agentveil/internal/domain"
	"gopkg.in/yaml.v3"
)

const maxOpenCodeConfigBytes = 1 << 20

type openCodeProvider struct {
	NPM     string `yaml:"npm"`
	Options struct {
		BaseURL string `yaml:"baseURL"`
	} `yaml:"options"`
}

type openCodeMCP struct {
	Type    string   `yaml:"type"`
	URL     string   `yaml:"url"`
	Command []string `yaml:"command"`
	Enabled *bool    `yaml:"enabled"`
}

type openCodeConfig struct {
	Model      string                      `yaml:"model"`
	SmallModel string                      `yaml:"small_model"`
	Providers  map[string]openCodeProvider `yaml:"provider"`
	MCP        map[string]openCodeMCP      `yaml:"mcp"`
}

// ParseOpenCodeConfig enumerates the documented model and MCP surfaces in an
// OpenCode JSON/JSONC configuration. Credentials and remote MCP headers are
// intentionally absent from the decoded shape, and all slots remain
// discovery-only until a versioned rewrite adapter is verified.
func ParseOpenCodeConfig(content []byte) ([]Slot, []string, error) {
	if len(content) == 0 || len(content) > maxOpenCodeConfigBytes {
		return nil, nil, openCodeConfigError("configuration is empty or too large")
	}
	cleaned, err := validateJSONC(content)
	if err != nil {
		return nil, nil, openCodeConfigError("configuration is invalid JSONC")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(cleaned, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || hasYAMLAlias(document.Content[0]) {
		return nil, nil, openCodeConfigError("configuration is invalid JSONC")
	}
	var config openCodeConfig
	if err := document.Content[0].Decode(&config); err != nil {
		return nil, nil, openCodeConfigError("configuration has an invalid shape")
	}
	for name := range config.Providers {
		if !safeHermesName(name) {
			return nil, nil, openCodeConfigError("provider name is unsafe")
		}
	}

	var slots []Slot
	if strings.TrimSpace(config.Model) != "" {
		slot, slotErr := openCodeModelSlot("primary", "Primary model", domain.SurfaceModelPrimary, config.Model, config.Providers, true)
		if slotErr != nil {
			return nil, nil, slotErr
		}
		slots = append(slots, slot)
	}
	if strings.TrimSpace(config.SmallModel) != "" {
		slot, slotErr := openCodeModelSlot("small", "Small model", domain.SurfaceModelAuxiliary, config.SmallModel, config.Providers, false)
		if slotErr != nil {
			return nil, nil, slotErr
		}
		slots = append(slots, slot)
	}

	names := make([]string, 0, len(config.MCP))
	for name := range config.MCP {
		names = append(names, name)
	}
	sort.Strings(names)
	localMCP := make([]string, 0, len(names))
	for _, name := range names {
		server := config.MCP[name]
		if server.Enabled != nil && !*server.Enabled {
			continue
		}
		if !safeHermesName(name) {
			return nil, nil, openCodeConfigError("MCP server name is unsafe")
		}
		typeName := strings.ToLower(strings.TrimSpace(server.Type))
		endpoint := strings.TrimSpace(server.URL)
		hasCommand := len(server.Command) != 0
		if (endpoint != "" && hasCommand) || (typeName == "local" && endpoint != "") || (typeName == "remote" && hasCommand) {
			return nil, nil, openCodeConfigError("MCP transport is ambiguous")
		}
		switch typeName {
		case "local":
			if !validOpenCodeCommand(server.Command) {
				return nil, nil, openCodeConfigError("local MCP command is invalid")
			}
			localMCP = append(localMCP, name)
		case "remote":
			if endpoint == "" {
				return nil, nil, openCodeConfigError("remote MCP URL is required")
			}
			protocolType := domain.ProtocolMCPStreamable
			if unresolvedOpenCodeValue(endpoint) {
				endpoint, protocolType = "", domain.ProtocolUnknown
			}
			slots = append(slots, Slot{ID: "mcp-" + strings.ReplaceAll(name, "_", "-"), Name: "Remote MCP " + name, Type: domain.SurfaceMCPHTTP, Protocol: protocolType, BaseURL: endpoint, Auth: openCodeAuth(), Rewritable: false})
		default:
			return nil, nil, openCodeConfigError("MCP type must be local or remote")
		}
	}
	return slots, localMCP, nil
}

func openCodeModelSlot(id, name string, surfaceType domain.SurfaceType, modelRef string, providers map[string]openCodeProvider, required bool) (Slot, error) {
	modelRef = strings.TrimSpace(modelRef)
	separator := strings.IndexByte(modelRef, '/')
	if separator < 1 || separator == len(modelRef)-1 || len(modelRef) > 256 || containsControl(modelRef) {
		return Slot{}, openCodeConfigError("model reference is invalid")
	}
	providerID := modelRef[:separator]
	if !safeHermesName(providerID) {
		return Slot{}, openCodeConfigError("model provider is unsafe")
	}
	provider, configured := providers[providerID]
	baseURL := strings.TrimSpace(provider.Options.BaseURL)
	protocolType := domain.ProtocolUnknown
	if configured && baseURL != "" {
		protocolType = openCodeProviderProtocol(provider.NPM)
	}
	if !configured {
		switch strings.ToLower(providerID) {
		case "anthropic":
			baseURL, protocolType = "https://api.anthropic.com", domain.ProtocolAnthropic
		case "google":
			baseURL, protocolType = "https://generativelanguage.googleapis.com", domain.ProtocolGemini
		}
	}
	if unresolvedOpenCodeValue(baseURL) {
		baseURL, protocolType = "", domain.ProtocolUnknown
	}
	metadata := map[string]string{"model_ref": modelRef, "provider": strings.ToLower(providerID)}
	return Slot{ID: id, Name: name, Type: surfaceType, Protocol: protocolType, BaseURL: baseURL, Auth: openCodeAuth(), Metadata: metadata, Rewritable: false, Required: required}, nil
}

func openCodeProviderProtocol(packageName string) domain.Protocol {
	packageName = strings.ToLower(strings.TrimSpace(packageName))
	switch {
	case strings.Contains(packageName, "openai-compatible"):
		return domain.ProtocolOpenAIChat
	case strings.Contains(packageName, "anthropic"):
		return domain.ProtocolAnthropic
	case strings.Contains(packageName, "google"):
		return domain.ProtocolGemini
	default:
		return domain.ProtocolUnknown
	}
}

func validOpenCodeCommand(command []string) bool {
	if len(command) == 0 || len(command) > 128 {
		return false
	}
	for _, argument := range command {
		if strings.TrimSpace(argument) == "" || len(argument) > 4096 || containsControl(argument) {
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func unresolvedOpenCodeValue(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "{env:") || strings.Contains(value, "{file:")
}

func openCodeAuth() domain.AuthStrategy {
	return domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:opencode-credentials"}
}

func openCodeConfigError(message string) error {
	return domain.NewError(domain.ErrInvalidContract, "parse opencode config", message)
}
