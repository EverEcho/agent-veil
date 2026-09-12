package integration

import (
	"sort"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"gopkg.in/yaml.v3"
)

const maxClineConfigBytes = 1 << 20

type clineProviderSettings struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
	BaseURL  string `yaml:"baseUrl"`
	Protocol string `yaml:"protocol"`
}

type clineProviderEntry struct {
	Settings clineProviderSettings `yaml:"settings"`
}

type clineProviderDocument struct {
	Version   int                           `yaml:"version"`
	Providers map[string]clineProviderEntry `yaml:"providers"`
}

type clineMCPServer struct {
	Type     string   `yaml:"type"`
	Command  string   `yaml:"command"`
	Args     []string `yaml:"args"`
	URL      string   `yaml:"url"`
	Disabled bool     `yaml:"disabled"`
}

type clineMCPDocument struct {
	Servers map[string]clineMCPServer `yaml:"mcpServers"`
}

// ParseClineProviders enumerates provider routes without decoding API keys,
// headers, OAuth state, or provider-specific credential objects.
func ParseClineProviders(content []byte) ([]Slot, error) {
	var document clineProviderDocument
	if err := parseClineJSON(content, &document, "provider"); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(document.Providers))
	for name := range document.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	slots := make([]Slot, 0, len(names))
	for _, name := range names {
		if !safeZedLabel(name) {
			return nil, clineConfigError("provider name is unsafe")
		}
		settings := document.Providers[name].Settings
		providerType := strings.ToLower(strings.TrimSpace(settings.Provider))
		if providerType == "" {
			providerType = strings.ToLower(name)
		}
		if !safeZedLabel(providerType) || strings.TrimSpace(settings.Model) != settings.Model || containsControl(settings.Model) || len(settings.Model) > 256 {
			return nil, clineConfigError("provider settings are unsafe")
		}
		baseURL := strings.TrimSpace(settings.BaseURL)
		protocolType := clineProtocol(settings.Protocol, providerType)
		if baseURL == "" {
			switch providerType {
			case "anthropic":
				baseURL = "https://api.anthropic.com"
			case "gemini":
				baseURL = "https://generativelanguage.googleapis.com"
			case "cline":
				baseURL = "https://api.cline.bot/api/v1"
			}
		}
		if unresolvedZedValue(baseURL) {
			baseURL, protocolType = "", domain.ProtocolUnknown
		}
		metadata := map[string]string{"provider": providerType, "provider_id": name}
		if settings.Model != "" {
			metadata["model_ref"] = settings.Model
		}
		slots = append(slots, Slot{ID: stableZedID("model", "cline\x00"+name), Name: "Cline provider " + name, Type: domain.SurfaceModelPrimary, Protocol: protocolType, BaseURL: baseURL, Auth: clineAuth(), Metadata: metadata, Rewritable: false, Required: true})
	}
	return slots, nil
}

// ParseClineMCP enumerates the CLI MCP settings. A missing type on a remote
// server is legacy SSE according to Cline's documented compatibility behavior.
func ParseClineMCP(content []byte) ([]Slot, []string, error) {
	var document clineMCPDocument
	if err := parseClineJSON(content, &document, "MCP"); err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(document.Servers))
	for name := range document.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	var slots []Slot
	var local []string
	for _, name := range names {
		server := document.Servers[name]
		if server.Disabled {
			continue
		}
		if !safeZedLabel(name) {
			return nil, nil, clineConfigError("MCP server name is unsafe")
		}
		command, endpoint := strings.TrimSpace(server.Command), strings.TrimSpace(server.URL)
		if command != "" && endpoint != "" {
			return nil, nil, clineConfigError("MCP transport is ambiguous")
		}
		if command != "" {
			if containsControl(command) || !validOptionalZedArguments(server.Args) {
				return nil, nil, clineConfigError("MCP command is invalid")
			}
			local = append(local, name)
			continue
		}
		if endpoint == "" {
			return nil, nil, clineConfigError("MCP endpoint is required")
		}
		var protocolType domain.Protocol
		switch strings.ToLower(strings.TrimSpace(server.Type)) {
		case "streamablehttp":
			protocolType = domain.ProtocolMCPStreamable
		case "", "sse":
			protocolType = domain.ProtocolMCPHTTP
		default:
			return nil, nil, clineConfigError("MCP transport type is unsupported")
		}
		if unresolvedZedValue(endpoint) {
			endpoint, protocolType = "", domain.ProtocolUnknown
		}
		slots = append(slots, Slot{ID: stableZedID("mcp", "cline\x00"+name), Name: "Remote MCP " + name, Type: domain.SurfaceMCPHTTP, Protocol: protocolType, BaseURL: endpoint, Auth: clineAuth(), Rewritable: false, Required: true})
	}
	return slots, local, nil
}

func parseClineJSON(content []byte, destination any, kind string) error {
	if len(content) == 0 || len(content) > maxClineConfigBytes {
		return clineConfigError(kind + " configuration is empty or too large")
	}
	cleaned, err := validateJSONC(content)
	if err != nil {
		return clineConfigError(kind + " configuration is invalid JSON")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(cleaned, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || hasYAMLAlias(document.Content[0]) {
		return clineConfigError(kind + " configuration is invalid JSON")
	}
	if err := document.Content[0].Decode(destination); err != nil {
		return clineConfigError(kind + " configuration has an invalid shape")
	}
	return nil
}

func clineProtocol(configured, provider string) domain.Protocol {
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case "openai-responses", "openai_responses":
		return domain.ProtocolOpenAIResponses
	case "openai-chat", "openai_chat":
		return domain.ProtocolOpenAIChat
	case "anthropic", "anthropic-messages":
		return domain.ProtocolAnthropic
	case "gemini", "google":
		return domain.ProtocolGemini
	case "":
		switch provider {
		case "anthropic":
			return domain.ProtocolAnthropic
		case "gemini":
			return domain.ProtocolGemini
		case "openai", "cline":
			return domain.ProtocolOpenAIChat
		}
	}
	return domain.ProtocolUnknown
}

func clineAuth() domain.AuthStrategy {
	return domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:cline-provider-store"}
}

func clineConfigError(message string) error {
	return domain.NewError(domain.ErrInvalidContract, "parse cline config", message)
}
