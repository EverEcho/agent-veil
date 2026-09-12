package integration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"gopkg.in/yaml.v3"
)

const maxHermesConfigBytes = 1 << 20

type hermesRoute struct {
	Provider          string        `yaml:"provider"`
	Model             string        `yaml:"model"`
	BaseURL           string        `yaml:"base_url"`
	APIMode           string        `yaml:"api_mode"`
	FallbackChain     []hermesRoute `yaml:"fallback_chain"`
	FallbackProviders []hermesRoute `yaml:"fallback_providers"`
}

type hermesProvider struct {
	API       string `yaml:"api"`
	BaseURL   string `yaml:"base_url"`
	Transport string `yaml:"transport"`
}

type hermesMCPServer struct {
	Command   string `yaml:"command"`
	URL       string `yaml:"url"`
	Transport string `yaml:"transport"`
	Enabled   *bool  `yaml:"enabled"`
}

type hermesConfig struct {
	ConfigVersion     int                        `yaml:"_config_version"`
	Model             hermesRoute                `yaml:"model"`
	Providers         map[string]hermesProvider  `yaml:"providers"`
	Auxiliary         map[string]hermesRoute     `yaml:"auxiliary"`
	FallbackProviders []hermesRoute              `yaml:"fallback_providers"`
	FallbackModel     *hermesRoute               `yaml:"fallback_model"`
	Delegation        hermesRoute                `yaml:"delegation"`
	MCPServers        map[string]hermesMCPServer `yaml:"mcp_servers"`
}

// ParseHermesConfig enumerates every configured model and MCP route without
// retaining credential values. The v0.20.6 integration is discovery-only, so
// network slots are deliberately not marked rewritable.
func ParseHermesConfig(content []byte) ([]Slot, []string, error) {
	if len(content) == 0 || len(content) > maxHermesConfigBytes {
		return nil, nil, domain.NewError(domain.ErrInvalidContract, "parse hermes config", "configuration is empty or too large")
	}
	var config hermesConfig
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, nil, domain.NewError(domain.ErrInvalidContract, "parse hermes config", "configuration is invalid YAML")
	}
	primary := resolveHermesRoute(config.Model, config.Providers, nil)
	slots := []Slot{hermesSlot("primary", "Primary model", domain.SurfaceModelPrimary, primary, true)}

	for index, fallback := range effectiveHermesFallbacks(config) {
		resolved := resolveHermesRoute(fallback, config.Providers, &primary)
		slots = append(slots, hermesSlot(fmt.Sprintf("fallback-%d", index+1), fmt.Sprintf("Fallback model %d", index+1), domain.SurfaceModelFallback, resolved, false))
	}

	auxiliaryNames := make([]string, 0, len(config.Auxiliary))
	for name := range config.Auxiliary {
		auxiliaryNames = append(auxiliaryNames, name)
	}
	sort.Strings(auxiliaryNames)
	for _, name := range auxiliaryNames {
		if !safeHermesName(name) {
			return nil, nil, domain.NewError(domain.ErrInvalidContract, "parse hermes config", "auxiliary task name is unsafe")
		}
		route := config.Auxiliary[name]
		resolved := resolveHermesRoute(route, config.Providers, &primary)
		surfaceType := domain.SurfaceModelAuxiliary
		if name == "vision" {
			surfaceType = domain.SurfaceVision
		}
		prefix := "aux-" + strings.ReplaceAll(name, "_", "-")
		slots = append(slots, hermesSlot(prefix, "Auxiliary "+name, surfaceType, resolved, false))
		fallbacks := append(append([]hermesRoute(nil), route.FallbackChain...), route.FallbackProviders...)
		for index, fallback := range fallbacks {
			resolvedFallback := resolveHermesRoute(fallback, config.Providers, &primary)
			slots = append(slots, hermesSlot(fmt.Sprintf("%s-fallback-%d", prefix, index+1), fmt.Sprintf("Auxiliary %s fallback %d", name, index+1), domain.SurfaceModelFallback, resolvedFallback, false))
		}
	}

	if configuredHermesRoute(config.Delegation) {
		resolved := resolveHermesRoute(config.Delegation, config.Providers, &primary)
		slots = append(slots, hermesSlot("delegation", "Delegated sub-agent model", domain.SurfaceSubAgent, resolved, false))
		for index, fallback := range config.Delegation.FallbackProviders {
			resolvedFallback := resolveHermesRoute(fallback, config.Providers, &primary)
			slots = append(slots, hermesSlot(fmt.Sprintf("delegation-fallback-%d", index+1), fmt.Sprintf("Delegation fallback %d", index+1), domain.SurfaceModelFallback, resolvedFallback, false))
		}
	}

	mcpNames := make([]string, 0, len(config.MCPServers))
	for name := range config.MCPServers {
		mcpNames = append(mcpNames, name)
	}
	sort.Strings(mcpNames)
	localMCP := make([]string, 0, len(mcpNames))
	for _, name := range mcpNames {
		server := config.MCPServers[name]
		if server.Enabled != nil && !*server.Enabled {
			continue
		}
		if !safeHermesName(name) {
			return nil, nil, domain.NewError(domain.ErrInvalidContract, "parse hermes config", "MCP server name is unsafe")
		}
		if strings.TrimSpace(server.Command) != "" && strings.TrimSpace(server.URL) != "" {
			return nil, nil, domain.NewError(domain.ErrInvalidContract, "parse hermes config", "MCP transport is ambiguous")
		}
		if strings.TrimSpace(server.Command) != "" {
			localMCP = append(localMCP, name)
			continue
		}
		protocolType := domain.ProtocolMCPStreamable
		if strings.EqualFold(strings.TrimSpace(server.Transport), "sse") {
			protocolType = domain.ProtocolMCPHTTP
		}
		baseURL := strings.TrimSpace(server.URL)
		if strings.Contains(baseURL, "${") {
			baseURL, protocolType = "", domain.ProtocolUnknown
		}
		slots = append(slots, Slot{ID: "mcp-" + strings.ReplaceAll(name, "_", "-"), Name: "Remote MCP " + name, Type: domain.SurfaceMCPHTTP, Protocol: protocolType, BaseURL: baseURL, Auth: hermesAuth(), Rewritable: false})
	}
	return slots, localMCP, nil
}

type resolvedHermesRoute struct {
	baseURL  string
	protocol domain.Protocol
}

func resolveHermesRoute(route hermesRoute, providers map[string]hermesProvider, inherited *resolvedHermesRoute) resolvedHermesRoute {
	providerName := strings.TrimSpace(route.Provider)
	if providerName == "main" && inherited != nil {
		return *inherited
	}
	baseURL := strings.TrimSpace(route.BaseURL)
	mode := strings.TrimSpace(route.APIMode)
	if provider, ok := providers[providerName]; ok {
		if baseURL == "" {
			baseURL = strings.TrimSpace(provider.API)
			if baseURL == "" {
				baseURL = strings.TrimSpace(provider.BaseURL)
			}
		}
		if mode == "" {
			mode = strings.TrimSpace(provider.Transport)
		}
	}
	protocolType := hermesProtocol(mode)
	if protocolType == domain.ProtocolUnknown && baseURL != "" && mode == "" {
		protocolType = domain.ProtocolOpenAIChat
	}
	if strings.Contains(baseURL, "${") {
		return resolvedHermesRoute{}
	}
	return resolvedHermesRoute{baseURL: baseURL, protocol: protocolType}
}

func hermesProtocol(value string) domain.Protocol {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "chat_completions", "openai_chat":
		return domain.ProtocolOpenAIChat
	case "codex_responses", "openai_responses":
		return domain.ProtocolOpenAIResponses
	case "anthropic_messages":
		return domain.ProtocolAnthropic
	default:
		return domain.ProtocolUnknown
	}
}

func hermesSlot(id, name string, surfaceType domain.SurfaceType, route resolvedHermesRoute, required bool) Slot {
	protocolType := route.protocol
	if protocolType == "" {
		protocolType = domain.ProtocolUnknown
	}
	return Slot{ID: id, Name: name, Type: surfaceType, Protocol: protocolType, BaseURL: route.baseURL, Auth: hermesAuth(), Rewritable: false, Required: required}
}

func hermesAuth() domain.AuthStrategy {
	return domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:hermes-credentials"}
}

func effectiveHermesFallbacks(config hermesConfig) []hermesRoute {
	if len(config.FallbackProviders) > 0 {
		return config.FallbackProviders
	}
	if config.FallbackModel != nil && configuredHermesRoute(*config.FallbackModel) {
		return []hermesRoute{*config.FallbackModel}
	}
	return nil
}

func configuredHermesRoute(route hermesRoute) bool {
	return strings.TrimSpace(route.Provider) != "" || strings.TrimSpace(route.Model) != "" || strings.TrimSpace(route.BaseURL) != "" || strings.TrimSpace(route.APIMode) != ""
}

func safeHermesName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}
