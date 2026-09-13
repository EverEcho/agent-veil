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
	Default           string        `yaml:"default"`
	BaseURL           string        `yaml:"base_url"`
	APIMode           string        `yaml:"api_mode"`
	FallbackChain     []hermesRoute `yaml:"fallback_chain"`
	FallbackProviders []hermesRoute `yaml:"fallback_providers"`
}

func (r *hermesRoute) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		if node.Tag != "!!str" || strings.TrimSpace(node.Value) == "" {
			return domain.NewError(domain.ErrInvalidContract, "parse hermes config", "model route is invalid")
		}
		*r = hermesRoute{Model: strings.TrimSpace(node.Value)}
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return domain.NewError(domain.ErrInvalidContract, "parse hermes config", "model route must be a string or mapping")
	}
	type rawHermesRoute hermesRoute
	var decoded rawHermesRoute
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*r = hermesRoute(decoded)
	return nil
}

type hermesRouteList []hermesRoute

func (r *hermesRouteList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case 0, yaml.ScalarNode:
		if node.Tag == "!!null" || strings.TrimSpace(node.Value) == "" {
			*r = nil
			return nil
		}
		return domain.NewError(domain.ErrInvalidContract, "parse hermes config", "fallback_model must be a mapping or list")
	case yaml.MappingNode:
		var route hermesRoute
		if err := node.Decode(&route); err != nil {
			return err
		}
		*r = []hermesRoute{route}
		return nil
	case yaml.SequenceNode:
		var routes []hermesRoute
		if err := node.Decode(&routes); err != nil {
			return err
		}
		*r = routes
		return nil
	default:
		return domain.NewError(domain.ErrInvalidContract, "parse hermes config", "fallback_model must be a mapping or list")
	}
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
	FallbackModel     hermesRouteList            `yaml:"fallback_model"`
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

	fallbacks, err := effectiveHermesFallbacks(config)
	if err != nil {
		return nil, nil, err
	}
	for index, fallback := range fallbacks {
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
	baseURL       string
	protocol      domain.Protocol
	model         string
	provider      string
	explicitRoute bool
}

func resolveHermesRoute(route hermesRoute, providers map[string]hermesProvider, inherited *resolvedHermesRoute) resolvedHermesRoute {
	providerName := strings.TrimSpace(route.Provider)
	model := strings.TrimSpace(route.Model)
	if model == "" {
		model = strings.TrimSpace(route.Default)
	}
	if providerName == "main" && inherited != nil {
		result := *inherited
		if model != "" {
			result.model = model
		}
		return result
	}
	_, userDefinedProvider := providers[providerName]
	stableBuiltin := !userDefinedProvider && hermesStableBuiltinProvider(providerName)
	if inherited != nil && (inherited.explicitRoute || stableBuiltin) && providerName != "" && providerName == inherited.provider && !hermesModelSpecificProvider(providerName) && strings.TrimSpace(route.BaseURL) == "" && strings.TrimSpace(route.APIMode) == "" {
		result := *inherited
		if model != "" {
			result.model = model
		}
		return result
	}
	baseURL := strings.TrimSpace(route.BaseURL)
	mode := strings.TrimSpace(route.APIMode)
	customProvider := false
	if provider, ok := providers[providerName]; ok {
		customProvider = true
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
	if !customProvider {
		protocolType = hermesRuntimeProtocol(providerName, model, mode, protocolType)
	}
	if protocolType == domain.ProtocolUnknown && baseURL != "" && mode == "" {
		protocolType = domain.ProtocolOpenAIChat
	}
	if strings.Contains(baseURL, "${") {
		return resolvedHermesRoute{}
	}
	return resolvedHermesRoute{baseURL: baseURL, protocol: protocolType, model: model, provider: providerName, explicitRoute: strings.TrimSpace(route.BaseURL) != "" && strings.TrimSpace(route.APIMode) != ""}
}

func hermesStableBuiltinProvider(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "openai-codex", "xai", "xai-oauth", "anthropic", "minimax-oauth":
		return true
	default:
		return false
	}
}

func hermesRuntimeProtocol(provider, model, mode string, configured domain.Protocol) domain.Protocol {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	switch normalized {
	case "openai-codex", "xai", "xai-oauth":
		return domain.ProtocolOpenAIResponses
	case "anthropic", "minimax-oauth":
		return domain.ProtocolAnthropic
	case "nous", "nous-portal", "nousresearch":
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), "anthropic/") {
			return domain.ProtocolAnthropic
		}
		return domain.ProtocolOpenAIChat
	}
	if strings.HasPrefix(normalized, "opencode-zen") || strings.HasPrefix(normalized, "opencode-go") || strings.HasPrefix(normalized, "opencode-free") || normalized == "azure-foundry" || normalized == "copilot" || normalized == "github-copilot" {
		return domain.ProtocolUnknown
	}
	if strings.TrimSpace(mode) == "" {
		switch normalized {
		case "openai-api", "actual":
			return domain.ProtocolOpenAIResponses
		case "minimax", "minimax-cn":
			return domain.ProtocolAnthropic
		}
	}
	return configured
}

func hermesModelSpecificProvider(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "nous" || normalized == "nous-portal" || normalized == "nousresearch" || normalized == "azure-foundry" || normalized == "copilot" || normalized == "github-copilot" {
		return true
	}
	return strings.HasPrefix(normalized, "opencode-zen") || strings.HasPrefix(normalized, "opencode-go") || strings.HasPrefix(normalized, "opencode-free")
}

func hermesProtocol(value string) domain.Protocol {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "chat_completions", "openai_chat", "openai", "openai-chat", "chat-completions", "chatcompletions":
		return domain.ProtocolOpenAIChat
	case "codex_responses", "openai_responses", "responses", "openai-responses":
		return domain.ProtocolOpenAIResponses
	case "anthropic_messages", "anthropic", "anthropic-messages", "messages":
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
	metadata := map[string]string{}
	if route.model != "" {
		metadata["model_ref"] = route.model
	}
	if route.provider != "" {
		metadata["provider"] = route.provider
	}
	if len(metadata) == 0 {
		metadata = nil
	}
	return Slot{ID: id, Name: name, Type: surfaceType, Protocol: protocolType, BaseURL: route.baseURL, Auth: hermesAuth(), Metadata: metadata, Rewritable: false, Required: required}
}

func hermesAuth() domain.AuthStrategy {
	return domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:hermes-credentials"}
}

func effectiveHermesFallbacks(config hermesConfig) ([]hermesRoute, error) {
	result := make([]hermesRoute, 0, len(config.FallbackProviders)+len(config.FallbackModel))
	seen := map[string]struct{}{}
	for _, route := range append(append([]hermesRoute(nil), config.FallbackProviders...), config.FallbackModel...) {
		model := strings.TrimSpace(route.Model)
		if model == "" {
			model = strings.TrimSpace(route.Default)
		}
		if strings.TrimSpace(route.Provider) == "" || model == "" {
			return nil, domain.NewError(domain.ErrInvalidContract, "parse hermes config", "fallback route is incomplete")
		}
		identity := strings.ToLower(strings.TrimSpace(route.Provider) + "\x00" + model + "\x00" + strings.TrimSuffix(strings.TrimSpace(route.BaseURL), "/"))
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		result = append(result, route)
	}
	return result, nil
}

func configuredHermesRoute(route hermesRoute) bool {
	return strings.TrimSpace(route.Provider) != "" || strings.TrimSpace(route.Model) != "" || strings.TrimSpace(route.Default) != "" || strings.TrimSpace(route.BaseURL) != "" || strings.TrimSpace(route.APIMode) != ""
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
