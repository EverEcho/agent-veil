package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/agentveil/agentveil/internal/domain"
	"gopkg.in/yaml.v3"
)

const maxZedConfigBytes = 1 << 20

type zedModel struct {
	Name              string `yaml:"name"`
	Protocol          string `yaml:"protocol"`
	CustomModelAPIURL string `yaml:"custom_model_api_url"`
	Capabilities      struct {
		ChatCompletions *bool `yaml:"chat_completions"`
	} `yaml:"capabilities"`
}

type zedProvider struct {
	APIURL          string     `yaml:"api_url"`
	AvailableModels []zedModel `yaml:"available_models"`
}

type zedContextServer struct {
	Enabled *bool    `yaml:"enabled"`
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
	URL     string   `yaml:"url"`
}

type zedAgentServer struct {
	Type    string   `yaml:"type"`
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

type zedConfig struct {
	LanguageModels map[string]yaml.Node        `yaml:"language_models"`
	ContextServers map[string]zedContextServer `yaml:"context_servers"`
	AgentServers   map[string]zedAgentServer   `yaml:"agent_servers"`
}

// ParseZedConfig enumerates explicitly configured custom model endpoints,
// custom MCP servers, and ACP agent processes. Keychain credentials, custom
// headers, and agent environment values are deliberately never retained.
func ParseZedConfig(content []byte) ([]Slot, []string, error) {
	if len(content) == 0 || len(content) > maxZedConfigBytes {
		return nil, nil, zedConfigError("configuration is empty or too large")
	}
	cleaned, err := validateJSONC(content)
	if err != nil {
		return nil, nil, zedConfigError("configuration is invalid JSONC")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(cleaned, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || hasYAMLAlias(document.Content[0]) {
		return nil, nil, zedConfigError("configuration is invalid JSONC")
	}
	var config zedConfig
	if err := document.Content[0].Decode(&config); err != nil {
		return nil, nil, zedConfigError("configuration has an invalid shape")
	}

	slots, err := zedModelSlots(config.LanguageModels)
	if err != nil {
		return nil, nil, err
	}
	localMCP, mcpSlots, err := zedContextServerSlots(config.ContextServers)
	if err != nil {
		return nil, nil, err
	}
	slots = append(slots, mcpSlots...)
	agentSlots, err := zedAgentServerSlots(config.AgentServers)
	if err != nil {
		return nil, nil, err
	}
	slots = append(slots, agentSlots...)
	return slots, localMCP, nil
}

func zedModelSlots(groups map[string]yaml.Node) ([]Slot, error) {
	names := sortedZedNodeKeys(groups)
	var slots []Slot
	for _, group := range names {
		node := groups[group]
		switch group {
		case "openai_compatible", "anthropic_compatible":
			var providers map[string]zedProvider
			if err := node.Decode(&providers); err != nil {
				return nil, zedConfigError("compatible provider configuration is invalid")
			}
			providerNames := make([]string, 0, len(providers))
			for name := range providers {
				providerNames = append(providerNames, name)
			}
			sort.Strings(providerNames)
			for _, name := range providerNames {
				if !safeZedLabel(name) {
					return nil, zedConfigError("provider name is unsafe")
				}
				protocolType := domain.ProtocolOpenAIChat
				if group == "anthropic_compatible" {
					protocolType = domain.ProtocolAnthropic
				}
				providerSlots, slotErr := zedProviderSlots(group, name, providers[name], protocolType)
				if slotErr != nil {
					return nil, slotErr
				}
				slots = append(slots, providerSlots...)
			}
		default:
			var provider zedProvider
			if err := node.Decode(&provider); err != nil {
				return nil, zedConfigError("provider configuration is invalid")
			}
			protocolType := zedProviderProtocol(group)
			providerSlots, slotErr := zedProviderSlots(group, group, provider, protocolType)
			if slotErr != nil {
				return nil, slotErr
			}
			slots = append(slots, providerSlots...)
		}
	}
	return slots, nil
}

func zedProviderSlots(group, providerName string, provider zedProvider, defaultProtocol domain.Protocol) ([]Slot, error) {
	baseURL := strings.TrimSpace(provider.APIURL)
	if len(provider.AvailableModels) == 0 {
		if baseURL == "" {
			return nil, nil
		}
		return []Slot{zedModelSlot(group, providerName, "", baseURL, defaultProtocol)}, nil
	}
	slots := make([]Slot, 0, len(provider.AvailableModels))
	for _, model := range provider.AvailableModels {
		if !safeZedLabel(model.Name) {
			return nil, zedConfigError("model name is unsafe")
		}
		modelURL := baseURL
		protocolType := defaultProtocol
		if strings.TrimSpace(model.CustomModelAPIURL) != "" {
			modelURL = strings.TrimSpace(model.CustomModelAPIURL)
		}
		if strings.TrimSpace(model.Protocol) != "" {
			protocolType = zedExplicitProtocol(model.Protocol)
		}
		if group == "openai_compatible" && model.Capabilities.ChatCompletions != nil && !*model.Capabilities.ChatCompletions {
			protocolType = domain.ProtocolOpenAIResponses
		}
		if modelURL == "" {
			continue
		}
		slots = append(slots, zedModelSlot(group, providerName, model.Name, modelURL, protocolType))
	}
	return slots, nil
}

func zedModelSlot(group, providerName, modelName, baseURL string, protocolType domain.Protocol) Slot {
	metadata := map[string]string{"provider": providerName, "provider_group": group}
	label := providerName
	if modelName != "" {
		metadata["model_ref"] = modelName
		label += "/" + modelName
	}
	if unresolvedZedValue(baseURL) {
		baseURL, protocolType = "", domain.ProtocolUnknown
	}
	return Slot{ID: stableZedID("model", group+"\x00"+label), Name: "Zed model " + label, Type: domain.SurfaceModelPrimary, Protocol: protocolType, BaseURL: baseURL, Auth: zedAuth(), Metadata: metadata, Rewritable: false, Required: true}
}

func zedContextServerSlots(servers map[string]zedContextServer) ([]string, []Slot, error) {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	var local []string
	var slots []Slot
	for _, name := range names {
		server := servers[name]
		if server.Enabled != nil && !*server.Enabled {
			continue
		}
		if !safeZedLabel(name) {
			return nil, nil, zedConfigError("context server name is unsafe")
		}
		command, endpoint := strings.TrimSpace(server.Command), strings.TrimSpace(server.URL)
		if command != "" && endpoint != "" {
			return nil, nil, zedConfigError("context server transport is ambiguous")
		}
		if command != "" {
			if containsControl(command) || !validOptionalZedArguments(server.Args) {
				return nil, nil, zedConfigError("context server command is invalid")
			}
			local = append(local, name)
			continue
		}
		if endpoint == "" {
			return nil, nil, zedConfigError("context server endpoint is required")
		}
		protocolType := domain.ProtocolMCPStreamable
		if unresolvedZedValue(endpoint) {
			endpoint, protocolType = "", domain.ProtocolUnknown
		}
		slots = append(slots, Slot{ID: stableZedID("mcp", name), Name: "Remote MCP " + name, Type: domain.SurfaceMCPHTTP, Protocol: protocolType, BaseURL: endpoint, Auth: zedAuth(), Rewritable: false, Required: true})
	}
	return local, slots, nil
}

func zedAgentServerSlots(servers map[string]zedAgentServer) ([]Slot, error) {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	slots := make([]Slot, 0, len(names))
	for _, name := range names {
		server := servers[name]
		if !safeZedLabel(name) || containsControl(server.Command) || !validOptionalZedArguments(server.Args) {
			return nil, zedConfigError("agent server configuration is unsafe")
		}
		if strings.EqualFold(strings.TrimSpace(server.Type), "custom") && strings.TrimSpace(server.Command) == "" {
			return nil, zedConfigError("custom agent server command is required")
		}
		metadata := map[string]string{"process_egress": "not-inspected"}
		if server.Type != "" {
			metadata["server_type"] = strings.TrimSpace(server.Type)
		}
		slots = append(slots, Slot{ID: stableZedID("acp", name), Name: "ACP agent " + name, Type: domain.SurfaceACP, Protocol: domain.ProtocolUnknown, Auth: zedAuth(), Metadata: metadata, Rewritable: false, Required: true})
	}
	return slots, nil
}

func zedProviderProtocol(provider string) domain.Protocol {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "anthropic", "anthropic_compatible":
		return domain.ProtocolAnthropic
	case "google":
		return domain.ProtocolGemini
	case "openai_compatible", "mistral", "deepseek", "x_ai", "open_router", "vercel_ai_gateway":
		return domain.ProtocolOpenAIChat
	default:
		return domain.ProtocolUnknown
	}
}

func zedExplicitProtocol(value string) domain.Protocol {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "anthropic":
		return domain.ProtocolAnthropic
	case "openai_responses":
		return domain.ProtocolOpenAIResponses
	case "openai_chat":
		return domain.ProtocolOpenAIChat
	case "google":
		return domain.ProtocolGemini
	default:
		return domain.ProtocolUnknown
	}
}

func validOptionalZedArguments(arguments []string) bool {
	if len(arguments) > 128 {
		return false
	}
	for _, argument := range arguments {
		if len(argument) > 4096 || containsControl(argument) {
			return false
		}
	}
	return true
}

func safeZedLabel(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func unresolvedZedValue(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "{env:") || strings.Contains(value, "{file:")
}

func stableZedID(prefix, value string) string {
	hash := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(hash[:8]))
}

func sortedZedNodeKeys(values map[string]yaml.Node) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func zedAuth() domain.AuthStrategy {
	return domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:zed-keychain-or-environment"}
}

func zedConfigError(message string) error {
	return domain.NewError(domain.ErrInvalidContract, "parse zed config", message)
}
