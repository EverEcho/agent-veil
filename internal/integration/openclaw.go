package integration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"gopkg.in/yaml.v3"
)

const maxOpenClawConfigBytes = 1 << 20

type openClawModelChoice struct {
	Primary   string   `yaml:"primary"`
	Fallbacks []string `yaml:"fallbacks"`
}

func (choice *openClawModelChoice) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		choice.Primary = node.Value
		return nil
	}
	type plain openClawModelChoice
	return node.Decode((*plain)(choice))
}

type openClawAgent struct {
	ID         string               `yaml:"id"`
	Model      openClawModelChoice  `yaml:"model"`
	ImageModel *openClawModelChoice `yaml:"imageModel"`
	PDFModel   *openClawModelChoice `yaml:"pdfModel"`
	Runtime    struct {
		Type string `yaml:"type"`
		ACP  struct {
			Agent   string `yaml:"agent"`
			Backend string `yaml:"backend"`
		} `yaml:"acp"`
	} `yaml:"runtime"`
}

type openClawDefaults struct {
	Model      openClawModelChoice  `yaml:"model"`
	ImageModel *openClawModelChoice `yaml:"imageModel"`
	PDFModel   *openClawModelChoice `yaml:"pdfModel"`
	Subagents  struct {
		Model openClawModelChoice `yaml:"model"`
	} `yaml:"subagents"`
}

type openClawProvider struct {
	BaseURL string `yaml:"baseUrl"`
	API     string `yaml:"api"`
}

type openClawMCPServer struct {
	Command   string `yaml:"command"`
	URL       string `yaml:"url"`
	Transport string `yaml:"transport"`
}

type openClawBrowser struct {
	Enabled        *bool                  `yaml:"enabled"`
	DefaultProfile string                 `yaml:"defaultProfile"`
	Profiles       map[string]interface{} `yaml:"profiles"`
}

type openClawConfig struct {
	Agents struct {
		Defaults openClawDefaults         `yaml:"defaults"`
		Entries  map[string]openClawAgent `yaml:"entries"`
		List     []openClawAgent          `yaml:"list"`
	} `yaml:"agents"`
	Models struct {
		Providers map[string]openClawProvider `yaml:"providers"`
	} `yaml:"models"`
	MCP struct {
		Servers map[string]openClawMCPServer `yaml:"servers"`
	} `yaml:"mcp"`
	ACP struct {
		Enabled       *bool    `yaml:"enabled"`
		DefaultAgent  string   `yaml:"defaultAgent"`
		AllowedAgents []string `yaml:"allowedAgents"`
	} `yaml:"acp"`
	Browser *openClawBrowser     `yaml:"browser"`
	Tools   map[string]yaml.Node `yaml:"tools"`
}

// ParseOpenClawConfig enumerates model egress without retaining provider keys.
// Slots remain discovery-only until a versioned Provider Bridge is verified.
func ParseOpenClawConfig(content []byte) ([]Slot, error) {
	if len(content) == 0 || len(content) > maxOpenClawConfigBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "configuration is empty or too large")
	}
	cleaned, err := stripJSON5Comments(content)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(cleaned, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || hasYAMLAlias(document.Content[0]) {
		return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "configuration is invalid JSON5")
	}
	var config openClawConfig
	if err := document.Content[0].Decode(&config); err != nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "configuration has an invalid model shape")
	}

	slots := openClawChoiceSlots("primary", "Primary model", domain.SurfaceModelPrimary, config.Agents.Defaults.Model, config.Models.Providers, true)
	slots = append(slots, openClawOptionalChoiceSlots("image", "Image model", domain.SurfaceVision, config.Agents.Defaults.ImageModel, config.Models.Providers)...)
	slots = append(slots, openClawOptionalChoiceSlots("pdf", "PDF model", domain.SurfaceModelAuxiliary, config.Agents.Defaults.PDFModel, config.Models.Providers)...)
	if configuredOpenClawChoice(config.Agents.Defaults.Subagents.Model) {
		slots = append(slots, openClawChoiceSlots("subagent", "Sub-agent model", domain.SurfaceSubAgent, config.Agents.Defaults.Subagents.Model, config.Models.Providers, false)...)
	}

	entries := make(map[string]openClawAgent, len(config.Agents.Entries)+len(config.Agents.List))
	for id, agent := range config.Agents.Entries {
		agent.ID = id
		entries[id] = agent
	}
	for _, agent := range config.Agents.List {
		if agent.ID == "" {
			return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "agent entry has no id")
		}
		if _, exists := entries[agent.ID]; exists {
			return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "agent entry id is duplicated")
		}
		entries[agent.ID] = agent
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !safeHermesName(id) {
			return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "agent entry id is unsafe")
		}
		agent := entries[id]
		prefix := "agent-" + strings.ReplaceAll(id, "_", "-")
		if configuredOpenClawChoice(agent.Model) {
			slots = append(slots, openClawChoiceSlots(prefix, "Agent "+id+" model", domain.SurfaceSubAgent, agent.Model, config.Models.Providers, false)...)
		}
		slots = append(slots, openClawOptionalChoiceSlots(prefix+"-image", "Agent "+id+" image model", domain.SurfaceVision, agent.ImageModel, config.Models.Providers)...)
		slots = append(slots, openClawOptionalChoiceSlots(prefix+"-pdf", "Agent "+id+" PDF model", domain.SurfaceModelAuxiliary, agent.PDFModel, config.Models.Providers)...)
		if strings.EqualFold(strings.TrimSpace(agent.Runtime.Type), "acp") {
			if !safeOptionalOpenClawName(agent.Runtime.ACP.Agent) || !safeOptionalOpenClawName(agent.Runtime.ACP.Backend) {
				return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "ACP runtime identifier is unsafe")
			}
			slots = append(slots, openClawACPSlot("acp-agent-"+strings.ReplaceAll(id, "_", "-"), "Agent "+id+" ACP runtime", agent.Runtime.ACP.Agent, agent.Runtime.ACP.Backend))
		}
	}
	mcpSlots, err := openClawMCPSlots(config.MCP.Servers)
	if err != nil {
		return nil, err
	}
	slots = append(slots, mcpSlots...)
	acpSlots, err := openClawGlobalACPSlots(config.ACP.Enabled, config.ACP.DefaultAgent, config.ACP.AllowedAgents)
	if err != nil {
		return nil, err
	}
	slots = append(slots, acpSlots...)
	if config.Browser != nil && (config.Browser.Enabled == nil || *config.Browser.Enabled) {
		metadata := map[string]string{"coverage": "dynamic-browser-targets"}
		if config.Browser.DefaultProfile != "" {
			if !safeHermesName(config.Browser.DefaultProfile) {
				return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "browser profile name is unsafe")
			}
			metadata["default_profile"] = config.Browser.DefaultProfile
		}
		if len(config.Browser.Profiles) != 0 {
			metadata["profile_count"] = fmt.Sprintf("%d", len(config.Browser.Profiles))
		}
		slots = append(slots, Slot{ID: "browser", Name: "Browser automation", Type: domain.SurfaceBrowser, Protocol: domain.ProtocolUnknown, Auth: openClawAuth(), Metadata: metadata, Rewritable: false})
	}
	if _, configured := config.Tools["web"]; configured {
		slots = append(slots, Slot{ID: "tool-web", Name: "Web tools", Type: domain.SurfaceToolHTTP, Protocol: domain.ProtocolUnknown, Auth: openClawAuth(), Metadata: map[string]string{"coverage": "dynamic-tool-targets"}, Rewritable: false})
	}
	return slots, nil
}

func openClawMCPSlots(servers map[string]openClawMCPServer) ([]Slot, error) {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	slots := make([]Slot, 0, len(names))
	for _, name := range names {
		if !safeHermesName(name) {
			return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "MCP server name is unsafe")
		}
		server := servers[name]
		command, endpoint := strings.TrimSpace(server.Command), strings.TrimSpace(server.URL)
		if command != "" && endpoint != "" {
			return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "MCP transport is ambiguous")
		}
		id := "mcp-" + strings.ReplaceAll(name, "_", "-")
		if command != "" {
			slots = append(slots, Slot{ID: id, Name: "Local MCP " + name, Type: domain.SurfaceMCPStdio, Protocol: domain.ProtocolLocalStdio, Auth: openClawAuth(), Metadata: map[string]string{"process_egress": "not-inspected"}, Rewritable: false})
			continue
		}
		protocolType := domain.ProtocolMCPStreamable
		if strings.EqualFold(strings.TrimSpace(server.Transport), "sse") {
			protocolType = domain.ProtocolMCPHTTP
		}
		if endpoint == "" || strings.Contains(endpoint, "${") {
			endpoint, protocolType = "", domain.ProtocolUnknown
		}
		slots = append(slots, Slot{ID: id, Name: "Remote MCP " + name, Type: domain.SurfaceMCPHTTP, Protocol: protocolType, BaseURL: endpoint, Auth: openClawAuth(), Rewritable: false})
	}
	return slots, nil
}

func openClawGlobalACPSlots(enabled *bool, defaultAgent string, allowedAgents []string) ([]Slot, error) {
	if enabled == nil || !*enabled {
		return nil, nil
	}
	agents := append([]string(nil), allowedAgents...)
	if len(agents) == 0 && strings.TrimSpace(defaultAgent) != "" {
		agents = append(agents, defaultAgent)
	}
	if len(agents) == 0 {
		return []Slot{openClawACPSlot("acp-runtime", "ACP runtime", "", "")}, nil
	}
	sort.Strings(agents)
	var slots []Slot
	seen := map[string]struct{}{}
	for _, agent := range agents {
		agent = strings.TrimSpace(agent)
		if !safeHermesName(agent) {
			return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "ACP agent identifier is unsafe")
		}
		if _, exists := seen[agent]; exists {
			continue
		}
		seen[agent] = struct{}{}
		slots = append(slots, openClawACPSlot("acp-"+strings.ReplaceAll(agent, "_", "-"), "ACP harness "+agent, agent, ""))
	}
	return slots, nil
}

func openClawACPSlot(id, name, agent, backend string) Slot {
	metadata := map[string]string{}
	if agent != "" {
		metadata["agent"] = agent
	}
	if backend != "" {
		metadata["backend"] = backend
	}
	return Slot{ID: id, Name: name, Type: domain.SurfaceACP, Protocol: domain.ProtocolUnknown, Auth: openClawAuth(), Metadata: metadata, Rewritable: false}
}

func openClawOptionalChoiceSlots(id, name string, surfaceType domain.SurfaceType, choice *openClawModelChoice, providers map[string]openClawProvider) []Slot {
	if choice == nil || !configuredOpenClawChoice(*choice) {
		return nil
	}
	return openClawChoiceSlots(id, name, surfaceType, *choice, providers, false)
}

func openClawChoiceSlots(id, name string, surfaceType domain.SurfaceType, choice openClawModelChoice, providers map[string]openClawProvider, required bool) []Slot {
	slots := []Slot{openClawSlot(id, name, surfaceType, choice.Primary, providers, required)}
	for index, fallback := range choice.Fallbacks {
		slots = append(slots, openClawSlot(fmt.Sprintf("%s-fallback-%d", id, index+1), fmt.Sprintf("%s fallback %d", name, index+1), domain.SurfaceModelFallback, fallback, providers, false))
	}
	return slots
}

func openClawSlot(id, name string, surfaceType domain.SurfaceType, modelRef string, providers map[string]openClawProvider, required bool) Slot {
	modelRef = strings.TrimSpace(modelRef)
	providerID := modelRef
	if separator := strings.IndexByte(modelRef, '/'); separator >= 0 {
		providerID = modelRef[:separator]
	}
	provider := providers[strings.ToLower(providerID)]
	baseURL := strings.TrimSpace(provider.BaseURL)
	protocolType := openClawProtocol(provider.API)
	if strings.Contains(baseURL, "${") {
		baseURL, protocolType = "", domain.ProtocolUnknown
	}
	metadata := map[string]string{}
	if modelRef != "" {
		metadata["model_ref"] = modelRef
	}
	if providerID != "" {
		metadata["provider"] = strings.ToLower(providerID)
	}
	return Slot{ID: id, Name: name, Type: surfaceType, Protocol: protocolType, BaseURL: baseURL, Auth: openClawAuth(), Metadata: metadata, Rewritable: false, Required: required}
}

func openClawAuth() domain.AuthStrategy {
	return domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:openclaw-provider"}
}

func safeOptionalOpenClawName(value string) bool {
	return strings.TrimSpace(value) == "" || safeHermesName(strings.TrimSpace(value))
}

func openClawProtocol(value string) domain.Protocol {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "openai-completions", "openai-chat":
		return domain.ProtocolOpenAIChat
	case "openai-responses":
		return domain.ProtocolOpenAIResponses
	case "anthropic-messages":
		return domain.ProtocolAnthropic
	case "google-generative-ai", "google-gemini":
		return domain.ProtocolGemini
	default:
		return domain.ProtocolUnknown
	}
}

func configuredOpenClawChoice(choice openClawModelChoice) bool {
	return strings.TrimSpace(choice.Primary) != "" || len(choice.Fallbacks) != 0
}

func hasYAMLAlias(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return true
	}
	for _, child := range node.Content {
		if hasYAMLAlias(child) {
			return true
		}
	}
	return false
}

func stripJSON5Comments(content []byte) ([]byte, error) {
	cleaned := append([]byte(nil), content...)
	var quote byte
	escaped := false
	for index := 0; index < len(cleaned); index++ {
		character := cleaned[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
			} else if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character != '/' || index+1 >= len(cleaned) {
			continue
		}
		switch cleaned[index+1] {
		case '/':
			for index < len(cleaned) && cleaned[index] != '\n' {
				cleaned[index] = ' '
				index++
			}
		case '*':
			cleaned[index], cleaned[index+1] = ' ', ' '
			index += 2
			closed := false
			for index < len(cleaned) {
				if index+1 < len(cleaned) && cleaned[index] == '*' && cleaned[index+1] == '/' {
					cleaned[index], cleaned[index+1] = ' ', ' '
					index++
					closed = true
					break
				}
				if cleaned[index] != '\n' && cleaned[index] != '\r' {
					cleaned[index] = ' '
				}
				index++
			}
			if !closed {
				return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "configuration has an unterminated comment")
			}
		}
	}
	if quote != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "parse openclaw config", "configuration has an unterminated string")
	}
	return cleaned, nil
}
