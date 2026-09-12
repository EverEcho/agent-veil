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

type openClawConfig struct {
	Agents struct {
		Defaults openClawDefaults         `yaml:"defaults"`
		Entries  map[string]openClawAgent `yaml:"entries"`
		List     []openClawAgent          `yaml:"list"`
	} `yaml:"agents"`
	Models struct {
		Providers map[string]openClawProvider `yaml:"providers"`
	} `yaml:"models"`
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
	}
	return slots, nil
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
	return Slot{ID: id, Name: name, Type: surfaceType, Protocol: protocolType, BaseURL: baseURL, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:openclaw-provider"}, Metadata: metadata, Rewritable: false, Required: required}
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
