package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/integration"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const defaultCodexAPIBaseURL = "https://api.openai.com/v1"
const defaultCodexChatGPTBaseURL = "https://chatgpt.com/backend-api/codex"
const codexMCPInventoryTimeout = 3 * time.Second

type codexMCPInventorySystem interface {
	CodexMCPList(context.Context, string) ([]byte, error)
}

type codexMCPEntry struct {
	Name      string `json:"name"`
	Enabled   *bool  `json:"enabled"`
	Transport struct {
		Type    string `json:"type"`
		URL     string `json:"url"`
		Command string `json:"command"`
	} `json:"transport"`
}

type codexProviderConfig struct {
	baseURL     string
	wireAPI     string
	envKey      string
	unsupported bool
}

type codexUserConfig struct {
	modelProvider  string
	openAIBaseURL  string
	chatGPTBaseURL string
	providers      map[string]codexProviderConfig
}

func inspectCodex(ctx context.Context, system System, executable, codexHome, configPath string) ([]integration.Slot, error) {
	parsed := codexUserConfig{providers: make(map[string]codexProviderConfig)}
	content, readErr := system.ReadFile(configPath)
	if readErr == nil {
		var err error
		parsed, err = parseCodexConfig(content)
		if err != nil {
			return nil, domain.NewError(domain.ErrInvalidContract, "discover codex", "configuration could not be parsed safely")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, domain.NewError(domain.ErrInvalidContract, "discover codex", "configuration could not be inspected")
	}

	selected := parsed.modelProvider
	if selected == "" {
		selected = "openai"
	}
	provider, configured := parsed.providers[selected]
	if selected != "openai" && !configured {
		return []integration.Slot{codexUnknownSlot("selected-provider", "selected model provider is not defined in the inspected user configuration")}, nil
	}
	if provider.wireAPI != "" && provider.wireAPI != "responses" {
		return []integration.Slot{codexUnknownSlot("selected-provider-wire-api", "selected model provider does not use the verified Responses protocol")}, nil
	}
	limitation := ""
	if provider.baseURL == "" {
		if selected != "openai" {
			return []integration.Slot{codexUnknownSlot("selected-provider-upstream", "selected custom model provider has no explicit base URL")}, nil
		}
		provider.baseURL, limitation = codexDefaultBaseURL(system, codexHome, parsed)
	} else if selected == "openai" && strings.TrimRight(provider.baseURL, "/") != strings.TrimRight(defaultCodexAPIBaseURL, "/") {
		limitation = "selected OpenAI provider overrides the version-verified default upstream"
	}

	auth := domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:codex-login-or-environment"}
	if provider.envKey != "" {
		auth = domain.AuthStrategy{Type: domain.AuthBearer, Source: "environment:" + provider.envKey}
		if value, ok := system.LookupEnv(provider.envKey); !ok || strings.TrimSpace(value) == "" {
			limitation = "selected provider credential environment variable is unavailable"
		}
	}
	rewritable := selected == "openai" && !provider.unsupported && limitation == ""
	metadata := map[string]string{"provider": selected}
	if selected != "openai" {
		rewritable = false
		metadata["reason"] = "custom model provider requires a versioned launch adapter"
	} else if provider.unsupported {
		metadata["reason"] = "provider query, header, dynamic discovery, or signer settings cannot yet be preserved"
	} else if limitation != "" {
		metadata["reason"] = limitation
	}
	slots := []integration.Slot{{
		ID: "primary", Name: "Primary model", Type: domain.SurfaceModelPrimary,
		Protocol: domain.ProtocolOpenAIResponses, BaseURL: provider.baseURL, Auth: auth,
		Network: environmentProxyRoute(system), Rewritable: rewritable, Required: true,
		Metadata: metadata,
	}}
	mcpSlots := inspectCodexMCP(ctx, system, executable)
	return append(slots, mcpSlots...), nil
}

func inspectCodexMCP(ctx context.Context, system System, executable string) []integration.Slot {
	inventory, ok := system.(codexMCPInventorySystem)
	if !ok {
		return []integration.Slot{codexUnknownSlot("mcp-inventory", "effective Codex MCP inventory could not be verified")}
	}
	payload, err := inventory.CodexMCPList(ctx, executable)
	if err != nil || jsonsafe.Validate(payload) != nil {
		return []integration.Slot{codexUnknownSlot("mcp-inventory", "effective Codex MCP inventory could not be verified")}
	}
	var entries []codexMCPEntry
	if json.Unmarshal(payload, &entries) != nil || len(entries) > 256 {
		return []integration.Slot{codexUnknownSlot("mcp-inventory", "effective Codex MCP inventory is invalid or exceeds its limit")}
	}
	seen := make(map[string]struct{}, len(entries))
	result := make([]integration.Slot, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" || len(name) > 256 || entry.Enabled == nil {
			return []integration.Slot{codexUnknownSlot("mcp-inventory", "effective Codex MCP inventory contains an invalid entry")}
		}
		if _, duplicate := seen[name]; duplicate {
			return []integration.Slot{codexUnknownSlot("mcp-inventory", "effective Codex MCP inventory contains duplicate entries")}
		}
		seen[name] = struct{}{}
		if !*entry.Enabled {
			continue
		}
		id := fmt.Sprintf("mcp-%x", sha256.Sum256([]byte(name)))[:20]
		switch entry.Transport.Type {
		case "stdio":
			if strings.TrimSpace(entry.Transport.Command) == "" {
				return []integration.Slot{codexUnknownSlot(id, "enabled Codex stdio MCP server has no executable command")}
			}
			result = append(result, integration.Slot{ID: id, Name: "Local MCP " + name, Type: domain.SurfaceMCPStdio, Protocol: domain.ProtocolLocalStdio, Required: true, Metadata: map[string]string{"reason": "stdio is local IPC; descendant process network egress is outside the model route"}})
		case "streamable_http", "http":
			endpoint, parseErr := url.Parse(entry.Transport.URL)
			if parseErr != nil || endpoint.User != nil || endpoint.Hostname() == "" || endpoint.Fragment != "" || endpoint.RawQuery != "" || endpoint.Scheme != "https" && endpoint.Scheme != "http" {
				return []integration.Slot{codexUnknownSlot(id, "enabled Codex HTTP MCP endpoint could not be represented safely")}
			}
			result = append(result, integration.Slot{ID: id, Name: "Remote MCP " + name, Type: domain.SurfaceMCPHTTP, Protocol: domain.ProtocolMCPStreamable, BaseURL: entry.Transport.URL, Auth: domain.AuthStrategy{Type: domain.AuthPassthrough}, Rewritable: false, Required: true, Metadata: map[string]string{"reason": "Codex remote MCP launch rewriting is not implemented"}})
		default:
			result = append(result, codexUnknownSlot(id, "enabled Codex MCP server uses an unrecognized transport"))
		}
	}
	return result
}

func (OSSystem) CodexMCPList(ctx context.Context, executable string) ([]byte, error) {
	if ctx == nil || !filepath.IsAbs(executable) {
		return nil, domain.NewError(domain.ErrInvalidContract, "inventory codex MCP", "context and absolute executable are required")
	}
	bounded, cancel := context.WithTimeout(ctx, codexMCPInventoryTimeout)
	defer cancel()
	output := &boundedVersionOutput{limit: maxAgentConfigBytes}
	command := exec.CommandContext(bounded, executable, "mcp", "list", "--json")
	configureVersionCommand(command)
	command.Stdout = output
	command.Stderr = io.Discard
	err := command.Run()
	cleanupVersionCommand(command)
	if output.Exceeded() {
		return nil, domain.NewError(domain.ErrInvalidContract, "inventory codex MCP", "MCP inventory exceeds its size limit")
	}
	if bounded.Err() != nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "inventory codex MCP", "MCP inventory command timed out or was cancelled")
	}
	if err != nil {
		return nil, err
	}
	return []byte(output.String()), nil
}

func codexDefaultBaseURL(system System, codexHome string, config codexUserConfig) (string, string) {
	if value, ok := system.LookupEnv("OPENAI_BASE_URL"); ok && strings.TrimSpace(value) != "" {
		return value, "OPENAI_BASE_URL overrides the version-verified default upstream"
	}
	if config.openAIBaseURL != "" {
		return config.openAIBaseURL, "openai_base_url overrides the version-verified default upstream"
	}
	if value, ok := system.LookupEnv("OPENAI_API_KEY"); ok && strings.TrimSpace(value) != "" {
		return defaultCodexAPIBaseURL, ""
	}
	content, err := system.ReadFile(filepath.Join(codexHome, "auth.json"))
	if err != nil || jsonsafe.Validate(content) != nil {
		return defaultCodexAPIBaseURL, "Codex authentication mode could not be verified"
	}
	var auth struct {
		Mode         string `json:"auth_mode"`
		OpenAIAPIKey string `json:"OPENAI_API_KEY"`
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if decoder.Decode(&auth) != nil {
		return defaultCodexAPIBaseURL, "Codex authentication mode could not be verified"
	}
	if auth.Mode == "apikey" || auth.Mode == "api_key" || strings.TrimSpace(auth.OpenAIAPIKey) != "" {
		return defaultCodexAPIBaseURL, ""
	}
	if auth.Mode != "chatgpt" {
		return defaultCodexAPIBaseURL, "Codex authentication mode could not be verified"
	}
	if config.chatGPTBaseURL != "" {
		return config.chatGPTBaseURL, "ChatGPT login and custom ChatGPT upstream takeover are not version-verified"
	}
	return defaultCodexChatGPTBaseURL, ""
}

func codexUnknownSlot(id, reason string) integration.Slot {
	return integration.Slot{ID: id, Name: "Unresolved Codex egress", Type: domain.SurfaceUnknown, Protocol: domain.ProtocolUnknown, Required: true, Metadata: map[string]string{"reason": reason}}
}

func parseCodexConfig(content []byte) (codexUserConfig, error) {
	result := codexUserConfig{providers: make(map[string]codexProviderConfig)}
	section := ""
	seen := make(map[string]struct{})
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(stripTOMLComment(rawLine))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return codexUserConfig{}, errors.New("unsupported TOML table syntax")
			}
			if strings.HasPrefix(line, "[[") {
				section = "__uninspected_array_table__"
				continue
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(rawValue)
		providerID, providerField, providerOK := codexProviderField(section, key)
		fieldID := section + "\x00" + key
		if _, duplicate := seen[fieldID]; duplicate {
			return codexUserConfig{}, errors.New("duplicate inspected TOML field")
		}
		seen[fieldID] = struct{}{}
		if section == "" {
			value, ok := parseTOMLString(rawValue)
			switch key {
			case "model_provider":
				if !ok || value == "" {
					return codexUserConfig{}, errors.New("invalid model_provider")
				}
				result.modelProvider = value
			case "openai_base_url":
				if !ok {
					return codexUserConfig{}, errors.New("invalid openai_base_url")
				}
				result.openAIBaseURL = value
			case "chatgpt_base_url":
				if !ok {
					return codexUserConfig{}, errors.New("invalid chatgpt_base_url")
				}
				result.chatGPTBaseURL = value
			}
			continue
		}
		if !providerOK {
			continue
		}
		provider := result.providers[providerID]
		switch providerField {
		case "base_url", "wire_api", "env_key":
			value, ok := parseTOMLString(rawValue)
			if !ok {
				return codexUserConfig{}, errors.New("invalid provider string")
			}
			switch providerField {
			case "base_url":
				provider.baseURL = value
			case "wire_api":
				provider.wireAPI = value
			case "env_key":
				if !validEnvironmentName(value) {
					return codexUserConfig{}, errors.New("invalid provider environment key")
				}
				provider.envKey = value
			}
		case "requires_openai_auth":
			if _, err := strconv.ParseBool(rawValue); err != nil {
				return codexUserConfig{}, errors.New("invalid provider auth flag")
			}
		case "query_params", "http_headers", "env_http_headers", "experimental_bearer_token", "auth", "aws", "discovery_url":
			provider.unsupported = true
		}
		result.providers[providerID] = provider
	}
	return result, nil
}

func codexProviderField(section, key string) (string, string, bool) {
	const prefix = "model_providers."
	if !strings.HasPrefix(section, prefix) {
		return "", "", false
	}
	provider := strings.TrimSpace(strings.TrimPrefix(section, prefix))
	if unquoted, ok := parseTOMLString(provider); ok {
		provider = unquoted
	}
	if provider == "" || strings.Contains(provider, ".") {
		return "", "", false
	}
	return provider, key, true
}

func parseTOMLString(value string) (string, bool) {
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1], !strings.ContainsRune(value[1:len(value)-1], '\n')
	}
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	decoded, err := strconv.Unquote(value)
	return decoded, err == nil
}

func stripTOMLComment(line string) string {
	quote := byte(0)
	escaped := false
	for index := 0; index < len(line); index++ {
		character := line[index]
		if quote == '"' && character == '\\' && !escaped {
			escaped = true
			continue
		}
		if (character == '"' || character == '\'') && !escaped {
			if quote == 0 {
				quote = character
			} else if quote == character {
				quote = 0
			}
		}
		if character == '#' && quote == 0 {
			return line[:index]
		}
		escaped = false
	}
	return line
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character == '_' || character >= 'A' && character <= 'Z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
