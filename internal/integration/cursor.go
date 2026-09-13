package integration

import (
	"sort"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"gopkg.in/yaml.v3"
)

const maxCursorConfigBytes = 1 << 20

type cursorMCPServer struct {
	Type     string   `yaml:"type"`
	Command  string   `yaml:"command"`
	Args     []string `yaml:"args"`
	URL      string   `yaml:"url"`
	Disabled bool     `yaml:"disabled"`
}

type cursorMCPDocument struct {
	Servers map[string]cursorMCPServer `yaml:"mcpServers"`
}

// ParseCursorMCP enumerates static MCP routes without decoding environment or
// header credentials. URL-only entries remain protocol-unknown because Cursor
// documents that a URL can represent either SSE or Streamable HTTP.
func ParseCursorMCP(content []byte) ([]Slot, []string, error) {
	var document cursorMCPDocument
	if err := parseCursorJSON(content, &document); err != nil {
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
			return nil, nil, cursorConfigError("MCP server name is unsafe")
		}
		command, endpoint := strings.TrimSpace(server.Command), strings.TrimSpace(server.URL)
		if command != "" && endpoint != "" {
			return nil, nil, cursorConfigError("MCP transport is ambiguous")
		}
		if command != "" {
			if containsControl(command) || !validOptionalZedArguments(server.Args) {
				return nil, nil, cursorConfigError("MCP command is invalid")
			}
			local = append(local, name)
			continue
		}
		if endpoint == "" {
			return nil, nil, cursorConfigError("MCP endpoint is required")
		}
		protocolType := cursorMCPProtocol(server.Type)
		if unresolvedZedValue(endpoint) {
			endpoint, protocolType = "", domain.ProtocolUnknown
		}
		slots = append(slots, Slot{ID: stableZedID("mcp", "cursor\x00"+name), Name: "Remote MCP " + name, Type: domain.SurfaceMCPHTTP, Protocol: protocolType, BaseURL: endpoint, Auth: cursorAuth(), Rewritable: false, Required: true})
	}
	return slots, local, nil
}

func parseCursorJSON(content []byte, destination any) error {
	if len(content) == 0 || len(content) > maxCursorConfigBytes {
		return cursorConfigError("configuration is empty or too large")
	}
	cleaned, err := validateJSONC(content)
	if err != nil {
		return cursorConfigError("configuration is invalid JSON")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(cleaned, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || hasYAMLAlias(document.Content[0]) {
		return cursorConfigError("configuration is invalid JSON")
	}
	if err := document.Content[0].Decode(destination); err != nil {
		return cursorConfigError("configuration has an invalid shape")
	}
	return nil
}

func cursorMCPProtocol(value string) domain.Protocol {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "streamablehttp", "streamable-http", "http":
		return domain.ProtocolMCPStreamable
	case "sse":
		return domain.ProtocolMCPLegacySSE
	default:
		return domain.ProtocolUnknown
	}
}

func cursorAuth() domain.AuthStrategy {
	return domain.AuthStrategy{Type: domain.AuthPassthrough, Source: "agent:cursor-mcp-credentials"}
}

func cursorConfigError(message string) error {
	return domain.NewError(domain.ErrInvalidContract, "parse cursor config", message)
}
