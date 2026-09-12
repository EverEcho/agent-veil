package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

const zedConfigFixture = `{
  "language_models": {
    "openai_compatible": {
      "corp gateway": {
        "api_url": "https://models.example/v1",
        "custom_headers": { "Authorization": "Bearer model-secret" },
        "available_models": [
          { "name": "chat-model" },
          { "name": "response-model", "capabilities": { "chat_completions": false } }
        ]
      }
    },
    "anthropic_compatible": {
      "Claude proxy": { "api_url": "https://claude.example", "available_models": [{ "name": "sonnet" }] }
    },
    "opencode": {
      "available_models": [{ "name": "custom-go", "protocol": "google", "custom_model_api_url": "https://google.example" }]
    }
  },
  "context_servers": {
    "filesystem": { "command": "server", "args": ["--stdio"], "env": { "TOKEN": "mcp-secret" } },
    "research": { "url": "https://mcp.example/mcp", "headers": { "Authorization": "Bearer mcp-secret" } },
    "off": { "enabled": false, "url": "https://off.example/mcp" }
  },
  "agent_servers": {
    "Codex": { "type": "custom", "command": "codex-acp", "args": ["--serve"], "env": { "API_KEY": "agent-secret" } }
  }
}`

func TestParseZedConfigEnumeratesExplicitSurfacesWithoutCredentials(t *testing.T) {
	slots, localMCP, err := ParseZedConfig([]byte(zedConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 6 || len(localMCP) != 1 || localMCP[0] != "filesystem" {
		t.Fatalf("slots=%+v local=%+v", slots, localMCP)
	}
	protocols := map[domain.Protocol]int{}
	types := map[domain.SurfaceType]int{}
	for _, slot := range slots {
		protocols[slot.Protocol]++
		types[slot.Type]++
		if slot.Rewritable || !slot.Required {
			t.Fatalf("Zed discovery slot overstated: %+v", slot)
		}
	}
	if protocols[domain.ProtocolOpenAIChat] != 1 || protocols[domain.ProtocolOpenAIResponses] != 1 || protocols[domain.ProtocolAnthropic] != 1 || protocols[domain.ProtocolGemini] != 1 || protocols[domain.ProtocolMCPStreamable] != 1 || types[domain.SurfaceACP] != 1 {
		t.Fatalf("protocols=%+v types=%+v", protocols, types)
	}
	encoded, err := json.Marshal(struct {
		Slots []Slot
		Local []string
	}{slots, localMCP})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"model-secret", "mcp-secret", "agent-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("credential %q retained: %s", secret, encoded)
		}
	}
}

func TestParseZedConfigLeavesSubstitutedTargetsUnknown(t *testing.T) {
	slots, _, err := ParseZedConfig([]byte(`{
  "language_models": { "openai_compatible": { "corp": { "api_url": "${MODEL_URL}" } } },
  "context_servers": { "remote": { "url": "{env:MCP_URL}" } }
}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range slots {
		if slot.Protocol != domain.ProtocolUnknown || slot.BaseURL != "" {
			t.Fatalf("substituted target was guessed: %+v", slot)
		}
	}
}

func TestParseZedConfigRejectsUnsafeOrAmbiguousSurfaces(t *testing.T) {
	for _, content := range []string{
		`{"context_servers":{"bad":{"command":"server","url":"https://mcp.example"}}}`,
		`{"context_servers":{"bad":{"enabled":true}}}`,
		`{"agent_servers":{"bad":{"type":"custom"}}}`,
		"{\"language_models\":{\"openai_compatible\":{\"bad\\nname\":{\"api_url\":\"https://models.example\"}}}}",
	} {
		if _, _, err := ParseZedConfig([]byte(content)); err == nil {
			t.Fatalf("accepted unsafe config: %q", content)
		}
	}
}
