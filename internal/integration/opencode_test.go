package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

const openCodeConfigFixture = `{
  // Model routes use provider/model references.
  "model": "corp/main",
  "small_model": "anthropic/claude-haiku",
  "provider": {
    "corp": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "https://models.example/v1", "apiKey": "model-secret" }
    }
  },
  "mcp": {
    "filesystem": { "type": "local", "command": ["npx", "-y", "server"] },
    "research": { "type": "remote", "url": "https://mcp.example/rpc", "headers": { "Authorization": "Bearer mcp-secret" } },
    "disabled": { "type": "remote", "url": "https://disabled.example/rpc", "enabled": false }
  }
}`

func TestParseOpenCodeConfigEnumeratesDocumentedSurfacesWithoutSecrets(t *testing.T) {
	slots, localMCP, err := ParseOpenCodeConfig([]byte(openCodeConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 3 || len(localMCP) != 1 || localMCP[0] != "filesystem" {
		t.Fatalf("slots=%+v local=%+v", slots, localMCP)
	}
	byID := make(map[string]Slot, len(slots))
	for _, slot := range slots {
		byID[slot.ID] = slot
		if slot.Rewritable {
			t.Fatalf("discovery-only slot was rewritable: %+v", slot)
		}
	}
	if byID["primary"].Protocol != domain.ProtocolOpenAIChat || byID["primary"].BaseURL != "https://models.example/v1" || !byID["primary"].Required {
		t.Fatalf("primary=%+v", byID["primary"])
	}
	if byID["small"].Protocol != domain.ProtocolAnthropic || byID["small"].BaseURL != "https://api.anthropic.com" {
		t.Fatalf("small=%+v", byID["small"])
	}
	if byID["mcp-research"].Protocol != domain.ProtocolMCPStreamable {
		t.Fatalf("remote MCP=%+v", byID["mcp-research"])
	}
	encoded, err := json.Marshal(struct {
		Slots []Slot
		Local []string
	}{slots, localMCP})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "model-secret") || strings.Contains(string(encoded), "mcp-secret") {
		t.Fatalf("credentials retained: %s", encoded)
	}
}

func TestParseOpenCodeConfigLeavesSubstitutedTargetsUnknown(t *testing.T) {
	slots, _, err := ParseOpenCodeConfig([]byte(`{
  "model": "corp/main",
  "provider": { "corp": { "npm": "@ai-sdk/openai-compatible", "options": { "baseURL": "{env:MODEL_URL}" } } },
  "mcp": { "remote": { "type": "remote", "url": "{file:./mcp-url}" } }
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

func TestParseOpenCodeConfigRejectsUnsafeOrAmbiguousShapes(t *testing.T) {
	for _, content := range []string{
		`{"model":"missing-separator"}`,
		`{"model":"bad provider/model"}`,
		`{"mcp":{"bad/name":{"type":"local","command":["server"]}}}`,
		`{"mcp":{"both":{"type":"remote","url":"https://mcp.example","command":["server"]}}}`,
		`{"mcp":{"missing":{"type":"remote"}}}`,
		`{"mcp":{"mystery":{"type":"other","url":"https://mcp.example"}}}`,
	} {
		if _, _, err := ParseOpenCodeConfig([]byte(content)); err == nil {
			t.Fatalf("accepted unsafe config: %s", content)
		}
	}
}
