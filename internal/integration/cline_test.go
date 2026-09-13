package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestParseClineProvidersEnumeratesRoutesWithoutCredentials(t *testing.T) {
	slots, err := ParseClineProviders([]byte(`{
  "version": 1,
  "providers": {
    "corp": { "settings": { "provider": "openai", "model": "main", "baseUrl": "https://models.example/v1", "apiKey": "model-secret" }, "tokenSource": "manual" },
    "responses": { "settings": { "provider": "custom", "model": "reasoner", "baseUrl": "https://responses.example/v1", "protocol": "openai-responses", "headers": { "Authorization": "model-secret" } } },
    "anthropic": { "settings": { "provider": "anthropic", "model": "sonnet", "apiKey": "model-secret" } }
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 3 {
		t.Fatalf("slots=%+v", slots)
	}
	protocols := map[domain.Protocol]int{}
	for _, slot := range slots {
		protocols[slot.Protocol]++
		if slot.Rewritable || !slot.Required {
			t.Fatalf("provider surface overstated: %+v", slot)
		}
	}
	if protocols[domain.ProtocolOpenAIChat] != 1 || protocols[domain.ProtocolOpenAIResponses] != 1 || protocols[domain.ProtocolAnthropic] != 1 {
		t.Fatalf("protocols=%+v", protocols)
	}
	encoded, _ := json.Marshal(slots)
	if strings.Contains(string(encoded), "model-secret") {
		t.Fatalf("credential retained: %s", encoded)
	}
}

func TestParseClineMCPHandlesStreamableLegacyAndLocal(t *testing.T) {
	slots, local, err := ParseClineMCP([]byte(`{
  "mcpServers": {
    "local": { "command": "server", "args": ["--stdio"], "env": { "TOKEN": "mcp-secret" } },
    "modern": { "type": "streamableHttp", "url": "https://modern.example/mcp", "headers": { "Authorization": "mcp-secret" } },
    "legacy": { "url": "https://legacy.example/sse" },
    "off": { "disabled": true, "url": "https://off.example/mcp" }
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 2 || len(local) != 1 || local[0] != "local" {
		t.Fatalf("slots=%+v local=%+v", slots, local)
	}
	protocols := map[domain.Protocol]int{}
	for _, slot := range slots {
		protocols[slot.Protocol]++
	}
	if protocols[domain.ProtocolMCPStreamable] != 1 || protocols[domain.ProtocolMCPLegacySSE] != 1 {
		t.Fatalf("protocols=%+v", protocols)
	}
	encoded, _ := json.Marshal(slots)
	if strings.Contains(string(encoded), "mcp-secret") {
		t.Fatalf("credential retained: %s", encoded)
	}
}

func TestParseClineConfigRejectsAmbiguousOrUnsafeShapes(t *testing.T) {
	for _, content := range []string{
		`{"mcpServers":{"both":{"command":"server","url":"https://mcp.example"}}}`,
		`{"mcpServers":{"missing":{}}}`,
		`{"mcpServers":{"bad":{"type":"websocket","url":"https://mcp.example"}}}`,
	} {
		if _, _, err := ParseClineMCP([]byte(content)); err == nil {
			t.Fatalf("accepted unsafe MCP config: %s", content)
		}
	}
	if _, err := ParseClineProviders([]byte("{\"providers\":{\"bad\\nname\":{\"settings\":{}}}}")); err == nil {
		t.Fatal("accepted unsafe provider name")
	}
}
