package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestParseCursorMCPEnumeratesStaticRoutesWithoutCredentials(t *testing.T) {
	slots, local, err := ParseCursorMCP([]byte(`{
  "mcpServers": {
    "local server": { "command": "server", "args": ["--stdio"], "env": { "TOKEN": "mcp-secret" } },
    "modern": { "type": "streamableHttp", "url": "https://modern.example/mcp", "headers": { "Authorization": "mcp-secret" } },
    "legacy": { "type": "sse", "url": "https://legacy.example/sse" },
    "unspecified": { "url": "https://unknown.example/mcp" },
    "off": { "disabled": true, "url": "https://off.example/mcp" }
  }
}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 3 || len(local) != 1 || local[0] != "local server" {
		t.Fatalf("slots=%+v local=%+v", slots, local)
	}
	protocols := map[domain.Protocol]int{}
	for _, slot := range slots {
		protocols[slot.Protocol]++
		if slot.Rewritable || !slot.Required {
			t.Fatalf("Cursor discovery slot overstated: %+v", slot)
		}
	}
	if protocols[domain.ProtocolMCPStreamable] != 1 || protocols[domain.ProtocolMCPHTTP] != 1 || protocols[domain.ProtocolUnknown] != 1 {
		t.Fatalf("protocols=%+v", protocols)
	}
	encoded, _ := json.Marshal(slots)
	if strings.Contains(string(encoded), "mcp-secret") {
		t.Fatalf("credential retained: %s", encoded)
	}
}

func TestParseCursorMCPRejectsAmbiguousOrUnsafeShapes(t *testing.T) {
	for _, content := range []string{
		`{"mcpServers":{"both":{"command":"server","url":"https://mcp.example"}}}`,
		`{"mcpServers":{"missing":{}}}`,
		"{\"mcpServers\":{\"bad\\nname\":{\"command\":\"server\"}}}",
	} {
		if _, _, err := ParseCursorMCP([]byte(content)); err == nil {
			t.Fatalf("accepted unsafe config: %q", content)
		}
	}
}
