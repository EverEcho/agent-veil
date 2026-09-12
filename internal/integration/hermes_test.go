package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

const hermesConfigFixture = `
_config_version: 39
model:
  provider: custom
  model: primary-model
  base_url: https://primary.example/gateway/v1
  api_mode: chat_completions
providers:
  corp:
    api: https://anthropic.example/service
    transport: anthropic_messages
    api_key: must-never-enter-the-manifest
fallback_providers:
  - provider: corp
    model: fallback-model
auxiliary:
  vision:
    provider: main
    model: vision-model
  compression:
    provider: corp
    model: compression-model
    fallback_chain:
      - provider: custom
        model: local-summary
        base_url: http://127.0.0.1:8080/v1
delegation:
  provider: corp
  model: worker-model
  fallback_providers:
    - provider: custom
      model: local-worker
      base_url: http://127.0.0.1:8081/v1
mcp_servers:
  filesystem:
    command: npx
  research:
    url: https://mcp.example/rpc
    transport: sse
    headers:
      Authorization: Bearer must-never-enter-the-manifest
  disabled:
    url: https://disabled.example/mcp
    enabled: false
`

func TestHermesConfigEnumeratesEveryIndependentSurface(t *testing.T) {
	slots, localMCP, err := ParseHermesConfig([]byte(hermesConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 8 || len(localMCP) != 1 || localMCP[0] != "filesystem" {
		t.Fatalf("slots=%+v local=%+v", slots, localMCP)
	}
	byID := map[string]Slot{}
	for _, slot := range slots {
		if _, exists := byID[slot.ID]; exists {
			t.Fatalf("duplicate slot id %q", slot.ID)
		}
		byID[slot.ID] = slot
		if slot.Rewritable {
			t.Fatalf("discovery-only slot claimed rewritable coverage: %+v", slot)
		}
	}
	if byID["primary"].Protocol != domain.ProtocolOpenAIChat || byID["primary"].BaseURL != "https://primary.example/gateway/v1" || !byID["primary"].Required {
		t.Fatalf("primary=%+v", byID["primary"])
	}
	if byID["aux-vision"].Type != domain.SurfaceVision || byID["aux-vision"].BaseURL != byID["primary"].BaseURL {
		t.Fatalf("vision did not explicitly inherit main route: %+v", byID["aux-vision"])
	}
	if byID["fallback-1"].Protocol != domain.ProtocolAnthropic || byID["delegation"].Type != domain.SurfaceSubAgent {
		t.Fatalf("fallback/delegation missing: fallback=%+v delegation=%+v", byID["fallback-1"], byID["delegation"])
	}
	if byID["mcp-research"].Protocol != domain.ProtocolMCPHTTP || byID["mcp-research"].Type != domain.SurfaceMCPHTTP {
		t.Fatalf("remote MCP=%+v", byID["mcp-research"])
	}
	encoded, _ := json.Marshal(struct {
		Slots []Slot
		Local []string
	}{slots, localMCP})
	if strings.Contains(string(encoded), "must-never-enter") {
		t.Fatalf("credential leaked from parsed config: %s", encoded)
	}
}

func TestHermesConfigFailsClosedOnUnsafeOrOversizedInput(t *testing.T) {
	for _, content := range [][]byte{
		[]byte("auxiliary:\n  dev@example.com:\n    provider: main\n"),
		[]byte("model: [not-a-route]\n"),
		[]byte("model:\n  provider: custom\n  base_url: https://api.example/v1\nmcp_servers:\n  ambiguous:\n    command: npx\n    url: https://mcp.example/rpc\n"),
		make([]byte, maxHermesConfigBytes+1),
	} {
		if _, _, err := ParseHermesConfig(content); err == nil {
			t.Fatal("unsafe Hermes configuration was accepted")
		}
	}
}

func TestHermesConfigLeavesUnresolvedReferencesUnknown(t *testing.T) {
	slots, _, err := ParseHermesConfig([]byte("model:\n  provider: custom\n  base_url: ${MODEL_BASE_URL}\nmcp_servers:\n  remote:\n    url: ${env:MCP_URL}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range slots {
		if slot.Protocol != domain.ProtocolUnknown || slot.BaseURL != "" {
			t.Fatalf("unresolved route guessed: %+v", slot)
		}
	}
}

func TestHermesConfigReadsDefaultModelAndMergesLegacyFallbacks(t *testing.T) {
	content := []byte(`
model:
  default: primary-model
  provider: custom
  base_url: https://primary.example/v1
fallback_providers:
  - provider: first
    model: one
    base_url: https://one.example/v1
fallback_model:
  - provider: first
    model: one
    base_url: https://one.example/v1/
  - provider: second
    model: two
    base_url: https://two.example/v1
`)
	slots, _, err := ParseHermesConfig(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 3 || slots[0].Metadata["model_ref"] != "primary-model" || slots[1].Metadata["model_ref"] != "one" || slots[2].Metadata["model_ref"] != "two" {
		t.Fatalf("slots=%+v", slots)
	}
}

func TestHermesConfigAcceptsCurrentScalarPrimaryModel(t *testing.T) {
	slots, _, err := ParseHermesConfig([]byte("model: openrouter/example-model\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 1 || slots[0].Metadata["model_ref"] != "openrouter/example-model" || slots[0].Protocol != domain.ProtocolUnknown || slots[0].BaseURL != "" {
		t.Fatalf("scalar primary model was guessed or lost: %+v", slots)
	}
}
