package integration

import (
	"encoding/json"
	"fmt"
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

func TestHermesProtocolMirrors0206ConfigAliases(t *testing.T) {
	tests := map[domain.Protocol][]string{
		domain.ProtocolOpenAIChat:      {"chat_completions", "openai_chat", "openai", "openai-chat", "chat-completions", "chatcompletions"},
		domain.ProtocolOpenAIResponses: {"codex_responses", "openai_responses", "responses", "openai-responses"},
		domain.ProtocolAnthropic:       {"anthropic_messages", "anthropic", "anthropic-messages", "messages"},
	}
	for expected, aliases := range tests {
		for _, alias := range aliases {
			if actual := hermesProtocol(alias); actual != expected {
				t.Fatalf("alias %q mapped to %q, want %q", alias, actual, expected)
			}
		}
	}
	for _, unsupported := range []string{"gemini", "bedrock_converse", "codex_app_server", ""} {
		if actual := hermesProtocol(unsupported); actual != domain.ProtocolUnknown {
			t.Fatalf("unsupported Hermes transport %q mapped to %q", unsupported, actual)
		}
	}
}

func TestHermesAuxiliaryInheritsIdenticalPrimaryProviderRoute(t *testing.T) {
	slots, _, err := ParseHermesConfig([]byte(`
model:
  provider: openai-codex
  model: primary
  base_url: https://chatgpt.com/backend-api/codex
  api_mode: chat_completions
auxiliary:
  approval:
    provider: openai-codex
    model: reviewer
  dynamic:
    provider: auto
    model: selected-at-runtime
`))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Slot{}
	for _, slot := range slots {
		byID[slot.ID] = slot
	}
	approval := byID["aux-approval"]
	if approval.Protocol != domain.ProtocolOpenAIResponses || approval.BaseURL != "https://chatgpt.com/backend-api/codex" || approval.Metadata["model_ref"] != "reviewer" {
		t.Fatalf("same-provider auxiliary did not inherit primary route: %+v", approval)
	}
	dynamic := byID["aux-dynamic"]
	if dynamic.Protocol != domain.ProtocolUnknown || dynamic.BaseURL != "" {
		t.Fatalf("dynamic provider inherited an unrelated route: %+v", dynamic)
	}
}

func TestHermesRuntimeProviderProtocolPrecedence(t *testing.T) {
	tests := []struct {
		provider string
		model    string
		mode     string
		want     domain.Protocol
	}{
		{provider: "openai-codex", mode: "chat_completions", want: domain.ProtocolOpenAIResponses},
		{provider: "xai", mode: "chat_completions", want: domain.ProtocolOpenAIResponses},
		{provider: "anthropic", mode: "chat_completions", want: domain.ProtocolAnthropic},
		{provider: "minimax-oauth", mode: "chat_completions", want: domain.ProtocolAnthropic},
		{provider: "openai-api", want: domain.ProtocolOpenAIResponses},
		{provider: "minimax-cn", want: domain.ProtocolAnthropic},
		{provider: "nous", model: "anthropic/claude", want: domain.ProtocolAnthropic},
		{provider: "nous", model: "deepseek/model", want: domain.ProtocolOpenAIChat},
		{provider: "opencode-go", model: "gpt-5", mode: "chat_completions", want: domain.ProtocolUnknown},
		{provider: "azure-foundry", model: "gpt-5", mode: "chat_completions", want: domain.ProtocolUnknown},
	}
	for _, test := range tests {
		configured := hermesProtocol(test.mode)
		if actual := hermesRuntimeProtocol(test.provider, test.model, test.mode, configured); actual != test.want {
			t.Fatalf("provider=%q model=%q mode=%q mapped to %q, want %q", test.provider, test.model, test.mode, actual, test.want)
		}
	}
}

func TestHermesUserProviderOverridesBuiltinName(t *testing.T) {
	slots, _, err := ParseHermesConfig([]byte(`
providers:
  anthropic:
    api: https://custom.example/v1
    transport: openai_chat
model:
  provider: anthropic
  model: custom-model
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 1 || slots[0].Protocol != domain.ProtocolOpenAIChat || slots[0].BaseURL != "https://custom.example/v1" {
		t.Fatalf("user provider was replaced by builtin semantics: %+v", slots)
	}
}

func TestHermesFixedBuiltinProviderCanInheritURLWithoutExplicitMode(t *testing.T) {
	slots, _, err := ParseHermesConfig([]byte(`
model:
  provider: openai-codex
  model: primary
  base_url: https://chatgpt.com/backend-api/codex
auxiliary:
  approval:
    provider: openai-codex
    model: reviewer
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 2 || slots[1].Protocol != domain.ProtocolOpenAIResponses || slots[1].BaseURL != slots[0].BaseURL {
		t.Fatalf("fixed builtin route was not inherited: %+v", slots)
	}
}

func TestHermesModelSpecificProvidersDoNotInheritPrimaryRoute(t *testing.T) {
	tests := []struct {
		provider string
		protocol domain.Protocol
	}{
		{"nous", domain.ProtocolOpenAIChat},
		{"nous-portal", domain.ProtocolOpenAIChat},
		{"nousresearch", domain.ProtocolOpenAIChat},
		{"opencode-zen", domain.ProtocolUnknown},
		{"opencode-go-bridge", domain.ProtocolUnknown},
		{"opencode-free", domain.ProtocolUnknown},
		{"azure-foundry", domain.ProtocolUnknown},
		{"copilot", domain.ProtocolUnknown},
		{"github-copilot", domain.ProtocolUnknown},
	}
	for _, test := range tests {
		content := fmt.Sprintf("model:\n  provider: %s\n  model: primary\n  base_url: https://provider.example/v1\n  api_mode: chat_completions\nauxiliary:\n  review:\n    provider: %s\n    model: alternate\n", test.provider, test.provider)
		slots, _, err := ParseHermesConfig([]byte(content))
		if err != nil {
			t.Fatal(err)
		}
		if len(slots) != 2 || slots[1].Protocol != test.protocol || slots[1].BaseURL != "" {
			t.Fatalf("model-specific provider %q inherited an ambiguous route: %+v", test.provider, slots)
		}
	}
}
