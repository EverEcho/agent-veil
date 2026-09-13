package integration

import (
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
	"gopkg.in/yaml.v3"
)

const hermesProtectedConfigFixture = `
model:
  provider: openai-codex
  model: gpt-5
  base_url: https://chatgpt.com/backend-api/codex
  api_mode: codex_responses
fallback_providers:
  - provider: openai-codex
    model: gpt-5-mini
auxiliary:
  vision:
    provider: main
    model: gpt-5
delegation:
  provider: auto
  model: gpt-5
mcp_servers:
  research:
    url: https://mcp.example/mcp
    headers:
      Authorization: Bearer must-never-enter-the-manifest
`

func TestRewriteHermesConfigBindsEverySurfaceIndependently(t *testing.T) {
	slots, _, err := ParseHermesConfig([]byte(hermesProtectedConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	bindings := make(map[string]HermesRouteBinding, len(slots))
	for index, slot := range slots {
		bindings[slot.ID] = HermesRouteBinding{RouteID: "route-" + slot.ID, Token: strings.Repeat(string(rune('a'+index)), 64)}
	}
	rewritten, err := RewriteHermesConfig([]byte(hermesProtectedConfigFixture), "http://127.0.0.1:44123", "session-1234567890abcdef", bindings)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := yaml.Unmarshal(rewritten, &config); err != nil {
		t.Fatal(err)
	}
	model := config["model"].(map[string]any)
	primaryURL := hermesProtectedBaseURL("http://127.0.0.1:44123", bindings["primary"].RouteID, slots[0].Protocol, false, "session-1234567890abcdef", bindings["primary"].Token)
	if model["provider"] != "openai-codex" || model["base_url"] != primaryURL || model["api_mode"] != "codex_responses" {
		t.Fatalf("primary route was not safely rewritten: %+v", model)
	}
	auxURL := hermesProtectedBaseURL("http://127.0.0.1:44123", bindings["aux-vision"].RouteID, slots[2].Protocol, false, "session-1234567890abcdef", bindings["aux-vision"].Token)
	vision := config["auxiliary"].(map[string]any)["vision"].(map[string]any)
	if vision["base_url"] != auxURL || vision["provider"] != "custom" {
		t.Fatalf("auxiliary capability binding=%+v", vision)
	}
	if providers, exists := config["providers"].(map[string]any); exists && len(providers) != 0 {
		t.Fatalf("model capability headers must not duplicate path capabilities: %+v", providers)
	}
	delegation := config["delegation"].(map[string]any)
	delegationURL := hermesProtectedBaseURL("http://127.0.0.1:44123", bindings["delegation"].RouteID, domain.ProtocolOpenAIResponses, false, "session-1234567890abcdef", bindings["delegation"].Token)
	if delegation["provider"] != "custom" || delegation["base_url"] != delegationURL || delegation["api_mode"] != "codex_responses" {
		t.Fatalf("delegation route was not converted to the protected Codex adapter: %+v", delegation)
	}
	mcp := config["mcp_servers"].(map[string]any)["research"].(map[string]any)
	mcpHeaders := mcp["headers"].(map[string]any)
	if mcp["url"] != "http://127.0.0.1:44123/route/route-mcp-research/mcp" || mcpHeaders["Authorization"] != "Bearer must-never-enter-the-manifest" || mcpHeaders["X-Veil-Route-Token"] != bindings["mcp-research"].Token {
		t.Fatalf("MCP route or original auth headers were lost: %+v", mcp)
	}
}

func TestRewriteHermesConfigExpandsAutoProviderBeforePinningRoute(t *testing.T) {
	config := []byte("model:\n  provider: openai-codex\n  model: gpt-5\n  base_url: https://chatgpt.com/backend-api/codex\n  api_mode: codex_responses\nauxiliary:\n  monitor:\n    provider: auto\n")
	tokenA := strings.Repeat("a", 64)
	tokenB := strings.Repeat("b", 64)
	rewritten, err := RewriteHermesConfig(config, "http://127.0.0.1:44123", "session-1234567890abcdef", map[string]HermesRouteBinding{
		"primary":     {RouteID: "route-primary", Token: tokenA},
		"aux-monitor": {RouteID: "route-monitor", Token: tokenB},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := yaml.Unmarshal(rewritten, &decoded); err != nil {
		t.Fatal(err)
	}
	monitor := decoded["auxiliary"].(map[string]any)["monitor"].(map[string]any)
	monitorURL := hermesProtectedBaseURL("http://127.0.0.1:44123", "route-monitor", domain.ProtocolOpenAIResponses, false, "session-1234567890abcdef", tokenB)
	if monitor["provider"] != "custom" || monitor["base_url"] != monitorURL || monitor["api_mode"] != "codex_responses" {
		t.Fatalf("auto provider was not pinned safely: %+v", monitor)
	}
}

func TestRewriteHermesConfigFailsClosed(t *testing.T) {
	valid := []byte("model:\n  provider: custom\n  model: x\n  base_url: https://api.example/v1\n  api_mode: chat_completions\n")
	binding := map[string]HermesRouteBinding{"primary": {RouteID: "route-primary", Token: strings.Repeat("a", 64)}}
	tests := []struct {
		name     string
		content  []byte
		bindings map[string]HermesRouteBinding
	}{
		{name: "missing binding", content: valid, bindings: map[string]HermesRouteBinding{}},
		{name: "unknown binding", content: valid, bindings: map[string]HermesRouteBinding{"primary": binding["primary"], "extra": binding["primary"]}},
		{name: "unresolved route", content: []byte("model: openrouter/example\n"), bindings: binding},
		{name: "duplicate key", content: []byte("model:\n  provider: custom\n  provider: other\n  model: x\n  base_url: https://api.example/v1\n  api_mode: chat_completions\n"), bindings: binding},
		{name: "alias", content: []byte("model: &route\n  provider: custom\n  model: x\n  base_url: https://api.example/v1\n  api_mode: chat_completions\ndelegation: *route\n"), bindings: binding},
		{name: "provider collision", content: []byte("model:\n  provider: custom\n  model: x\n  base_url: https://api.example/v1\n  api_mode: chat_completions\nproviders:\n  agentveil_primary:\n    base_url: https://attacker.example/v1\n"), bindings: binding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := RewriteHermesConfig(test.content, "http://127.0.0.1:44123", "session-1234567890abcdef", test.bindings); err == nil {
				t.Fatal("unsafe rewrite input was accepted")
			}
		})
	}
}

func TestRewriteHermesConfigRejectsDuplicateRouteCapabilities(t *testing.T) {
	config := []byte("model:\n  provider: openai-codex\n  model: x\n  base_url: https://chatgpt.com/backend-api/codex\n  api_mode: codex_responses\nfallback_providers:\n  - provider: openai-codex\n    model: y\n")
	token := strings.Repeat("a", 64)
	bindings := map[string]HermesRouteBinding{
		"primary":    {RouteID: "same-route", Token: token},
		"fallback-1": {RouteID: "same-route", Token: token},
	}
	if _, err := RewriteHermesConfig(config, "http://127.0.0.1:44123", "session-1234567890abcdef", bindings); err == nil {
		t.Fatal("duplicate route capability was accepted")
	}
}

func TestRewriteHermesConfigRejectsDuplicateRouteTokens(t *testing.T) {
	config := []byte("model:\n  provider: openai-codex\n  model: x\n  base_url: https://chatgpt.com/backend-api/codex\n  api_mode: codex_responses\nfallback_providers:\n  - provider: openai-codex\n    model: y\n")
	token := strings.Repeat("a", 64)
	bindings := map[string]HermesRouteBinding{
		"primary":    {RouteID: "route-primary", Token: token},
		"fallback-1": {RouteID: "route-fallback", Token: token},
	}
	if _, err := RewriteHermesConfig(config, "http://127.0.0.1:44123", "session-1234567890abcdef", bindings); err == nil {
		t.Fatal("duplicate route token was accepted")
	}
}
