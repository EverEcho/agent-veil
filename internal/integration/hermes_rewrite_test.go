package integration

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRewriteHermesConfigBindsEverySurfaceIndependently(t *testing.T) {
	slots, _, err := ParseHermesConfig([]byte(hermesConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	bindings := make(map[string]HermesRouteBinding, len(slots))
	for index, slot := range slots {
		bindings[slot.ID] = HermesRouteBinding{RouteID: "route-" + slot.ID, Token: strings.Repeat(string(rune('a'+index)), 64)}
	}
	rewritten, err := RewriteHermesConfig([]byte(hermesConfigFixture), "http://127.0.0.1:44123", "session-1234567890abcdef", bindings)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := yaml.Unmarshal(rewritten, &config); err != nil {
		t.Fatal(err)
	}
	model := config["model"].(map[string]any)
	if model["provider"] != "custom" || model["base_url"] != "http://127.0.0.1:44123/route/route-primary/v1" || model["api_mode"] != "chat_completions" {
		t.Fatalf("primary route was not safely rewritten: %+v", model)
	}
	providers := config["providers"].(map[string]any)
	if len(providers) != 8 {
		t.Fatalf("provider count=%d, want original plus seven protected header bindings", len(providers))
	}
	protected := providers["agentveil_aux_vision"].(map[string]any)
	headers := protected["extra_headers"].(map[string]any)
	if protected["base_url"] != "http://127.0.0.1:44123/route/route-aux-vision/v1" || headers["X-Veil-Session"] != "session-1234567890abcdef" || headers["X-Veil-Route-Token"] != bindings["aux-vision"].Token {
		t.Fatalf("auxiliary capability binding=%+v", protected)
	}
	delegation := config["delegation"].(map[string]any)
	if delegation["provider"] != "corp" || delegation["base_url"] != "http://127.0.0.1:44123/route/route-delegation" || delegation["api_mode"] != "anthropic_messages" {
		t.Fatalf("delegation provider semantics were lost: %+v", delegation)
	}
	mcp := config["mcp_servers"].(map[string]any)["research"].(map[string]any)
	mcpHeaders := mcp["headers"].(map[string]any)
	if mcp["url"] != "http://127.0.0.1:44123/route/route-mcp-research/mcp" || mcpHeaders["Authorization"] != "Bearer must-never-enter-the-manifest" || mcpHeaders["X-Veil-Route-Token"] != bindings["mcp-research"].Token {
		t.Fatalf("MCP route or original auth headers were lost: %+v", mcp)
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
	config := []byte("model:\n  provider: custom\n  model: x\n  base_url: https://one.example/v1\n  api_mode: chat_completions\nfallback_providers:\n  - provider: custom\n    model: y\n    base_url: https://two.example/v1\n    api_mode: chat_completions\n")
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
	config := []byte("model:\n  provider: custom\n  model: x\n  base_url: https://one.example/v1\n  api_mode: chat_completions\nfallback_providers:\n  - provider: custom\n    model: y\n    base_url: https://two.example/v1\n    api_mode: chat_completions\n")
	token := strings.Repeat("a", 64)
	bindings := map[string]HermesRouteBinding{
		"primary":    {RouteID: "route-primary", Token: token},
		"fallback-1": {RouteID: "route-fallback", Token: token},
	}
	if _, err := RewriteHermesConfig(config, "http://127.0.0.1:44123", "session-1234567890abcdef", bindings); err == nil {
		t.Fatal("duplicate route token was accepted")
	}
}
