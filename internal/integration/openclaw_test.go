package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

const openClawConfigFixture = `
{
  // OpenClaw accepts JSON5 comments and trailing commas.
  agents: {
    defaults: {
      model: {
        primary: "corp/main-model",
        fallbacks: ["anthropic/claude-fallback"],
      },
      imageModel: "vision/image-model",
      subagents: {
        model: { primary: "corp/worker", fallbacks: ["corp/worker-backup"] },
      },
    },
    entries: {
      reviewer: {
        model: { primary: "corp/reviewer", fallbacks: ["openai/gpt-fallback"] },
      },
    },
  },
  models: {
    providers: {
      corp: {
        baseUrl: "https://models.example/gateway/v1",
        apiKey: "must-never-enter-the-manifest",
        api: "openai-completions",
      },
      vision: {
        baseUrl: "https://vision.example/v1", /* block comment */
        apiKey: "another-secret",
        api: "openai-responses",
      },
    },
  },
}
`

func TestOpenClawConfigEnumeratesDefaultFallbackPurposeAndPerAgentModels(t *testing.T) {
	slots, err := ParseOpenClawConfig([]byte(openClawConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 7 {
		t.Fatalf("slots=%+v", slots)
	}
	byID := map[string]Slot{}
	for _, slot := range slots {
		byID[slot.ID] = slot
		if slot.Rewritable {
			t.Fatalf("discovery-only slot claimed rewritable coverage: %+v", slot)
		}
	}
	if byID["primary"].Protocol != domain.ProtocolOpenAIChat || byID["primary"].BaseURL != "https://models.example/gateway/v1" || !byID["primary"].Required {
		t.Fatalf("primary=%+v", byID["primary"])
	}
	if byID["image"].Type != domain.SurfaceVision || byID["image"].Protocol != domain.ProtocolOpenAIResponses {
		t.Fatalf("image=%+v", byID["image"])
	}
	if byID["primary-fallback-1"].Protocol != domain.ProtocolUnknown || byID["agent-reviewer"].Type != domain.SurfaceSubAgent {
		t.Fatalf("unconfigured fallback or per-agent model was guessed: %+v", slots)
	}
	if byID["subagent-fallback-1"].Metadata["model_ref"] != "corp/worker-backup" || byID["agent-reviewer-fallback-1"].Metadata["provider"] != "openai" {
		t.Fatalf("fallback metadata missing: %+v", slots)
	}
	encoded, _ := json.Marshal(slots)
	if strings.Contains(string(encoded), "must-never-enter") || strings.Contains(string(encoded), "another-secret") {
		t.Fatalf("credential leaked from parsed config: %s", encoded)
	}
}

func TestOpenClawConfigFailsClosedOnUnsafeInput(t *testing.T) {
	for _, content := range [][]byte{
		[]byte(`{ agents: { entries: { "dev@example.com": { model: "corp/a" } } } }`),
		[]byte(`{ agents: { defaults: { model: ["invalid"] } } }`),
		[]byte(`{ /* unterminated`),
		make([]byte, maxOpenClawConfigBytes+1),
	} {
		if _, err := ParseOpenClawConfig(content); err == nil {
			t.Fatal("unsafe OpenClaw configuration was accepted")
		}
	}
}

func TestOpenClawConfigLeavesUnresolvedProviderUnknown(t *testing.T) {
	slots, err := ParseOpenClawConfig([]byte(`{
  agents: { defaults: { model: "corp/main" } },
  models: { providers: { corp: { baseUrl: "${MODEL_BASE_URL}", api: "openai-completions" } } },
}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 1 || slots[0].Protocol != domain.ProtocolUnknown || slots[0].BaseURL != "" {
		t.Fatalf("unresolved provider was guessed: %+v", slots)
	}
}
