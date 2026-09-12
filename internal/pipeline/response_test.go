package pipeline

import (
	"encoding/json"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/redactor"
	"strings"
	"testing"
)

func TestResponseRestoresContentButNeverIntegrityFields(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 2, MaxOriginalBytes: 100})
	placeholder, _ := vault.Store("email", "dev@example.com")
	body, _ := json.Marshal(map[string]any{"content": []any{map[string]any{"type": "thinking", "thinking": placeholder, "signature": placeholder}, map[string]any{"type": "text", "text": "hello " + placeholder}}})
	result, err := ProcessResponse(domain.ProtocolAnthropic, "application/json", body, detector.NewDefault(), vault)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatal(err)
	}
	blocks := decoded["content"].([]any)
	thinking := blocks[0].(map[string]any)
	text := blocks[1].(map[string]any)
	if thinking["thinking"] != placeholder || thinking["signature"] != placeholder || !strings.Contains(text["text"].(string), "dev@example.com") {
		t.Fatalf("response=%s", result)
	}
}
func TestResponseBlocksNewSecret(t *testing.T) {
	vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
	_, err := ProcessResponse(domain.ProtocolOpenAIResponses, "application/json", []byte(`{"output_text":"ghp_abcdefghijklmnopqrstuvwxyz"}`), detector.NewDefault(), vault)
	if err == nil {
		t.Fatal("new response secret was not blocked")
	}
}
