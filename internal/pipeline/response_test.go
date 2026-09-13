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
	result, err := ProcessResponseDetailed(domain.ProtocolOpenAIResponses, "application/json", []byte(`{"output_text":"ghp_abcdefghijklmnopqrstuvwxyz"}`), detector.NewDefault(), vault)
	if err == nil || len(result.Findings) != 1 || result.Findings[0].Category != "secret.github_pat" || len(result.Body) != 0 {
		t.Fatalf("new response secret was not safely reported: result=%+v err=%v", result, err)
	}
}

func TestResponseProtocolErrorsCannotEchoSensitiveContent(t *testing.T) {
	for _, protocolType := range []domain.Protocol{domain.ProtocolOpenAIChat, domain.ProtocolOpenAIResponses, domain.ProtocolAnthropic, domain.ProtocolGemini, domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable} {
		vault, _ := redactor.NewVault([]byte(strings.Repeat("a", 32)), redactor.Limits{MaxEntries: 1, MaxOriginalBytes: 100})
		body := []byte(`{"error":{"message":"request contained dev@example.com"}}`)
		if _, err := ProcessResponse(protocolType, "application/json", body, detector.NewDefault(), vault); err == nil {
			t.Fatalf("protocol %s returned a sensitive error payload", protocolType)
		}
	}
}
